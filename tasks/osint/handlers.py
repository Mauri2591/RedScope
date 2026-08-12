import json
from config import Config
from models.proyecto import Proyecto
from models.osint_ejecucion import OsintEjecucion
from db import get_db_connection
from datetime import datetime
import subprocess
import socket
import requests
import os
import dns.resolver
import dns.reversename
import dns.exception

# ══════════════════════════════════════════════════════════════════
# HELPERS GLOBALES OSINT
# ══════════════════════════════════════════════════════════════════

def _parse_multiline_config(value):
    """Limpia y parsea valores multilinea de configuración"""
    if not value:
        return []
    return [item.strip() for item in value.replace('\r\n', '\n').split('\n') if item.strip()]

def _run_osint_job(ejecucion_id, fn):
    """Wrapper para todos los jobs OSINT."""
    try:
        OsintEjecucion.mark_running(ejecucion_id)
        resultado = fn()
        OsintEjecucion.mark_completed(ejecucion_id, resultado)
    except Exception as e:
        OsintEjecucion.mark_failed(ejecucion_id, str(e))
        print(f"[OSINT ERROR] {str(e)}")

# ══════════════════════════════════════════════════════════════════
# HELPERS DNS MEJORADO (Multi-Resolver)
# ══════════════════════════════════════════════════════════════════

# IPs de resolvers DNS públicos a filtrar (no son del objetivo)
PUBLIC_DNS_IPS = {
    '8.8.8.8', '8.8.4.4',  # Google
    '1.1.1.1', '1.0.0.1',  # Cloudflare
    '9.9.9.9', '149.112.112.112',  # Quad9
    '208.67.222.222', '208.67.220.220',  # OpenDNS
    '4.4.4.4', '208.67.222.123', '208.67.220.123',  # Otros
    '1.8.8.8', '64.6.64.6', '64.6.65.6',  # Verisign
    '9.9.9.10',  # Quad9 sin filtro
}

def _resolve_domain_multi_resolver(domain):
    """
    Resuelve un dominio usando múltiples resolvers DNS.
    Retorna dict con IPs y información de resolvers.
    """
    ips_by_resolver = {}

    # Lista de resolvers públicos (IP, Nombre)
    resolvers = [
        ('8.8.8.8', 'Google'),
        ('1.1.1.1', 'Cloudflare'),
        ('9.9.9.9', 'Quad9'),
        ('208.67.222.222', 'OpenDNS'),
    ]

    # Método 1: usar dnspython si está disponible
    try:
        for resolver_ip, resolver_name in resolvers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [resolver_ip]
                resolver.timeout = 5
                resolver.lifetime = 5

                answers = resolver.resolve(domain, 'A')
                ips = [str(rdata) for rdata in answers]
                ips_by_resolver[resolver_name] = ips
                print(f"[DNS] {resolver_name} ({resolver_ip}): {ips}")
            except dns.exception.Timeout:
                print(f"[DNS] {resolver_name} ({resolver_ip}): TIMEOUT")
            except dns.exception.NXDOMAIN:
                print(f"[DNS] {resolver_name} ({resolver_ip}): NXDOMAIN")
            except Exception as e:
                print(f"[DNS] {resolver_name} ({resolver_ip}): {str(e)}")
    except ImportError:
        print("[DNS] dnspython no disponible, usando nslookup")

    # Método 2: usar nslookup (siempre como fallback)
    try:
        result = subprocess.run(
            ['nslookup', domain],
            capture_output=True,
            text=True,
            timeout=10
        )
        ips = []
        for line in result.stdout.split('\n'):
            if 'Address:' in line and not line.startswith(';'):
                ip = line.split('Address:')[1].strip()
                # Remover puerto si está presente (ej: 8.8.8.8#53)
                if '#' in ip:
                    ip = ip.split('#')[0].strip()
                if ip and not ip.startswith('#') and ':' not in ip:
                    ips.append(ip)
        if ips:
            ips_by_resolver['System'] = ips
            print(f"[DNS] System (default): {ips}")
    except Exception as e:
        print(f"[DNS] nslookup error: {e}")

    # Consolidar IPs únicas (filtrar IPs de resolvers DNS públicos)
    all_ips = set()
    for ips in ips_by_resolver.values():
        all_ips.update(ips)

    # Remover IPs de servidores DNS públicos
    all_ips = {ip for ip in all_ips if ip not in PUBLIC_DNS_IPS}

    return {
        'ips': sorted(list(all_ips)),
        'by_resolver': ips_by_resolver
    }


def _reverse_dns_multi_resolver(ip):
    """
    Intenta resolver reverso una IP usando múltiples métodos.
    Retorna dict con hostname y información de resolvers.
    """
    reverses_by_resolver = {}

    # Método 1: usar dnspython
    try:
        for resolver_ip, resolver_name in [('8.8.8.8', 'Google'), ('1.1.1.1', 'Cloudflare')]:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [resolver_ip]
                resolver.timeout = 5
                resolver.lifetime = 5

                rev_name = dns.reversename.from_address(ip)
                answers = resolver.resolve(rev_name, 'PTR')
                hostnames = [str(rdata).rstrip('.') for rdata in answers]
                reverses_by_resolver[resolver_name] = hostnames
                print(f"[Reverse DNS] {resolver_name}: {hostnames}")
            except dns.exception.Timeout:
                print(f"[Reverse DNS] {resolver_name}: TIMEOUT")
            except dns.exception.NXDOMAIN:
                print(f"[Reverse DNS] {resolver_name}: NXDOMAIN (no reverse DNS)")
            except Exception as e:
                print(f"[Reverse DNS] {resolver_name}: {str(e)}")
    except ImportError:
        print("[Reverse DNS] dnspython no disponible")

    # Método 2: usar nslookup
    try:
        result = subprocess.run(
            ['nslookup', ip],
            capture_output=True,
            text=True,
            timeout=5
        )
        hostname = None
        for line in result.stdout.split('\n'):
            if 'name =' in line:
                hostname = line.split('name =')[1].strip().rstrip('.')
                break
        if hostname and hostname != 'unknown':
            reverses_by_resolver['System'] = [hostname]
            print(f"[Reverse DNS] System: {hostname}")
    except Exception as e:
        print(f"[Reverse DNS] nslookup error: {e}")

    # Consolidar hostnames
    all_hostnames = set()
    for hostnames in reverses_by_resolver.values():
        all_hostnames.update(hostnames)

    return {
        'hostnames': sorted(list(all_hostnames)),
        'by_resolver': reverses_by_resolver,
        'status': 'success' if all_hostnames else 'no_reverse_dns'
    }

# ══════════════════════════════════════════════════════════════════
# HANDLERS OSINT
# ══════════════════════════════════════════════════════════════════

def discovery_subdominios(ejecucion_id, proyecto_id):
    """
    Descubrimiento de subdominios con subfinder - ITERATIVO

    Busca subdominios de:
    1. Dominios del scope inicial (DOMINIO configurado)
    2. Dominios descubiertos por reverse DNS en mapeo_ips

    Esto permite descubrimiento más profundo sin depender solo del scope inicial
    """
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio_scope = config.get('DOMINIO', '').strip() if config else ''

        # 1. Obtener dominios del scope inicial (OPCIONAL)
        dominios_scope = _parse_multiline_config(dominio_scope) if dominio_scope else []
        if dominios_scope:
            print(f"[discovery_subdominios] Dominios del scope: {dominios_scope}")
        else:
            print(f"[discovery_subdominios] Sin dominios configurados en DOMINIO, buscando en mapeo_ips...")

        # 2. Obtener dominios descubiertos por reverse DNS (mapeo_ips)
        # Se usan como fallback si DOMINIO no está configurado
        dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(proyecto_id)
        if dominios_from_ips:
            print(f"[discovery_subdominios] Dominios descubiertos por reverse DNS: {dominios_from_ips}")

        # 3. Combinar dominios del scope + dominios descubiertos
        todos_los_dominios = list(set(dominios_scope + dominios_from_ips))

        # 4. Validar que hay dominios para escanear
        if not todos_los_dominios:
            raise Exception("No hay dominios para escanear (DOMINIO no configurado y mapeo_ips sin resultados)")

        print(f"[discovery_subdominios] Total dominios a escanear con subfinder: {len(todos_los_dominios)}")

        subdominios = set()

        # 5. Ejecutar subfinder para cada dominio
        for dom in sorted(todos_los_dominios):
            try:
                print(f"[subfinder] Escaneando {dom}...")
                OsintEjecucion.update_resultado(ejecucion_id, {
                    "tipo": "discovery_subdominios",
                    "dominios_scope": dominios_scope,
                    "dominios_from_ips": dominios_from_ips,
                    "total_dominios_buscados": len(todos_los_dominios),
                    "total_subdominios": len(subdominios),
                    "subdominios": sorted(list(filter(None, subdominios))),
                    "estado": f"Escaneando {dom}..."
                })

                result = subprocess.run(
                    ['subfinder', '-d', dom, '-silent'],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if result.stdout:
                    nuevos = result.stdout.strip().split('\n')
                    subdominios.update(nuevos)
                    print(f"[subfinder] {dom} → {len(nuevos)} subdominios encontrados")
            except subprocess.TimeoutExpired:
                print(f"[subfinder] Timeout para {dom}")
            except Exception as e:
                print(f"[subfinder] Error en {dom}: {e}")

        subdominios = sorted(list(filter(None, subdominios)))

        return {
            "tipo": "discovery_subdominios",
            "dominios_scope": dominios_scope,
            "dominios_from_ips": dominios_from_ips,
            "total_dominios_buscados": len(todos_los_dominios),
            "total_subdominios": len(subdominios),
            "subdominios": subdominios
        }

    _run_osint_job(ejecucion_id, job)

def enumeracion_servicios(ejecucion_id, proyecto_id):
    """Enumeración de servicios con nmap - usa puertos de BD

    Fallback cascade:
    1. DOMINIO configurado
    2. Dominios descubiertos desde mapeo_ips (reverse DNS)
    3. Subdominios descubiertos
    4. Fallar si no hay datos en ninguna fuente
    """
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio_config = config.get('DOMINIO', '').strip()

        # 1. Obtener dominios del scope inicial (OPCIONAL)
        dominios_scope = _parse_multiline_config(dominio_config) if dominio_config else []
        if dominios_scope:
            print(f"[enumeracion_servicios] Dominios del scope encontrados: {dominios_scope}")
        else:
            print(f"[enumeracion_servicios] Sin dominios configurados en DOMINIO")

        # 2. Fallback: Obtener dominios descubiertos por reverse DNS (mapeo_ips)
        dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(proyecto_id)
        if dominios_from_ips:
            print(f"[enumeracion_servicios] Dominios del objetivo desde mapeo_ips: {dominios_from_ips}")

        # 3. Fallback: Obtener subdominios descubiertos
        subdominios_descubiertos = OsintEjecucion.get_discovered_subdomains(proyecto_id)
        if subdominios_descubiertos:
            print(f"[enumeracion_servicios] Subdominios descubiertos: {len(subdominios_descubiertos)}")

        # 4. Combinar todas las fuentes de dominios
        todos_los_dominios = list(set(dominios_scope + dominios_from_ips + subdominios_descubiertos))

        # 5. Validar que hay dominios para escanear
        if not todos_los_dominios:
            raise Exception("No hay dominios para escanear (DOMINIO no configurado, mapeo_ips vacío y sin subdominios descubiertos)")

        servicios = []
        puertos_dict = OsintEjecucion.top_100_common_ports()
        if not puertos_dict:
            puertos_dict = {'80': 'http', '443': 'https', '22': 'ssh', '3306': 'mysql'}

        puertos_str = ','.join(puertos_dict.keys())
        print(f"[nmap] Escaneando {len(puertos_dict)} puertos comunes en {len(todos_los_dominios)} dominios")

        for dom in todos_los_dominios:
            try:
                result_ip = subprocess.run(
                    ['nslookup', dom],
                    capture_output=True,
                    text=True,
                    timeout=15
                )

                ips = []
                for line in result_ip.stdout.split('\n'):
                    if 'Address:' in line and not line.startswith(';'):
                        ip = line.split('Address:')[1].strip()
                        if ip and not ip.startswith('#'):
                            ips.append(ip)

                for ip in ips:
                    print(f"[nmap] Escaneando {dom} ({ip})...")
                    result = subprocess.run(
                        ['nmap', '-p', puertos_str, '--open', ip],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )

                    for line in result.stdout.split('\n'):
                        if 'open' in line:
                            puerto_num = line.split('/')[0].strip()
                            servicios.append({
                                'dominio': dom,
                                'ip': ip,
                                'puerto': puerto_num,
                                'servicio': puertos_dict.get(puerto_num, 'unknown')
                            })
            except subprocess.TimeoutExpired:
                print(f"[nmap] Timeout para {dom}")
            except Exception as e:
                print(f"[nmap] Error en {dom}: {e}")

        return {
            "tipo": "enumeracion_servicios",
            "dominios_scope": dominios_scope,
            "dominios_from_ips": dominios_from_ips,
            "subdominios_descubiertos": subdominios_descubiertos,
            "total_dominios": len(todos_los_dominios),
            "total": len(servicios),
            "servicios": servicios
        }

    _run_osint_job(ejecucion_id, job)

def mapeo_ips(ejecucion_id, proyecto_id):
    """
    Mapeo y resolución de IPs mejorado con múltiples resolvers DNS.
    - Combina IPs configuradas + dominios resueltos
    - Usa múltiples resolvers (Google, Cloudflare, Quad9) para validar
    - Proporciona información detallada de reverse DNS
    """
    def job():
        config = Proyecto.get_osint_config(proyecto_id)

        ips_analizadas = []
        ips_a_analizar = set()
        resolution_metadata = {
            'dominios_resueltos': {},
            'ips_configuradas': []
        }

        # 1. Agregar IPs configuradas directamente (filtrar IPs de DNS públicos)
        ips_str = config.get('IPS', '').strip() if config else ''
        if ips_str:
            ips_configuradas = _parse_multiline_config(ips_str)
            # Filtrar IPs de resolvers DNS públicos
            ips_configuradas_filtradas = [ip for ip in ips_configuradas if ip not in PUBLIC_DNS_IPS]
            ips_a_analizar.update(ips_configuradas_filtradas)
            resolution_metadata['ips_configuradas'] = ips_configuradas_filtradas
            print(f"[mapeo_ips] IPs configuradas: {ips_configuradas_filtradas}")

        # 2. Resolver dominios configurados usando múltiples resolvers
        dominio = config.get('DOMINIO', '').strip() if config else ''
        if dominio:
            dominios = _parse_multiline_config(dominio)
            for dom in dominios:
                try:
                    print(f"[mapeo_ips] Resolviendo dominio {dom} con múltiples resolvers...")
                    resolution_result = _resolve_domain_multi_resolver(dom)

                    ips_a_analizar.update(resolution_result['ips'])
                    resolution_metadata['dominios_resueltos'][dom] = resolution_result['by_resolver']

                    print(f"[mapeo_ips] {dom} → {resolution_result['ips']}")
                except Exception as e:
                    print(f"[mapeo_ips] Error resolviendo {dom}: {e}")

        if not ips_a_analizar:
            raise Exception("No hay IPs ni dominios configurados para analizar")

        print(f"[mapeo_ips] Total IPs a analizar: {len(ips_a_analizar)}")

        # 3. Hacer reverse DNS para cada IP
        ips_success = []

        # Crear mapeo de IP → dominios que la resolvieron (sin duplicados)
        ip_to_dominios = {}
        for dom, resolvers_data in resolution_metadata['dominios_resueltos'].items():
            for ips_list in resolvers_data.values():
                for ip in ips_list:
                    if ip not in ip_to_dominios:
                        ip_to_dominios[ip] = set()
                    ip_to_dominios[ip].add(dom)

        # Convertir sets a listas ordenadas
        ip_to_dominios = {ip: sorted(list(doms)) for ip, doms in ip_to_dominios.items()}

        # Obtener dominio objetivo para validar hostnames
        dominio_objetivo = None
        dominios_config = _parse_multiline_config(dominio) if dominio else []
        if dominios_config:
            dominio_objetivo = dominios_config[0]

        for ip in sorted(ips_a_analizar):
            try:
                print(f"[mapeo_ips] Reverse DNS para {ip}...")
                reverse_result = _reverse_dns_multi_resolver(ip)

                # Tomar el primer hostname si hay múltiples, o marcar como unknown
                hostname = reverse_result['hostnames'][0] if reverse_result['hostnames'] else 'unknown'
                status = reverse_result['status']

                # Validar que sea una IP del objetivo
                # Es válido si: tiene from_domains (fue resuelto desde un dominio scope)
                # El reverse DNS puede estar bloqueado/mal configurado, pero la IP es del objetivo
                from_domains = ip_to_dominios.get(ip, [])
                hostname_valido = False

                if from_domains:
                    # IP fue resuelto desde un dominio scope = IP del objetivo (aunque reverse DNS sea del proveedor)
                    hostname_valido = True

                entry = {
                    'ip': ip,
                    'hostname': hostname,
                    'status': status,
                    'from_domains': ip_to_dominios.get(ip, []),
                    'es_valido': hostname_valido
                }
                ips_analizadas.append(entry)

                # Agregar solo los success Y válidos a la lista resumida (formato limpio)
                if status == 'success' and hostname_valido:
                    ips_success.append({
                        'ip': ip,
                        'hostname': hostname,
                        'status': status
                    })

            except Exception as e:
                print(f"[mapeo_ips] Error en reverse DNS {ip}: {e}")
                ips_analizadas.append({
                    'ip': ip,
                    'hostname': 'error',
                    'status': 'error'
                })

        return {
            "tipo": "mapeo_ips",
            "total_ips": len(ips_a_analizar),
            "total_success": len(ips_success),
            "ips_success": ips_success,
            "ips_todas": ips_analizadas
        }

    _run_osint_job(ejecucion_id, job)

def recon_cloud(ejecucion_id, proyecto_id):
    """Reconocimiento de buckets S3 y servicios cloud con fallback automático"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio_scope = config.get('DOMINIO', '').strip() if config else ''

        # 1. Obtener dominios de configuración inicial (OPCIONAL)
        dominios_config = _parse_multiline_config(dominio_scope) if dominio_scope else []
        if dominios_config:
            print(f"[recon_cloud] Dominios del scope: {dominios_config}")
        else:
            print(f"[recon_cloud] Sin DOMINIO configurado, buscando fallbacks...")

        # 2. FALLBACK 1: Dominios válidos de mapeo_ips (si DOMINIO vacío)
        dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(proyecto_id) if not dominios_config else []
        if dominios_from_ips:
            print(f"[recon_cloud] Dominios de mapeo_ips: {dominios_from_ips}")

        # 3. FALLBACK 2: Subdominios descubiertos (si DOMINIO y mapeo_ips vacíos)
        dominios_descubiertos = OsintEjecucion.get_discovered_subdomains(proyecto_id)
        if dominios_descubiertos:
            print(f"[recon_cloud] Subdominios descubiertos: {len(dominios_descubiertos)}")

        # 4. Combinar todas las fuentes
        todos_los_dominios = list(set(dominios_config + dominios_from_ips + dominios_descubiertos))

        if not todos_los_dominios:
            raise Exception("No hay dominios para escanear (DOMINIO vacío, mapeo_ips sin resultados, subdominios no descubiertos)")

        print(f"[recon_cloud] Dominios scope: {len(dominios_config)}, De mapeo_ips: {len(dominios_from_ips)}, Subdominios descubiertos: {len(dominios_descubiertos)}")
        print(f"[recon_cloud] Total dominios a escanear: {len(todos_los_dominios)}")

        recursos = []
        for dom in todos_los_dominios:
            try:
                print(f"[recon_cloud] Escaneando buckets S3 para {dom}...")
                bucket_names = _generate_bucket_candidates(dom)
                bucket_names.extend(_find_buckets_wayback(dom))
                bucket_names.extend(_find_buckets_from_ct(dom))
                # DESACTIVADO: _scan_with_wordlist es muy lento (125+ llamadas a AWS por dominio)
                # Generalmente los buckets vía wayback y CT logs son suficientes
                # bucket_names.extend(_scan_with_wordlist(dom))

                bucket_names = list(set(filter(None, bucket_names)))
                print(f"[recon_cloud] {dom} → {len(bucket_names)} candidatos de buckets")

                for bucket in bucket_names:
                    recursos.extend(_verify_bucket(bucket, dom))
            except Exception as e:
                print(f"[recon_cloud] Error escaneando {dom}: {e}")

        return {
            "tipo": "recon_cloud",
            "dominio_scope": dominio_scope,
            "total_dominios_scope": len(dominios_config),
            "total_dominios_from_ips": len(dominios_from_ips),
            "total_subdominios_descubiertos": len(dominios_descubiertos),
            "total_dominios_buscados": len(todos_los_dominios),
            "total_recursos": len(recursos),
            "recursos": recursos
        }

    _run_osint_job(ejecucion_id, job)


def _generate_bucket_candidates(dominio):
    """Genera variaciones de nombres de buckets"""
    domain_base = dominio.split('.')[0]
    domain_clean = dominio.replace('.', '-').replace('_', '-')
    domain_nodots = dominio.replace('.', '')
    company = domain_base

    candidates = [
        dominio,
        domain_clean,
        domain_nodots,
        f"{company}-bucket",
        f"bucket-{company}",
        f"{company}-aws",
        f"{company}-s3",
        f"s3-{company}",
        f"{company}-data",
        f"{company}-assets",
        f"{company}-backup",
        f"{company}-files",
        f"{company}-media",
        f"{company}-logs",
        f"{company}-public",
        f"{company}-com-ar",
        f"{company}-{dominio.split('.')[-2]}",
    ]

    return candidates


def _find_buckets_wayback(dominio):
    """Busca referencias a buckets en Wayback Machine"""
    buckets = []
    try:
        print(f"[wayback] Buscando buckets en histórico de {dominio}...")

        result = subprocess.run(
            ['waybackurls', dominio],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.stdout:
            urls = result.stdout.strip().split('\n')

            for url in urls:
                if 's3' in url.lower():
                    if 's3://' in url:
                        bucket = url.split('s3://')[1].split('/')[0]
                        if bucket and '.' not in bucket:
                            buckets.append(bucket)
                    elif 'amazonaws' in url:
                        parts = url.split('/')
                        for part in parts:
                            if 's3' in part and 'amazonaws' in part:
                                bucket = part.split('.')[0]
                                if bucket:
                                    buckets.append(bucket)

    except FileNotFoundError:
        print("[wayback] waybackurls no instalado")
    except Exception as e:
        print(f"[wayback] Error: {e}")

    return buckets


def _find_buckets_from_ct(dominio):
    """Busca buckets en subdominios vía CT logs"""
    buckets = []
    try:
        print(f"[ct-logs] Buscando subdominios de {dominio}...")

        result = subprocess.run(
            ['curl', '-s', f'https://crt.sh/?q=%.{dominio}&output=json'],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.stdout:
            try:
                certs = json.loads(result.stdout)
                subdomains = set()

                for cert in certs:
                    name_value = cert.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip()
                        if name and not name.startswith('*.'):
                            subdomains.add(name)

                for sub in subdomains:
                    buckets.append(sub.replace('.', '-'))
                    buckets.append(sub.replace('.', ''))

            except json.JSONDecodeError:
                pass

    except Exception as e:
        print(f"[ct-logs] Error: {e}")

    return buckets


def _scan_with_wordlist(dominio):
    """Fuzzing agresivo de buckets con wordlist"""
    buckets = []

    suffixes = [
        '', '-backup', '-backup-data', '-backups', '-bucket', '-aws', '-s3',
        '-data', '-files', '-assets', '-media', '-logs', '-public', '-private',
        '-test', '-dev', '-prod', '-staging', '-temp', '-archive',
        '-documents', '-images', '-storage', '-uploads', '-downloads',
        '-code', '-repo', '-git', '-source', '-build', '-dist',
    ]

    prefixes = ['', 'aws-', 's3-', 'bucket-', 'data-']

    domain_base = dominio.split('.')[0]

    candidates = []
    for prefix in prefixes:
        for suffix in suffixes:
            candidates.append(f"{prefix}{domain_base}{suffix}")

    print(f"[fuzzing] Probando {len(candidates)} candidatos...")

    for bucket in candidates:
        try:
            result = subprocess.run(
                ['aws', 's3api', 'head-bucket', '--bucket', bucket],
                capture_output=True,
                text=True,
                timeout=3
            )
            if result.returncode == 0:
                buckets.append(bucket)
                print(f"✓ Encontrado: {bucket}")
        except:
            pass

    return buckets


def _check_bucket_anonymous_access(bucket_name):
    """Verifica si el bucket permite acceso anónimo (sin credenciales AWS)"""
    try:
        # Intentar listar bucket via HTTP anónimo
        url = f"https://{bucket_name}.s3.amazonaws.com/"
        result = subprocess.run(
            ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', url],
            capture_output=True,
            text=True,
            timeout=5
        )

        http_code = result.stdout.strip()

        # 200 = acceso público, 403 = privado, 404 = no existe
        if http_code == '200':
            return 'anónimo'  # ← BUCKET ABIERTO AL PÚBLICO
        elif http_code == '403':
            return 'privado'
        else:
            return 'desconocido'
    except:
        return 'error'

def _verify_bucket(bucket_name, dominio):
    """Verifica si un bucket existe y obtiene info + acceso anónimo"""
    resultado = []

    try:
        result = subprocess.run(
            ['aws', 's3', 'ls', f"s3://{bucket_name}", '--max-items', '1'],
            capture_output=True,
            text=True,
            timeout=5
        )

        # Verificar acceso anónimo (sin credenciales)
        acceso_anonimo = _check_bucket_anonymous_access(bucket_name)

        if result.returncode == 0:
            resultado.append({
                'tipo': 's3_bucket',
                'nombre': bucket_name,
                'dominio': dominio,
                'acceso': 'público_o_auth',
                'acceso_anonimo': acceso_anonimo,
                'estado': 'existe'
            })
        elif 'NoSuchBucket' not in result.stderr:
            resultado.append({
                'tipo': 's3_bucket',
                'nombre': bucket_name,
                'dominio': dominio,
                'acceso': 'privado',
                'acceso_anonimo': acceso_anonimo,
                'estado': 'existe'
            })

    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        pass

    return resultado

def escaneo_repositorios(ejecucion_id, proyecto_id):
    """Búsqueda de secretos en repositorios públicos con fallback automático"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio_scope = config.get('DOMINIO', '').strip() if config else ''

        # 1. Obtener dominios de configuración inicial (OPCIONAL)
        dominios_config = _parse_multiline_config(dominio_scope) if dominio_scope else []
        if dominios_config:
            print(f"[escaneo_repositorios] Dominios del scope: {dominios_config}")
        else:
            print(f"[escaneo_repositorios] Sin DOMINIO configurado, buscando fallbacks...")

        # 2. FALLBACK 1: Dominios válidos de mapeo_ips (si DOMINIO vacío)
        dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(proyecto_id) if not dominios_config else []
        if dominios_from_ips:
            print(f"[escaneo_repositorios] Dominios de mapeo_ips: {dominios_from_ips}")

        # 3. Subdominios descubiertos (solo para información, NO para búsqueda)
        dominios_descubiertos = OsintEjecucion.get_discovered_subdomains(proyecto_id)
        if dominios_descubiertos:
            print(f"[escaneo_repositorios] Subdominios descubiertos: {len(dominios_descubiertos)}")

        # 4. ⚠️ IMPORTANTE: Solo buscar dominios RAÍZ (config + mapeo_ips)
        # NO buscar subdominios descubiertos (evita falsos positivos como imap, secure, jenkins)
        dominios_para_buscar = list(set(dominios_config + dominios_from_ips))

        if not dominios_para_buscar:
            raise Exception("No hay dominios raíz para escanear (DOMINIO vacío, mapeo_ips sin resultados)")

        print(f"[escaneo_repositorios] Dominios raíz a buscar: {len(dominios_para_buscar)}")
        print(f"[escaneo_repositorios] Subdominios descubiertos (solo info): {len(dominios_descubiertos)}")

        hallazgos_raw = []
        for dom in dominios_para_buscar:
            # 1. Búsqueda en GitHub via API pública (SOLO DOMINIOS RAÍZ)
            hallazgos_raw.extend(_search_github(dom))

            # 2. Intentar con trufflehog si está instalado (SOLO DOMINIOS RAÍZ)
            hallazgos_raw.extend(_search_trufflehog(dom))

        # Deduplicar y agrupar por repositorio (con filtro de relevancia)
        hallazgos_dedup = _deduplicate_github_results(hallazgos_raw, dominios_para_buscar)

        return {
            "tipo": "escaneo_repositorios",
            "dominio_scope": dominio_scope,
            "total_dominios_scope": len(dominios_config),
            "total_dominios_from_ips": len(dominios_from_ips),
            "total_subdominios_descubiertos": len(dominios_descubiertos),
            "total_dominios_raiz_buscados": len(dominios_para_buscar),
            "total_hallazgos_unicos": len(hallazgos_dedup),
            "hallazgos": hallazgos_dedup
        }

    _run_osint_job(ejecucion_id, job)


def _search_github(dominio):
    """Busca en GitHub repositorios públicos del dominio"""
    import urllib.parse

    hallazgos = []
    GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')

    if not GITHUB_TOKEN:
        print("[github] Token no configurado en .env")
        return hallazgos

    try:
        print(f"[github] Buscando repositorios de {dominio}...")

        # Extrae el dominio base (sin www)
        dom_parts = dominio.split('.')
        if dom_parts[0].lower() == 'www' and len(dom_parts) > 2:
            domain_base = '.'.join(dom_parts[1:])  # www.ater.gob.ar → ater.gob.ar
        else:
            domain_base = dominio

        # ✅ BÚSQUEDAS INTELIGENTES: Palabra clave + archivos típicos de credenciales
        # Para "ater.gob.ar" → buscar "ater" en archivos específicos
        # Los subdominios NO se buscan individuales (evita falsos positivos)

        domain_parts = domain_base.split('.')
        keyword = domain_parts[0]  # 'ater' de 'ater.gob.ar'

        searches = [
            # 1. Búsquedas por palabra clave en archivos de credenciales
            f'filename:.env {keyword}',                    # .env files
            f'filename:.env.example {keyword}',            # .env.example files
            f'filename:config.json {keyword}',             # config.json
            f'filename:secrets.json {keyword}',            # secrets.json
            f'filename:credentials.json {keyword}',        # credentials.json
            f'filename:.postman_collection.json {keyword}',# Postman collections
            f'filename:docker-compose.yml {keyword}',      # docker-compose

            # 2. Búsquedas generales
            f'{keyword} API_KEY',
            f'{keyword} SECRET',
            f'{keyword} PASSWORD',
            f'{keyword} TOKEN',
            f'{keyword} CREDENTIALS',

            # 3. Variantes comunes del nombre
            f'"{keyword}apps"',                            # aterapps
            f'"{keyword}-api"',                            # ater-api
            f'"customer-{keyword}"',                       # customer-ater

            # 4. Búsquedas por dominio
            f'"{domain_base}"',                            # "ater.gob.ar"
        ]

        for search_query in searches:
            try:
                # URL encode la query
                encoded_query = urllib.parse.quote(search_query)
                
                result = subprocess.run(
                    ['curl', '-s', '-H', f'Authorization: token {GITHUB_TOKEN}',
                     f'https://api.github.com/search/code?q={encoded_query}&per_page=10'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.stdout:
                    data = json.loads(result.stdout)
                    items = data.get('items', [])

                    for item in items:
                        hallazgos.append({
                            'tipo': 'github_repo',
                            'nombre': item.get('name', ''),
                            'url': item.get('html_url', ''),
                            'repo': item.get('repository', {}).get('full_name', ''),
                            'query': search_query
                        })
            except Exception as e:
                print(f"[github] Error en query '{search_query}': {e}")

    except Exception as e:
        print(f"[github] Error: {e}")

    return hallazgos


def _generate_domain_variants(dominios):
    """Genera todas las variantes posibles de uno o múltiples dominios

    Ejemplo: ['capacita.ater.gob.ar', 'www.ater.gob.ar'] genera:
    - capacita.ater.gob.ar, ater.gob.ar, capacita.ater.gob, ater.gob, capacita.ater, ater
    - www.ater.gob.ar, ater.gob.ar, www.ater.gob, ater.gob, www.ater, ater
    """
    variants = set()

    # Si recibe string, convertir a lista
    if isinstance(dominios, str):
        dominios = [dominios.strip()]
    else:
        dominios = [d.strip() for d in dominios if d.strip()]

    for dominio in dominios:
        parts = dominio.lower().split('.')

        # Agregar el dominio completo
        variants.add(dominio.lower())

        # Generar todas las combinaciones eliminando partes desde el inicio
        for i in range(1, len(parts)):
            variant = '.'.join(parts[i:])
            variants.add(variant)

        # Agregar cada palabra individual (útil para búsquedas en repos)
        for part in parts:
            if part and len(part) > 2:  # Ignorar TLDs cortos
                variants.add(part)

    return variants


def _deduplicate_github_results(hallazgos_raw, dominio=''):
    """Deduplica y agrupa hallazgos por repositorio, filtrando SOLO repos relevantes"""
    repos_dict = {}

    # Generar todas las variantes del dominio
    domain_variants = set()
    if dominio:
        domain_variants = _generate_domain_variants(dominio)
        print(f"[github] Variantes de dominio (ANTES): {sorted(domain_variants)}")

        # ✅ ARREGLO 2: Remover palabras cortas que causan falsos positivos
        # Mantener solo variantes que:
        # - Contienen un punto (son dominios con múltiples partes)
        # - O tienen más de 3 caracteres (como 'ater')
        domain_variants = {v for v in domain_variants if '.' in v or len(v) > 3}
        print(f"[github] Variantes de dominio (DESPUÉS): {sorted(domain_variants)}")

    for item in hallazgos_raw:
        if item.get('tipo') != 'github_repo':
            continue

        repo = item.get('repo', '').replace('[', '').replace('](', '/').replace(')', '')
        if not repo:
            continue

        repo_lower = repo.lower()

        # Filtro 1: El nombre del repo DEBE contener una variante del dominio
        # PERMISIVO: trae de más, el pentester limpia lo que no sirve
        if domain_variants:
            has_variant = any(var in repo_lower for var in domain_variants)
            if not has_variant:
                continue

        # Filtro 2: Remover repos que sean claramente no relacionados
        # (incluso si mencionan el dominio, no son de ATER)
        exclusion_keywords = [
            'privatdb', 'gfw', 'piiexel', 'random', 'immobiliaria',
            'cerosmrt', 'pasxalisk', 'rahultop', 'swrdfgd'
        ]
        if any(excl in repo_lower for excl in exclusion_keywords):
            print(f"[github] Rechazado (exclusion list): {repo}")
            continue

        if repo not in repos_dict:
            repos_dict[repo] = {
                'tipo': 'github_repo',
                'repo': repo,
                'url': f'https://github.com/{repo}',
                'archivos': set(),
                'queries': set()
            }

        # Agregar archivo si existe
        if item.get('nombre'):
            repos_dict[repo]['archivos'].add(item.get('nombre'))

        # Agregar query
        if item.get('query'):
            repos_dict[repo]['queries'].add(item.get('query'))

    # Convertir sets a listas ordenadas
    resultado = []
    for repo, data in sorted(repos_dict.items()):
        resultado.append({
            'tipo': data['tipo'],
            'repo': repo,
            'url': data['url'],
            'queries_encontradas': len(data['queries']),
            'queries': sorted(list(data['queries'])),
            'archivos': sorted(list(data['archivos']))
        })

    return resultado


def _search_trufflehog(dominio):
    """Placeholder - La búsqueda en GitHub ya proporciona resultados suficientes"""
    print(f"[osint] Búsqueda de secretos via GitHub API completada en _search_github")
    return []

def analisis_dns(ejecucion_id, proyecto_id):
    """Análisis de registros DNS con dig

    Fallback cascade:
    1. DOMINIO configurado
    2. Dominios descubiertos desde mapeo_ips (reverse DNS)
    3. Subdominios descubiertos
    4. Fallar si no hay datos en ninguna fuente
    """
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio_config = config.get('DOMINIO', '').strip()

        # 1. Obtener dominios del scope inicial (OPCIONAL)
        dominios_scope = _parse_multiline_config(dominio_config) if dominio_config else []
        if dominios_scope:
            print(f"[analisis_dns] Dominios del scope encontrados: {dominios_scope}")
        else:
            print(f"[analisis_dns] Sin dominios configurados en DOMINIO")

        # 2. Fallback: Obtener dominios descubiertos por reverse DNS (mapeo_ips)
        dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(proyecto_id)
        if dominios_from_ips:
            print(f"[analisis_dns] Dominios del objetivo desde mapeo_ips: {dominios_from_ips}")

        # 3. Fallback: Obtener subdominios descubiertos
        subdominios_descubiertos = OsintEjecucion.get_discovered_subdomains(proyecto_id)
        if subdominios_descubiertos:
            print(f"[analisis_dns] Subdominios descubiertos: {len(subdominios_descubiertos)}")

        # 4. Combinar todas las fuentes de dominios
        todos_los_dominios = list(set(dominios_scope + dominios_from_ips + subdominios_descubiertos))

        # 5. Validar que hay dominios para escanear
        if not todos_los_dominios:
            raise Exception("No hay dominios para escanear (DOMINIO no configurado, mapeo_ips vacío y sin subdominios descubiertos)")

        registros = {}
        tipos = ['A', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        print(f"[dig] Analizando {len(todos_los_dominios)} dominios - tipos: {tipos}")

        for dom in todos_los_dominios:
            registros[dom] = {}

            for tipo in tipos:
                try:
                    result = subprocess.run(
                        ['dig', dom, tipo, '+short'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.stdout.strip():
                        registros[dom][tipo] = result.stdout.strip().split('\n')
                except Exception as e:
                    print(f"[dig] Error consultando {tipo} para {dom}: {e}")

        return {
            "tipo": "analisis_dns",
            "dominios_scope": dominios_scope,
            "dominios_from_ips": dominios_from_ips,
            "subdominios_descubiertos": subdominios_descubiertos,
            "total_dominios": len(todos_los_dominios),
            "registros": registros
        }

    _run_osint_job(ejecucion_id, job)

def busqueda_endpoints(ejecucion_id, proyecto_id):
    """Búsqueda de endpoints - múltiples estrategias (waybackurls, fuzzing, GitHub)

    Fallback cascade:
    1. DOMINIO configurado
    2. Dominios descubiertos desde mapeo_ips (reverse DNS)
    3. Subdominios descubiertos
    4. Fallar si no hay datos en ninguna fuente
    """
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio_config = config.get('DOMINIO', '').strip()

        # 1. Obtener dominios del scope inicial (OPCIONAL)
        dominios_scope = _parse_multiline_config(dominio_config) if dominio_config else []
        if dominios_scope:
            print(f"[busqueda_endpoints] Dominios del scope encontrados: {dominios_scope}")
        else:
            print(f"[busqueda_endpoints] Sin dominios configurados en DOMINIO")

        # 2. Fallback: Obtener dominios descubiertos por reverse DNS (mapeo_ips)
        dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(proyecto_id)
        if dominios_from_ips:
            print(f"[busqueda_endpoints] Dominios del objetivo desde mapeo_ips: {dominios_from_ips}")

        # 3. Fallback: Obtener subdominios descubiertos
        subdominios_descubiertos = OsintEjecucion.get_discovered_subdomains(proyecto_id)
        if subdominios_descubiertos:
            print(f"[busqueda_endpoints] Subdominios descubiertos: {len(subdominios_descubiertos)}")

        # 4. Combinar todas las fuentes de dominios
        todos_los_dominios = list(set(dominios_scope + dominios_from_ips + subdominios_descubiertos))

        # 5. Validar que hay dominios para escanear
        if not todos_los_dominios:
            raise Exception("No hay dominios para escanear (DOMINIO no configurado, mapeo_ips vacío y sin subdominios descubiertos)")

        endpoints = set()
        print(f"[busqueda_endpoints] Buscando endpoints en {len(todos_los_dominios)} dominios...")

        for dom in todos_los_dominios:
            print(f"[busqueda_endpoints] Escaneando {dom}...")

            # 1. Wayback Machine (URLs históricas)
            endpoints.update(_search_waybackurls(dom))

            # 2. Fuzzing de directorios comunes
            endpoints.update(_fuzz_common_endpoints(dom))

            # 3. Búsqueda en GitHub (código que referencia endpoints)
            endpoints.update(_search_github_endpoints(dom))

        endpoints = sorted(list(filter(None, endpoints)))

        return {
            "tipo": "busqueda_endpoints",
            "dominios_scope": dominios_scope,
            "dominios_from_ips": dominios_from_ips,
            "subdominios_descubiertos": subdominios_descubiertos,
            "total_dominios": len(todos_los_dominios),
            "total": len(endpoints),
            "endpoints": endpoints
        }

    _run_osint_job(ejecucion_id, job)


def _search_waybackurls(dominio):
    """Busca URLs en Wayback Machine"""
    endpoints = set()
    try:
        print(f"[waybackurls] Buscando en Wayback Machine para {dominio}...")
        result = subprocess.run(
            ['waybackurls', dominio],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.stdout:
            urls = result.stdout.strip().split('\n')
            endpoints.update([url for url in urls if url])
            print(f"[waybackurls] Encontrados {len(endpoints)} endpoints")
    except FileNotFoundError:
        print(f"[waybackurls] No instalado (instalar: go install github.com/tomnomnom/waybackurls@latest)")
    except subprocess.TimeoutExpired:
        print(f"[waybackurls] Timeout")
    except Exception as e:
        print(f"[waybackurls] Error: {e}")

    return endpoints


def _fuzz_common_endpoints(dominio):
    """Fuzzing de directorios/endpoints comunes"""
    endpoints = set()

    # Palabras clave comunes en APIs y aplicaciones
    common_paths = [
        '/api', '/api/v1', '/api/v2', '/api/v3',
        '/admin', '/admin/panel', '/admin/dashboard',
        '/login', '/signin', '/logout',
        '/users', '/user', '/profile', '/account',
        '/search', '/query', '/data', '/list',
        '/backup', '/backups', '/export',
        '/config', '/configuration', '/settings',
        '/test', '/debug', '/status', '/health',
        '/wp-admin', '/wp-login.php',
        '/.git', '/.svn', '/.env',
        '/swagger', '/swagger-ui', '/api-docs',
        '/actuator', '/graphql', '/graphiql',
        '/rest', '/service', '/services',
        '/download', '/upload', '/file',
        '/webhook', '/webhooks',
        '/oauth', '/auth', '/authorize',
        '/api/auth', '/api/login', '/api/token',
    ]

    print(f"[fuzzing] Probando {len(common_paths)} endpoints comunes en {dominio}...")

    # Status codes que indican que el endpoint EXISTE
    valid_status_codes = ['200', '201', '204', '301', '302', '307', '308', '400', '401', '403', '405']

    for path in common_paths:
        url = f"https://{dominio}{path}"
        try:
            result = subprocess.run(
                ['curl', '-s', '-I', '-m', '3', '--insecure', url],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                # Extraer el status code de la respuesta
                status_code = None
                for line in result.stdout.split('\n'):
                    if line.startswith('HTTP'):
                        # Extraer código: "HTTP/1.1 200 OK" → "200"
                        parts = line.split()
                        if len(parts) >= 2:
                            status_code = parts[1]
                            break

                # Solo agregar si el status code indica que existe
                if status_code and status_code in valid_status_codes:
                    endpoint_info = f"{url} [{status_code}]"
                    endpoints.add(endpoint_info)
                    print(f"✓ {endpoint_info}")
        except:
            pass

    print(f"[fuzzing] Encontrados {len(endpoints)} endpoints activos (status válido)")
    return endpoints


def _search_github_endpoints(dominio):
    """Busca referencias a endpoints en GitHub"""
    endpoints = set()
    GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')

    if not GITHUB_TOKEN:
        print("[github] Token no configurado, saltando búsqueda de endpoints en GitHub")
        return endpoints

    try:
        print(f"[github] Buscando endpoints en GitHub para {dominio}...")
        import urllib.parse

        # Buscar patterns de rutas en código
        searches = [
            f'"{dominio}/api',
            f'"/api/{dominio.split(".")[0]}',
            f'endpoint.*{dominio}',
        ]

        for search_query in searches:
            try:
                encoded_query = urllib.parse.quote(search_query)
                result = subprocess.run(
                    ['curl', '-s', '-H', f'Authorization: token {GITHUB_TOKEN}',
                     f'https://api.github.com/search/code?q={encoded_query}&per_page=5'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.stdout:
                    data = json.loads(result.stdout)
                    items = data.get('items', [])

                    for item in items:
                        # Extraer URLs/paths del código
                        url = item.get('html_url', '')
                        if url:
                            endpoints.add(url)
            except:
                pass

        print(f"[github] Encontrados {len(endpoints)} referencias en GitHub")
    except Exception as e:
        print(f"[github] Error: {e}")

    return endpoints

def google_dorking(ejecucion_id, proyecto_id):
    """Google Dorking - búsquedas especializadas con resultados reales

    Fallback cascade:
    1. DOMINIO configurado
    2. Dominios descubiertos desde mapeo_ips (reverse DNS)
    3. Subdominios descubiertos
    4. Fallar si no hay datos en ninguna fuente
    """
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio_config = config.get('DOMINIO', '').strip()

        # 1. Obtener dominios del scope inicial (OPCIONAL)
        dominios_scope = _parse_multiline_config(dominio_config) if dominio_config else []
        if dominios_scope:
            print(f"[google_dorking] Dominios del scope encontrados: {dominios_scope}")
        else:
            print(f"[google_dorking] Sin dominios configurados en DOMINIO")

        # 2. Fallback: Obtener dominios descubiertos por reverse DNS (mapeo_ips)
        dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(proyecto_id)
        if dominios_from_ips:
            print(f"[google_dorking] Dominios del objetivo desde mapeo_ips: {dominios_from_ips}")

        # 3. Fallback: Obtener subdominios descubiertos
        subdominios_descubiertos = OsintEjecucion.get_discovered_subdomains(proyecto_id)
        if subdominios_descubiertos:
            print(f"[google_dorking] Subdominios descubiertos: {len(subdominios_descubiertos)}")

        # 4. Combinar todas las fuentes de dominios
        todos_los_dominios = list(set(dominios_scope + dominios_from_ips + subdominios_descubiertos))

        # 5. Validar que hay dominios para escanear
        if not todos_los_dominios:
            raise Exception("No hay dominios para escanear (DOMINIO no configurado, mapeo_ips vacío y sin subdominios descubiertos)")

        resultados = []
        print(f"[google_dorking] Ejecutando dorks en {len(todos_los_dominios)} dominios...")

        for dom in todos_los_dominios:
            # Dorks comunes para encontrar información sensible
            dorks = [
                f'site:{dom} inurl:admin',
                f'site:{dom} filetype:pdf',
                f'site:{dom} inurl:login',
                f'site:{dom} "password"',
                f'site:{dom} inurl:backup',
                f'site:{dom} inurl:config',
                f'site:{dom} filetype:xlsx',
                f'site:{dom} filetype:docx',
                f'site:{dom} "api_key"',
                f'site:{dom} "secret"',
            ]

            for dork in dorks:
                hallazgos = _ejecutar_google_dork(dom, dork)
                resultados.extend(hallazgos)

        return {
            "tipo": "google_dorking",
            "dominios_scope": dominios_scope,
            "dominios_from_ips": dominios_from_ips,
            "subdominios_descubiertos": subdominios_descubiertos,
            "total_dominios": len(todos_los_dominios),
            "total": len(resultados),
            "resultados": resultados
        }

    _run_osint_job(ejecucion_id, job)


def _ejecutar_google_dork(dominio, dork_query):
    """Ejecuta un dork en Google y obtiene resultados"""
    resultados = []
    try:
        print(f"[google] Ejecutando dork: {dork_query}")

        # Usar curl con User-Agent para simular navegador
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        # Construir URL de búsqueda (sin usar API oficial)
        search_url = f'https://www.google.com/search?q={dork_query}'

        result = subprocess.run(
            ['curl', '-s', '-H', f'User-Agent: {headers["User-Agent"]}', search_url],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.stdout:
            # Extraer URLs del HTML
            import re
            # Patrón para encontrar URLs en resultados de Google
            url_pattern = r'href="(/url\?q=([^"&]+))'
            matches = re.findall(url_pattern, result.stdout)

            for match in matches[:5]:  # Top 5 resultados
                try:
                    url = match[1]
                    # Decodificar URL si es necesario
                    if url and not url.startswith('http'):
                        url = 'http://' + url

                    resultados.append({
                        'dork': dork_query,
                        'dominio': dominio,
                        'url': url,
                        'tipo': 'google_search_result'
                    })
                except:
                    pass

    except Exception as e:
        print(f"[google] Error ejecutando dork: {e}")
        # Fallback: devolver al menos la estructura del dork
        resultados.append({
            'dork': dork_query,
            'dominio': dominio,
            'url': None,
            'tipo': 'google_search_result',
            'error': str(e)
        })

    return resultados