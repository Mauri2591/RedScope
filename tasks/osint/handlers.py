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

def _get_severidad_por_confianza(confianza_score):
    """
    Mapea confianza (0-100) a severidad de BD.

    Normaliza confianza 0-100 a score 0-10 y busca severidad correspondiente.

    Args:
        confianza_score (int): Puntuación de confianza 0-100

    Returns:
        dict: Severidad de BD con score correspondiente
    """
    try:
        severidades = Proyecto.get_severidades()

        if not severidades or len(severidades) == 0:
            return None

        # Normalizar confianza (0-100) a score (0-10)
        score_normalizado = (confianza_score / 100) * 10

        # Ordenar por score
        severidades_sorted = sorted(severidades, key=lambda x: x.get('score', 0))

        # Buscar severidad cuyo score sea <= score_normalizado
        severidad_seleccionada = severidades_sorted[0]  # Comienza con la más baja
        for sev in severidades_sorted:
            if sev.get('score', 0) <= score_normalizado:
                severidad_seleccionada = sev

        return severidad_seleccionada

    except Exception as e:
        print(f"[severidad] Error: {e}")
        return None

def _parse_multiline_config(value):
    """Limpia y parsea valores multilinea de configuración"""
    if not value:
        return []
    return [item.strip() for item in value.replace('\r\n', '\n').split('\n') if item.strip()]

def _find_gau_path():
    """Busca el ejecutable 'gau' en múltiples ubicaciones"""
    import shutil

    # 1. Primero intenta encontrar en PATH
    gau_path = shutil.which('gau')
    if gau_path:
        return gau_path

    # 2. Intenta Go bin paths comunes
    possible_paths = [
        os.path.expanduser('~/go/bin/gau'),
        '/root/go/bin/gau',
        os.path.expanduser('~/.local/go/bin/gau'),
        '/usr/local/go/bin/gau',
    ]

    for path in possible_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    # 3. Intenta desde variable de ambiente
    gau_env = os.environ.get('GAU_PATH')
    if gau_env and os.path.isfile(gau_env) and os.access(gau_env, os.X_OK):
        return gau_env

    return None

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


def _validate_hostname_belongs_to_domain(hostname, domain_objetivo, ip=None):
    """
    Valida si un hostname pertenece realmente al dominio objetivo.
    Retorna dict con validación y detalles.

    Criterios:
    1. El hostname contiene el dominio objetivo (ej: server.example.com contiene example.com)
    2. El hostname NO es un dominio genérico de proveedor (AWS, Azure, etc.)
    3. OPCIONAL: Verificar que el hostname se resuelve de vuelta a la IP (reverse validation)
    """
    validation = {
        'es_valido': False,
        'razon': 'unknown',
        'tipo_hostname': 'unknown'
    }

    if not hostname or hostname == 'unknown':
        validation['razon'] = 'sin_hostname'
        return validation

    hostname_lower = hostname.lower()
    domain_lower = domain_objetivo.lower() if domain_objetivo else ''

    # Proveedores cloud/ISPs genéricos (no son del objetivo)
    generic_providers = [
        'amazonaws.com',
        'azurewebsites.net',
        'cloudflare.com',
        'akamai.net',
        'fastly.net',
        'cloudfront.net',
        'google.com',
        'gcr.io',
        'heroku.com',
        'github.io',
        'bitbucket.io',
        'amazonaws.com.ar',
        'aws.amazon.com',
    ]

    # 1. Validar que NO sea un hostname genérico de proveedor
    if any(provider in hostname_lower for provider in generic_providers):
        validation['tipo_hostname'] = 'cloud_provider'
        validation['razon'] = f'hostname_generico_proveedor: {hostname}'
        return validation

    # 2. Validar que contenga el dominio objetivo
    if domain_lower:
        if domain_lower in hostname_lower:
            # ✓ El hostname contiene el dominio objetivo
            validation['es_valido'] = True
            validation['tipo_hostname'] = 'coincide_dominio'
            validation['razon'] = f'hostname contiene dominio objetivo: {domain_lower}'

            # BONUS: Validación opcional - verificar reverse lookup
            if ip:
                try:
                    # Intentar resolver el hostname para verificar que apunta a esta IP
                    result = subprocess.run(
                        ['nslookup', hostname],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if ip in result.stdout:
                        validation['razon'] += ' [reverse_lookup_ok]'
                    else:
                        validation['razon'] += ' [reverse_lookup_diferente]'
                except:
                    pass

            return validation
        else:
            # ✗ El hostname NO contiene el dominio objetivo
            validation['tipo_hostname'] = 'no_coincide'
            validation['razon'] = f'hostname no contiene dominio objetivo: {domain_lower}'
            return validation

    # Si no hay dominio objetivo, confiar en que no sea genérico
    validation['es_valido'] = True
    validation['tipo_hostname'] = 'sin_validacion_dominio'
    validation['razon'] = 'sin dominio objetivo para validar'
    return validation


def _geolocate_ip(ip):
    """
    Obtiene información geográfica de una IP usando ipapi.co (gratuito, sin API key)
    Retorna dict con país, ciudad, ISP, ASN
    """
    try:
        result = requests.get(
            f'https://ipapi.co/{ip}/json/',
            timeout=5
        )
        if result.status_code == 200:
            data = result.json()
            return {
                'pais': data.get('country_name', 'unknown'),
                'ciudad': data.get('city', 'unknown'),
                'isp': data.get('org', 'unknown'),
                'asn': data.get('asn', 'unknown'),
                'latitud': data.get('latitude'),
                'longitud': data.get('longitude')
            }
    except requests.exceptions.Timeout:
        print(f"[geo] Timeout para {ip}")
    except Exception as e:
        print(f"[geo] Error geolocalizando {ip}: {e}")

    return {
        'pais': 'unknown',
        'ciudad': 'unknown',
        'isp': 'unknown',
        'asn': 'unknown',
        'latitud': None,
        'longitud': None
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
    """Descubrimiento de subdominios con subfinder

    Busca subdominios de:
    1. DOMINIO + SUBDOMINIO + SERVICIOS del scope
    2. Dominios de mapeo_ips (fallback)

    Retorna SOLO subdominios descubiertos.
    """
    def job():
        # 1. Obtener scope: DOMINIO + SUBDOMINIO + SERVICIOS
        scope = OsintEjecucion.get_scope_completo(proyecto_id)
        todos_los_dominios = scope['dominio'] + scope['subdominio'] + scope['servicios']

        # 2. Fallback: Obtener dominios de mapeo_ips
        dominios_from_ips = []
        if not todos_los_dominios:
            dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(proyecto_id)
            todos_los_dominios = dominios_from_ips

        if not todos_los_dominios:
            raise Exception("No hay dominios configurados (scope vacío y mapeo_ips sin resultados)")

        subdominios = set()
        print(f"[discovery_subdominios] Escaneando {len(todos_los_dominios)} dominios con subfinder")

        for dom in sorted(todos_los_dominios):
            try:
                print(f"[subfinder] Escaneando {dom}...")
                OsintEjecucion.update_resultado(ejecucion_id, {
                    "tipo": "discovery_subdominios",
                    "dominios_scope": scope['dominio'] + scope['subdominio'] + scope['servicios'],
                    "total_dominios_escaneados": len(todos_los_dominios),
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
                    print(f"[subfinder] {dom} → {len(nuevos)} subdominios")
            except subprocess.TimeoutExpired:
                print(f"[subfinder] Timeout para {dom}")
            except Exception as e:
                print(f"[subfinder] Error en {dom}: {e}")

        subdominios = sorted(list(filter(None, subdominios)))

        return {
            "tipo": "discovery_subdominios",
            "dominios_scope": scope['dominio'] + scope['subdominio'] + scope['servicios'],
            "total_dominios_escaneados": len(todos_los_dominios),
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
    Mapeo y resolución de IPs mejorado con múltiples resolvers DNS + Geolocalización.
    - Combina IPs configuradas + dominios resueltos
    - Usa múltiples resolvers (Google, Cloudflare, Quad9) para validar
    - Proporciona información detallada de reverse DNS
    - ✨ MEJORADO: Agrega geolocalización (país, ciudad, ISP) a cada IP
    - ✨ MEJORADO: Incluye IPs válidas aunque reverse DNS falle
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

        # 3. Hacer reverse DNS + Geolocalización para cada IP
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
                print(f"[mapeo_ips] Analizando {ip}...")

                # Reverse DNS
                reverse_result = _reverse_dns_multi_resolver(ip)
                hostname = reverse_result['hostnames'][0] if reverse_result['hostnames'] else 'unknown'
                status = reverse_result['status']

                # ✨ NUEVO: Geolocalización
                geo_data = _geolocate_ip(ip)

                # ✨ NUEVO: Validar que el hostname pertenece al dominio objetivo
                hostname_validation = _validate_hostname_belongs_to_domain(hostname, dominio_objetivo, ip)

                # Validar que sea una IP del objetivo
                # Es válido si: tiene from_domains (fue resuelto desde un dominio scope)
                from_domains = ip_to_dominios.get(ip, [])
                hostname_valido = bool(from_domains)

                # ✨ ARREGLADO: La validación de hostname es solo informativa
                # Una IP es realmente válida si fue resuelta desde un dominio scope
                # No importa qué diga el reverse DNS (puede ser del ISP)
                es_realmente_valida = hostname_valido
                # hostname_validation es solo contexto/info, no rechaza la IP

                entry = {
                    'ip': ip,
                    'hostname': hostname,
                    'status': status,
                    'from_domains': from_domains,
                    'es_valido': es_realmente_valida,  # ✨ MEJORADO: validación más estricta
                    'hostname_validation': hostname_validation,  # ✨ NUEVO: detalles de validación
                    'geo': geo_data
                }
                ips_analizadas.append(entry)

                # Incluir en ips_success solo si la IP es realmente válida
                if es_realmente_valida:
                    ips_success.append({
                        'ip': ip,
                        'hostname': hostname,
                        'status': status,
                        'from_domains': from_domains,
                        'hostname_validation': hostname_validation['razon'],
                        'geo': geo_data
                    })
                    print(f"[mapeo_ips] ✓ {ip} ({hostname}) - {geo_data['pais']}, {geo_data['ciudad']} [VÁLIDO]")
                    print(f"              Hostname info: {hostname_validation.get('razon', 'N/A')}")
                else:
                    # IPs sin from_domains (no resueltas desde dominio scope)
                    print(f"[mapeo_ips] ⊘ {ip} ({hostname}) - No fue resuelto desde dominio scope")

            except Exception as e:
                print(f"[mapeo_ips] Error analizando {ip}: {e}")
                ips_analizadas.append({
                    'ip': ip,
                    'hostname': 'error',
                    'status': 'error',
                    'from_domains': ip_to_dominios.get(ip, []),
                    'es_valido': False,
                    'hostname_validation': None,
                    'geo': None
                })

        return {
            "tipo": "mapeo_ips",
            "total_ips": len(ips_a_analizar),
            "total_success": len(ips_success),
            "ips_success": ips_success,  # ← IPs válidas con geolocalización
            "ips_todas": ips_analizadas   # ← Todas las IPs analizadas (debug)
        }

    _run_osint_job(ejecucion_id, job)

def recon_cloud(ejecucion_id, proyecto_id):
    """Reconocimiento de buckets S3 y servicios cloud con fallback automático

    PRIORIDADES:
    1. TIER 0-3: Buscar patrones del DOMINIO RAÍZ (ej: "ater" de "ater.gob.ar")
    2. Si no hay resultados, entonces usar TIER 0-3 en SUBDOMINIOS combinados con el raíz
       (ej: "ser-ater", "seater" de "ser.ater.gob.ar", NO solo "ser")
    """
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

        # 4. Crear lista de dominios PRINCIPALES (scope + fallbacks)
        # IMPORTANTE: Los subdominios solo se usan si no hay hallazgos en los dominios principales
        dominios_principales = list(set(dominios_config + dominios_from_ips))

        if not dominios_principales and not dominios_descubiertos:
            raise Exception("No hay dominios para escanear (DOMINIO vacío, mapeo_ips sin resultados, subdominios no descubiertos)")

        # 5. EXTRAER DOMINIO RAÍZ (ej: "ater" de "ater.gob.ar")
        # Este será la base para todos los patrones de búsqueda
        dominio_raiz = None
        if dominios_principales:
            # Tomar el primer dominio principal y extraer la parte raíz
            primer_dominio = dominios_principales[0]
            partes = primer_dominio.split('.')
            if len(partes) >= 2:
                # ej: ater.gob.ar → "ater"
                dominio_raiz = partes[0]
            else:
                # Si es un dominio simple, usarlo como raíz
                dominio_raiz = primer_dominio

        print(f"[recon_cloud] Dominios principales: {len(dominios_principales)}, Subdominios descubiertos: {len(dominios_descubiertos)}")
        if dominio_raiz:
            print(f"[recon_cloud] DOMINIO RAÍZ IDENTIFICADO: '{dominio_raiz}'")

        recursos = []

        # ═══════════════════════════════════════════════════════════════════════
        # FASE 1: Escanear DOMINIOS PRINCIPALES con TIER 0-3
        # ═══════════════════════════════════════════════════════════════════════
        print(f"[recon_cloud] ════════════════════════════════════════════")
        print(f"[recon_cloud] FASE 1: Escaneando DOMINIOS PRINCIPALES")
        print(f"[recon_cloud] ════════════════════════════════════════════")

        for dom in dominios_principales:
            try:
                print(f"[recon_cloud] Escaneando buckets S3 para {dom}...")

                # ═══════════════════════════════════════════════════════
                # TIER 0: DIRECTO - Probar el dominio/subdominio COMO NOMBRE DE BUCKET
                # ej: level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud →
                #     prueba "level2-c8b217a33fcf1f839f6f1f73a00a9ae7" como bucket directo
                # ej: flaws.cloud → prueba "flaws" Y "flaws-cloud" como buckets
                # ═══════════════════════════════════════════════════════
                print(f"[recon_cloud] TIER 0: Probando {dom} directamente como nombre de bucket...")
                # Extraer la parte del subdominio si es necesario
                dom_parts = dom.split('.')
                bucket_directo = dom_parts[0] if len(dom_parts) > 1 else dom  # level2-xxx de level2-xxx.flaws.cloud

                resultado = _verify_bucket(bucket_directo, dom)
                if resultado:
                    recursos.extend(resultado)
                    print(f"[recon_cloud] ✓ TIER 0: Encontrado: {bucket_directo}")

                # ⭐ IMPORTANTE: También probar el dominio COMPLETO con guiones
                # Esto es crítico para dominios como "flaws.cloud" donde el bucket se llama "flaws.cloud" (con guion)
                if len(dom_parts) > 1:
                    bucket_completo = '-'.join(dom_parts)  # "flaws-cloud"
                    print(f"[recon_cloud] TIER 0b: Probando dominio completo con guiones: {bucket_completo}...")
                    resultado_completo = _verify_bucket(bucket_completo, dom)
                    if resultado_completo:
                        recursos.extend(resultado_completo)
                        print(f"[recon_cloud] ✓ TIER 0b: Encontrado: {bucket_completo}")

                # ═══════════════════════════════════════════════════════
                # TIER 1: Buckets REALES (encontrados en CT logs/Wayback)
                # ═══════════════════════════════════════════════════════
                print(f"[recon_cloud] TIER 1: Buckets encontrados en CT logs/Wayback...")
                buckets_tier1 = _find_buckets_wayback(dom)
                buckets_tier1.extend(_find_buckets_from_ct(dom))
                buckets_tier1 = list(set(filter(None, buckets_tier1)))

                print(f"[recon_cloud] TIER 1: {len(buckets_tier1)} buckets reales encontrados")
                for bucket in buckets_tier1:
                    recursos.extend(_verify_bucket(bucket, dom))

                # ═══════════════════════════════════════════════════════
                # TIER 2: Candidatos ESPECÍFICOS del dominio (EXPANDIDO)
                # ⭐ IMPORTANTE: Pasar el dominio COMPLETO (ej: "ater.gob.ar")
                # La función generará variaciones intermedias: ater, ater-gob, ater-gob-ar
                # ═══════════════════════════════════════════════════════
                print(f"[recon_cloud] TIER 2: Candidatos específicos del dominio...")
                buckets_tier2 = _generate_bucket_candidates(dom, tier='tier2')
                buckets_tier2 = list(set(filter(None, buckets_tier2)))

                print(f"[recon_cloud] TIER 2: {len(buckets_tier2)} candidatos a verificar")
                verified_tier2 = 0
                for bucket in buckets_tier2:
                    result = _verify_bucket(bucket, dom)
                    if result:
                        recursos.extend(result)
                        verified_tier2 += 1
                print(f"[recon_cloud] TIER 2: {verified_tier2} buckets verificados positivamente")

                # ═══════════════════════════════════════════════════════
                # TIER 3: Candidatos MENOS ESPECÍFICOS (HABILITADO POR DEFECTO)
                # Ahora incluido para mejorar cobertura sin depender de Wayback/CT
                # ⭐ IMPORTANTE: Pasar el dominio COMPLETO para variaciones intermedias
                # ═══════════════════════════════════════════════════════
                print(f"[recon_cloud] TIER 3: Candidatos del domain name...")
                buckets_tier3 = _generate_bucket_candidates(dom, tier='tier3')
                buckets_tier3 = list(set(filter(None, buckets_tier3)))

                print(f"[recon_cloud] TIER 3: {len(buckets_tier3)} candidatos a verificar")
                verified_tier3 = 0
                for bucket in buckets_tier3:
                    result = _verify_bucket(bucket, dom)
                    if result:
                        recursos.extend(result)
                        verified_tier3 += 1
                print(f"[recon_cloud] TIER 3: {verified_tier3} buckets verificados positivamente")

                # ═══════════════════════════════════════════════════════
                # RESUMEN POR DOMINIO
                # ═══════════════════════════════════════════════════════
                total_encontrados = len([r for r in recursos if r.get('dominio') == dom])
                print(f"[recon_cloud] ✓ TOTAL para {dom}: {total_encontrados} buckets públicos encontrados")

            except Exception as e:
                print(f"[recon_cloud] Error escaneando {dom}: {e}")

        # ═══════════════════════════════════════════════════════════════════════
        # FASE 2: Si FASE 1 no encuentra nada, escanear SUBDOMINIOS DESCUBIERTOS
        # IMPORTANTE: Combinar subdominio con dominio_raiz (ej: ser-ater)
        # NO buscar solo la primera parte del subdominio (ej: NO solo "ser")
        # ═══════════════════════════════════════════════════════════════════════
        if not recursos and dominios_descubiertos and dominio_raiz:
            print(f"[recon_cloud] ════════════════════════════════════════════")
            print(f"[recon_cloud] FASE 2: FASE 1 sin resultados → FALLBACK a SUBDOMINIOS")
            print(f"[recon_cloud] Escaneando {len(dominios_descubiertos)} subdominios descubiertos")
            print(f"[recon_cloud] Combinándolos con dominio raíz: '{dominio_raiz}'")
            print(f"[recon_cloud] ════════════════════════════════════════════")

            for subdom in dominios_descubiertos:
                try:
                    print(f"[recon_cloud] [FALLBACK] Escaneando buckets S3 para {subdom}...")

                    # TIER 0a: Probar el subdomain_name SOLO primero
                    # Para dominios como flaws.cloud donde el bucket ES el subdominio
                    # ej: level2-xxx.flaws.cloud → el bucket es "level2-xxx"
                    subdom_parts = subdom.split('.')
                    subdomain_name = subdom_parts[0]  # "level2-xxx" de "level2-xxx.flaws.cloud"

                    print(f"[recon_cloud] [FALLBACK] TIER 0a: Probando subdomain '{subdomain_name}' directamente como bucket...")
                    resultado = _verify_bucket(subdomain_name, subdom)
                    if resultado:
                        recursos.extend(resultado)
                        print(f"[recon_cloud] ✓ [FALLBACK] TIER 0a: Encontrado: {subdomain_name}")

                    # TIER 0b: Si no encontró nada, probar combinando con dominio_raiz
                    # ej: ser.ater.gob.ar → probar "ser-ater"
                    if not resultado:
                        subdom_combined = f"{subdomain_name}-{dominio_raiz}"  # "ser-ater"
                        print(f"[recon_cloud] [FALLBACK] TIER 0b: Probando {subdom} como '{subdom_combined}'...")

                        resultado = _verify_bucket(subdom_combined, subdom)
                        if resultado:
                            recursos.extend(resultado)
                            print(f"[recon_cloud] ✓ [FALLBACK] TIER 0b: Encontrado: {subdom_combined}")

                    # TIER 1: Buckets reales encontrados en Wayback/CT
                    buckets_tier1 = _find_buckets_wayback(subdom)
                    buckets_tier1.extend(_find_buckets_from_ct(subdom))
                    buckets_tier1 = list(set(filter(None, buckets_tier1)))

                    for bucket in buckets_tier1:
                        recursos.extend(_verify_bucket(bucket, subdom))

                    # TIER 2 y 3: Candidatos generados (usando dominio COMPLETO para variaciones)
                    # ⭐ IMPORTANTE: Pasar subdominio completo para generar variaciones intermedias
                    # Ejemplo: vpn.ater.gob.ar → genera: vpn-ater, vpn-ater-gob, vpn-ater-gob-ar
                    buckets_tier2 = _generate_bucket_candidates(subdom, tier='tier2')
                    buckets_tier2 = list(set(filter(None, buckets_tier2)))

                    for bucket in buckets_tier2:
                        result = _verify_bucket(bucket, subdom)
                        if result:
                            recursos.extend(result)

                    buckets_tier3 = _generate_bucket_candidates(subdom, tier='tier3')
                    buckets_tier3 = list(set(filter(None, buckets_tier3)))

                    for bucket in buckets_tier3:
                        result = _verify_bucket(bucket, subdom)
                        if result:
                            recursos.extend(result)

                except Exception as e:
                    print(f"[recon_cloud] [FALLBACK] Error escaneando {subdom}: {e}")

        return {
            "tipo": "recon_cloud",
            "dominio_scope": dominio_scope,
            "total_dominios_scope": len(dominios_config),
            "total_dominios_from_ips": len(dominios_from_ips),
            "total_subdominios_descubiertos": len(dominios_descubiertos),
            "total_dominios_buscados": len(dominios_principales),
            "total_recursos": len(recursos),
            "recursos": recursos
        }

    _run_osint_job(ejecucion_id, job)


def _generate_bucket_candidates(dominio, tier='all'):
    """
    Genera candidatos de buckets por tiers de confianza - MEJORADO para autonomía.

    REGLA FUNDAMENTAL: SOLO la primera parte del dominio es única y específica
    - ater.gob.ar → usar SOLO "ater" (gob.ar es genérico)
    - vpn.ater.gob.ar → usar SOLO "vpn-ater" (ater es la parte única)
    - NO generar candidatos con partes genéricas (gob, ar, com, etc.)

    TIER 1 (Muy probable): Buckets encontrados en CT logs / Wayback
    TIER 2 (Probable): Específicos del dominio - EXPANDIDO para autonomía
    TIER 3 (Posible): Del domain name + variaciones - INCLUIDO por defecto
    TIER 4 (Improbable): Ultra-genéricos → NO USAR (mucho ruido)

    Args:
        dominio (str): Dominio/subdominio (ej: "ater", "vpn-ater", "vpn.ater.gob.ar")
        tier (str): 'tier1', 'tier2', 'tier3', 'all'

    Returns:
        list: Candidatos ordenados por probabilidad (descendente)
    """
    parts = dominio.split('.')

    # ⭐ REGLA FUNDAMENTAL:
    # - Dominio simple (3 partes): ater.gob.ar → base="ater", variaciones: ater, ater-gob, ater-gob-ar
    # - Subdominio (4+ partes): vpn.ater.gob.ar → base="vpn-ater", variaciones: vpn-ater, vpn-ater-gob, vpn-ater-gob-ar
    # - Ya procesado (sin puntos): vpn-ater → Generar: vpn-ater (solo una opción)

    intermediate_variations = []

    if len(parts) == 1:
        # Ya viene procesado (ej: "vpn-ater" o "ater")
        domain_name = parts[0]
        subdomain = None
        full_base_dash = domain_name
        # No hay variaciones intermedias porque ya viene sin puntos

    elif len(parts) == 2:
        # Dominio simple de 2 partes (ej: "ater.gob")
        domain_name = parts[0]  # "ater"
        subdomain = None
        full_base_dash = domain_name
        # Generar: ater, ater-gob
        intermediate_variations.append('-'.join(parts[:2]))

    elif len(parts) == 3:
        # Dominio común (ej: "ater.gob.ar")
        domain_name = parts[0]  # "ater" ← La parte ÚNICA
        subdomain = None
        full_base_dash = domain_name
        # Generar variaciones: ater, ater-gob, ater-gob-ar
        for i in range(1, len(parts)):
            intermediate = '-'.join(parts[:i+1])
            intermediate_variations.append(intermediate)

    else:
        # Subdominio (4+ partes, ej: "vpn.ater.gob.ar")
        # parts = ["vpn", "ater", "gob", "ar"]
        # base debe ser parts[0] + parts[1] = "vpn-ater" ← La combinación ÚNICA
        domain_name = '-'.join(parts[:2])  # "vpn-ater"
        subdomain = parts[0]  # "vpn"
        full_base_dash = domain_name
        # Generar variaciones: vpn-ater, vpn-ater-gob, vpn-ater-gob-ar
        for i in range(2, len(parts)):
            intermediate = '-'.join(parts[:i+1])
            intermediate_variations.append(intermediate)

    # ══════════════════════════════════════════════════════════════
    # TIER 1: Buckets REALES (encontrados en CT logs / Wayback)
    # ══════════════════════════════════════════════════════════════
    tier1 = []
    # Estos se cargan de _find_buckets_wayback() y _find_buckets_from_ct()
    # No generamos, sino que verificamos los ENCONTRADOS

    # ══════════════════════════════════════════════════════════════
    # TIER 2: Específicos del dominio (MÁS PROBABLE) - EXPANDIDO PARA AUTONOMÍA
    # REGLA FUNDAMENTAL: TODOS los candidatos DEBEN comenzar con la parte única
    # ✅ ater, ater-gob-ar, ater-backup, aws-ater
    # ❌ gob-ar, gob, ar (NO comienzan con ater/vpn-ater)
    # ══════════════════════════════════════════════════════════════
    tier2 = [
        # ⭐ CANDIDATOS BÁSICOS PRIMERO (nombres simples que son MÁS comunes)
        domain_name,  # ater (nombre exacto del domain ÚNICO)

        # ⭐ Variaciones intermedias (ej: ater, ater-gob, ater-gob-ar)
        *intermediate_variations,

        # Dominio completo CON guiones (pero SIEMPRE comienza con ater)
        dominio.lower().replace('.', '-'),  # ater-gob-ar ✅ (comienza con ater)

        # Combinaciones subdominio + domain (SOLO si hay subdominio)
        f"{full_base_dash}-bucket",  # vpn-ater-bucket
        f"{full_base_dash}-backup",  # vpn-ater-backup
        f"{full_base_dash}-data",
        f"{full_base_dash}-assets",
        f"{full_base_dash}-storage",
        f"{full_base_dash}-files",
        f"{full_base_dash}-logs",
        f"{full_base_dash}-db",
        f"{full_base_dash}-media",
        f"{full_base_dash}-uploads",
        f"{full_base_dash}-download",
        f"{full_base_dash}-public",
        f"{full_base_dash}-private",
        f"{full_base_dash}-prod",
        f"{full_base_dash}-staging",
        f"{full_base_dash}-test",
        f"{full_base_dash}-dev",
        f"{full_base_dash}-content",
        f"{full_base_dash}-static",
        f"{full_base_dash}-archive",
        f"{full_base_dash}-temp",

        # Variaciones con prefijos comunes (SIEMPRE con la parte única)
        f"aws-{full_base_dash}",  # aws-ater o aws-vpn-ater
        f"s3-{full_base_dash}",
        f"bucket-{full_base_dash}",
        f"storage-{full_base_dash}",
        f"data-{full_base_dash}",
    ]

    # ══════════════════════════════════════════════════════════════
    # TIER 3: Del domain name (MENOS PROBABLE pero ÚTIL) - INCLUIDO POR DEFECTO
    # REGLA: TODOS comienzan con la parte única
    # ✅ ater-bucket, ater-gob, aws-ater, etc.
    # ❌ gob, ar, gob-ar (sin la parte única)
    # ══════════════════════════════════════════════════════════════
    tier3 = [
        # ⭐ Variaciones intermedias (ej: ater, ater-gob, ater-gob-ar)
        *intermediate_variations,

        # Combinaciones básicas del domain name ÚNICO
        f"{domain_name}-bucket",  # ater-bucket
        f"{domain_name}-backup",  # ater-backup
        f"{domain_name}-data",  # ater-data
        f"{domain_name}-assets",
        f"{domain_name}-storage",
        f"{domain_name}-files",
        f"{domain_name}-logs",
        f"{domain_name}-db",
        f"{domain_name}-media",
        f"{domain_name}-uploads",
        f"{domain_name}-download",
        f"{domain_name}-public",
        f"{domain_name}-private",
        f"{domain_name}-prod",
        f"{domain_name}-staging",
        f"{domain_name}-test",
        f"{domain_name}-dev",
        f"{domain_name}-content",
        f"{domain_name}-static",

        # Con prefijos comunes (comienzan con parte única)
        f"bucket-{domain_name}",  # bucket-ater
        f"aws-{domain_name}",     # aws-ater
        f"s3-{domain_name}",      # s3-ater
        f"storage-{domain_name}",
        f"data-{domain_name}",
        f"{domain_name}-aws",
        f"{domain_name}-s3",
        f"{domain_name}-gcp",
        f"{domain_name}-azure",

        # Variaciones con números (comienzan con parte única)
        f"01-{domain_name}",
        f"prod-{domain_name}",
        # Variaciones de full_base_dash si hay subdominio
        f"01-{full_base_dash}" if subdomain else None,
        f"prod-{full_base_dash}" if subdomain else None,
    ]

    # ══════════════════════════════════════════════════════════════
    # TIER 4: NO USAR - Ultra genéricos (demasiado ruido)
    # ══════════════════════════════════════════════════════════════
    # backup, data, media, files, logs, db, assets, storage (sin empresa)
    # Estos generan miles de falsos positivos

    # ══════════════════════════════════════════════════════════════
    # Compilar según tier solicitado
    # ══════════════════════════════════════════════════════════════
    candidates = []
    if tier in ['tier1', 'all']:
        candidates.extend(tier1)
    if tier in ['tier2', 'all']:
        candidates.extend(tier2)
    if tier in ['tier3', 'all']:
        candidates.extend(tier3)

    # Remover Nones y duplicados, mantener orden
    seen = set()
    unique_candidates = []
    for c in candidates:
        if c and c not in seen:
            seen.add(c)
            unique_candidates.append(c)

    return unique_candidates


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
    """Verifica si el bucket permite acceso anónimo (sin credenciales AWS)

    ⭐ MEJORADO: Usa AWS CLI (aws s3 ls --no-sign-request) que es la forma
    CORRECTA de verificar acceso público anónimo, mucho más confiable que
    verificar HTTP status codes.
    """
    try:
        # ⭐ FORMA CORRECTA: Intentar listar bucket con AWS CLI sin credenciales
        print(f"[s3-anon] Verificando acceso anónimo a s3://{bucket_name}/...")

        result = subprocess.run(
            ['aws', 's3', 'ls', f"s3://{bucket_name}/", '--no-sign-request', '--max-items', '1'],
            capture_output=True,
            text=True,
            timeout=10
        )

        # Analizar resultado
        stderr = result.stderr.lower()
        stdout = result.stdout.lower()
        returncode = result.returncode

        print(f"[s3-anon] {bucket_name}: returncode={returncode}")

        # ✅ returncode == 0 = Acceso público permitido
        if returncode == 0:
            print(f"[s3-anon] ✅ {bucket_name} - ACCESO ANÓNIMO CONFIRMADO (aws s3 ls devolvió 0)")
            return 'anónimo'  # ← BUCKET ABIERTO AL PÚBLICO

        # ❌ NoSuchBucket = El bucket no existe
        if 'nosuchbucket' in stderr or 'does not exist' in stderr:
            print(f"[s3-anon] ❌ {bucket_name} - El bucket no existe (NoSuchBucket)")
            return 'no_existe'

        # 🔒 Access Denied / AllAccessDisabled = Privado o restringido
        if 'accessdenied' in stderr or 'allaccessdisabled' in stderr or 'signaturemismatch' in stderr:
            print(f"[s3-anon] 🔒 {bucket_name} - Acceso denegado (bucket privado)")
            return 'privado'

        # ❓ Otros errores
        if returncode != 0:
            print(f"[s3-anon] ⚠️  {bucket_name} - Error: {result.stderr[:200]}")
            return 'error'

        return 'desconocido'

    except subprocess.TimeoutExpired:
        print(f"[s3-anon] ⏱ {bucket_name} - Timeout (aws s3 ls tardó > 10s)")
        return 'timeout'
    except FileNotFoundError:
        print(f"[s3-anon] ⚠️  {bucket_name} - AWS CLI no está instalado")
        return 'error'
    except Exception as e:
        print(f"[s3-anon] ⚠ {bucket_name} - Error: {str(e)[:200]}")
        return 'error'

def _validate_bucket_domain_correlation(bucket_name, dominio):
    """
    Valida si un bucket S3 realmente pertenece/está asociado a un dominio específico.

    Retorna dict con validación y nivel de confianza (0-100)
    Métodos de validación:
    1. DNS: ¿El dominio apunta al bucket S3? (+50 puntos)
    2. Contenido: ¿Hay referencias a dominio/empresa en archivos? (+30 puntos)
    3. Metadatos: ¿Tags del bucket mencionan dominio? (+15 puntos)
    4. IP: ¿IP del dominio es rango AWS? (±10 puntos)
    """
    validation = {
        'es_correlacionado': False,
        'confianza': 0,
        'metodos_confirmados': [],
        'evidencias': {},
        'razon': 'sin_validación'
    }

    try:
        # MÉTODO 1: Verificar DNS del dominio
        print(f"[s3-correlation] Método 1: Verificar DNS de {dominio}")
        try:
            dns_result = subprocess.run(
                ['dig', dominio, 'CNAME', '+short'],
                capture_output=True,
                text=True,
                timeout=5
            )
            dns_cname = dns_result.stdout.strip()
            validation['evidencias']['dns_cname'] = dns_cname

            if dns_cname:
                print(f"[s3-correlation] DNS CNAME: {dns_cname}")
                # Verificar si apunta a S3 o contiene el nombre del bucket
                if 's3.amazonaws.com' in dns_cname or bucket_name in dns_cname:
                    print(f"[s3-correlation] ✅ DNS apunta a S3/bucket")
                    validation['metodos_confirmados'].append('dns_cname')
                    validation['confianza'] += 50
                else:
                    print(f"[s3-correlation] ❌ DNS no apunta a S3. Apunta a: {dns_cname}")
                    validation['evidencias']['dns_no_apunta_s3'] = True
            else:
                print(f"[s3-correlation] ⚠️  No hay CNAME para {dominio}")
                validation['evidencias']['sin_cname'] = True
        except Exception as e:
            print(f"[s3-correlation] Error en DNS check: {e}")

        # MÉTODO 2: Buscar evidencia en contenido del bucket
        print(f"[s3-correlation] Método 2: Buscar referencias en contenido del bucket")
        try:
            content = subprocess.run(
                ['curl', '-s', f'https://{bucket_name}.s3.amazonaws.com/', '--max-time', '10'],
                capture_output=True,
                text=True,
                timeout=15
            )

            # Palabras clave a buscar (dominio, empresa, país)
            domain_parts = dominio.lower().split('.')
            keywords = [
                dominio.lower(),
                domain_parts[0] if domain_parts else '',  # Subdominio (ej: "ws" de "ws.ater.gob.ar")
                'ater', 'gob.ar', 'argentina', 'gobierno',
                'entre rios', 'energia', 'tecnologia'
            ]
            keywords = [k for k in keywords if k]  # Remover vacíos

            found_keywords = []
            for keyword in keywords:
                if keyword in content.stdout.lower():
                    found_keywords.append(keyword)

            if found_keywords:
                print(f"[s3-correlation] ✅ Encontradas referencias: {found_keywords}")
                validation['metodos_confirmados'].append('contenido_keywords')
                validation['evidencias']['keywords_encontradas'] = found_keywords
                validation['confianza'] += 30
            else:
                print(f"[s3-correlation] ❌ No hay referencias a dominio/empresa en contenido")
                validation['evidencias']['sin_keywords'] = True
        except Exception as e:
            print(f"[s3-correlation] Error consultando contenido: {e}")

        # MÉTODO 3: Verificar propiedades del bucket (tagging, cors, etc)
        print(f"[s3-correlation] Método 3: Verificar propiedades/metadatos del bucket")
        try:
            # Intentar obtener tagging (si es público)
            tagging = subprocess.run(
                ['curl', '-s', f'https://{bucket_name}.s3.amazonaws.com/?tagging', '--max-time', '5'],
                capture_output=True,
                text=True,
                timeout=8
            )

            if 'Tag' in tagging.stdout or '<Key>' in tagging.stdout:
                tags = []
                # Extraer tags básicamente
                for tag in tagging.stdout.split('<Key>')[1:]:
                    if '</Key>' in tag:
                        tag_name = tag.split('</Key>')[0]
                        tags.append(tag_name)
                if tags:
                    print(f"[s3-correlation] Tags encontrados: {tags}")
                    validation['evidencias']['tags'] = tags

                    # Verificar si algún tag menciona el dominio
                    if any(dominio.split('.')[0].lower() in tag.lower() for tag in tags):
                        validation['metodos_confirmados'].append('bucket_tags')
                        validation['confianza'] += 15
        except:
            pass

        # MÉTODO 4: Información de la IP (si está disponible)
        print(f"[s3-correlation] Método 4: Verificar IP del dominio")
        try:
            ip_result = subprocess.run(
                ['dig', dominio, 'A', '+short'],
                capture_output=True,
                text=True,
                timeout=5
            )
            domain_ip = ip_result.stdout.strip()

            if domain_ip:
                validation['evidencias']['domain_ip'] = domain_ip
                print(f"[s3-correlation] IP del dominio: {domain_ip}")

                # Verificar si es rango AWS (generalmente 52.*, 54.*, 35.*)
                aws_ranges = ['52.', '54.', '35.', '176.', '177.']
                if any(domain_ip.startswith(range_ip) for range_ip in aws_ranges):
                    print(f"[s3-correlation] ⚠️  IP es rango AWS (pero no necesariamente S3)")
                    validation['evidencias']['is_aws_ip'] = True
                else:
                    print(f"[s3-correlation] ❌ IP NO es rango AWS")
                    validation['evidencias']['not_aws_ip'] = True
                    validation['confianza'] -= 10
        except Exception as e:
            print(f"[s3-correlation] Error resolviendo IP: {e}")

        # DECISIÓN FINAL
        if validation['confianza'] >= 50:
            validation['es_correlacionado'] = True
            validation['razon'] = f"Confirmado por {len(validation['metodos_confirmados'])} métodos (confianza: {validation['confianza']}%)"
        elif validation['confianza'] >= 30:
            validation['es_correlacionado'] = True  # Débilmente correlacionado
            validation['razon'] = f"Débilmente confirmado ({validation['confianza']}%) - Revisar manualmente"
        else:
            validation['es_correlacionado'] = False
            validation['razon'] = f"Sin confirmar (confianza: {validation['confianza']}%) - Posible falso positivo"

        print(f"[s3-correlation] VEREDICTO: {validation['razon']}")

    except Exception as e:
        print(f"[s3-correlation] Error general: {e}")
        validation['razon'] = f"Error en validación: {str(e)}"

    return validation

def _verify_bucket(bucket_name, dominio):
    """Verifica si un bucket existe y obtiene info + acceso anónimo

    MEJORADO: Valida correlación entre bucket y dominio
    Prioridad:
    1. Verificar acceso anónimo (HTTP sin credenciales)
    2. Validar que realmente pertenece al dominio
    3. Solo reportar si correlación es suficientemente fuerte
    """
    resultado = []

    try:
        # 1. PRIMERO: Verificar acceso anónimo (sin credenciales)
        # Esto nos dice si el bucket existe realmente
        acceso_anonimo = _check_bucket_anonymous_access(bucket_name)

        # 2. Si HTTP devuelve 404, el bucket NO existe → No reportar
        if acceso_anonimo == 'no_existe':
            print(f"[s3-verify] {bucket_name} - No existe (HTTP 404) → IGNORAR")
            return resultado

        # 3. NUEVO: Validar correlación entre bucket y dominio
        # Esto evita falsos positivos
        print(f"[s3-verify] Validando correlación: {bucket_name} ↔ {dominio}")
        correlation = _validate_bucket_domain_correlation(bucket_name, dominio)

        # 4. SEGUNDO: Verificar con AWS CLI (requiere credenciales)
        result = subprocess.run(
            ['aws', 's3', 'ls', f"s3://{bucket_name}", '--max-items', '1'],
            capture_output=True,
            text=True,
            timeout=5
        )

        # 5. Determinar nivel de acceso y severidad basada en correlación
        if acceso_anonimo == 'anónimo':
            # ¡BUCKET ABIERTO AL PÚBLICO!

            # 🚨 FILTRO ANTI-FALSOS POSITIVOS
            # Rechazar si:
            # 1. Confianza negativa (claro falso positivo)
            # 2. IP NO es AWS + confianza muy baja (bucket en otro servicio, no S3)
            if correlation['confianza'] < 0:
                print(f"[s3-verify] ❌ {bucket_name} RECHAZADO: Confianza negativa ({correlation['confianza']}%) - FALSO POSITIVO")
                return resultado

            if correlation['evidencias'].get('not_aws_ip') and correlation['confianza'] < 50:
                print(f"[s3-verify] ❌ {bucket_name} RECHAZADO: IP no-AWS ({correlation['evidencias'].get('domain_ip')}) + baja correlación ({correlation['confianza']}%) - FALSO POSITIVO")
                return resultado

            # ⭐ MEJORADO: HTTP 200 anónimo es evidencia REAL de que el bucket es accesible
            # Reducir threshold a 30% para buckets públicos (menos estricto)
            # Si alguien puede acceder sin credenciales, ES un hallazgo, aunque la correlación sea débil
            if correlation['confianza'] < 30:
                print(f"[s3-verify] ⚠️  {bucket_name} abierto pero CORRELACIÓN MUY BAJA ({correlation['confianza']}%) → REPORTAR COMO HALLAZGO DÉBIL")
                # Igual lo reportamos pero con severidad más baja
                # porque HTTP 200 anónimo es real
            elif correlation['confianza'] < 50:
                print(f"[s3-verify] ⚠️  {bucket_name} abierto con BAJA CORRELACIÓN ({correlation['confianza']}%) → REPORTAR CON SEVERIDAD MEDIA")

            # Obtener severidad dinámica desde BD basada en confianza
            # ⭐ MEJORADO: Si correlación < 50%, usar nivel más bajo pero igual reportar
            confianza_ajustada = max(correlation['confianza'], 30)  # Mínimo 30% para buckets públicos
            severidad_obj = _get_severidad_por_confianza(confianza_ajustada)
            severidad_nombre = severidad_obj.get('nombre') if severidad_obj else 'UNKNOWN'
            severidad_id = severidad_obj.get('id') if severidad_obj else None

            # Etiqueta de confianza para legibilidad
            if correlation['confianza'] >= 50:
                confianza_label = 'ALTA'
            elif correlation['confianza'] >= 30:
                confianza_label = 'MEDIA'
            else:
                confianza_label = 'BAJA'

            print(f"[s3-verify] ✅ REPORTAR: {bucket_name} (acceso=abierto, confianza={correlation['confianza']}%, severidad={severidad_nombre})")

            # ⭐ NUEVO: Generar comandos POC para explotar el bucket
            poc_commands = {
                'aws_cli': f"aws s3 ls s3://{bucket_name}/ --no-sign-request",
                'aws_cli_download': f"aws s3 sync s3://{bucket_name}/ ./{bucket_name}/ --no-sign-request",
                'curl': f"curl https://{bucket_name}.s3.amazonaws.com/",
                's3cmd': f"s3cmd ls s3://{bucket_name}/"
            }

            resultado.append({
                'tipo': 's3_bucket',
                'nombre': bucket_name,
                'dominio': dominio,
                'acceso': 'anónimo_abierto',  # ← CRÍTICO: ACCESO PÚBLICO
                'acceso_anonimo': acceso_anonimo,
                'estado': 'existe',
                'correlacion_validada': correlation['es_correlacionado'],  # ← NUEVO
                'confianza_correlacion': correlation['confianza'],  # ← NUEVO (0-100)
                'confianza_label': confianza_label,  # ← NUEVO (ALTA/MEDIA/BAJA)
                'metodos_confirmados': correlation['metodos_confirmados'],  # ← NUEVO
                'evidencias': correlation['evidencias'],  # ← NUEVO (detalles)
                'razon_correlacion': correlation['razon'],  # ← NUEVO (descripción)
                'severidad_id': severidad_id,  # ← NUEVO: ID de severidad desde BD
                'severidad': severidad_nombre,  # ← MEJORADO: Dinámico desde BD
                'poc_commands': poc_commands  # ⭐ NUEVO: Comandos para explotar el bucket
            })
        elif result.returncode == 0:
            # Acceso con credenciales AWS (BAJO VALOR - No reportar)
            print(f"[s3-verify] ℹ️  {bucket_name} requiere auth → NO REPORTAR (bajo valor)")
            return resultado

        elif 'NoSuchBucket' not in result.stderr:
            # Existe pero está privado (MÍNIMO VALOR - No reportar)
            print(f"[s3-verify] ℹ️  {bucket_name} privado → NO REPORTAR (sin acceso)")
            return resultado

    except subprocess.TimeoutExpired:
        print(f"[s3-verify] Timeout verificando {bucket_name}")
    except Exception as e:
        print(f"[s3-verify] Error: {e}")

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

        # 3. Subdominios descubiertos (solo para información, NO para búsqueda en GitHub)
        # Los subdominios son internos - GitHub indexa código, no subdominios específicos
        dominios_descubiertos = OsintEjecucion.get_discovered_subdomains(proyecto_id)
        if dominios_descubiertos:
            print(f"[escaneo_repositorios] Subdominios descubiertos (solo info): {len(dominios_descubiertos)}")

        # 4. Buscar SOLO dominios raíz (config + mapeo_ips)
        # NO incluir subdominios descubiertos (evita falsos positivos masivos)
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

        # BÚSQUEDAS INTELIGENTES: Palabra clave + archivos típicos de credenciales
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

            # 2. Búsquedas generales - Credenciales y secretos
            f'{keyword} API_KEY',
            f'{keyword} SECRET',
            f'{keyword} PASSWORD',
            f'{keyword} TOKEN',
            f'{keyword} CREDENTIALS',
            f'{keyword} DATABASE',
            f'{keyword} DB_PASSWORD',
            f'{keyword} PRIVATE_KEY',
            f'{keyword} ACCESS_KEY',

            # 2b. Búsquedas por ambiente
            f'{keyword} prod',
            f'{keyword} production',
            f'{keyword} staging',
            f'{keyword} dev',
            f'{keyword} development',
            f'{keyword} test',
            f'{keyword} qa',

            # 2c. Búsquedas por tipo de datos sensibles
            f'{keyword} backup',
            f'{keyword} export',
            f'{keyword} dump',
            f'{keyword} private',
            f'{keyword} confidential',

            # 3. Variantes comunes del nombre
            f'"{keyword}apps"',                            # aterapps
            f'"{keyword}-api"',                            # ater-api
            f'"customer-{keyword}"',                       # customer-ater
            f'{keyword}-api',                              # ater-api (sin comillas)
            f'customer-{keyword}',                         # customer-ater (sin comillas)

            # 4. Búsquedas por dominio COMPLETO + palabras sensibles
            f'"{domain_base}"',                            # "ater.gob.ar"
            f'"{domain_base}" secret',                     # "ater.gob.ar" secret
            f'"{domain_base}" password',                   # "ater.gob.ar" password
            f'"{domain_base}" token',                      # "ater.gob.ar" token
            f'"{domain_base}" api',                        # "ater.gob.ar" api
            f'"{domain_base}" credentials',                # "ater.gob.ar" credentials
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

    # Convertir sets a listas ordenadas + Clasificar por status
    resultado = []
    for repo, data in sorted(repos_dict.items()):
        # Determinar status del repo
        repo_lower = repo.lower()

        # Variantes válidas exactas
        valid_variants = ['aterapps', 'ater-api', 'customer-ater', 'ater.gob.ar']
        is_valid = any(var in repo_lower for var in valid_variants)

        # Palabras que contienen "ater" pero no son ATER
        false_positives = ['aternos', 'water', 'crater', 'eater', 'eatery', 'beat', 'theatre']
        is_false_positive = any(fp in repo_lower for fp in false_positives)

        # Clasificar
        if is_valid:
            status = 'valid'
        elif is_false_positive:
            status = 'false_positive'
        else:
            status = 'suspected'

        resultado.append({
            'tipo': data['tipo'],
            'repo': repo,
            'url': data['url'],
            'status': status,  # ← NUEVO: valid, suspected, false_positive
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

    Busca dominios en este orden (fallback INCLUSIVO):
    1. DOMINIO + SUBDOMINIO + SERVICIOS del scope
    2. SIEMPRE agregar subdominios descubiertos si existen (discovery_subdominios)
    3. Si no hay nada, fallback a dominios de mapeo_ips

    Retorna SOLO los registros DNS, sin listas innecesarias.
    """
    def job():
        # 1. Obtener TODO el scope: DOMINIO + SUBDOMINIO + SERVICIOS
        scope = OsintEjecucion.get_scope_completo(proyecto_id)
        todos_los_dominios = scope['dominio'] + scope['subdominio'] + scope['servicios']

        # 2. SIEMPRE obtener subdominios descubiertos si existen (lógica INCLUSIVA)
        subdominios_descubiertos = OsintEjecucion.get_discovered_subdomains(proyecto_id)
        todos_los_dominios.extend(subdominios_descubiertos)

        # 3. Fallback: Si no hay nada, usar dominios de mapeo_ips
        if not todos_los_dominios:
            dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(proyecto_id)
            todos_los_dominios.extend(dominios_from_ips)

        if not todos_los_dominios:
            raise Exception(
                "No hay dominios para analizar. "
                "Configurar DOMINIO/SUBDOMINIO/SERVICIOS en proyecto_osint_config o ejecutar discovery_subdominios"
            )

        # Deduplicar y ordenar
        todos_los_dominios = sorted(list(set(todos_los_dominios)))

        registros = {}
        tipos = ['A', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

        print(f"[analisis_dns] Analizando {len(todos_los_dominios)} dominios")
        print(f"  - Scope: {len(scope['dominio']) + len(scope['subdominio']) + len(scope['servicios'])}")
        print(f"  - Discovery subdominios: {len(subdominios_descubiertos)}")

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
                    print(f"[dig] Error: {tipo} en {dom}: {e}")

        return {
            "tipo": "analisis_dns",
            "total_dominios_analizados": len(todos_los_dominios),
            "dominios_scope": len(scope['dominio']) + len(scope['subdominio']) + len(scope['servicios']),
            "subdominios_descubiertos": len(subdominios_descubiertos),
            "registros": registros
        }

    _run_osint_job(ejecucion_id, job)

def busqueda_endpoints(ejecucion_id, proyecto_id):
    """Búsqueda de endpoints - múltiples estrategias (waybackurls, fuzzing, GitHub)

    Busca en:
    1. DOMINIO configurado + subdominios descubiertos (lógica INCLUSIVA)
    2. Fallback: dominios de mapeo_ips si no hay nada
    """
    def job():
        # 1. DOMINIO del scope
        dominios_scope = OsintEjecucion.get_dominio_from_config(proyecto_id)

        # 2. SIEMPRE agregar subdominios descubiertos (lógica INCLUSIVA)
        subdominios_descubiertos = OsintEjecucion.get_discovered_subdomains(proyecto_id)

        todos_los_dominios = dominios_scope + subdominios_descubiertos

        # 3. Fallback: dominios de mapeo_ips si no hay nada
        if not todos_los_dominios:
            dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(proyecto_id)
            todos_los_dominios = dominios_from_ips
        else:
            dominios_from_ips = []

        # Deduplicar
        todos_los_dominios = sorted(list(set(todos_los_dominios)))

        if not todos_los_dominios:
            raise Exception("No hay dominios para buscar endpoints")

        endpoints = set()
        print(f"[busqueda_endpoints] Buscando endpoints en {len(todos_los_dominios)} dominios...")
        print(f"  - Dominios scope: {len(dominios_scope)}")
        print(f"  - Subdominios descubiertos: {len(subdominios_descubiertos)}")

        for dom in todos_los_dominios:
            endpoints.update(_search_waybackurls(dom))
            endpoints.update(_fuzz_common_endpoints(dom))
            endpoints.update(_search_github_endpoints(dom))

        endpoints = sorted(list(filter(None, endpoints)))

        # FILTRAR: Solo endpoints con status 200
        endpoints_200 = [ep for ep in endpoints if '[200]' in ep]

        return {
            "tipo": "busqueda_endpoints",
            "total_dominios": len(todos_los_dominios),
            "dominios_scope": len(dominios_scope),
            "subdominios_descubiertos": len(subdominios_descubiertos),
            "total_encontrados": len(endpoints),
            "total_status_200": len(endpoints_200),
            "endpoints": endpoints_200  # ← Solo endpoints con status 200
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
    """Fuzzing de directorios/endpoints comunes - SIGUE REDIRECTS

    Mejora: Ahora sigue 301/302 redirects y reporta solo si el destino
    devuelve 200/401/403 (no 404)
    """
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

    print(f"[fuzzing] Probando {len(common_paths)} endpoints comunes en {dominio} (siguiendo redirects)...")

    # Status codes que indican que el endpoint REALMENTE EXISTE (después de seguir redirects)
    # 200: OK, 401/403: Acceso denegado (pero existe), 405: Método no permitido
    valid_status_codes = ['200', '201', '204', '400', '401', '403', '405']

    for path in common_paths:
        url = f"https://{dominio}{path}"
        try:
            # -L: seguir redirects, -I: solo headers
            result = subprocess.run(
                ['curl', '-s', '-I', '-L', '-m', '5', '--insecure', url],
                capture_output=True,
                text=True,
                timeout=6
            )

            if result.returncode == 0:
                # Extraer el ÚLTIMO status code (después de seguir redirects)
                status_code = None
                for line in result.stdout.split('\n'):
                    if line.startswith('HTTP'):
                        # Capturar todas las líneas HTTP (para tomar la última)
                        parts = line.split()
                        if len(parts) >= 2:
                            status_code = parts[1]  # Sobreescribe con la última

                # Solo agregar si el status code FINAL indica que existe
                # Ignora 404 (no existe) y 301/302 (redirect loop)
                if status_code and status_code in valid_status_codes:
                    endpoint_info = f"{url} [{status_code}]"
                    endpoints.add(endpoint_info)
                    print(f"✓ {endpoint_info}")
                elif status_code == '404':
                    print(f"✗ {url} [404 - No existe]")
        except subprocess.TimeoutExpired:
            pass
        except:
            pass

    print(f"[fuzzing] Encontrados {len(endpoints)} endpoints accesibles (no 404)")
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

def urls_historicas(ejecucion_id, proyecto_id):
    """Búsqueda de URLs históricas con GAU - múltiples fuentes públicas

    Fallback cascade:
    1. DOMINIO configurado
    2. Dominios descubiertos desde mapeo_ips (reverse DNS)
    3. Subdominios descubiertos
    4. Fallar si no hay datos en ninguna fuente

    GAU obtiene URLs de:
    - Wayback Machine
    - Common Crawl
    - URLScan
    - AlienVault OTX
    """
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio_config = config.get('DOMINIO', '').strip()

        # 1. Obtener dominios del scope inicial (OPCIONAL)
        dominios_scope = _parse_multiline_config(dominio_config) if dominio_config else []
        if dominios_scope:
            print(f"[gau] Dominios del scope encontrados: {dominios_scope}")
        else:
            print(f"[gau] Sin dominios configurados en DOMINIO")

        # 2. Fallback: Obtener dominios descubiertos por reverse DNS (mapeo_ips)
        dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(proyecto_id)
        if dominios_from_ips:
            print(f"[gau] Dominios del objetivo desde mapeo_ips: {dominios_from_ips}")

        # 3. Fallback: Obtener subdominios descubiertos
        subdominios_descubiertos = OsintEjecucion.get_discovered_subdomains(proyecto_id)
        if subdominios_descubiertos:
            print(f"[gau] Subdominios descubiertos: {len(subdominios_descubiertos)}")

        # 4. Obtener IPs válidas desde mapeo_ips
        ips_validas = _get_valid_ips_from_mapeo(proyecto_id)
        if ips_validas:
            print(f"[gau] IPs válidas desde mapeo_ips: {ips_validas}")

        # 5. Combinar todas las fuentes de dominios
        todos_los_dominios = list(set(dominios_scope + dominios_from_ips + subdominios_descubiertos))

        # 6. Validar que hay algo para escanear
        if not todos_los_dominios and not ips_validas:
            raise Exception("No hay dominios ni IPs para escanear (DOMINIO no configurado, mapeo_ips vacío y sin subdominios descubiertos)")

        urls = set()

        # 7. Buscar URLs de dominios
        if todos_los_dominios:
            print(f"[gau] Buscando URLs históricas en {len(todos_los_dominios)} dominios...")
            for dom in todos_los_dominios:
                print(f"[gau] Escaneando dominio: {dom}...")
                urls.update(_search_gau(dom))

        # 8. Buscar URLs de IPs válidas
        if ips_validas:
            print(f"[gau] Buscando URLs históricas en {len(ips_validas)} IPs...")
            for ip in ips_validas:
                print(f"[gau] Escaneando IP: {ip}...")
                urls.update(_search_gau(ip))

        urls = sorted(list(filter(None, urls)))

        return {
            "tipo": "busqueda_urls_historicas",
            "dominios_scope": dominios_scope,
            "dominios_from_ips": dominios_from_ips,
            "subdominios_descubiertos": subdominios_descubiertos,
            "ips_validas": ips_validas,
            "total_dominios": len(todos_los_dominios),
            "total_ips": len(ips_validas),
            "total": len(urls),
            "urls": urls
        }

    _run_osint_job(ejecucion_id, job)


def _get_valid_ips_from_mapeo(proyecto_id):
    """Obtiene IPs válidas (es_valido=true) del resultado de mapeo_ips"""
    try:
        resultado = OsintEjecucion.get_latest_resultado(proyecto_id, 'mapeo_ips')
        if not resultado:
            return []

        ips_success = resultado.get('ips_success', [])
        ips = [ip_data['ip'] for ip_data in ips_success if ip_data.get('es_valido')]
        return ips
    except Exception as e:
        print(f"[mapeo_ips] Error obteniendo IPs válidas: {e}")
        return []

def _search_gau(target):
    """Busca URLs históricas usando GAU (múltiples fuentes)

    Target puede ser:
    - Un dominio (ej: "example.com")
    - Una IP (ej: "192.168.1.1")
    """
    urls = set()
    try:
        print(f"[gau] Buscando URLs históricas de {target}...")

        # Busca el comando gau
        gau_path = _find_gau_path()
        if not gau_path:
            print(f"[gau] No encontrado. Intenta: go install github.com/lc/gau/v2/cmd/gau@latest")
            return urls

        # Ejecuta con filtros para evitar descargar archivos multimedia
        # Nota: no usamos --subs porque causa problemas con algunos dominios
        result = subprocess.run(
            [gau_path, '--blacklist', 'jpg,jpeg,png,gif,svg,css,js,woff,woff2,ttf,eot', target],
            capture_output=True,
            text=True,
            timeout=300  # 5 minutos - gau puede tardar para dominios grandes
        )

        if result.stdout:
            urls_found = result.stdout.strip().split('\n')
            urls.update([url for url in urls_found if url])
            print(f"[gau] Encontradas {len(urls_found)} URLs históricas para {target}")
        else:
            print(f"[gau] No se encontraron URLs para {target}")
    except subprocess.TimeoutExpired:
        print(f"[gau] Timeout para {target} (dominios muy grandes pueden tardar >5 min)")
    except Exception as e:
        print(f"[gau] Error en {target}: {e}")

    return urls

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