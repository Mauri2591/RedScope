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
    try:
        result = requests.get(f'https://ipapi.co/{ip}/json/', timeout=5)
        if result.status_code == 200:
            data = result.json()
            return {
                'pais': data.get('country_name', 'unknown'),
                'ciudad': data.get('city', 'unknown'),
                'isp': data.get('org', 'unknown'),
                'asn': data.get('asn', 'unknown'),
                'latitud': data.get('latitude'),
                'longitud': data.get('longitude'),
                'fuente': 'ipapi.co'
            }
    except Exception as e:
        print(f"[geo] ipapi.co fallo para {ip}: {str(e)[:60]}")

    try:
        result = subprocess.run(['geoiplookup', ip], capture_output=True, text=True, timeout=2)
        if result.returncode == 0 and result.stdout:
            parts = result.stdout.strip().split(',')
            return {
                'pais': parts[2].strip() if len(parts) > 2 else 'unknown',
                'ciudad': parts[1].strip() if len(parts) > 1 else 'unknown',
                'isp': 'unknown',
                'asn': 'unknown',
                'latitud': float(parts[3]) if len(parts) > 3 else None,
                'longitud': float(parts[4]) if len(parts) > 4 else None,
                'fuente': 'maxmind'
            }
    except Exception as e:
        print(f"[geo] geoiplookup fallo para {ip}: {str(e)[:60]}")

    try:
        result = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            geo = {
                'pais': 'unknown',
                'ciudad': 'unknown',
                'isp': 'unknown',
                'asn': 'unknown',
                'latitud': None,
                'longitud': None,
                'fuente': 'whois',
                'owner': 'unknown',
                'responsible': 'unknown',
                'phone': 'unknown',
                'address': 'unknown'
            }
            address_lines = []
            for line in result.stdout.split('\n'):
                line_lower = line.lower()
                if 'country:' in line_lower:
                    geo['pais'] = line.split(':', 1)[1].strip().upper()
                elif 'address:' in line_lower:
                    addr = line.split(':', 1)[1].strip()
                    if addr:
                        address_lines.append(addr)
                elif 'owner:' in line_lower and geo['owner'] == 'unknown':
                    geo['owner'] = line.split(':', 1)[1].strip()
                elif 'responsible:' in line_lower and geo['responsible'] == 'unknown':
                    geo['responsible'] = line.split(':', 1)[1].strip()
                elif 'phone:' in line_lower and geo['phone'] == 'unknown':
                    phone = line.split(':', 1)[1].strip()
                    if phone and phone != 'not available':
                        geo['phone'] = phone
                elif 'org:' in line_lower and geo['isp'] == 'unknown':
                    geo['isp'] = line.split(':', 1)[1].strip()

            if address_lines:
                geo['address'] = ' | '.join(address_lines)
                for addr in address_lines:
                    if geo['ciudad'] == 'unknown':
                        if '(' in addr and '-' in addr:
                            parts = [p.strip() for p in addr.split('-') if p.strip()]
                            if parts:
                                candidate = parts[-1] if len(parts) > 1 else parts[0]
                                if '(' in candidate:
                                    candidate = candidate.split('(')[0].strip()
                                if candidate and len(candidate) > 2 and not any(c.isdigit() for c in candidate[:3]):
                                    geo['ciudad'] = candidate
                                    break
                for addr in address_lines:
                    if geo['ciudad'] == 'unknown' and ',' in addr and addr[0] not in ['-', ' ']:
                        parts = [p.strip() for p in addr.split(',')]
                        if parts and len(parts[0]) > 2 and not any(c.isdigit() for c in parts[0][:5]):
                            geo['ciudad'] = parts[0]
                            break

            if geo['pais'] != 'unknown':
                return geo
    except Exception as e:
        print(f"[geo] whois fallo para {ip}: {str(e)[:60]}")

    return {
        'pais': 'unknown',
        'ciudad': 'unknown',
        'isp': 'unknown',
        'asn': 'unknown',
        'latitud': None,
        'longitud': None,
        'fuente': None
    }


def _reverse_dns_multi_resolver(ip):
    reverses_by_resolver = {}
    resolvers = [
        ('8.8.8.8', 'Google'),
        ('1.1.1.1', 'Cloudflare'),
        ('9.9.9.9', 'Quad9'),
        ('208.67.222.222', 'OpenDNS'),
    ]
 
    try:
        for resolver_ip, resolver_name in resolvers:
            for attempt in range(3):
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [resolver_ip]
                    resolver.timeout = 3 + (attempt * 2)
                    resolver.lifetime = resolver.timeout
                    rev_name = dns.reversename.from_address(ip)
                    answers = resolver.resolve(rev_name, 'PTR')
                    reverses_by_resolver[resolver_name] = [str(rdata).rstrip('.') for rdata in answers]
                    break
                except dns.exception.Timeout:
                    pass
                except dns.exception.NXDOMAIN:
                    break
                except:
                    pass
    except:
        pass
 
    try:
        result = subprocess.run(['nslookup', ip], capture_output=True, text=True, timeout=10)
        for line in result.stdout.split('\n'):
            if 'name =' in line.lower():
                hostname = line.split('=')[1].strip().rstrip('.')
                if hostname and hostname != 'unknown':
                    reverses_by_resolver['System'] = [hostname]
                break
    except:
        pass
 
    all_hostnames = set()
    for hostnames in reverses_by_resolver.values():
        if isinstance(hostnames, list):
            all_hostnames.update(hostnames)
 
    all_hostnames = {h for h in all_hostnames if h and h != 'unknown' and not h.startswith('.')}
 
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
        import sys
        print(f"[mapeo_ips] ⏱️ INICIANDO - proyecto_id={proyecto_id}", flush=True)
        sys.stdout.flush()

        print(f"[mapeo_ips] ⏱️ Llamando get_osint_config...", flush=True)
        sys.stdout.flush()
        config = Proyecto.get_osint_config(proyecto_id)
        print(f"[mapeo_ips] ✅ get_osint_config completado", flush=True)
        sys.stdout.flush()

        ips_analizadas = []
        ips_a_analizar = set()
        resolution_metadata = {
            'dominios_resueltos': {},
            'ips_configuradas': []
        }

        # 1. Agregar IPs configuradas directamente (filtrar IPs de DNS públicos)
        print(f"[mapeo_ips] ⏱️ Procesando IPs configuradas...", flush=True)
        sys.stdout.flush()
        ips_str = config.get('IPS', '').strip() if config else ''
        if ips_str:
            ips_configuradas = _parse_multiline_config(ips_str)
            # Filtrar IPs de resolvers DNS públicos
            ips_configuradas_filtradas = [ip for ip in ips_configuradas if ip not in PUBLIC_DNS_IPS]
            ips_a_analizar.update(ips_configuradas_filtradas)
            resolution_metadata['ips_configuradas'] = ips_configuradas_filtradas
            print(f"[mapeo_ips] ✅ IPs configuradas: {ips_configuradas_filtradas}", flush=True)
        else:
            print(f"[mapeo_ips] ✅ Sin IPs configuradas", flush=True)
        sys.stdout.flush()

        # 2. Resolver dominios + subdominios del scope
        print(f"[mapeo_ips] ⏱️ Extrayendo DOMINIO scope...", flush=True)
        sys.stdout.flush()
        dominio = config.get('DOMINIO', '').strip() if config else ''
        print(f"[mapeo_ips] ✅ DOMINIO extraído: len={len(dominio)}", flush=True)
        sys.stdout.flush()

        print(f"[mapeo_ips] ⏱️ Extrayendo SUBDOMINIO scope...", flush=True)
        sys.stdout.flush()
        subdominio = config.get('SUBDOMINIO', '').strip() if config else ''
        print(f"[mapeo_ips] ✅ SUBDOMINIO extraído: len={len(subdominio)}", flush=True)
        sys.stdout.flush()

        dominios_scope = []
        if dominio:
            dominios_scope.extend(_parse_multiline_config(dominio))
        if subdominio:
            dominios_scope.extend(_parse_multiline_config(subdominio))

        print(f"[mapeo_ips] ⏱️ Dominios del scope a resolver: {dominios_scope}", flush=True)
        sys.stdout.flush()

        print(f"[mapeo_ips] ⏱️ Resolviendo {len(dominios_scope)} dominios scope...", flush=True)
        sys.stdout.flush()
        for idx, dom in enumerate(dominios_scope, 1):
            try:
                print(f"[mapeo_ips] [{idx}/{len(dominios_scope)}] Resolviendo {dom}...", flush=True)
                sys.stdout.flush()
                resolution_result = _resolve_domain_multi_resolver(dom)

                ips_a_analizar.update(resolution_result['ips'])
                resolution_metadata['dominios_resueltos'][dom] = resolution_result['by_resolver']

                print(f"[mapeo_ips] ✅ {dom} → {resolution_result['ips']}", flush=True)
                sys.stdout.flush()
            except Exception as e:
                print(f"[mapeo_ips] ❌ Error resolviendo {dom}: {e}", flush=True)
                sys.stdout.flush()

        # 2b. Resolver subdominios descubiertos (opcional)
        print(f"[mapeo_ips] ⏱️ Llamando get_discovered_subdomains...", flush=True)
        sys.stdout.flush()
        try:
            subdominios_descubiertos = OsintEjecucion.get_discovered_subdomains(proyecto_id)
            print(f"[mapeo_ips] ✅ get_discovered_subdomains completado", flush=True)
            sys.stdout.flush()
            if subdominios_descubiertos and isinstance(subdominios_descubiertos, (list, tuple)):
                print(f"[mapeo_ips] ⏱️ Resolviendo {len(subdominios_descubiertos)} subdominios descubiertos...", flush=True)
                sys.stdout.flush()
                for idx, subdom in enumerate(subdominios_descubiertos, 1):
                    if not subdom:
                        continue
                    try:
                        print(f"[mapeo_ips] [{idx}/{len(subdominios_descubiertos)}] Resolviendo {subdom}...", flush=True)
                        sys.stdout.flush()
                        resolution_result = _resolve_domain_multi_resolver(subdom)
                        if resolution_result and resolution_result.get('ips'):
                            ips_a_analizar.update(resolution_result['ips'])
                            resolution_metadata['dominios_resueltos'][subdom] = resolution_result['by_resolver']
                            print(f"[mapeo_ips] ✅ {subdom} → {resolution_result['ips']}", flush=True)
                            sys.stdout.flush()
                    except Exception as e:
                        print(f"[mapeo_ips] ❌ Error en subdominio {subdom}: {str(e)[:60]}", flush=True)
                        sys.stdout.flush()
            else:
                print(f"[mapeo_ips] ✅ Sin subdominios descubiertos", flush=True)
                sys.stdout.flush()
        except AttributeError:
            print(f"[mapeo_ips] ℹ️ get_discovered_subdomains no disponible (primera ejecución)", flush=True)
            sys.stdout.flush()
        except Exception as e:
            print(f"[mapeo_ips] ❌ Error resolviendo subdominios descubiertos: {str(e)[:100]}", flush=True)
            sys.stdout.flush()

        if not ips_a_analizar:
            print(f"[mapeo_ips] ⚠️ No hay IPs ni dominios configurados para analizar", flush=True)
            sys.stdout.flush()
            raise Exception("No hay IPs ni dominios configurados para analizar")

        print(f"[mapeo_ips] ✅ Total IPs a analizar: {len(ips_a_analizar)}", flush=True)
        sys.stdout.flush()

        # 3. Hacer reverse DNS + Geolocalización para cada IP
        print(f"[mapeo_ips] ⏱️ Preparando mapeo de IP→dominios...", flush=True)
        sys.stdout.flush()
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
        print(f"[mapeo_ips] ✅ Mapeo IP→dominios completado", flush=True)
        sys.stdout.flush()

        # Obtener dominio objetivo para validar hostnames
        print(f"[mapeo_ips] ⏱️ Extrayendo dominio objetivo...", flush=True)
        sys.stdout.flush()
        dominio_objetivo = None
        dominios_config = _parse_multiline_config(dominio) if dominio else []
        if dominios_config:
            dominio_objetivo = dominios_config[0]
        print(f"[mapeo_ips] ✅ Dominio objetivo: {dominio_objetivo}", flush=True)
        sys.stdout.flush()

        print(f"[mapeo_ips] ⏱️ Analizando {len(ips_a_analizar)} IPs (Reverse DNS + Geolocalización)...", flush=True)
        sys.stdout.flush()
        for idx, ip in enumerate(sorted(ips_a_analizar), 1):
            try:
                print(f"[mapeo_ips] [{idx}/{len(ips_a_analizar)}] Analizando {ip}...", flush=True)
                sys.stdout.flush()

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
                    print(f"[mapeo_ips] ✅ {ip} ({hostname}) - {geo_data['pais']}, {geo_data['ciudad']} [VÁLIDO]", flush=True)
                    print(f"              Hostname info: {hostname_validation.get('razon', 'N/A')}", flush=True)
                    sys.stdout.flush()
                else:
                    # IPs sin from_domains (no resueltas desde dominio scope)
                    print(f"[mapeo_ips] ⊘ {ip} ({hostname}) - No fue resuelto desde dominio scope", flush=True)
                    sys.stdout.flush()

            except Exception as e:
                print(f"[mapeo_ips] ❌ Error analizando {ip}: {e}", flush=True)
                sys.stdout.flush()
                geo_data_fallback = _geolocate_ip(ip)
                ips_analizadas.append({
                    'ip': ip,
                    'hostname': 'unknown',
                    'status': 'error',
                    'from_domains': ip_to_dominios.get(ip, []),
                    'es_valido': False,
                    'hostname_validation': None,
                    'geo': geo_data_fallback
                })

        print(f"[mapeo_ips] ⏱️ Compilando resultados finales...", flush=True)
        sys.stdout.flush()
        result = {
            "tipo": "mapeo_ips",
            "total_ips": len(ips_a_analizar),
            "total_success": len(ips_success),
            "ips_success": ips_success,  # ← IPs válidas con geolocalización
            "ips_todas": ips_analizadas   # ← Todas las IPs analizadas (debug)
        }
        print(f"[mapeo_ips] ✅ COMPLETADO - Total: {len(ips_a_analizar)} IPs, Válidas: {len(ips_success)}", flush=True)
        sys.stdout.flush()
        return result

    _run_osint_job(ejecucion_id, job)

def recon_cloud(ejecucion_id, proyecto_id):
    """Reconocimiento MULTICLOUD - Almacenamiento + APIs públicas

    ✨ Busca en:
    - AWS: S3 buckets + API Gateway
    - Azure: Blob Storage + API Management
    - Google Cloud: Cloud Storage + APIs

    FALLBACK CASCADE:
    1. DOMINIO del scope
    2. SUBDOMINIO del scope
    3. Resultados de discovery_subdominios
    4. FALLBACK: Dominios de mapeo_ips

    RÁPIDO: Solo genera candidatos + verifica acceso directo
    """
    def job():
        import sys
        print(f"[recon_cloud] ⏱️ INICIANDO - proyecto_id={proyecto_id}", flush=True)
        sys.stdout.flush()

        print(f"[recon_cloud] ⏱️ Llamando get_osint_config...", flush=True)
        sys.stdout.flush()
        config = Proyecto.get_osint_config(proyecto_id)
        print(f"[recon_cloud] ✅ get_osint_config completado", flush=True)
        sys.stdout.flush()

        # 1. DOMINIO del scope (estado_id=1)
        print(f"[recon_cloud] ⏱️ Extrayendo DOMINIO scope...", flush=True)
        sys.stdout.flush()
        dominio_scope = config.get('DOMINIO', '').strip() if config else ''
        print(f"[recon_cloud] ✅ DOMINIO extraído: len={len(dominio_scope)}", flush=True)
        sys.stdout.flush()

        print(f"[recon_cloud] ⏱️ Parseando DOMINIO scope...", flush=True)
        sys.stdout.flush()
        dominios_config = _parse_multiline_config(dominio_scope) if dominio_scope else []
        print(f"[recon_cloud] ✅ DOMINIO parseado: {dominios_config}", flush=True)
        sys.stdout.flush()

        if dominios_config:
            print(f"[recon_cloud] DOMINIO scope (estado_id=1): {dominios_config}", flush=True)
        else:
            print(f"[recon_cloud] Sin DOMINIO configurado", flush=True)
        sys.stdout.flush()

        # 2. SUBDOMINIO del scope (estado_id=1)
        print(f"[recon_cloud] ⏱️ Extrayendo SUBDOMINIO scope...", flush=True)
        sys.stdout.flush()
        subdominio_scope = config.get('SUBDOMINIO', '').strip() if config else ''
        print(f"[recon_cloud] ✅ SUBDOMINIO extraído: len={len(subdominio_scope)}", flush=True)
        sys.stdout.flush()

        print(f"[recon_cloud] ⏱️ Parseando SUBDOMINIO scope...", flush=True)
        sys.stdout.flush()
        subdominios_config = _parse_multiline_config(subdominio_scope) if subdominio_scope else []
        print(f"[recon_cloud] ✅ SUBDOMINIO parseado: {subdominios_config}", flush=True)
        sys.stdout.flush()

        if subdominios_config:
            print(f"[recon_cloud] SUBDOMINIO scope (estado_id=1): {subdominios_config}", flush=True)
        sys.stdout.flush()

        # 3. Resultados de discovery_subdominios (estado_id=1)
        print(f"[recon_cloud] ⏱️ Llamando get_discovered_subdomains...", flush=True)
        sys.stdout.flush()
        dominios_descubiertos = OsintEjecucion.get_discovered_subdomains(proyecto_id)
        print(f"[recon_cloud] ✅ get_discovered_subdomains completado", flush=True)
        sys.stdout.flush()

        if dominios_descubiertos:
            print(f"[recon_cloud] Subdominios descubiertos (estado_id=1): {len(dominios_descubiertos)}", flush=True)
        else:
            print(f"[recon_cloud] Sin subdominios descubiertos", flush=True)
        sys.stdout.flush()

        # Combinar: scope + descubiertos
        print(f"[recon_cloud] ⏱️ Combinando dominios...", flush=True)
        sys.stdout.flush()
        todos_los_dominios = dominios_config + subdominios_config + dominios_descubiertos
        print(f"[recon_cloud] ✅ Dominios combinados: {len(todos_los_dominios)}", flush=True)
        sys.stdout.flush()

        if not todos_los_dominios:
            raise Exception("No hay dominios para escanear (DOMINIO/SUBDOMINIO vacío o discovery sin resultados con estado_id=1)")

        # ═══════════════════════════════════════════════════════════════
        # GENERAR CASCADAS DE DOMINIOS
        # SCOPE (DOMINIO + SUBDOMINIO) + DISCOVERY (estado_id=1)
        # Ej: ater.gob.ar → [ater.gob.ar, ater.gob, ater]
        # Ej: vpn.ater.gob.ar → [vpn.ater.gob.ar, vpn.ater.gob, vpn.ater]
        # ═══════════════════════════════════════════════════════════════
        def _generate_domain_cascades(dominio):
            """Genera variaciones en cascada de un dominio reduciendo desde el final."""
            parts = dominio.split('.')
            variaciones = []
            # Generar desde completo hasta un segmento
            for i in range(len(parts), 0, -1):
                variaciones.append('.'.join(parts[:i]))
            return variaciones

        # Expandir dominios con cascadas
        dominios_expandidos = []

        # Cascadas para SCOPE (DOMINIO + SUBDOMINIO con estado_id=1)
        print(f"[recon_cloud] ⏱️ Generando cascadas para SCOPE...", flush=True)
        sys.stdout.flush()
        print(f"[recon_cloud] ════ Generando cascadas para SCOPE ════", flush=True)
        for dom in dominios_config + subdominios_config:
            cascadas = _generate_domain_cascades(dom)
            dominios_expandidos.extend(cascadas)
            print(f"[recon_cloud] Cascadas: {dom} → {cascadas}", flush=True)
        print(f"[recon_cloud] ✅ Cascadas SCOPE completadas", flush=True)
        sys.stdout.flush()

        # Cascadas para DISCOVERY (estado_id=1)
        if dominios_descubiertos:
            print(f"[recon_cloud] ⏱️ Generando cascadas para DISCOVERY...", flush=True)
            sys.stdout.flush()
            print(f"[recon_cloud] ════ Generando cascadas para DISCOVERY ════", flush=True)
            for dom in dominios_descubiertos:
                cascadas = _generate_domain_cascades(dom)
                dominios_expandidos.extend(cascadas)
                print(f"[recon_cloud] Cascadas: {dom} → {cascadas}", flush=True)
            print(f"[recon_cloud] ✅ Cascadas DISCOVERY completadas", flush=True)
            sys.stdout.flush()

        print(f"[recon_cloud] ⏱️ Eliminando duplicados...", flush=True)
        sys.stdout.flush()
        todos_los_dominios = list(set(dominios_expandidos))  # Eliminar duplicados
        print(f"[recon_cloud] ✅ Total dominios a escanear (con cascadas): {len(todos_los_dominios)}", flush=True)
        sys.stdout.flush()

        # Extraer dominio raíz para variaciones
        dominio_raiz = None
        if dominios_config:
            primer_dominio = dominios_config[0]
            partes = primer_dominio.split('.')
            dominio_raiz = partes[0] if len(partes) >= 2 else primer_dominio

        print(f"[recon_cloud] ════════════════════════════════════════════", flush=True)
        print(f"[recon_cloud] MULTICLOUD: Buscando almacenamiento + APIs", flush=True)
        print(f"[recon_cloud] ════════════════════════════════════════════", flush=True)
        sys.stdout.flush()

        recursos = []

        # ═══════════════════════════════════════════════════════════════
        # AWS: S3 Buckets
        # ═══════════════════════════════════════════════════════════════
        print(f"[recon_cloud] ⏱️ INICIANDO AWS S3 Buckets...", flush=True)
        sys.stdout.flush()
        print(f"[recon_cloud] ════ AWS S3 Buckets ════", flush=True)
        s3_count = 0
        for dom in todos_los_dominios:
            s3_count += 1
            print(f"[recon_cloud] S3 [{s3_count}/{len(todos_los_dominios)}] Generando candidatos para {dom}...", flush=True)
            sys.stdout.flush()

            candidatos_s3 = _generate_s3_candidates(dom)
            print(f"[recon_cloud] S3 [{s3_count}/{len(todos_los_dominios)}] Probando {len(candidatos_s3)} candidatos para {dom}...", flush=True)
            sys.stdout.flush()

            for bucket in candidatos_s3:
                resultado = _verify_s3_bucket(bucket, dom)
                if resultado:
                    for r in resultado:
                        r['proveedor'] = 'AWS'
                    recursos.extend(resultado)

        print(f"[recon_cloud] ✅ AWS S3 completado", flush=True)
        sys.stdout.flush()

        # ═══════════════════════════════════════════════════════════════
        # AWS: API Gateway
        # ═══════════════════════════════════════════════════════════════
        print(f"[recon_cloud] ⏱️ INICIANDO AWS API Gateway...", flush=True)
        sys.stdout.flush()
        print(f"[recon_cloud] ════ AWS API Gateway ════", flush=True)
        api_count = 0
        for dom in todos_los_dominios:
            api_count += 1
            print(f"[recon_cloud] API-AWS [{api_count}/{len(todos_los_dominios)}] Probando candidatos para {dom}...", flush=True)
            sys.stdout.flush()

            candidatos_api = _generate_api_candidates(dom, 'aws')

            for api_name in candidatos_api:
                resultado = _verify_aws_api_gateway(api_name, dom)
                if resultado:
                    for r in resultado:
                        r['proveedor'] = 'AWS'
                    recursos.extend(resultado)

        print(f"[recon_cloud] ✅ AWS API Gateway completado", flush=True)
        sys.stdout.flush()

        # ═══════════════════════════════════════════════════════════════
        # AZURE: Blob Storage
        # ═══════════════════════════════════════════════════════════════
        print(f"[recon_cloud] ⏱️ INICIANDO Azure Blob Storage...", flush=True)
        sys.stdout.flush()
        print(f"[recon_cloud] ════ Azure Blob Storage ════", flush=True)
        blob_count = 0
        for dom in todos_los_dominios:
            blob_count += 1
            print(f"[recon_cloud] BLOB [{blob_count}/{len(todos_los_dominios)}] Probando candidatos para {dom}...", flush=True)
            sys.stdout.flush()

            candidatos_azure = _generate_azure_candidates(dom)

            for storage_account in candidatos_azure:
                resultado = _verify_azure_blob(storage_account, dom)
                if resultado:
                    for r in resultado:
                        r['proveedor'] = 'Azure'
                    recursos.extend(resultado)

        print(f"[recon_cloud] ✅ Azure Blob Storage completado", flush=True)
        sys.stdout.flush()

        # ═══════════════════════════════════════════════════════════════
        # AZURE: API Management
        # ═══════════════════════════════════════════════════════════════
        print(f"[recon_cloud] ⏱️ INICIANDO Azure API Management...", flush=True)
        sys.stdout.flush()
        print(f"[recon_cloud] ════ Azure API Management ════", flush=True)
        apim_count = 0
        for dom in todos_los_dominios:
            apim_count += 1
            print(f"[recon_cloud] APIM [{apim_count}/{len(todos_los_dominios)}] Probando candidatos para {dom}...", flush=True)
            sys.stdout.flush()

            candidatos_api = _generate_api_candidates(dom, 'azure')

            for api_name in candidatos_api:
                resultado = _verify_azure_api_management(api_name, dom)
                if resultado:
                    for r in resultado:
                        r['proveedor'] = 'Azure'
                    recursos.extend(resultado)

        print(f"[recon_cloud] ✅ Azure API Management completado", flush=True)
        sys.stdout.flush()

        # ═══════════════════════════════════════════════════════════════
        # GOOGLE: Cloud Storage
        # ═══════════════════════════════════════════════════════════════
        print(f"[recon_cloud] ⏱️ INICIANDO Google Cloud Storage...", flush=True)
        sys.stdout.flush()
        print(f"[recon_cloud] ════ Google Cloud Storage ════", flush=True)
        gcp_count = 0
        for dom in todos_los_dominios:
            gcp_count += 1
            print(f"[recon_cloud] GCP [{gcp_count}/{len(todos_los_dominios)}] Probando candidatos para {dom}...", flush=True)
            sys.stdout.flush()

            candidatos_gcp = _generate_gcp_candidates(dom)

            for bucket in candidatos_gcp:
                resultado = _verify_gcp_bucket(bucket, dom)
                if resultado:
                    for r in resultado:
                        r['proveedor'] = 'GCP'
                    recursos.extend(resultado)

        print(f"[recon_cloud] ✅ Google Cloud Storage completado", flush=True)
        sys.stdout.flush()

        print(f"[recon_cloud] ⏱️ Preparando resultado final...", flush=True)
        sys.stdout.flush()

        resultado_final = {
            "tipo": "recon_cloud",
            "dominio_scope": dominio_scope,
            "subdominio_scope": subdominio_scope,
            "total_dominios_config": len(dominios_config) + len(subdominios_config),
            "total_dominios_descubiertos": len(dominios_descubiertos),
            "total_dominios_buscados": len(todos_los_dominios),
            "total_recursos": len(recursos),
            "recursos": recursos
        }

        print(f"[recon_cloud] ✅ COMPLETADO - Encontrados {len(recursos)} recursos en {len(todos_los_dominios)} dominios", flush=True)
        sys.stdout.flush()

        return resultado_final

    _run_osint_job(ejecucion_id, job)


# ═══════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS FOR CLOUD SERVICE RECONNAISSANCE
# ═══════════════════════════════════════════════════════════════════════

def _extract_org_name(dominio):
    """
    Extrae el nombre de la organización del dominio.
    Para subdomios (4+ partes): usa la segunda parte
    Ejemplo: www.ater.gob.ar -> ater
    Para dominios regulares (3 partes): usa la primera parte
    Ejemplo: ater.gob.ar -> ater
    """
    parts = dominio.split('.')

    # Si es un subdominio (4+ partes), usar la segunda parte
    if len(parts) >= 4:
        return parts[1]
    # Si es un dominio regular, usar la primera parte
    else:
        return parts[0]


# ═══════════════════════════════════════════════════════════════════════
# AWS S3 HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _generate_s3_candidates(dominio):
    """Genera candidatos de buckets S3 (RÁPIDO)"""
    parts = dominio.split('.')
    org_name = _extract_org_name(dominio)
    domain_name = org_name

    candidates = [
        domain_name,
        '-'.join(parts) if len(parts) > 1 else domain_name,
        f"{domain_name}-backup",
        f"{domain_name}-data",
        f"{domain_name}-assets",
        f"{domain_name}-storage",
        f"{domain_name}-prod",
        f"{domain_name}-staging",
        f"aws-{domain_name}",
        f"s3-{domain_name}",
    ]

    return list(set(filter(None, candidates)))


def _verify_s3_bucket(bucket_name, dominio):
    """Verifica si bucket S3 existe y es público (usando curl - más rápido)"""
    resultado = []

    try:
        # Usar curl en lugar de aws CLI (más rápido y respeta timeouts)
        url = f"https://{bucket_name}.s3.amazonaws.com/"
        result = subprocess.run(
            ['curl', '-s', '-I', '--max-time', '5', url],
            capture_output=True,
            text=True,
            timeout=6
        )

        if '200' in result.stdout:
            # Bucket abierto al público
            print(f"[s3] ✅ PÚBLICO: {bucket_name}")
            resultado.append({
                'tipo': 's3_bucket',
                'nombre': bucket_name,
                'dominio': dominio,
                'acceso': 'público',
                'url': url,
                'poc': [
                    f"aws s3 ls s3://{bucket_name}/ --no-sign-request",
                    f"s3cmd ls s3://{bucket_name}/",
                    f"curl {url}"
                ]
            })
        elif '403' in result.stdout:
            # Existe pero privado
            pass
        else:
            # No existe o error
            pass

    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        print(f"[s3] Error verificando {bucket_name}: {e}")

    return resultado


# ═══════════════════════════════════════════════════════════════════════
# AZURE Blob Storage HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _generate_azure_candidates(dominio):
    """Genera candidatos de storage accounts Azure (RÁPIDO)"""
    base = _extract_org_name(dominio)

    candidates = [
        base,
        f"{base}storage",
        f"{base}data",
        f"{base}backup",
        f"storage{base}",
        f"data{base}",
        f"{base}blob",
        f"blob{base}",
        f"azure{base}",
    ]

    return list(set(filter(None, candidates)))


def _verify_azure_blob(storage_account, dominio):
    """Verifica si Azure Blob Storage existe y es público"""
    resultado = []

    try:
        # Azure Blob Storage URL estándar
        url = f"https://{storage_account}.blob.core.windows.net/"

        # Intentar listar contenedores públicos
        result = subprocess.run(
            ['curl', '-s', '-I', '--max-time', '5', url],
            capture_output=True,
            text=True,
            timeout=6
        )

        if '200' in result.stdout or '403' in result.stdout:
            # 200 = público, 403 = existe pero privado
            if '200' in result.stdout:
                print(f"[azure] ✅ PÚBLICO: {storage_account}")
                acceso = 'público'
            else:
                print(f"[azure] 🔒 Privado: {storage_account}")
                acceso = 'privado'

            resultado.append({
                'tipo': 'azure_blob_storage',
                'nombre': storage_account,
                'dominio': dominio,
                'acceso': acceso,
                'url': url,
                'poc': [
                    f"curl -v {url}",
                    f"curl -I {url}",
                    f"az storage container list --account-name {storage_account}"
                ]
            })

    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        print(f"[azure] Error verificando {storage_account}: {e}")

    return resultado


# ═══════════════════════════════════════════════════════════════════════
# GOOGLE Cloud Storage HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _generate_gcp_candidates(dominio):
    """Genera candidatos de buckets GCP (RÁPIDO)"""
    base = _extract_org_name(dominio)

    candidates = [
        base,
        f"{base}-bucket",
        f"{base}-storage",
        f"{base}-data",
        f"{base}-backup",
        f"gcp-{base}",
        f"cloud-{base}",
        f"{base}-gcp",
        f"gs-{base}",
    ]

    return list(set(filter(None, candidates)))


def _verify_gcp_bucket(bucket_name, dominio):
    """Verifica si GCP bucket existe y es público"""
    resultado = []

    try:
        # GCP Cloud Storage URL
        url = f"https://storage.googleapis.com/{bucket_name}/"

        # Intentar acceder sin autenticación
        result = subprocess.run(
            ['curl', '-s', '-I', '--max-time', '5', url],
            capture_output=True,
            text=True,
            timeout=6
        )

        if '200' in result.stdout:
            print(f"[gcp] ✅ PÚBLICO: {bucket_name}")
            resultado.append({
                'tipo': 'gcp_cloud_storage',
                'nombre': bucket_name,
                'dominio': dominio,
                'acceso': 'público',
                'url': url,
                'poc': [
                    f"gsutil ls gs://{bucket_name}/",
                    f"curl {url}",
                    f"gcloud storage buckets list --filter=name={bucket_name}"
                ]
            })
        elif '403' in result.stdout:
            print(f"[gcp] 🔒 Privado: {bucket_name}")
            resultado.append({
                'tipo': 'gcp_cloud_storage',
                'nombre': bucket_name,
                'dominio': dominio,
                'acceso': 'privado',
                'url': url,
                'poc': [
                    f"gsutil ls gs://{bucket_name}/",
                    f"curl -v {url}",
                    f"gcloud storage buckets describe {bucket_name}"
                ]
            })

    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        print(f"[gcp] Error verificando {bucket_name}: {e}")

    return resultado


# ═══════════════════════════════════════════════════════════════════════
# API GATEWAY HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _generate_api_candidates(dominio, provider='aws'):
    """Genera candidatos de APIs (AWS API Gateway / Azure API Management)"""
    base = _extract_org_name(dominio)

    candidates = [
        base,
        f"{base}-api",
        f"{base}-gateway",
        f"api-{base}",
        f"gateway-{base}",
        f"{base}-service",
        f"service-{base}",
    ]

    return list(set(filter(None, candidates)))


def _verify_aws_api_gateway(api_name, dominio):
    """Verifica si AWS API Gateway existe"""
    resultado = []

    # Regiones comunes a probar
    regiones = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'ap-northeast-1']

    for region in regiones:
        try:
            url = f"https://{api_name}.execute-api.{region}.amazonaws.com/"

            result = subprocess.run(
                ['curl', '-s', '-I', '--max-time', '5', url],
                capture_output=True,
                text=True,
                timeout=6
            )

            if '200' in result.stdout or '403' in result.stdout or '404' in result.stdout:
                # API Gateway encontrado (puede retornar 404 si no existe recurso, pero domain existe)
                acceso = 'público' if '200' in result.stdout else 'privado'
                print(f"[aws-api] ✅ ENCONTRADO: {api_name} en {region}")
                resultado.append({
                    'tipo': 'aws_api_gateway',
                    'nombre': api_name,
                    'region': region,
                    'dominio': dominio,
                    'acceso': acceso,
                    'url': url,
                    'poc': [
                        f"curl {url}",
                        f"curl -v {url}",
                        f"aws apigateway get-rest-apis --region {region}",
                        f"aws apigateway get-stages --rest-api-id <API_ID> --region {region}"
                    ]
                })
                break  # Si encontramos en una región, no seguir

        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            pass

    return resultado


def _verify_azure_api_management(api_name, dominio):
    """Verifica si Azure API Management existe"""
    resultado = []

    try:
        url = f"https://{api_name}.azure-api.net/"

        result = subprocess.run(
            ['curl', '-s', '-I', '--max-time', '5', url],
            capture_output=True,
            text=True,
            timeout=6
        )

        if '200' in result.stdout:
            print(f"[azure-api] ✅ PÚBLICO: {api_name}")
            acceso = 'público'
        elif '401' in result.stdout or '403' in result.stdout:
            print(f"[azure-api] 🔒 Encontrado (privado): {api_name}")
            acceso = 'privado'
        else:
            # No encontrado
            return resultado

        resultado.append({
            'tipo': 'azure_api_management',
            'nombre': api_name,
            'dominio': dominio,
            'acceso': acceso,
            'url': url,
            'poc': [
                f"curl {url}",
                f"curl -v -H 'Ocp-Apim-Subscription-Key: <KEY>' {url}",
                f"az apim api list --resource-group <RG> --service-name {api_name}"
            ]
        })

    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        print(f"[azure-api] Error verificando {api_name}: {e}")

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

def _filter_urls_by_extension(urls):
    """
    Filtra URLs descartando SOLO extensiones inútiles para pentest.
    
    DESCARTA:
    - .gif, .png, .ico, .svg (iconos y gráficos)
    - .css, .js, .woff, .woff2, .ttf, .eot (recursos frontend)
    
    MANTIENE TODO LO DEMÁS:
    - .jpg, .jpeg (imágenes para extraer metadatos)
    - .php, .html, .pdf, .doc, .docx, .xlsx, etc.
    - URLs sin extensión (directorios, APIs)
    - Cualquier otra cosa que NO esté en la lista de exclusión
    """
    
    # SOLO extensiones INÚTILES para pentest
    EXCLUDE_EXTENSIONS = {
        '.gif', '.png', '.ico', '.svg',  # Imágenes que no aportan info
        '.css', '.js',                    # Código frontend
        '.woff', '.woff2', '.ttf', '.eot' # Fuentes
    }
    
    urls_filtradas = []
    descartadas = 0
    
    for url in urls:
        if not url or not isinstance(url, str):
            continue
            
        # Obtener extensión (ignorar parámetros GET)
        path = url.split('?')[0] if '?' in url else url
        path = path.split('#')[0] if '#' in path else path
        
        # Obtener extensión
        import os
        _, ext = os.path.splitext(path)
        ext = ext.lower()
        
        # Si está en la lista de EXCLUSIÓN → descartar
        if ext in EXCLUDE_EXTENSIONS:
            descartadas += 1
            continue
        
        # Si NO está en EXCLUSIÓN → mantener (imágenes, php, pdf, etc.)
        urls_filtradas.append(url)
    print(f"[filter_urls] URLs originales: {len(urls)}")
    print(f"[filter_urls] URLs descartadas: {descartadas}")
    print(f"[filter_urls] URLs finales: {len(urls_filtradas)}")    
    
    return urls_filtradas

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
        result = subprocess.run(
            [gau_path, '--blacklist', 'jpg,jpeg,png,gif,svg,css,js,woff,woff2,ttf,eot', target],
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.stdout:
            urls_raw = result.stdout.strip().split('\n')
            urls.update([url for url in urls_raw if url])
            print(f"[gau] Encontradas {len(urls)} URLs históricas para {target}")
            
            # ✨ NUEVO: Filtrar extensiones inútiles
            urls_filtradas = set(_filter_urls_by_extension(list(urls)))
            print(f"[gau] Después de filtrado: {len(urls_filtradas)} URLs válidas")
            
            return urls_filtradas
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