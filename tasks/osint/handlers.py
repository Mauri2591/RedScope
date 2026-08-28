import tempfile
from urllib.parse import urljoin, urlparse
from pathlib import Path
import re
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
import traceback
import sys
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin

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
        severidades_sorted = sorted(
            severidades, key=lambda x: x.get('score', 0))

        # Buscar severidad cuyo score sea <= score_normalizado
        # Comienza con la más baja
        severidad_seleccionada = severidades_sorted[0]
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
    """Wrapper mejorado para todos los jobs OSINT.

    Mejoras:
    - Loguea excepciones con stack trace completo
    - Retorna resultado para que RQ lo procese
    - Re-lanza excepciones para estabilidad del worker
    - Mejor visibilidad en logs
    """
    try:
        print(f"[OSINT] ========================================")
        print(f"[OSINT] Job {ejecucion_id} INICIANDO")
        print(f"[OSINT] Tiempo: {datetime.now().isoformat()}")
        print(f"[OSINT] ========================================")

        OsintEjecucion.mark_running(ejecucion_id)
        print(f"[OSINT] Estado marcado como RUNNING")

        resultado = fn()

        print(f"[OSINT] ========================================")
        print(f"[OSINT] ✅ Job {ejecucion_id} COMPLETADO")
        print(f"[OSINT] Tiempo: {datetime.now().isoformat()}")
        print(f"[OSINT] ========================================")

        OsintEjecucion.mark_completed(ejecucion_id, resultado)
        return resultado

    except Exception as e:
        error_trace = traceback.format_exc()

        print(f"[OSINT] ========================================")
        print(f"[OSINT] ❌ ERROR en Job {ejecucion_id}")
        print(f"[OSINT] Mensaje: {str(e)}")
        print(f"[OSINT] Stack trace:")
        print(error_trace)
        print(f"[OSINT] Tiempo: {datetime.now().isoformat()}")
        print(f"[OSINT] ========================================")

        try:
            OsintEjecucion.mark_failed(ejecucion_id, str(e))
        except Exception as db_error:
            print(f"[OSINT] Error marcando fallo en BD: {db_error}")

        # Re-lanzar para que RQ maneje correctamente
        raise

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
    '127.0.0.53',  # systemd-resolved local DNS
    '127.0.0.1',   # localhost
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
    """Geolocaliza una IP usando múltiples fuentes en cascada"""
    print(f"[geo] Iniciando geolocalización para {ip}")

    # ═════════════════════════════════════════════════════════════════
    # 1️ EARLY RETURN para localhost (AGREGADO)
    # ═════════════════════════════════════════════════════════════════
    if ip.startswith('127.') or ip == 'localhost':
        print(f"[geo] {ip} es localhost → retornar unknown")
        return {
            'pais': 'unknown',
            'ciudad': 'unknown',
            'isp': 'unknown',
            'asn': 'unknown',
            'latitud': None,
            'longitud': None,
            'fuente': 'localhost'
        }

    # ═════════════════════════════════════════════════════════════════
    # MÉTODO 1: ipapi.co
    # ═════════════════════════════════════════════════════════════════
    try:
        print(f"[geo] Intentando ipapi.co para {ip}...")
        result = requests.get(f'https://ipapi.co/{ip}/json/', timeout=5)
        print(f"[geo] ipapi.co status: {result.status_code}")
        if result.status_code == 200:
            data = result.json()  # ✓ Solo UNA vez (antes estaba dos veces)
            print(f"[geo] ipapi.co data: {data}")
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

    # ═════════════════════════════════════════════════════════════════
    # MÉTODO 2: geoiplookup
    # ═════════════════════════════════════════════════════════════════
    try:
        print(f"[geo] Intentando geoiplookup para {ip}...")
        result = subprocess.run(['geoiplookup', ip],
                                capture_output=True, text=True, timeout=2)
        if result.returncode == 0 and result.stdout:
            parts = result.stdout.strip().split(',')

            # Construir dict primero
            geo_data = {
                'pais': parts[2].strip() if len(parts) > 2 else 'unknown',
                'ciudad': parts[1].strip() if len(parts) > 1 else 'unknown',
                'isp': 'unknown',
                'asn': 'unknown',
                'latitud': float(parts[3]) if len(parts) > 3 else None,
                'longitud': float(parts[4]) if len(parts) > 4 else None,
                'fuente': 'maxmind'
            }

            # CRITICAL FIX: Solo retornar si encontró país real
            if geo_data['pais'] != 'unknown':
                print(
                    f"[geo] geoiplookup encontró país: {geo_data['pais']} → retornando")
                return geo_data
            else:
                print(
                    f"[geo] geoiplookup retornó pais='unknown' → continuando a whois")
                # NO RETORNA - continúa a la siguiente sección (whois)

    except Exception as e:
        print(f"[geo] geoiplookup fallo para {ip}: {str(e)[:60]}")

    # ═════════════════════════════════════════════════════════════════
    # MÉTODO 3: whois
    # ═════════════════════════════════════════════════════════════════
    try:
        print(f"[geo] Intentando whois para {ip}...")
        result = subprocess.run(
            ['whois', ip], capture_output=True, text=True, timeout=15)
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
                # 2️ EXTRACCIÓN DE ASN (AGREGADO)
                elif geo['asn'] == 'unknown' and any(key in line_lower for key in ['originasn:', 'origin-as:', 'asn:']):
                    try:
                        asn_value = line.split(':', 1)[1].strip(
                        ) if ':' in line else line.split()[-1]
                        asn_value = asn_value.replace(
                            'AS', '').replace('as', '').strip()
                        if asn_value and asn_value != 'not available' and asn_value.isdigit():
                            geo['asn'] = asn_value
                            print(f"[geo] whois ASN extraído: {asn_value}")
                    except:
                        pass

            if address_lines:
                geo['address'] = ' | '.join(address_lines)
                for addr in address_lines:
                    if geo['ciudad'] == 'unknown':
                        if '(' in addr and '-' in addr:
                            parts = [p.strip()
                                     for p in addr.split('-') if p.strip()]
                            if parts:
                                candidate = parts[-1] if len(
                                    parts) > 1 else parts[0]
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

            # 3️ PRINT DE CONFIRMACIÓN (AGREGADO)
            print(
                f"[geo] whois completo: país={geo['pais']}, ciudad={geo['ciudad']}, isp={geo['isp']}, asn={geo['asn']}")
            if geo['pais'] != 'unknown':
                return geo
    except Exception as e:
        print(f"[geo] whois fallo para {ip}: {str(e)[:60]}")

    print(f"[geo] ❌ Todas las fuentes agotadas para {ip}")
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
                    reverses_by_resolver[resolver_name] = [
                        str(rdata).rstrip('.') for rdata in answers]
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
        result = subprocess.run(
            ['nslookup', ip], capture_output=True, text=True, timeout=10)
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

    all_hostnames = {h for h in all_hostnames if h and h !=
                     'unknown' and not h.startswith('.')}

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
    print(f"[OSINT-DISCOVERY] Handler iniciado para ejecución {ejecucion_id}")

    def job():
        # 1. Obtener scope: DOMINIO + SUBDOMINIO + SERVICIOS
        scope = OsintEjecucion.get_scope_completo(proyecto_id)
        todos_los_dominios = scope['dominio'] + \
            scope['subdominio'] + scope['servicios']

        # 2. Fallback: Obtener dominios de mapeo_ips
        dominios_from_ips = []
        if not todos_los_dominios:
            dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(
                proyecto_id)
            todos_los_dominios = dominios_from_ips

        if not todos_los_dominios:
            raise Exception(
                "No hay dominios configurados (scope vacío y mapeo_ips sin resultados)")

        subdominios = set()
        print(
            f"[discovery_subdominios] Escaneando {len(todos_los_dominios)} dominios con subfinder")

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
        dominios_scope = _parse_multiline_config(
            dominio_config) if dominio_config else []
        if dominios_scope:
            print(
                f"[enumeracion_servicios] Dominios del scope encontrados: {dominios_scope}")
        else:
            print(f"[enumeracion_servicios] Sin dominios configurados en DOMINIO")

        # 2. Fallback: Obtener dominios descubiertos por reverse DNS (mapeo_ips)
        dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(
            proyecto_id)
        if dominios_from_ips:
            print(
                f"[enumeracion_servicios] Dominios del objetivo desde mapeo_ips: {dominios_from_ips}")

        # 3. Fallback: Obtener subdominios descubiertos
        subdominios_descubiertos = OsintEjecucion.get_discovered_subdomains(
            proyecto_id)
        if subdominios_descubiertos:
            print(
                f"[enumeracion_servicios] Subdominios descubiertos: {len(subdominios_descubiertos)}")

        # 4. Combinar todas las fuentes de dominios
        todos_los_dominios = list(
            set(dominios_scope + dominios_from_ips + subdominios_descubiertos))

        # 5. Validar que hay dominios para escanear
        if not todos_los_dominios:
            raise Exception(
                "No hay dominios para escanear (DOMINIO no configurado, mapeo_ips vacío y sin subdominios descubiertos)")

        servicios = []
        puertos_dict = OsintEjecucion.top_100_common_ports()
        if not puertos_dict:
            puertos_dict = {'80': 'http', '443': 'https',
                            '22': 'ssh', '3306': 'mysql'}

        puertos_str = ','.join(puertos_dict.keys())
        print(
            f"[nmap] Escaneando {len(puertos_dict)} puertos comunes en {len(todos_los_dominios)} dominios")

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
    print(f"[OSINT-MAPEO-IPS] Handler iniciado para ejecución {ejecucion_id}")

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
            ips_configuradas_filtradas = [
                ip for ip in ips_configuradas if ip not in PUBLIC_DNS_IPS]
            ips_a_analizar.update(ips_configuradas_filtradas)
            resolution_metadata['ips_configuradas'] = ips_configuradas_filtradas
            print(
                f"[mapeo_ips] IPs configuradas: {ips_configuradas_filtradas}")

        # 2. Resolver dominios + subdominios del scope
        dominio = config.get('DOMINIO', '').strip() if config else ''
        subdominio = config.get('SUBDOMINIO', '').strip() if config else ''

        dominios_scope = []
        if dominio:
            dominios_scope.extend(_parse_multiline_config(dominio))
        if subdominio:
            dominios_scope.extend(_parse_multiline_config(subdominio))

        print(f"[mapeo_ips] Dominios del scope a resolver: {dominios_scope}")

        for dom in dominios_scope:
            try:
                print(
                    f"[mapeo_ips] Resolviendo {dom} con múltiples resolvers...")
                resolution_result = _resolve_domain_multi_resolver(dom)

                ips_a_analizar.update(resolution_result['ips'])
                resolution_metadata['dominios_resueltos'][dom] = resolution_result['by_resolver']

                print(f"[mapeo_ips] {dom} → {resolution_result['ips']}")
            except Exception as e:
                print(f"[mapeo_ips] Error resolviendo {dom}: {e}")

        # 2b. Resolver subdominios descubiertos (opcional)
        try:
            subdominios_descubiertos = OsintEjecucion.get_discovered_subdomains(
                proyecto_id)
            if subdominios_descubiertos and isinstance(subdominios_descubiertos, (list, tuple)):
                print(
                    f"[mapeo_ips] Resolviendo {len(subdominios_descubiertos)} subdominios descubiertos...")
                for subdom in subdominios_descubiertos:
                    if not subdom:
                        continue
                    try:
                        resolution_result = _resolve_domain_multi_resolver(
                            subdom)
                        if resolution_result and resolution_result.get('ips'):
                            ips_a_analizar.update(resolution_result['ips'])
                            resolution_metadata['dominios_resueltos'][subdom] = resolution_result['by_resolver']
                            print(
                                f"[mapeo_ips] {subdom} → {resolution_result['ips']}")
                    except Exception as e:
                        print(
                            f"[mapeo_ips] Error en subdominio {subdom}: {str(e)[:60]}")
        except AttributeError:
            print(
                f"[mapeo_ips] get_discovered_subdomains no disponible (primera ejecución)")
        except Exception as e:
            print(
                f"[mapeo_ips] Error resolviendo subdominios descubiertos: {str(e)[:100]}")

        if not ips_a_analizar:
            raise Exception(
                "No hay IPs ni dominios configurados para analizar")

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
        ip_to_dominios = {ip: sorted(list(doms))
                          for ip, doms in ip_to_dominios.items()}

        # Obtener dominio objetivo para validar hostnames
        dominio_objetivo = None
        dominios_config = _parse_multiline_config(dominio) if dominio else []
        if dominios_config:
            dominio_objetivo = dominios_config[0]

        # ★ FILTRO CRÍTICO: Eliminar IPs de DNS públicas antes de analizar
        # ★ FILTRO CRÍTICO: Eliminar IPs de DNS públicas antes de analizar
        print(f"[DEBUG] ips_a_analizar ANTES de filtrar: {ips_a_analizar}")
        print(f"[DEBUG] PUBLIC_DNS_IPS: {PUBLIC_DNS_IPS}")
        ips_a_analizar = {
            ip for ip in ips_a_analizar if ip not in PUBLIC_DNS_IPS}
        print(f"[DEBUG] ips_a_analizar DESPUÉS de filtrar: {ips_a_analizar}")

        print(
            f"[mapeo_ips] IPs después de filtrar DNS públicas: {len(ips_a_analizar)}")

        # 3. Hacer reverse DNS + Geolocalización para cada IP
        ips_success = []

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
                hostname_validation = _validate_hostname_belongs_to_domain(
                    hostname, dominio_objetivo, ip)

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
                    print(
                        f"[mapeo_ips] ✓ {ip} ({hostname}) - {geo_data['pais']}, {geo_data['ciudad']} [VÁLIDO]")
                    print(
                        f"              Hostname info: {hostname_validation.get('razon', 'N/A')}")
                else:
                    # IPs sin from_domains (no resueltas desde dominio scope)
                    print(
                        f"[mapeo_ips] ⊘ {ip} ({hostname}) - No fue resuelto desde dominio scope")

            except Exception as e:
                print(f"[mapeo_ips] Error analizando {ip}: {e}")
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

        return {
            "tipo": "mapeo_ips",
            "total_ips": len(ips_a_analizar),
            "total_success": len(ips_success),
            "ips_success": ips_success,  # ← IPs válidas con geolocalización
            "ips_todas": ips_analizadas   # ← Todas las IPs analizadas (debug)
        }

    _run_osint_job(ejecucion_id, job)


# ══════════════════════════════════════════════════════════════════════════════════════════
# ENHANCED RECON_CLOUD - MULTI-CLOUD PROVIDER SUPPORT
# ══════════════════════════════════════════════════════════════════════════════════════════
#
# CAMBIOS PRINCIPALES:
# 1. AWS S3 - Mantiene funcionamiento existente (tier-based bucket discovery)
# 2. Azure Blob Storage - Nuevas URLs: https://{account}.blob.core.windows.net
# 3. Google Cloud Storage - Nuevas URLs: https://storage.googleapis.com/{bucket}
# 4. DigitalOcean Spaces - Nuevas URLs: https://{space}.{region}.digitaloceanspaces.com
# 5. Backblaze B2 - Nuevas URLs: https://f{id}.backblazeb2.com/file/{bucket}
#
# ESTRUCTURA NUEVA:
# - recon_cloud() - Mantiene interface existente, ahora llama a cada proveedor
# - _scan_provider_storages() - Nueva función que scanea cada proveedor
# - _verify_provider_bucket() - Nueva función dispatcher para validación
# - Provider-specific functions: _check_azure_access(), _check_gcp_access(), etc.
#
# EVITA DUPLICACIÓN:
# - Enfocado en Cloud Storage (buckets, containers, spaces)
# - NO busca URLs históricas (ese es urls_historicas handler)
# - NO busca endpoints de API genéricos (ese es otro handler)
# - Enfocado en enumeration de storage directamente accesible
#
# ══════════════════════════════════════════════════════════════════════════════════════════

def recon_cloud(ejecucion_id, proyecto_id):
    """Reconocimiento multi-cloud EXTENDIDO: Storage + Databases + Caches + APIs

    AHORA BUSCA:
    1. Cloud Storage (S3, Azure Blob, GCP Storage, DO Spaces, B2)
    2. Databases Públicas (RDS, Azure Database, Cloud SQL)
    3. Caches Expuestos (ElastiCache, Azure Cache, Memorystore)
    4. APIs Públicas (API Gateway, Cloud Functions, Lambda URLs)
    5. Servicios Serverless (Cloud Run, Functions, etc)
    """
    print(f"[OSINT-CLOUD] Handler iniciado para ejecución {ejecucion_id}")

    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio_scope = config.get('DOMINIO', '').strip() if config else ''

        # 1. Obtener dominios de configuración inicial
        dominios_config = _parse_multiline_config(
            dominio_scope) if dominio_scope else []
        if dominios_config:
            print(f"[recon_cloud] Dominios del scope: {dominios_config}")
        else:
            print(f"[recon_cloud] Sin DOMINIO configurado, buscando fallbacks...")

        # 2. FALLBACK 1: Dominios válidos de mapeo_ips
        dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(
            proyecto_id) if not dominios_config else []
        if dominios_from_ips:
            print(f"[recon_cloud] Dominios de mapeo_ips: {dominios_from_ips}")

        # 3. FALLBACK 2: Subdominios descubiertos
        dominios_descubiertos = OsintEjecucion.get_discovered_subdomains(
            proyecto_id)
        if dominios_descubiertos:
            print(
                f"[recon_cloud] Subdominios descubiertos: {len(dominios_descubiertos)}")

        # 4. Crear lista de dominios PRINCIPALES
        dominios_principales = list(set(dominios_config + dominios_from_ips))

        if not dominios_principales and not dominios_descubiertos:
            raise Exception(
                "No hay dominios para escanear (DOMINIO vacío, mapeo_ips sin resultados, subdominios no descubiertos)")

        # 5. EXTRAER DOMINIO RAÍZ
        dominio_raiz = None
        if dominios_principales:
            primer_dominio = dominios_principales[0]
            partes = primer_dominio.split('.')
            if len(partes) >= 2:
                dominio_raiz = partes[0]
            else:
                dominio_raiz = primer_dominio

        print(
            f"[recon_cloud] Dominios principales: {len(dominios_principales)}, Subdominios: {len(dominios_descubiertos)}")
        if dominio_raiz:
            print(f"[recon_cloud] DOMINIO RAÍZ IDENTIFICADO: '{dominio_raiz}'")

        # ═══════════════════════════════════════════════════════════════════════
        # CATEGORÍAS DE SERVICIOS A ESCANEAR
        # ═══════════════════════════════════════════════════════════════════════
        proveedores = [
            # STORAGE
            {'nombre': 'AWS S3', 'id': 'aws_s3', 'categoria': 'storage'},
            {'nombre': 'Azure Blob Storage',
                'id': 'azure_blob', 'categoria': 'storage'},
            {'nombre': 'Google Cloud Storage',
                'id': 'gcp_storage', 'categoria': 'storage'},
            {'nombre': 'DigitalOcean Spaces',
                'id': 'do_spaces', 'categoria': 'storage'},
            {'nombre': 'Backblaze B2', 'id': 'b2_cloud', 'categoria': 'storage'},

            # DATABASES
            {'nombre': 'AWS RDS', 'id': 'aws_rds', 'categoria': 'database'},
            {'nombre': 'Azure Database', 'id': 'azure_database',
                'categoria': 'database'},
            {'nombre': 'Google Cloud SQL',
                'id': 'gcp_cloudsql', 'categoria': 'database'},
            {'nombre': 'DigitalOcean Managed DB',
                'id': 'do_database', 'categoria': 'database'},

            # CACHES
            {'nombre': 'AWS ElastiCache',
                'id': 'aws_elasticache', 'categoria': 'cache'},
            {'nombre': 'Azure Cache for Redis',
                'id': 'azure_cache', 'categoria': 'cache'},
            {'nombre': 'Google Cloud Memorystore',
                'id': 'gcp_memorystore', 'categoria': 'cache'},

            # APIS & SERVERLESS
            {'nombre': 'AWS API Gateway', 'id': 'aws_api_gateway', 'categoria': 'api'},
            {'nombre': 'AWS Lambda URLs', 'id': 'aws_lambda_urls',
                'categoria': 'serverless'},
            {'nombre': 'AWS AppSync (GraphQL)',
             'id': 'aws_appsync', 'categoria': 'api'},
            {'nombre': 'Google Cloud Functions',
                'id': 'gcp_cloudfunctions', 'categoria': 'serverless'},
            {'nombre': 'Google Cloud Run', 'id': 'gcp_cloudrun',
                'categoria': 'serverless'},
            {'nombre': 'Google Firebase/Firestore',
                'id': 'gcp_firebase', 'categoria': 'database'},
            {'nombre': 'Azure Functions', 'id': 'azure_functions',
                'categoria': 'serverless'},
        ]

        recursos_totales = []

        # ═══════════════════════════════════════════════════════════════════════
        # FASE 1: Escanear DOMINIOS PRINCIPALES en TODOS LOS PROVEEDORES
        # ═══════════════════════════════════════════════════════════════════════
        print(f"[recon_cloud] ════════════════════════════════════════════")
        print(
            f"[recon_cloud] FASE 1: Escaneando {len(dominios_principales)} dominios")
        print(
            f"[recon_cloud]         en {len(proveedores)} servicios/proveedores")
        print(f"[recon_cloud] ════════════════════════════════════════════")

        # Agrupar por categoría para mejor logging
        categorias = {}
        for prov in proveedores:
            cat = prov['categoria']
            if cat not in categorias:
                categorias[cat] = []
            categorias[cat].append(prov)

        print(f"[recon_cloud] Categorías:")
        for cat, provs in categorias.items():
            print(f"[recon_cloud]   - {cat.upper()}: {len(provs)} servicios")

        for dom in dominios_principales:
            for proveedor in proveedores:
                try:
                    categoria = proveedor['categoria']
                    print(
                        f"[recon_cloud] [{categoria.upper()}] Escaneando {proveedor['nombre']} para {dom}...")

                    recursos = _scan_cloud_service(
                        dom, proveedor, dominio_raiz, 'principal')
                    recursos_totales.extend(recursos)

                    if recursos:
                        print(
                            f"[recon_cloud] ✓ {proveedor['nombre']}: {len(recursos)} recursos encontrados")
                except Exception as e:
                    print(
                        f"[recon_cloud] Error escaneando {proveedor['nombre']} para {dom}: {e}")

        # ═══════════════════════════════════════════════════════════════════════
        # FASE 2: FALLBACK a SUBDOMINIOS si FASE 1 no encuentra nada
        # ═══════════════════════════════════════════════════════════════════════
        if not recursos_totales and dominios_descubiertos and dominio_raiz:
            print(f"[recon_cloud] ════════════════════════════════════════════")
            print(
                f"[recon_cloud] FASE 2: FALLBACK a {len(dominios_descubiertos)} SUBDOMINIOS")
            print(f"[recon_cloud] ════════════════════════════════════════════")

            # Limitar a 10 subdominios para no saturar
            for subdom in dominios_descubiertos[:10]:
                for proveedor in proveedores:
                    try:
                        categoria = proveedor['categoria']
                        print(
                            f"[recon_cloud] [FALLBACK-{categoria.upper()}] Escaneando {proveedor['nombre']} para {subdom}...")
                        recursos = _scan_cloud_service(
                            subdom, proveedor, dominio_raiz, 'fallback')
                        recursos_totales.extend(recursos)
                    except Exception as e:
                        print(f"[recon_cloud] [FALLBACK] Error: {e}")

        # ═══════════════════════════════════════════════════════════════════════
        # RESUMEN POR CATEGORÍA
        # ═══════════════════════════════════════════════════════════════════════
        print(f"[recon_cloud] ════════════════════════════════════════════")
        print(f"[recon_cloud] RESUMEN DE HALLAZGOS")
        print(f"[recon_cloud] ════════════════════════════════════════════")

        resumen_por_categoria = {}
        for recurso in recursos_totales:
            tipo = recurso.get('tipo', 'unknown')
            categoria = recurso.get('categoria', 'unknown')
            if categoria not in resumen_por_categoria:
                resumen_por_categoria[categoria] = {
                    'total': 0, 'critica': 0, 'alta': 0}
            resumen_por_categoria[categoria]['total'] += 1
            severidad = recurso.get('severidad', 'INFO').upper()
            if severidad == 'CRÍTICA':
                resumen_por_categoria[categoria]['critica'] += 1
            elif severidad == 'ALTA':
                resumen_por_categoria[categoria]['alta'] += 1

        for categoria, stats in sorted(resumen_por_categoria.items()):
            print(
                f"[recon_cloud] {categoria.upper():15} → Total: {stats['total']:2} | CRÍTICA: {stats['critica']:2} | ALTA: {stats['alta']:2}")

        return {
            "tipo": "recon_cloud_extendido",
            "dominio_scope": dominio_scope,
            "total_dominios_scope": len(dominios_config),
            "total_dominios_from_ips": len(dominios_from_ips),
            "total_subdominios_descubiertos": len(dominios_descubiertos),
            "total_dominios_buscados": len(dominios_principales),
            "total_proveedores_escaneados": len(proveedores),
            "total_recursos": len(recursos_totales),
            "proveedores": [p['nombre'] for p in proveedores],
            "categorias": list(resumen_por_categoria.keys()),
            "resumen": resumen_por_categoria,
            "recursos": recursos_totales
        }

    return _run_osint_job(ejecucion_id, job)


def _scan_cloud_service(dominio, proveedor, dominio_raiz, fase='principal'):
    """
    Escanea un servicio cloud específico (storage, database, cache, api, etc).

    Cada proveedor tiene su propia lógica de descubrimiento y verificación.
    """
    recursos = []
    proveedor_id = proveedor['id']
    categoria = proveedor['categoria']

    try:
        # Dispatcher por categoría
        if categoria == 'storage':
            recursos = _scan_storage_service(dominio, proveedor, dominio_raiz)
        elif categoria == 'database':
            recursos = _scan_database_service(dominio, proveedor, dominio_raiz)
        elif categoria == 'cache':
            recursos = _scan_cache_service(dominio, proveedor, dominio_raiz)
        elif categoria in ['api', 'serverless']:
            recursos = _scan_api_serverless_service(
                dominio, proveedor, dominio_raiz)

    except Exception as e:
        print(f"[recon_cloud-{proveedor_id}] Error: {e}")

    return recursos


def _scan_storage_service(dominio, proveedor, dominio_raiz):
    """Escanea servicios de storage (S3, Blob, GCS, etc) - MANTIENE LÓGICA EXISTENTE"""
    recursos = []
    proveedor_id = proveedor['id']

    # Generar candidatos de nombres
    candidatos = _generate_cloud_candidates(
        dominio, dominio_raiz, proveedor_id)
    print(
        f"[recon_cloud-{proveedor_id}] Generados {len(candidatos)} candidatos a verificar")

    for candidato in candidatos:
        try:
            resultado = _verify_provider_bucket(candidato, dominio, proveedor)
            if resultado:
                recursos.extend(resultado)
        except Exception as e:
            print(
                f"[recon_cloud-{proveedor_id}] Error verificando {candidato}: {e}")

    return recursos


def _scan_database_service(dominio, proveedor, dominio_raiz):
    """Escanea databases públicas en la nube"""
    recursos = []
    proveedor_id = proveedor['id']

    # Generar candidatos de nombres de database
    candidatos_db = _generate_database_candidates(
        dominio, dominio_raiz, proveedor_id)
    print(
        f"[recon_cloud-{proveedor_id}] Generados {len(candidatos_db)} candidatos de database a verificar")

    for candidato in candidatos_db:
        try:
            resultado = _verify_database(candidato, dominio, proveedor)
            if resultado:
                recursos.extend(resultado)
        except Exception as e:
            print(
                f"[recon_cloud-{proveedor_id}] Error verificando {candidato}: {e}")

    return recursos


def _scan_cache_service(dominio, proveedor, dominio_raiz):
    """Escanea caches públicos (Redis, Memcached, etc)"""
    recursos = []
    proveedor_id = proveedor['id']

    # Generar candidatos de nombres de cache
    candidatos_cache = _generate_cache_candidates(
        dominio, dominio_raiz, proveedor_id)
    print(
        f"[recon_cloud-{proveedor_id}] Generados {len(candidatos_cache)} candidatos de cache a verificar")

    for candidato in candidatos_cache:
        try:
            resultado = _verify_cache(candidato, dominio, proveedor)
            if resultado:
                recursos.extend(resultado)
        except Exception as e:
            print(
                f"[recon_cloud-{proveedor_id}] Error verificando {candidato}: {e}")

    return recursos


def _scan_api_serverless_service(dominio, proveedor, dominio_raiz):
    """Escanea APIs y funciones serverless públicas"""
    recursos = []
    proveedor_id = proveedor['id']

    # Generar candidatos de URLs de API/Serverless
    candidatos_api = _generate_api_candidates(
        dominio, dominio_raiz, proveedor_id)
    print(
        f"[recon_cloud-{proveedor_id}] Generados {len(candidatos_api)} candidatos de API/Serverless a verificar")

    for candidato in candidatos_api:
        try:
            resultado = _verify_api_endpoint(candidato, dominio, proveedor)
            if resultado:
                recursos.extend(resultado)
        except Exception as e:
            print(
                f"[recon_cloud-{proveedor_id}] Error verificando {candidato}: {e}")

    return recursos


# ══════════════════════════════════════════════════════════════════════════════════════════
# GENERATORS - CANDIDATOS POR TIPO DE SERVICIO
# ══════════════════════════════════════════════════════════════════════════════════════════

def _generate_database_candidates(dominio, dominio_raiz, proveedor_id):
    """Genera candidatos de nombres de database según el proveedor"""
    parts = dominio.split('.')
    domain_name = parts[0] if parts else dominio

    candidates = [
        # Nombres básicos
        domain_name,
        f"{domain_name}-db",
        f"{domain_name}-prod",
        f"{domain_name}-staging",
        f"{domain_name}-data",

        # Con variantes
        f"db-{domain_name}",
        f"postgres-{domain_name}",
        f"mysql-{domain_name}",
        f"{domain_name}-postgres",
        f"{domain_name}-mysql",

        # Comunes
        f"{domain_name}-app",
        f"app-{domain_name}",
        f"{domain_name}-backend",
    ]

    # AWS RDS específico
    if proveedor_id == 'aws_rds':
        # Formato: {nombre}.{id_aleatorio}.{region}.rds.amazonaws.com
        # Generamos candidatos que pueden ser válidos
        candidates = [c.replace('_', '-').lower() for c in candidates]

    elif proveedor_id == 'azure_database':
        # Formato: {nombre}.{tipo}.database.azure.com
        # Azure usa nombres específicos para cada tipo (postgres, mysql, mariadb)
        candidates = [c.replace('_', '-').lower() for c in candidates]

    elif proveedor_id == 'gcp_cloudsql':
        # Formato: {proyecto}:{instancia}
        # O acceso via Cloud SQL Proxy
        candidates = [c.replace('_', '-').lower() for c in candidates]

    return list(set(filter(None, candidates)))


def _generate_cache_candidates(dominio, dominio_raiz, proveedor_id):
    """Genera candidatos de nombres de cache (Redis, Memcached)"""
    parts = dominio.split('.')
    domain_name = parts[0] if parts else dominio

    candidates = [
        # Nombres básicos
        domain_name,
        f"{domain_name}-cache",
        f"{domain_name}-redis",
        f"redis-{domain_name}",
        f"{domain_name}-memcached",
        f"cache-{domain_name}",

        # Comunes en producción
        f"{domain_name}-prod",
        f"{domain_name}-session",
        f"session-{domain_name}",
    ]

    # Normalizar
    candidates = [c.replace('_', '-').lower() for c in candidates]
    return list(set(filter(None, candidates)))


def _generate_api_candidates(dominio, dominio_raiz, proveedor_id):
    """Genera candidatos de URLs de APIs y funciones serverless"""
    parts = dominio.split('.')
    domain_name = parts[0] if parts else dominio

    candidates = []

    if proveedor_id == 'aws_api_gateway':
        # Formato: https://{api_id}.execute-api.{region}.amazonaws.com/
        candidates = [
            f"{domain_name}",
            f"{domain_name}-api",
            f"api-{domain_name}",
            f"{domain_name}-v1",
            f"{domain_name}-prod",
            f"{domain_name}-graphql",
        ]

    elif proveedor_id == 'aws_lambda_urls':
        # Formato: https://{url_id}.lambda-url.{region}.on.aws/
        candidates = [
            f"{domain_name}-function",
            f"{domain_name}-handler",
            f"function-{domain_name}",
        ]

    elif proveedor_id == 'aws_appsync':
        # GraphQL endpoint: https://{id}.appsync-api.{region}.amazonaws.com/graphql
        candidates = [
            f"{domain_name}-graphql",
            f"graphql-{domain_name}",
            f"{domain_name}-api",
        ]

    elif proveedor_id in ['gcp_cloudfunctions', 'gcp_cloudrun']:
        # Formato: https://{region}-{project}.cloudfunctions.net/{function}
        # o https://{service}-{hash}.{region}.run.app
        candidates = [
            f"{domain_name}",
            f"{domain_name}-api",
            f"api-{domain_name}",
            f"service-{domain_name}",
            f"{domain_name}-function",
        ]

    elif proveedor_id == 'azure_functions':
        # Formato: https://{nombre}.azurewebsites.net/api/{función}
        candidates = [
            f"{domain_name}",
            f"{domain_name}-api",
            f"function-{domain_name}",
        ]

    elif proveedor_id == 'gcp_firebase':
        # Formato: https://{proyecto}.firebaseio.com/
        candidates = [
            f"{domain_name}",
            f"{domain_name}-db",
            f"{domain_name}-app",
        ]

    candidates = [c.replace('_', '-').lower() for c in candidates]
    return list(set(filter(None, candidates)))


# ══════════════════════════════════════════════════════════════════════════════════════════
# VERIFICADORES - CHECKERS POR TIPO DE SERVICIO
# ══════════════════════════════════════════════════════════════════════════════════════════

def _verify_database(nombre, dominio, proveedor):
    """Verifica si una database está accesible públicamente"""
    resultado = []
    proveedor_id = proveedor['id']

    try:
        print(f"[database-verify] Verificando {proveedor['nombre']}: {nombre}")

        if proveedor_id == 'aws_rds':
            resultado.extend(_verify_aws_rds(nombre, dominio))
        elif proveedor_id == 'azure_database':
            resultado.extend(_verify_azure_database(nombre, dominio))
        elif proveedor_id == 'gcp_cloudsql':
            resultado.extend(_verify_gcp_cloudsql(nombre, dominio))
        elif proveedor_id == 'do_database':
            resultado.extend(_verify_do_database(nombre, dominio))

    except Exception as e:
        print(f"[database-verify] Error: {e}")

    return resultado


def _verify_aws_rds(nombre, dominio):
    """Verifica RDS de AWS"""
    resultado = []
    # RDS format: {nombre}.{random}.{region}.rds.amazonaws.com

    # Probar en regiones comunes
    regiones = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']

    for region in regiones:
        try:
            # Construir endpoint probable
            endpoint = f"{nombre}.{region}.rds.amazonaws.com"

            # Intentar conexión TCP en puerto 3306 (MySQL/MariaDB)
            result = subprocess.run(
                ['timeout', '3', 'bash', '-c', f'</dev/tcp/{endpoint}/3306'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                print(f"[rds] ✅ {endpoint} - PUERTO 3306 ACCESIBLE")
                sev = _get_severidad_por_confianza(
                    90)  # Puerto abierto = CRÍTICA
                resultado.append({
                    'tipo': 'aws_rds_database',
                    'nombre': nombre,
                    'dominio': dominio,
                    'categoria': 'database',
                    'endpoint': endpoint,
                    'puerto': 3306,
                    'acceso': 'puerto_abierto',
                    'severidad': sev.get('nombre', 'CRÍTICA') if sev else 'CRÍTICA',
                    'severidad_score': sev.get('score', 9) if sev else 9,
                    'estado': 'potencial',
                    'poc_commands': {
                        'nc': f"nc -zv {endpoint} 3306",
                        'mysql': f"mysql -h {endpoint} -u admin -p",
                        'telnet': f"telnet {endpoint} 3306"
                    }
                })
                break
        except Exception as e:
            pass

    return resultado


def _verify_azure_database(nombre, dominio):
    """Verifica Azure Database for PostgreSQL/MySQL"""
    resultado = []

    # Azure format: {nombre}.postgres.database.azure.com o .mysql.database.azure.com
    endpoints_a_probar = [
        f"{nombre}.postgres.database.azure.com",
        f"{nombre}.mysql.database.azure.com",
        f"{nombre}.mariadb.database.azure.com",
    ]

    for endpoint in endpoints_a_probar:
        try:
            # Intentar conexión TCP
            result = subprocess.run(
                ['timeout', '3', 'bash', '-c',
                    f'</dev/tcp/{endpoint}/5432 || </dev/tcp/{endpoint}/3306'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                tipo_db = "PostgreSQL" if "postgres" in endpoint else "MySQL"
                puerto = 5432 if "postgres" in endpoint else 3306

                print(
                    f"[azure] ✅ {endpoint} - PUERTO {puerto} ACCESIBLE ({tipo_db})")
                sev = _get_severidad_por_confianza(
                    90)  # Puerto abierto = CRÍTICA
                resultado.append({
                    'tipo': f'azure_database_{tipo_db.lower()}',
                    'nombre': nombre,
                    'dominio': dominio,
                    'categoria': 'database',
                    'endpoint': endpoint,
                    'puerto': puerto,
                    'db_type': tipo_db,
                    'acceso': 'puerto_abierto',
                    'severidad': sev.get('nombre', 'CRÍTICA') if sev else 'CRÍTICA',
                    'severidad_score': sev.get('score', 9) if sev else 9,
                    'estado': 'potencial',
                    'poc_commands': {
                        'nc': f"nc -zv {endpoint} {puerto}",
                        'psql/mysql': f"psql -h {endpoint} -U admin" if tipo_db == "PostgreSQL" else f"mysql -h {endpoint} -u admin"
                    }
                })
                break
        except:
            pass

    return resultado


def _verify_gcp_cloudsql(nombre, dominio):
    """Verifica Google Cloud SQL"""
    resultado = []

    # GCP Cloud SQL: {proyecto}:{instancia}
    # O via Cloud SQL Proxy: 127.0.0.1:3306

    # Intentar descubrir vía DNS (si tienen IP pública)
    try:
        # Cloud SQL Instances pueden estar configuradas con IP pública
        # Formato típico: {nombre}-db.c.{proyecto}.internal (privada)
        # o con IP pública directa

        # Intentar conexión a puerto 3306 (MySQL) o 5432 (PostgreSQL)
        result = subprocess.run(
            ['timeout', '3', 'bash', '-c', f'</dev/tcp/{nombre}/3306'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            print(f"[gcp-cloudsql] ✅ {nombre} - PUERTO 3306 ACCESIBLE")
            sev = _get_severidad_por_confianza(90)  # Puerto abierto = CRÍTICA
            resultado.append({
                'tipo': 'gcp_cloudsql_database',
                'nombre': nombre,
                'dominio': dominio,
                'categoria': 'database',
                'endpoint': nombre,
                'puerto': 3306,
                'acceso': 'puerto_abierto',
                'severidad': sev.get('nombre', 'CRÍTICA') if sev else 'CRÍTICA',
                'severidad_score': sev.get('score', 9) if sev else 9,
                'estado': 'potencial',
                'notas': 'Cloud SQL con IP pública configurada',
                'poc_commands': {
                    'gcloud': f"gcloud sql connect {nombre} --user=root",
                    'mysql': f"mysql -h {nombre} -u root -p"
                }
            })
    except:
        pass

    return resultado


def _verify_do_database(nombre, dominio):
    """Verifica DigitalOcean Managed Databases"""
    resultado = []

    # DO format: {nombre}-{hash}.db.ondigitalocean.com
    # Probar endpoint directo
    try:
        endpoint = f"{nombre}.db.ondigitalocean.com"

        result = subprocess.run(
            ['timeout', '3', 'bash', '-c', f'</dev/tcp/{endpoint}/3306'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            print(f"[do-db] ✅ {endpoint} - PUERTO 3306 ACCESIBLE")
            sev = _get_severidad_por_confianza(90)  # Puerto abierto = CRÍTICA
            resultado.append({
                'tipo': 'do_managed_database',
                'nombre': nombre,
                'dominio': dominio,
                'categoria': 'database',
                'endpoint': endpoint,
                'puerto': 3306,
                'acceso': 'puerto_abierto',
                'severidad': sev.get('nombre', 'CRÍTICA') if sev else 'CRÍTICA',
                'severidad_score': sev.get('score', 9) if sev else 9,
                'estado': 'potencial'
            })
    except:
        pass

    return resultado


def _verify_cache(nombre, dominio, proveedor):
    """Verifica si un cache (Redis, Memcached) está accesible públicamente"""
    resultado = []
    proveedor_id = proveedor['id']

    try:
        print(f"[cache-verify] Verificando {proveedor['nombre']}: {nombre}")

        if proveedor_id == 'aws_elasticache':
            resultado.extend(_verify_aws_elasticache(nombre, dominio))
        elif proveedor_id == 'azure_cache':
            resultado.extend(_verify_azure_cache(nombre, dominio))
        elif proveedor_id == 'gcp_memorystore':
            resultado.extend(_verify_gcp_memorystore(nombre, dominio))

    except Exception as e:
        print(f"[cache-verify] Error: {e}")

    return resultado


def _verify_aws_elasticache(nombre, dominio):
    """Verifica AWS ElastiCache (Redis/Memcached)"""
    resultado = []
    regiones = ['us-east-1', 'us-west-2', 'eu-west-1']

    for region in regiones:
        try:
            # Redis: puerto 6379, Memcached: puerto 11211
            for puerto, tipo in [(6379, 'Redis'), (11211, 'Memcached')]:
                endpoint = f"{nombre}.{region}.cache.amazonaws.com"

                result = subprocess.run(
                    ['timeout', '3', 'bash', '-c',
                        f'</dev/tcp/{endpoint}/{puerto}'],
                    capture_output=True,
                    timeout=5
                )

                if result.returncode == 0:
                    print(
                        f"[elasticache] ✅ {endpoint}:{puerto} - ACCESIBLE ({tipo})")
                    sev = _get_severidad_por_confianza(
                        90)  # Puerto abierto = CRÍTICA
                    resultado.append({
                        'tipo': f'aws_elasticache_{tipo.lower()}',
                        'nombre': nombre,
                        'dominio': dominio,
                        'categoria': 'cache',
                        'endpoint': endpoint,
                        'puerto': puerto,
                        'cache_type': tipo,
                        'acceso': 'puerto_abierto',
                        'severidad': sev.get('nombre', 'CRÍTICA') if sev else 'CRÍTICA',
                        'severidad_score': sev.get('score', 9) if sev else 9,
                        'estado': 'potencial',
                        'poc_commands': {
                            'redis-cli': f"redis-cli -h {endpoint} -p {puerto} PING" if tipo == 'Redis' else None,
                            'memcached': f"echo 'stats' | nc {endpoint} {puerto}" if tipo == 'Memcached' else None
                        }
                    })
        except:
            pass

    return resultado


def _verify_azure_cache(nombre, dominio):
    """Verifica Azure Cache for Redis"""
    resultado = []

    try:
        endpoint = f"{nombre}.redis.cache.windows.net"
        puerto = 6379

        result = subprocess.run(
            ['timeout', '3', 'bash', '-c', f'</dev/tcp/{endpoint}/{puerto}'],
            capture_output=True,
            timeout=5
        )

        if result.returncode == 0:
            print(f"[azure-cache] ✅ {endpoint}:{puerto} - ACCESIBLE")
            sev = _get_severidad_por_confianza(90)  # Puerto abierto = CRÍTICA
            resultado.append({
                'tipo': 'azure_cache_redis',
                'nombre': nombre,
                'dominio': dominio,
                'categoria': 'cache',
                'endpoint': endpoint,
                'puerto': puerto,
                'acceso': 'puerto_abierto',
                'severidad': sev.get('nombre', 'CRÍTICA') if sev else 'CRÍTICA',
                'severidad_score': sev.get('score', 9) if sev else 9,
                'estado': 'potencial',
                'poc_commands': {
                    'redis-cli': f"redis-cli -h {endpoint} -p {puerto} -a PASSWORD PING"
                }
            })
    except:
        pass

    return resultado


def _verify_gcp_memorystore(nombre, dominio):
    """Verifica Google Cloud Memorystore (Redis)"""
    resultado = []

    try:
        # Memorystore instances suelen estar en VPC pero algunos tienen acceso público
        endpoint = f"{nombre}-redis"
        puerto = 6379

        result = subprocess.run(
            ['timeout', '3', 'bash', '-c', f'</dev/tcp/{endpoint}/{puerto}'],
            capture_output=True,
            timeout=5
        )

        if result.returncode == 0:
            print(f"[gcp-memorystore] ✅ {endpoint}:{puerto} - ACCESIBLE")
            sev = _get_severidad_por_confianza(90)  # Puerto abierto = CRÍTICA
            resultado.append({
                'tipo': 'gcp_memorystore_redis',
                'nombre': nombre,
                'dominio': dominio,
                'categoria': 'cache',
                'endpoint': endpoint,
                'puerto': puerto,
                'acceso': 'puerto_abierto',
                'severidad': sev.get('nombre', 'CRÍTICA') if sev else 'CRÍTICA',
                'severidad_score': sev.get('score', 9) if sev else 9,
                'estado': 'potencial'
            })
    except:
        pass

    return resultado


def _verify_api_endpoint(url_candidato, dominio, proveedor):
    """Verifica si un endpoint de API/Serverless está accesible"""
    resultado = []
    proveedor_id = proveedor['id']

    try:
        # Construir URL según el proveedor
        if proveedor_id == 'aws_api_gateway':
            # Probar en regiones comunes
            for region in ['us-east-1', 'us-west-2', 'eu-west-1']:
                urls_a_probar = [
                    f"https://{url_candidato}.execute-api.{region}.amazonaws.com/prod",
                    f"https://{url_candidato}.execute-api.{region}.amazonaws.com/dev",
                ]
                for url in urls_a_probar:
                    resultado.extend(_test_http_endpoint(
                        url, dominio, proveedor, 'api_gateway'))

        elif proveedor_id == 'gcp_cloudfunctions':
            for region in ['us-central1', 'us-east1', 'europe-west1']:
                url = f"https://{region}-PROJECT.cloudfunctions.net/{url_candidato}"
                resultado.extend(_test_http_endpoint(
                    url, dominio, proveedor, 'cloud_function'))

        elif proveedor_id == 'gcp_cloudrun':
            for region in ['us-central1', 'us-east1', 'europe-west1']:
                url = f"https://{url_candidato}-{region}.run.app"
                resultado.extend(_test_http_endpoint(
                    url, dominio, proveedor, 'cloud_run'))

        elif proveedor_id == 'azure_functions':
            url = f"https://{url_candidato}.azurewebsites.net/api/function"
            resultado.extend(_test_http_endpoint(
                url, dominio, proveedor, 'azure_function'))

        elif proveedor_id == 'gcp_firebase':
            url = f"https://{url_candidato}.firebaseio.com/.json"
            resultado.extend(_test_http_endpoint(
                url, dominio, proveedor, 'firebase'))

    except Exception as e:
        print(f"[api-verify] Error: {e}")

    return resultado


def _test_http_endpoint(url, dominio, proveedor, tipo):
    """Prueba si un endpoint HTTP está accesible"""
    resultado = []

    try:
        print(f"[api] Probando {url}...")

        result = subprocess.run(
            ['curl', '-s', '-I', '-m', '5', '--insecure', url],
            capture_output=True,
            text=True,
            timeout=8
        )

        # Extraer status code
        status = None
        for line in result.stdout.split('\n'):
            if line.startswith('HTTP'):
                parts = line.split()
                if len(parts) >= 2:
                    status = parts[1]
                    break

        if status and status != '404':
            print(f"[api] ✅ {url} - HTTP {status} ACCESIBLE")
            # Determinar confianza basado en status code
            if status == '200':
                confianza = 85  # Acceso directo = ALTA
            elif status in ['401', '403']:
                confianza = 65  # Requiere auth = MEDIA-ALTA
            else:
                confianza = 45  # Otros = MEDIA
            sev = _get_severidad_por_confianza(confianza)
            resultado.append({
                'tipo': f'{tipo}_endpoint',
                'nombre': url.split('/')[-1],
                'dominio': dominio,
                'categoria': 'api' if 'api' in tipo else 'serverless',
                'url': url,
                'http_status': status,
                'acceso': 'accesible',
                'severidad': sev.get('nombre', 'MEDIA') if sev else 'MEDIA',
                'severidad_score': sev.get('score', 5) if sev else 5,
                'estado': 'activo' if status == '200' else 'requiere_auth',
                'poc_commands': {
                    'curl': f"curl -v {url}",
                    'wget': f"wget -O - {url}"
                }
            })

    except subprocess.TimeoutExpired:
        print(f"[api] ⏱ {url} - Timeout")
    except Exception as e:
        pass

    return resultado


# ══════════════════════════════════════════════════════════════════════════════════════════
# KEEP EXISTING STORAGE FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════════════════

# [Las funciones de storage existentes (_verify_s3_bucket, _verify_azure_container, etc)
#  se mantienen iguales - ver archivo anterior recon_cloud_enhanced.py]

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
            print(
                f"[s3-verify] {bucket_name} - No existe (HTTP 404) → IGNORAR")
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
                print(
                    f"[s3-verify] ❌ {bucket_name} RECHAZADO: Confianza negativa ({correlation['confianza']}%) - FALSO POSITIVO")
                return resultado

            if correlation['evidencias'].get('not_aws_ip') and correlation['confianza'] < 50:
                print(
                    f"[s3-verify] ❌ {bucket_name} RECHAZADO: IP no-AWS ({correlation['evidencias'].get('domain_ip')}) + baja correlación ({correlation['confianza']}%) - FALSO POSITIVO")
                return resultado

            # ⭐ MEJORADO: HTTP 200 anónimo es evidencia REAL de que el bucket es accesible
            # Reducir threshold a 30% para buckets públicos (menos estricto)
            # Si alguien puede acceder sin credenciales, ES un hallazgo, aunque la correlación sea débil
            if correlation['confianza'] < 30:
                print(
                    f"[s3-verify] ⚠️  {bucket_name} abierto pero CORRELACIÓN MUY BAJA ({correlation['confianza']}%) → REPORTAR COMO HALLAZGO DÉBIL")
                # Igual lo reportamos pero con severidad más baja
                # porque HTTP 200 anónimo es real
            elif correlation['confianza'] < 50:
                print(
                    f"[s3-verify] ⚠️  {bucket_name} abierto con BAJA CORRELACIÓN ({correlation['confianza']}%) → REPORTAR CON SEVERIDAD MEDIA")

            # Obtener severidad dinámica desde BD basada en confianza
            # ⭐ MEJORADO: Si correlación < 50%, usar nivel más bajo pero igual reportar
            # Mínimo 30% para buckets públicos
            confianza_ajustada = max(correlation['confianza'], 30)
            severidad_obj = _get_severidad_por_confianza(confianza_ajustada)
            severidad_nombre = severidad_obj.get(
                'nombre') if severidad_obj else 'UNKNOWN'
            severidad_id = severidad_obj.get('id') if severidad_obj else None

            # Etiqueta de confianza para legibilidad
            if correlation['confianza'] >= 50:
                confianza_label = 'ALTA'
            elif correlation['confianza'] >= 30:
                confianza_label = 'MEDIA'
            else:
                confianza_label = 'BAJA'

            print(
                f"[s3-verify] ✅ REPORTAR: {bucket_name} (acceso=abierto, confianza={correlation['confianza']}%, severidad={severidad_nombre})")

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
                # ← NUEVO
                'correlacion_validada': correlation['es_correlacionado'],
                # ← NUEVO (0-100)
                'confianza_correlacion': correlation['confianza'],
                # ← NUEVO (ALTA/MEDIA/BAJA)
                'confianza_label': confianza_label,
                # ← NUEVO
                'metodos_confirmados': correlation['metodos_confirmados'],
                'evidencias': correlation['evidencias'],  # ← NUEVO (detalles)
                # ← NUEVO (descripción)
                'razon_correlacion': correlation['razon'],
                'severidad_id': severidad_id,  # ← NUEVO: ID de severidad desde BD
                'severidad': severidad_nombre,  # ← MEJORADO: Dinámico desde BD
                'poc_commands': poc_commands  # ⭐ NUEVO: Comandos para explotar el bucket
            })
        elif result.returncode == 0:
            # Acceso con credenciales AWS (BAJO VALOR - No reportar)
            print(
                f"[s3-verify] ℹ️  {bucket_name} requiere auth → NO REPORTAR (bajo valor)")
            return resultado

        elif 'NoSuchBucket' not in result.stderr:
            # Existe pero está privado (MÍNIMO VALOR - No reportar)
            print(
                f"[s3-verify] ℹ️  {bucket_name} privado → NO REPORTAR (sin acceso)")
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
        dominios_config = _parse_multiline_config(
            dominio_scope) if dominio_scope else []
        if dominios_config:
            print(
                f"[escaneo_repositorios] Dominios del scope: {dominios_config}")
        else:
            print(
                f"[escaneo_repositorios] Sin DOMINIO configurado, buscando fallbacks...")

        # 2. FALLBACK 1: Dominios válidos de mapeo_ips (si DOMINIO vacío)
        dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(
            proyecto_id) if not dominios_config else []
        if dominios_from_ips:
            print(
                f"[escaneo_repositorios] Dominios de mapeo_ips: {dominios_from_ips}")

        # 3. Subdominios descubiertos (solo para información, NO para búsqueda en GitHub)
        # Los subdominios son internos - GitHub indexa código, no subdominios específicos
        dominios_descubiertos = OsintEjecucion.get_discovered_subdomains(
            proyecto_id)
        if dominios_descubiertos:
            print(
                f"[escaneo_repositorios] Subdominios descubiertos (solo info): {len(dominios_descubiertos)}")

        # 4. Buscar SOLO dominios raíz (config + mapeo_ips)
        # NO incluir subdominios descubiertos (evita falsos positivos masivos)
        dominios_para_buscar = list(set(dominios_config + dominios_from_ips))

        if not dominios_para_buscar:
            raise Exception(
                "No hay dominios raíz para escanear (DOMINIO vacío, mapeo_ips sin resultados)")

        print(
            f"[escaneo_repositorios] Dominios raíz a buscar: {len(dominios_para_buscar)}")
        print(
            f"[escaneo_repositorios] Subdominios descubiertos (solo info): {len(dominios_descubiertos)}")

        hallazgos_raw = []
        for dom in dominios_para_buscar:
            # 1. Búsqueda en GitHub via API pública (SOLO DOMINIOS RAÍZ)
            hallazgos_raw.extend(_search_github(dom))

            # 2. Intentar con trufflehog si está instalado (SOLO DOMINIOS RAÍZ)
            hallazgos_raw.extend(_search_trufflehog(dom))

        # Deduplicar y agrupar por repositorio (con filtro de relevancia)
        hallazgos_dedup = _deduplicate_github_results(
            hallazgos_raw, dominios_para_buscar)

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
            # www.ater.gob.ar → ater.gob.ar
            domain_base = '.'.join(dom_parts[1:])
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
            # Postman collections
            f'filename:.postman_collection.json {keyword}',
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
            # ater-api (sin comillas)
            f'{keyword}-api',
            # customer-ater (sin comillas)
            f'customer-{keyword}',

            # 4. Búsquedas por dominio COMPLETO + palabras sensibles
            f'"{domain_base}"',                            # "ater.gob.ar"
            # "ater.gob.ar" secret
            f'"{domain_base}" secret',
            # "ater.gob.ar" password
            f'"{domain_base}" password',
            # "ater.gob.ar" token
            f'"{domain_base}" token',
            f'"{domain_base}" api',                        # "ater.gob.ar" api
            # "ater.gob.ar" credentials
            f'"{domain_base}" credentials',
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
        print(
            f"[github] Variantes de dominio (ANTES): {sorted(domain_variants)}")

        # ✅ ARREGLO 2: Remover palabras cortas que causan falsos positivos
        # Mantener solo variantes que:
        # - Contienen un punto (son dominios con múltiples partes)
        # - O tienen más de 3 caracteres (como 'ater')
        domain_variants = {
            v for v in domain_variants if '.' in v or len(v) > 3}
        print(
            f"[github] Variantes de dominio (DESPUÉS): {sorted(domain_variants)}")

    for item in hallazgos_raw:
        if item.get('tipo') != 'github_repo':
            continue

        repo = item.get('repo', '').replace(
            '[', '').replace('](', '/').replace(')', '')
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
        valid_variants = ['aterapps', 'ater-api',
                          'customer-ater', 'ater.gob.ar']
        is_valid = any(var in repo_lower for var in valid_variants)

        # Palabras que contienen "ater" pero no son ATER
        false_positives = ['aternos', 'water', 'crater',
                           'eater', 'eatery', 'beat', 'theatre']
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
    print(f"[OSINT-DNS] Handler iniciado para ejecución {ejecucion_id}")

    def job():
        # 1. Obtener TODO el scope: DOMINIO + SUBDOMINIO + SERVICIOS
        scope = OsintEjecucion.get_scope_completo(proyecto_id)
        todos_los_dominios = scope['dominio'] + \
            scope['subdominio'] + scope['servicios']

        # 2. SIEMPRE obtener subdominios descubiertos si existen (lógica INCLUSIVA)
        subdominios_descubiertos = OsintEjecucion.get_discovered_subdomains(
            proyecto_id)
        todos_los_dominios.extend(subdominios_descubiertos)

        # 3. Fallback: Si no hay nada, usar dominios de mapeo_ips
        if not todos_los_dominios:
            dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(
                proyecto_id)
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
        print(
            f"  - Scope: {len(scope['dominio']) + len(scope['subdominio']) + len(scope['servicios'])}")
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
                        registros[dom][tipo] = result.stdout.strip().split(
                            '\n')
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
        subdominios_descubiertos = OsintEjecucion.get_discovered_subdomains(
            proyecto_id)

        todos_los_dominios = dominios_scope + subdominios_descubiertos

        # 3. Fallback: dominios de mapeo_ips si no hay nada
        if not todos_los_dominios:
            dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(
                proyecto_id)
            todos_los_dominios = dominios_from_ips
        else:
            dominios_from_ips = []

        # Deduplicar
        todos_los_dominios = sorted(list(set(todos_los_dominios)))

        if not todos_los_dominios:
            raise Exception("No hay dominios para buscar endpoints")

        endpoints = set()
        print(
            f"[busqueda_endpoints] Buscando endpoints en {len(todos_los_dominios)} dominios...")
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
        print(
            f"[waybackurls] No instalado (instalar: go install github.com/tomnomnom/waybackurls@latest)")
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

    print(
        f"[fuzzing] Probando {len(common_paths)} endpoints comunes en {dominio} (siguiendo redirects)...")

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
                            # Sobreescribe con la última
                            status_code = parts[1]

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

    print(
        f"[fuzzing] Encontrados {len(endpoints)} endpoints accesibles (no 404)")
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
        dominios_scope = _parse_multiline_config(
            dominio_config) if dominio_config else []
        if dominios_scope:
            print(f"[gau] Dominios del scope encontrados: {dominios_scope}")
        else:
            print(f"[gau] Sin dominios configurados en DOMINIO")

        # 2. Fallback: Obtener dominios descubiertos por reverse DNS (mapeo_ips)
        dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(
            proyecto_id)
        if dominios_from_ips:
            print(
                f"[gau] Dominios del objetivo desde mapeo_ips: {dominios_from_ips}")

        # 3. Fallback: Obtener subdominios descubiertos
        subdominios_descubiertos = OsintEjecucion.get_discovered_subdomains(
            proyecto_id)
        if subdominios_descubiertos:
            print(
                f"[gau] Subdominios descubiertos: {len(subdominios_descubiertos)}")

        # 4. Obtener IPs válidas desde mapeo_ips
        ips_validas = _get_valid_ips_from_mapeo(proyecto_id)
        if ips_validas:
            print(f"[gau] IPs válidas desde mapeo_ips: {ips_validas}")

        # 5. Combinar todas las fuentes de dominios
        todos_los_dominios = list(
            set(dominios_scope + dominios_from_ips + subdominios_descubiertos))

        # 6. Validar que hay algo para escanear
        if not todos_los_dominios and not ips_validas:
            raise Exception(
                "No hay dominios ni IPs para escanear (DOMINIO no configurado, mapeo_ips vacío y sin subdominios descubiertos)")

        urls = set()

        # 7. Buscar URLs de dominios
        if todos_los_dominios:
            print(
                f"[gau] Buscando URLs históricas en {len(todos_los_dominios)} dominios...")
            for dom in todos_los_dominios:
                print(f"[gau] Escaneando dominio: {dom}...")
                urls.update(_search_gau(dom))

        # 8. Buscar URLs de IPs válidas
        if ips_validas:
            print(
                f"[gau] Buscando URLs históricas en {len(ips_validas)} IPs...")
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
        resultado = OsintEjecucion.get_latest_resultado(
            proyecto_id, 'mapeo_ips')
        if not resultado:
            return []

        ips_success = resultado.get('ips_success', [])
        ips = [ip_data['ip']
               for ip_data in ips_success if ip_data.get('es_valido')]
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
        '.woff', '.woff2', '.ttf', '.eot'  # Fuentes
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
            print(
                f"[gau] No encontrado. Intenta: go install github.com/lc/gau/v2/cmd/gau@latest")
            return urls

        # Ejecuta con filtros para evitar descargar archivos multimedia
        result = subprocess.run(
            [gau_path, '--blacklist',
                'jpg,jpeg,png,gif,svg,css,js,woff,woff2,ttf,eot', target],
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.stdout:
            urls_raw = result.stdout.strip().split('\n')
            urls.update([url for url in urls_raw if url])
            print(
                f"[gau] Encontradas {len(urls)} URLs históricas para {target}")

            # ✨ NUEVO: Filtrar extensiones inútiles
            urls_filtradas = set(_filter_urls_by_extension(list(urls)))
            print(
                f"[gau] Después de filtrado: {len(urls_filtradas)} URLs válidas")

            return urls_filtradas
        else:
            print(f"[gau] No se encontraron URLs para {target}")

    except subprocess.TimeoutExpired:
        print(
            f"[gau] Timeout para {target} (dominios muy grandes pueden tardar >5 min)")
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
        dominios_scope = _parse_multiline_config(
            dominio_config) if dominio_config else []
        if dominios_scope:
            print(
                f"[google_dorking] Dominios del scope encontrados: {dominios_scope}")
        else:
            print(f"[google_dorking] Sin dominios configurados en DOMINIO")

        # 2. Fallback: Obtener dominios descubiertos por reverse DNS (mapeo_ips)
        dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(
            proyecto_id)
        if dominios_from_ips:
            print(
                f"[google_dorking] Dominios del objetivo desde mapeo_ips: {dominios_from_ips}")

        # 3. Fallback: Obtener subdominios descubiertos
        subdominios_descubiertos = OsintEjecucion.get_discovered_subdomains(
            proyecto_id)
        if subdominios_descubiertos:
            print(
                f"[google_dorking] Subdominios descubiertos: {len(subdominios_descubiertos)}")

        # 4. Combinar todas las fuentes de dominios
        todos_los_dominios = list(
            set(dominios_scope + dominios_from_ips + subdominios_descubiertos))

        # 5. Validar que hay dominios para escanear
        if not todos_los_dominios:
            raise Exception(
                "No hay dominios para escanear (DOMINIO no configurado, mapeo_ips vacío y sin subdominios descubiertos)")

        resultados = []
        print(
            f"[google_dorking] Ejecutando dorks en {len(todos_los_dominios)} dominios...")

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
            ['curl', '-s', '-H',
                f'User-Agent: {headers["User-Agent"]}', search_url],
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


# ════════════════════════════════════════════════════════════════════════════════
# Handler SENSITIVE DATA EXTRACTION
# ════════════════════════════════════════════════════════════════════════════════

PALABRAS_CLAVE = [
    # API Keys & Tokens - MÁS ESPECÍFICOS
    'api_key', 'apikey', 'api-key', 'api_secret', 'apisecret',
    'access_token', 'bearer', 'refresh_token', 'auth_token',
    'authorization', 'x-api-key', 'x-auth-token', 'x-access-token',

    # Contraseñas - SOLO CON CONTEXTO
    'password', 'passwd', 'db_password', 'db_pass',
    'admin_password', 'root_password', 'user_password',
    'mysql_password', 'postgres_password',

    # Secretos - MÁS ESPECÍFICOS
    'secret', 'client_secret', 'app_secret', 'shared_secret', 'secret_key',
    'api_secret', 'consumer_secret', 'signing_secret', 'webhook_secret',
    'encryption_key', 'secret_token',

    # AWS - ESPECÍFICOS
    'aws_access_key', 'aws_secret', 'aws_session_token',
    'aws_access_key_id', 'aws_secret_access_key', 'AKIA',

    # Google & Cloud - ESPECÍFICOS
    'google_api_key', 'google_oauth', 'google_access_token',
    'firebase_key', 'firebase_token', 'firebase_app_id',
    'gcp_', 'firebase_',

    # Microsoft Azure - ESPECÍFICOS
    'azure_key', 'azure_connection_string', 'azure_storage_key',

    # Cloud Services - ESPECÍFICOS
    'heroku_api_key', 'heroku_auth_token',
    'stripe_key', 'stripe_secret', 'sk_live_', 'pk_live_',
    'twilio_auth_token', 'twilio_api_key', 'twilio_account_sid',
    'sendgrid_api_key', 'sendgrid_key',
    'mailgun_api_key', 'mailgun_key',
    'github_token', 'github_key', 'github_pat',
    'gitlab_token', 'gitlab_key',
    'slack_token', 'slack_webhook', 'slack_bot_token',
    'discord_token', 'discord_webhook', 'discord_bot_token',
    'telegram_bot_token',

    # Bases de Datos - ESPECÍFICOS
    'database_url', 'db_url', 'database_uri', 'db_uri',
    'mongodb', 'mongodb+srv', 'mongo_url',
    'postgresql', 'postgres_url', 'pg_url',
    'mysql_url', 'mysql_host', 'mysql_user',
    'redis_url', 'redis_password', 'redis_auth',
    'connection_string',

    # Encriptación - ESPECÍFICOS
    'SECRET', 'ENCRYPT', 'RSA', 'AES-256', 'AES-128',
    'private_key', 'privatekey', 'private-key',
    'public_key', 'publickey', 'public-key',
    'certificate', 'ssl_key', 'tls_key',
    'passphrase', 'pem', 'ppk',

    # Webhooks & URLs Internas - ESPECÍFICOS
    'webhook', 'webhook_url', 'webhook_secret',
    'callback_url', 'redirect_uri',

    # OAuth & Auth - ESPECÍFICOS
    'oauth', 'oauth_token', 'oauth_secret',
    'oauth2', 'openid', 'client_id', 'client_secret',
    'consumer_key', 'consumer_secret',
    'iam_', 'auth_',

    # SSH & Keys - ESPECÍFICOS
    'ssh_key', 'ssh_password', 'rsa_key', 'dsa_key', 'ed25519',

    # JWT & Sessions - ESPECÍFICOS
    'jwt', 'jwt_secret', 'jwt_key', 'jwt_token',
    'session_key', 'session_secret', 'session_token',

    # Servicios - ESPECÍFICOS
    'datadog_', 'pagerduty_', 'newrelic_', 'sentry_',
    'splunk_', 'elastic_', 'grafana_', 'prometheus_',
    'jira_token', 'confluence_token',
    'docker_', 'kubernetes_', 'vault_token',

    # Patrones de asignación - ESPECÍFICOS
    'password=', 'token=', 'api_key=', 'apikey=',
    'secret=', 'key=', 'auth=', 'bearer=',
    ':token', ':secret', ':password', ':key', ':auth',

    # Español - ESPECÍFICOS
    'clave', 'contraseña', 'secreto', 'credencial',
    'autenticación',
]

# ════════════════════════════════════════════════════════════════════════════════
# PATRONES DE VULNERABILIDADES
# ════════════════════════════════════════════════════════════════════════════════
PATRONES_VULNERABILIDADES = {
    'reverse_shell_bash': {
        'patron': r'bash\s+-i\s+>(&|\|)\s*/dev/tcp',
        'severidad_esperada': 'CRITICAL',
        'descripcion': 'Reverse shell bash detectado'
    },
    'reverse_shell_netcat': {
        'patron': r'nc\s+(-e|--exec)\s+/bin/(sh|bash)',
        'severidad_esperada': 'CRITICAL',
        'descripcion': 'Reverse shell netcat detectado'
    },
    'reverse_shell_powershell': {
        'patron': r'powershell.*IEX|Invoke-WebRequest.*IEX',
        'severidad_esperada': 'CRITICAL',
        'descripcion': 'Reverse shell PowerShell detectado'
    },
    'command_injection': {
        'patron': r'cmd\.exe\s*/c|sh\s+-c|bash\s+-c',
        'severidad_esperada': 'HIGH',
        'descripcion': 'Potencial command injection'
    },
    'eval_dinamico': {
        'patron': r'\beval\s*\(|Function\s*\(\s*["\'].*["\']',
        'severidad_esperada': 'HIGH',
        'descripcion': 'Código dinámico ejecutado con eval()'
    },
    'exec_python': {
        'patron': r'\bexec\s*\(|__import__\s*\(',
        'severidad_esperada': 'HIGH',
        'descripcion': 'Ejecución dinámica de código Python'
    },
    'deserialization': {
        'patron': r'unserialize\s*\(|pickle\.loads|base64_decode\s*\(\s*\$_',
        'severidad_esperada': 'HIGH',
        'descripcion': 'Deserialización potencialmente insegura'
    },
    'atob_decode': {
        'patron': r'atob\s*\(\s*["\']([A-Za-z0-9+/=]{20,})',
        'severidad_esperada': 'MEDIUM',
        'descripcion': 'Decodificación base64 sospechosa'
    },
    'string_fromcharcode': {
        'patron': r'String\.fromCharCode\s*\((?:\d+\s*,\s*)*\d+',
        'severidad_esperada': 'MEDIUM',
        'descripcion': 'Construcción dinámica de strings'
    },
    'sql_injection': {
        'patron': r"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\+\s*.*['\"]",
        'severidad_esperada': 'HIGH',
        'descripcion': 'Patrón de SQL injection'
    },
    'hardcoded_credentials': {
        'patron': r'(?:user|pass|password|username)\s*[:=]\s*["\'](?![\*\{])[^\s\"\'{}\[\]]{5,}["\']',
        'severidad_esperada': 'CRITICAL',
        'descripcion': 'Credenciales hardcodeadas'
    },
    'shell_exec': {
        'patron': r'(?:shell_exec|system|passthru|exec|proc_open)\s*\(',
        'severidad_esperada': 'CRITICAL',
        'descripcion': 'Función de ejecución del sistema'
    },
}


# ════════════════════════════════════════════════════════════════════════════════
# FUNCIONES HELPER
# ════════════════════════════════════════════════════════════════════════════════

def _parse_multiline_config(texto):
    """Parsea configuración multilinea"""
    if not texto:
        return []
    items = [linea.strip() for linea in texto.split('\n') if linea.strip()]
    return items


def _es_ip(texto):
    """Detectar si es una IP (IPv4)"""
    patron_ip = r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$'
    return bool(re.match(patron_ip, texto))


def _run_osint_job(ejecucion_id, job_func):
    """Ejecuta un job OSINT y maneja su ciclo de vida"""
    try:
        ejecucion = OsintEjecucion.objects.get(id=ejecucion_id)
        ejecucion.estado = 'RUNNING'
        ejecucion.save()
        print(f"[OSINT] Ejecución {ejecucion_id} en estado RUNNING")

        resultados = job_func()

        ejecucion.estado = 'COMPLETED'
        ejecucion.resultados = resultados
        ejecucion.save()
        print(f"[OSINT] Ejecución {ejecucion_id} COMPLETADA")

        return resultados

    except Exception as e:
        print(f"[OSINT] Error en ejecución {ejecucion_id}: {e}")
        ejecucion = OsintEjecucion.objects.get(id=ejecucion_id)
        ejecucion.estado = 'FAILED'
        ejecucion.save()
        raise


# ════════════════════════════════════════════════════════════════════════════════
# FUNCIONES DE VALIDACIÓN
# ════════════════════════════════════════════════════════════════════════════════

def _es_potencial_secreto_linea(linea, palabra_clave):
    """
    Valida UNA LÍNEA para filtrar ruido
    Retorna: True si es potencial secreto REAL, False si es falso positivo
    """
    linea_limpia = linea.strip()

    # 1. IGNORAR COMENTARIOS
    if linea_limpia.startswith('//') or linea_limpia.startswith('#'):
        return False
    if '/*' in linea_limpia or '*/' in linea_limpia:
        return False
    if '<!--' in linea_limpia or '-->' in linea_limpia:
        return False

    # 2. LA PALABRA DEBE SER PALABRA COMPLETA
    patron_palabra = r'\b' + re.escape(palabra_clave) + r'\b'
    match = re.search(patron_palabra, linea_limpia, re.IGNORECASE)
    if not match:
        return False

    # 3. DEBE HABER CONTEXTO DE ASIGNACIÓN O VALOR
    idx = match.start()
    antes = linea_limpia[:idx]
    despues = linea_limpia[idx + len(palabra_clave):]

    tiene_contexto = (
        bool(re.search(r'[=:\'"({]', despues[:15])) or
        bool(re.search(r'[=:\'")}]', antes[-5:]))
    )

    if not tiene_contexto:
        return False

    # 4. DEBE HABER VALOR SIGNIFICATIVO (6+ caracteres)
    if not re.search(r'[a-zA-Z0-9]{6,}', despues):
        return False

    # 5. FILTROS ADICIONALES ANTI-RUIDO
    if re.search(r'\b(typeof|instanceof)\s+\w+', linea_limpia):
        return False

    if '.prototype' in linea_limpia or '.constructor' in linea_limpia:
        return False

    if re.search(r'===|!==|==|!=|typeof|instanceof', linea_limpia):
        return False

    if re.search(r'interface\s+|type\s+|:\s*string|:\s*boolean', linea_limpia):
        return False

    return True


def _buscar_secretos_en_contenido(contenido, url_origen):
    """Buscar secretos usando SOLO GREP - línea por línea"""
    secretos = []
    lineas = contenido.split('\n')
    palabras_encontradas = set()

    for num_linea, linea in enumerate(lineas, 1):
        for palabra_clave in PALABRAS_CLAVE:
            if palabra_clave in palabras_encontradas:
                continue

            if _es_potencial_secreto_linea(linea, palabra_clave):
                secretos.append({
                    'url': url_origen,
                    'palabra_clave': palabra_clave,
                    'linea': linea[:250],
                    'numero_linea': num_linea,
                    'severidad': 'MEDIUM',
                    'metodo': 'grep (palabra clave)'
                })
                palabras_encontradas.add(palabra_clave)

    return secretos


def _deteccion_de_vulnerabilidades(contenido, url_origen, mapa_severidades):
    """Detecta backdoors, reverse shells, ofuscación y código malicioso"""
    vulnerabilidades = []

    for nombre_patron, config in PATRONES_VULNERABILIDADES.items():
        try:
            severidad_esperada = config['severidad_esperada']
            severidad_real = severidad_esperada if severidad_esperada in mapa_severidades else 'MEDIUM'

            regex = re.compile(config['patron'], re.IGNORECASE | re.MULTILINE)

            for i, linea in enumerate(contenido.split('\n'), 1):
                linea_limpia = linea.strip()

                if linea_limpia.startswith('//') or linea_limpia.startswith('#'):
                    continue

                if regex.search(linea_limpia):
                    vulnerabilidades.append({
                        'url': url_origen,
                        'tipo': nombre_patron,
                        'severidad': severidad_real,
                        'descripcion': config['descripcion'],
                        'codigo': linea_limpia[:250],
                        'numero_linea': i
                    })
                    break

        except Exception as e:
            print(f"  [ERROR] Patrón '{nombre_patron}': {e}")

    return vulnerabilidades


def _analizar_url(url, mapa_severidades):
    """Descarga y analiza JavaScript de una URL"""
    secretos_encontrados = []
    vulnerabilidades_encontrados = []

    try:
        response = requests.get(
            url, timeout=10, verify=False, allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 (RedScope)'}
        )
        response.raise_for_status()

        try:
            soup = BeautifulSoup(response.content, 'html.parser')

            # Scripts externos (src attribute)
            for script in soup.find_all('script', src=True):
                js_url = script['src']

                # FILTRAR MINIFICADOS
                if js_url.endswith('.min.js'):
                    print(f"  [SKIP] {js_url} (archivo minificado)")
                    continue

                if js_url.startswith('http'):
                    js_url_completa = js_url
                else:
                    js_url_completa = urljoin(url, js_url)

                try:
                    js_response = requests.get(
                        js_url_completa, timeout=10, verify=False,
                        headers={'User-Agent': 'Mozilla/5.0 (RedScope)'}
                    )
                    js_response.raise_for_status()
                    contenido = js_response.text

                    secretos = _buscar_secretos_en_contenido(contenido, js_url_completa)
                    secretos_encontrados.extend(secretos)

                    vulnerabilidades = _deteccion_de_vulnerabilidades(
                        contenido, js_url_completa, mapa_severidades
                    )
                    vulnerabilidades_encontrados.extend(vulnerabilidades)

                except Exception as e:
                    print(f"  [ERROR] Script externo {js_url_completa}: {type(e).__name__}")

            # Scripts inline
            for i, script in enumerate(soup.find_all('script')):
                if not script.get('src') and script.string:
                    contenido = script.string.strip()
                    if len(contenido) > 50:
                        secretos = _buscar_secretos_en_contenido(
                            contenido, f"{url}#inline-{i}"
                        )
                        secretos_encontrados.extend(secretos)

                        vulnerabilidades = _deteccion_de_vulnerabilidades(
                            contenido, f"{url}#inline-{i}", mapa_severidades
                        )
                        vulnerabilidades_encontrados.extend(vulnerabilidades)

        except Exception as e:
            print(f"  [WARN] No es HTML válido: {type(e).__name__}")

    except Exception as e:
        print(f"  [ERROR] Descargando {url}: {type(e).__name__}")

    return secretos_encontrados, vulnerabilidades_encontrados


# ════════════════════════════════════════════════════════════════════════════════
# HANDLER PRINCIPAL
# ════════════════════════════════════════════════════════════════════════════════

def sensitive_data_extraction(ejecucion_id, proyecto_id):
    """
    HANDLER PRINCIPAL - Extracción de datos sensibles en JavaScript
    FASE 1: scope (dominios + subdominios + servicios SIN IPs)
    FASE 2: SOLO si FASE 1 sin subdominios → usa descubrimientos
    """
    print(f"[OSINT-SENSITIVE-DATA] Handler iniciado para ejecución {ejecucion_id}")
    print(f"[OSINT-SENSITIVE-DATA] Proyecto ID: {proyecto_id}")

    def job():
        # OBTENER SEVERIDADES DEL MODELO
        severidades = Proyecto.get_severidades()
        print(f"[OSINT-SENSITIVE-DATA] Severidades: {[s['nombre'] for s in severidades]}")
        mapa_severidades = {sev['nombre']: sev for sev in severidades}

        # FASE 1: URLs desde SCOPE
        print(f"[sensitive_data] FASE 1: Construyendo URLs desde SCOPE")

        config = Proyecto.get_osint_config(proyecto_id)
        urls_scope = {}

        # Dominios del scope (SIN IPs)
        dominios_scope = _parse_multiline_config(
            config.get('DOMINIO', '').strip() if config else '')
        for dom in dominios_scope:
            if not _es_ip(dom):
                urls_scope[f"http://{dom}"] = dom
                urls_scope[f"https://{dom}"] = dom

        # Subdominios del scope (SIN IPs)
        subdominios_scope = _parse_multiline_config(
            config.get('SUBDOMINIO', '').strip() if config else '')
        for subdom in subdominios_scope:
            if not _es_ip(subdom):
                urls_scope[f"http://{subdom}"] = subdom
                urls_scope[f"https://{subdom}"] = subdom

        # Servicios del scope (SIN IPs)
        servicios_scope = _parse_multiline_config(
            config.get('SERVICIOS', '').strip() if config else '')
        for servicio in servicios_scope:
            if not _es_ip(servicio):
                if ':' in servicio:
                    host, puerto = servicio.rsplit(':', 1)
                    protocolo = 'https' if puerto == '443' else 'http'
                    urls_scope[f"{protocolo}://{host}:{puerto}"] = host
                else:
                    urls_scope[f"http://{servicio}"] = servicio
                    urls_scope[f"https://{servicio}"] = servicio

        print(f"[sensitive_data] FASE 1: {len(urls_scope)} URLs")

        # FASE 2: SOLO si FASE 1 NO tiene subdominios
        todas_las_urls = urls_scope
        fase_usada = 'FASE 1'

        if len(subdominios_scope) == 0:
            print(f"[sensitive_data] Fase 1 sin subdominios. Activando FASE 2")
            fase_usada = 'FASE 2'

            urls_fase2 = {}

            try:
                subdominios_desc = OsintEjecucion.get_discovered_subdomains(proyecto_id)
                for subdom in subdominios_desc:
                    urls_fase2[f"http://{subdom}"] = subdom
                    urls_fase2[f"https://{subdom}"] = subdom
                print(f"[sensitive_data] FASE 2: {len(urls_fase2)} URLs")
            except Exception as e:
                print(f"[sensitive_data] Sin subdominios descubiertos: {type(e).__name__}")

            todas_las_urls = {**urls_scope, **urls_fase2}

        if not todas_las_urls:
            raise Exception("No hay URLs para analizar")

        print(f"[sensitive_data] Total URLs: {len(todas_las_urls)} ({fase_usada})")

        # ANÁLISIS DE JAVASCRIPT
        hallazgos_secretos = {}
        hallazgos_vulnerabilidades = {}
        total_secretos = 0
        total_vulnerabilidades = 0

        for url in todas_las_urls.keys():
            try:
                # FILTRAR MINIFICADOS
                if url.endswith('.min.js'):
                    print(f"[sensitive_data] SKIP {url} (archivo minificado)")
                    continue

                print(f"[sensitive_data] Analizando: {url}")
                secretos, vulnerabilidades = _analizar_url(url, mapa_severidades)

                if secretos:
                    hallazgos_secretos[url] = secretos
                    total_secretos += len(secretos)

                if vulnerabilidades:
                    hallazgos_vulnerabilidades[url] = vulnerabilidades
                    total_vulnerabilidades += len(vulnerabilidades)

                print(f"  ✓ Secretos: {len(secretos)}, Vulnerabilidades: {len(vulnerabilidades)}")

            except Exception as e:
                print(f"[sensitive_data] Error {url}: {type(e).__name__}: {str(e)[:100]}")
                continue

        # RETORNO DE RESULTADOS
        vulnerabilidades_por_severidad = {}
        for severidad in severidades:
            nombre_sev = severidad['nombre']
            count = len([v for vv in hallazgos_vulnerabilidades.values()
                        for v in vv if v.get('severidad') == nombre_sev])
            vulnerabilidades_por_severidad[nombre_sev] = count

        return {
            "tipo": "sensitive_data_extraction",
            "fase_usada": fase_usada,
            "total_urls_analizadas": len(todas_las_urls),
            "total_secretos_encontrados": total_secretos,
            "total_vulnerabilidades_encontradas": total_vulnerabilidades,
            "secretos": hallazgos_secretos,
            "vulnerabilidades": hallazgos_vulnerabilidades,
            "resumen": {
                "secretos_por_metodo": {
                    "grep": len([s for ss in hallazgos_secretos.values() for s in ss if s.get('metodo') == 'grep (palabra clave)'])
                },
                "vulnerabilidades_por_severidad": vulnerabilidades_por_severidad
            }
        }

    # EJECUTAR CON MANEJO DE ERRORES
    try:
        _run_osint_job(ejecucion_id, job)
    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        print(f"[OSINT-SENSITIVE-DATA] ERROR CRÍTICO: {error_msg}")
        try:
            OsintEjecucion.mark_failed(ejecucion_id, error_msg)
        except:
            pass
        raise