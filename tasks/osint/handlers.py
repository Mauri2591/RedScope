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
import dns.resolver
from dns.exception import DNSException
import phonenumbers
from phonenumbers import PhoneNumberType, carrier, geocoder, timezone
CACHE_FILE = '/tmp/ipinfo_cache.json'


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


# Extrae el primer dominio/subdominio válido de una cadena (limpia basura tipo
# "[www.ater.gob.ar](https://www.ater.gob.ar)" -> "www.ater.gob.ar" y quita protocolos)
_EXTRAER_DOMINIO_RE = re.compile(
    r'([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)'
)


def _extraer_dominio(valor):
    """Devuelve el primer dominio válido dentro de 'valor', en minúscula, o None."""
    if not valor:
        return None
    m = _EXTRAER_DOMINIO_RE.search(str(valor).strip())
    return m.group(1).lower() if m else None


def _sanitizar_lista_dominios(lista):
    """Sanitiza y deduplica una lista de dominios/subdominios (descarta inválidos)."""
    vistos = set()
    salida = []
    for x in (lista or []):
        d = _extraer_dominio(x)
        if d and d not in vistos:
            vistos.add(d)
            salida.append(d)
    return salida


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
PUBLIC_DNS_IPS = {'8.8.8.8', '8.8.4.4', '1.1.1.1',
                  '1.0.0.1', '9.9.9.9', '149.112.112.112'}


def _resolve_domain_multi_resolver(dominio, timeout=5):
    """Resuelve dominio - ligero, sin múltiples resolvers"""
    try:
        ips = socket.getaddrinfo(
            dominio, None, socket.AF_INET, timeout=timeout)
        ip_set = set(ip[4][0] for ip in ips)
        return {'ips': ip_set, 'by_resolver': {'default': list(ip_set)}}
    except Exception as e:
        print(f"  [WARN] Resolver {dominio}: {type(e).__name__}")
        return {'ips': set(), 'by_resolver': {}}


def _validate_hostname_belongs_to_domain(hostname, dominio_objetivo, ip):
    """Validación simple de hostname"""
    if not dominio_objetivo or not hostname:
        return {'valido': False, 'razon': 'Datos insuficientes'}

    if dominio_objetivo.lower() in hostname.lower():
        return {'valido': True, 'razon': f'Hostname contiene {dominio_objetivo}'}

    return {'valido': False, 'razon': f'Hostname no pertenece a {dominio_objetivo}'}


def _geolocate_ip(ip):
    """Geolocalización - SOLO si es necesario, sin API externa"""
    # Usar mmdb-geoip2 si está disponible, sino solo metadatos básicos
    return {
        'pais': 'Unknown',
        'ciudad': 'Unknown',
        'isp': 'Unknown',
        'ip': ip
    }


def _reverse_dns_multi_resolver(ip, timeout=5):
    """Reverse DNS - simple"""
    hostnames = []
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        hostnames = [hostname]
        status = 'success'
    except socket.herror:
        status = 'no_reverse_dns'
    except socket.timeout:
        status = 'timeout'
    except Exception as e:
        status = f'error: {type(e).__name__}'

    return {'hostnames': hostnames, 'status': status}

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
        # 1. Obtener scope: DOMINIO + SUBDOMINIO + SERVICIOS (sanitizado)
        scope = OsintEjecucion.get_scope_completo(proyecto_id)
        # Limpiar entradas mal formadas del scope (Markdown, protocolos) en el origen
        dominios_scope = _sanitizar_lista_dominios(
            scope['dominio'] + scope['subdominio'] + scope['servicios'])
        todos_los_dominios = list(dominios_scope)

        # 2. Fallback: Obtener dominios de mapeo_ips
        dominios_from_ips = []
        if not todos_los_dominios:
            dominios_from_ips = _sanitizar_lista_dominios(
                OsintEjecucion.get_discovered_domains_from_ips(proyecto_id))
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
                    "dominios_scope": dominios_scope,
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
                    # Sanitizar la salida de subfinder por las dudas
                    nuevos = _sanitizar_lista_dominios(result.stdout.strip().split('\n'))
                    subdominios.update(nuevos)
                    print(f"[subfinder] {dom} → {len(nuevos)} subdominios")
            except subprocess.TimeoutExpired:
                print(f"[subfinder] Timeout para {dom}")
            except Exception as e:
                print(f"[subfinder] Error en {dom}: {e}")

        subdominios = sorted(list(filter(None, subdominios)))

        return {
            "tipo": "discovery_subdominios",
            "dominios_scope": dominios_scope,
            "total_dominios_escaneados": len(todos_los_dominios),
            "total_subdominios": len(subdominios),
            "subdominios": subdominios
        }

    return _run_osint_job(ejecucion_id, job)


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

    return _run_osint_job(ejecucion_id, job)


# ════════════════════════════════════════════════════════════════════════════════
# Handler MAPEO DE IPs - VERSIÓN ENRIQUECIDA (Local)
# ════════════════════════════════════════════════════════════════════════════════

def _get_asn_info(ip, timeout=5):
    """Obtiene ASN desde ipinfo.io (con cache)"""
    cached = _get_cached_ipinfo(ip)
    if cached:
        return {'asn': cached['asn'], 'isp': cached['isp']}
    
    try:
        import requests
        response = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=timeout,
            verify=False
        )
        if response.status_code == 200:
            data = response.json()
            isp = data.get('org', 'unknown')
            asn = isp.split()[0] if isp and isp != 'unknown' else 'unknown'
            
            result = {'asn': asn, 'isp': isp}
            _save_ipinfo_cache(ip, result)
            return result
    except Exception as e:
        print(f"[asn] Error: {type(e).__name__}")
    
    return {'asn': 'unknown', 'isp': 'unknown'}


def _get_geoip_info(ip, timeout=5):
    """Obtiene geolocalización desde ipinfo.io (con cache)"""
    cached = _get_cached_ipinfo(ip)
    if cached:
        return {
            'pais': cached['pais'], 
            'ciudad': cached['ciudad'],
            'latitud': cached.get('latitud', 'unknown'),
            'longitud': cached.get('longitud', 'unknown')
        }
    
    try:
        import requests
        response = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=timeout,
            verify=False
        )
        if response.status_code == 200:
            data = response.json()
            
            # Extraer coordenadas del campo "loc" (formato: "latitud,longitud")
            loc = data.get('loc', '').split(',')
            latitud = loc[0] if len(loc) > 0 else 'unknown'
            longitud = loc[1] if len(loc) > 1 else 'unknown'
            
            result = {
                'pais': data.get('country', 'unknown'),
                'ciudad': data.get('city', 'unknown'),
                'latitud': latitud,
                'longitud': longitud
            }
            _save_ipinfo_cache(ip, result)
            return result
    except Exception as e:
        print(f"[geoip] Error: {type(e).__name__}")
    
    return {'pais': 'unknown', 'ciudad': 'unknown', 'latitud': 'unknown', 'longitud': 'unknown'}

def _get_whois_info(ip, timeout=5):
    """Obtiene info WHOIS desde ipinfo.io (con cache)"""
    cached = _get_cached_ipinfo(ip)
    if cached:
        return {
            'organizacion': cached.get('organizacion', 'unknown'),
            'pais': cached.get('pais', 'unknown')
        }
    
    try:
        import requests
        response = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=timeout,
            verify=False
        )
        if response.status_code == 200:
            data = response.json()
            isp = data.get('org', 'unknown')
            asn = isp.split()[0] if isp and isp != 'unknown' else 'unknown'
            
            result = {
                'organizacion': asn,
                'pais': data.get('country', 'unknown')
            }
            _save_ipinfo_cache(ip, result)
            return result
    except Exception as e:
        print(f"[whois] Error: {type(e).__name__}")
    
    return {'organizacion': 'unknown', 'pais': 'unknown'}

def _get_cached_ipinfo(ip):
    """Obtiene datos del cache local"""
    try:
        from pathlib import Path
        cache_file = '/tmp/ipinfo_cache.json'
        if Path(cache_file).exists():
            with open(cache_file, 'r') as f:
                cache = json.load(f)
                if ip in cache:
                    return cache[ip]
    except:
        pass
    return None


def _save_ipinfo_cache(ip, ipinfo):
    """Guarda datos en cache local"""
    try:
        from pathlib import Path
        cache_file = '/tmp/ipinfo_cache.json'
        cache = {}
        if Path(cache_file).exists():
            with open(cache_file, 'r') as f:
                cache = json.load(f)
        cache[ip] = ipinfo
        with open(cache_file, 'w') as f:
            json.dump(cache, f, indent=2)
    except:
        pass


def _get_geoip_info(ip, timeout=5):
    """Obtiene geolocalización usando API HTTP (ipinfo.io)"""
    try:
        import requests
        
        response = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=timeout,
            verify=False
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                'pais': data.get('country', 'unknown'),
                'ciudad': data.get('city', 'unknown'),
                'latitud': data.get('loc', 'unknown').split(',')[0] if data.get('loc') else 'unknown',
                'longitud': data.get('loc', 'unknown').split(',')[1] if data.get('loc') else 'unknown'
            }
    except Exception as e:
        print(f"[geoip-api] Error: {type(e).__name__}")
    
    return {
        'pais': 'unknown',
        'ciudad': 'unknown',
        'latitud': 'unknown',
        'longitud': 'unknown'
    }


def _get_whois_info(ip, timeout=5):
    """Obtiene info usando API HTTP (ipinfo.io) - sin WHOIS directo"""
    try:
        import requests
        
        # ipinfo.io - GRATIS, requiere HTTP/HTTPS
        response = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=timeout,
            verify=False  # Por si hay cert issues
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                'organizacion': data.get('org', 'unknown').split()[0] if data.get('org') else 'unknown',
                'pais': data.get('country', 'unknown')
            }
    except Exception as e:
        print(f"[whois-api] Error: {type(e).__name__}")
    
    return {
        'organizacion': 'unknown',
        'pais': 'unknown'
    }


def _validar_reverse_lookup(ip, dominios_scope, subdominios_scope, subdominios_discovery):
    """Valida qué dominio/subdominio resuelve a esta IP (reverse lookup)"""
    todos_dominios = []

    # Agregar scope
    todos_dominios.extend(
        [{'dominio': d, 'tipo': 'dominio_scope'} for d in dominios_scope])
    todos_dominios.extend(
        [{'dominio': s, 'tipo': 'subdominio_scope'} for s in subdominios_scope])
    todos_dominios.extend(
        [{'dominio': s, 'tipo': 'subdominio_discovery'} for s in subdominios_discovery])

    dominios_resuelven = []

    for item in todos_dominios:
        dominio = item['dominio']
        tipo = item['tipo']

        try:
            # Resolver dominio
            ips_resueltas = set()
            try:
                ips_resueltas.update(
                    [ip[4][0] for ip in socket.getaddrinfo(dominio, None)])
            except Exception:
                pass

            # ¿Resuelve a nuestra IP?
            if ip in ips_resueltas:
                dominios_resuelven.append({
                    'dominio': dominio,
                    'tipo': tipo
                })
        except Exception:
            continue

    return dominios_resuelven


def mapeo_ips(ejecucion_id, proyecto_id):
    """Mapeo de IPs enriquecido - Scope → Descubrimiento"""
    print(f"[OSINT-MAPEO-IPS] Handler iniciado para ejecución {ejecucion_id}")

    def job():
        config = Proyecto.get_osint_config(proyecto_id)

        ips_a_analizar = set()
        ip_origen = {}

        # 1. IPs CONFIGURADAS DIRECTAMENTE
        ips_str = config.get('IPS', '').strip() if config else ''
        if ips_str:
            ips_configuradas = _parse_multiline_config(ips_str)
            ips_configuradas_filtradas = [
                ip for ip in ips_configuradas if ip not in PUBLIC_DNS_IPS]
            for ip in ips_configuradas_filtradas:
                ips_a_analizar.add(ip)
                ip_origen[ip] = {'tipo': 'configurada',
                                 'fuente': '[Config IPS]', 'fase': 'DIRECTA'}
            print(
                f"[mapeo_ips] IPs configuradas: {len(ips_configuradas_filtradas)}")

        # 2. RESOLVER DOMINIOS SCOPE
        dominio = config.get('DOMINIO', '').strip() if config else ''
        dominios_scope = _parse_multiline_config(dominio) if dominio else []

        print(
            f"[mapeo_ips] Resolviendo {len(dominios_scope)} dominios del SCOPE...")
        for dom in dominios_scope:
            try:
                ips_resueltas = _resolve_domain_multi_resolver(dom, timeout=5)[
                    'ips']
                for ip in ips_resueltas:
                    if ip not in PUBLIC_DNS_IPS:
                        ips_a_analizar.add(ip)
                        ip_origen[ip] = {
                            'tipo': 'resuelto_dominio_scope',
                            'fuente': dom,
                            'fase': 'FASE 1'
                        }
                print(f"  ✓ {dom} → {len(ips_resueltas)} IPs")
            except Exception as e:
                print(f"  ✗ Error resolviendo {dom}: {type(e).__name__}")
                continue

        # 3. RESOLVER SUBDOMINIOS SCOPE
        subdominio = config.get('SUBDOMINIO', '').strip() if config else ''
        subdominios_scope = _parse_multiline_config(
            subdominio) if subdominio else []

        print(
            f"[mapeo_ips] Resolviendo {len(subdominios_scope)} subdominios del SCOPE...")
        for subdom in subdominios_scope:
            try:
                ips_resueltas = _resolve_domain_multi_resolver(subdom, timeout=5)[
                    'ips']
                for ip in ips_resueltas:
                    if ip not in PUBLIC_DNS_IPS:
                        ips_a_analizar.add(ip)
                        if ip not in ip_origen or 'dominio_scope' not in ip_origen[ip]['tipo']:
                            ip_origen[ip] = {
                                'tipo': 'resuelto_subdominio_scope',
                                'fuente': subdom,
                                'fase': 'FASE 1'
                            }
                print(f"  ✓ {subdom} → {len(ips_resueltas)} IPs")
            except Exception as e:
                print(f"  ✗ Error resolviendo {subdom}: {type(e).__name__}")
                continue

        # 4. FALLBACK - RESOLVER SUBDOMINIOS DESCUBIERTOS
        fase_usada = 'FASE 1'
        subdominios_discovery = []

        if len(subdominios_scope) == 0:
            print(
                f"[mapeo_ips] Sin subdominios en SCOPE. Activando FASE 2 (Discovery)...")
            try:
                subdominios_desc = OsintEjecucion.get_discovered_subdomains(
                    proyecto_id)
                if subdominios_desc:
                    subdominios_discovery = subdominios_desc[:50]
                    print(
                        f"[mapeo_ips] Resolviendo {len(subdominios_discovery)} subdominios DESCUBIERTOS...")
                    for subdom in subdominios_discovery:
                        try:
                            ips_resueltas = _resolve_domain_multi_resolver(subdom, timeout=5)[
                                'ips']
                            for ip in ips_resueltas:
                                if ip not in PUBLIC_DNS_IPS and ip not in ip_origen:
                                    ips_a_analizar.add(ip)
                                    ip_origen[ip] = {
                                        'tipo': 'resuelto_subdominio_descubierto',
                                        'fuente': subdom,
                                        'fase': 'FASE 2 (Discovery)'
                                    }
                        except Exception:
                            continue
                    fase_usada = 'FASE 2 (Discovery)'
                    print(f"[mapeo_ips] FASE 2 completada")
            except Exception as e:
                print(
                    f"[mapeo_ips] Error accediendo Discovery: {type(e).__name__}")

        if not ips_a_analizar:
            raise Exception("No hay IPs para analizar")

        print(f"[mapeo_ips] Total IPs: {len(ips_a_analizar)} ({fase_usada})")

        # 5. ENRIQUECER DATOS DE CADA IP
        ips_success = []
        ips_analizadas = []

        for ip in sorted(ips_a_analizar)[:100]:  # ⚠️ LÍMITE: 100 IPs
            try:
                print(f"[mapeo_ips] Enriqueciendo {ip}...")

                # Reverse DNS
                reverse_result = _reverse_dns_multi_resolver(ip, timeout=5)
                hostname = reverse_result['hostnames'][0] if reverse_result['hostnames'] else 'unknown'

                # ✨ NUEVO: ASN
                asn_info = _get_asn_info(ip)

                # ✨ NUEVO: Geolocalización
                geo_info = _get_geoip_info(ip)

                # ✨ NUEVO: WHOIS
                whois_info = _get_whois_info(ip, timeout=5)

                # ✨ NUEVO: Validar reverse lookup
                reverse_dominios = _validar_reverse_lookup(
                    ip, dominios_scope, subdominios_scope, subdominios_discovery
                )

                # Obtener origen
                origen = ip_origen.get(ip, {
                    'tipo': 'desconocido',
                    'fuente': 'unknown',
                    'fase': 'UNKNOWN'
                })

                entry = {
                    'ip': ip,
                    'hostname': hostname,
                    'status': reverse_result['status'],
                    # Origen
                    'origen_tipo': origen['tipo'],
                    'origen_fuente': origen['fuente'],
                    'fase': origen['fase'],
                    'asn': asn_info['asn'],
                    'isp': asn_info['isp'],
                    'pais': geo_info['pais'],
                    'ciudad': geo_info['ciudad'],
                    'latitud': geo_info['latitud'],        # ← Cambiar ipinfo por geo_info
                    'longitud': geo_info['longitud'],
                    'organizacion': whois_info['organizacion'],
                    'resuelve_a_dominio_scope': len([d for d in reverse_dominios if d['tipo'] == 'dominio_scope']) > 0,
                    'resuelve_a_subdominio_scope': len([d for d in reverse_dominios if d['tipo'] == 'subdominio_scope']) > 0,
                    'resuelve_a_subdominio_discovery': len([d for d in reverse_dominios if d['tipo'] == 'subdominio_discovery']) > 0,
                    'dominios_que_resuelven': reverse_dominios,
                    'valido': True
                }

                ips_analizadas.append(entry)
                ips_success.append(entry)

                print(
                    f"[mapeo_ips] ✓ {ip} ({hostname}) [{asn_info['asn']}] [{geo_info['pais']}]")

            except Exception as e:
                print(f"[mapeo_ips] Error {ip}: {type(e).__name__}")
                origen = ip_origen.get(
                    ip, {'tipo': 'desconocido', 'fuente': 'unknown', 'fase': 'UNKNOWN'})
                ips_analizadas.append({
                    'ip': ip,
                    'hostname': 'unknown',
                    'status': f'error: {type(e).__name__}',
                    'origen_tipo': origen['tipo'],
                    'origen_fuente': origen['fuente'],
                    'fase': origen['fase'],
                    'asn': 'unknown',
                    'isp': 'unknown',
                    'pais': 'unknown',
                    'ciudad': 'unknown',
                    'organizacion': 'unknown',
                    'dominios_que_resuelven': [],
                    'valido': False
                })
                continue

        return {
            "tipo": "mapeo_ips",
            "fase_usada": fase_usada,
            "total_ips": len(ips_a_analizar),
            "total_success": len(ips_success),
            "ips_success": ips_success,
            "ips_todas": ips_analizadas,
            "resumen": {
                "configuradas": len([ip for ip, o in ip_origen.items() if o['tipo'] == 'configurada']),
                "resueltas_dominio_scope": len([ip for ip, o in ip_origen.items() if o['tipo'] == 'resuelto_dominio_scope']),
                "resueltas_subdominio_scope": len([ip for ip, o in ip_origen.items() if o['tipo'] == 'resuelto_subdominio_scope']),
                "resueltas_discovery": len([ip for ip, o in ip_origen.items() if o['tipo'] == 'resuelto_subdominio_descubierto'])
            }
        }

    try:
        return _run_osint_job(ejecucion_id, job)
    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        print(f"[OSINT-MAPEO-IPS] ERROR: {error_msg}")
        try:
            OsintEjecucion.mark_failed(ejecucion_id, error_msg)
        except:
            pass
        raise

# ══════════════════════════════════════════════════════════════════════════════════════════
# ENHANCED RECON_CLOUD - MULTI-CLOUD PROVIDER SUPPORT
# ══════════════════════════════════════════════════════════════════════════════════════════


def recon_cloud(ejecucion_id, proyecto_id):
    """Reconocimiento multi-cloud: Encuentra TODOS los recursos (públicos/privados) con POC"""
    import socket
    import requests

    print(f"[OSINT-CLOUD] Handler iniciado para ejecución {ejecucion_id}")

    def _check_dns(hostname):
        """Verifica si un hostname resuelve"""
        try:
            socket.gethostbyname(hostname)
            return True
        except:
            return False

    def _get_status(url, timeout=3):
        """Obtiene status HTTP y determina tipo de hallazgo"""
        try:
            response = requests.head(
                url, timeout=timeout, allow_redirects=False)
            return response.status_code
        except requests.exceptions.Timeout:
            return "timeout"
        except requests.exceptions.ConnectionError:
            return "no_conecta"
        except:
            return "error"

    def _search_s3(dominio):
        """Busca buckets S3 usando aws s3 ls - más efectivo que HEAD requests"""
        hallazgos = []
        patrones_s3 = [
            dominio,  # Intenta nombre directo: "ater" o "ater.cloud"
            f"{dominio}-backup",
            f"{dominio}-assets",
            f"{dominio}-storage",
            f"{dominio}-uploads",
            f"{dominio}-files",
            f"cdn-{dominio}",
            f"media-{dominio}",
            f"static-{dominio}",
            f"public-{dominio}",
            f"bucket-{dominio}",
        ]

        for bucket in patrones_s3:
            try:
                # Intenta listar el bucket con AWS CLI
                result = subprocess.run(
                    ['aws', 's3', 'ls',
                        f's3://{bucket}/', '--no-sign-request'],
                    capture_output=True,
                    timeout=3,
                    text=True
                )

                if result.returncode == 0:
                    # Éxito = bucket listable públicamente
                    print(f"[recon_cloud] [S3] ✓✓ ANÓNIMO: {bucket}")
                    hallazgos.append({
                        "HALLAZGO": "bucket s3 anónimo",
                        "recurso": bucket,
                        "status": "listable sin credenciales",
                        "status_code": 200,
                        "poc": f"aws s3 ls s3://{bucket}/ --no-sign-request"
                    })
                elif 'Access Denied' in result.stderr:
                    # Bucket existe pero está protegido
                    print(f"[recon_cloud] [S3] ✓ PRIVADO: {bucket}")
                    hallazgos.append({
                        "HALLAZGO": "bucket s3 privado",
                        "recurso": bucket,
                        "status": "existe pero protegido",
                        "status_code": 403,
                        "poc": f"aws s3 ls s3://{bucket}/ --no-sign-request"
                    })
            except subprocess.TimeoutExpired:
                pass
            except Exception as e:
                pass

        return hallazgos

    def _search_azure_blob(dominio):
        """Busca Azure Blob Storage usando az CLI"""
        hallazgos = []
        patrones_azure = [
            dominio,
            f"{dominio}-backup",
            f"{dominio}-assets",
            f"{dominio}-files",
            f"{dominio}-storage",
        ]

        for account_name in patrones_azure:
            try:
                # Intenta listar blobs con az CLI
                result = subprocess.run(
                    ['az', 'storage', 'blob', 'list', '--account-name',
                        account_name, '--auth-mode', 'login'],
                    capture_output=True,
                    timeout=3,
                    text=True
                )

                if result.returncode == 0 and result.stdout.strip():
                    # Éxito = storage account accesible
                    print(f"[recon_cloud] [AZURE] ✓✓ ANÓNIMO: {account_name}")
                    hallazgos.append({
                        "HALLAZGO": "azure blob storage anónimo",
                        "recurso": account_name,
                        "status": "listable sin credenciales",
                        "status_code": 200,
                        "poc": f"az storage blob list --account-name {account_name} --auth-mode login"
                    })
                elif 'not found' in result.stderr.lower() or 'resourcenotfound' in result.stderr.lower():
                    pass  # No existe
                elif result.returncode != 0:
                    # Storage account existe pero no accesible
                    print(f"[recon_cloud] [AZURE] ✓ PRIVADO: {account_name}")
                    hallazgos.append({
                        "HALLAZGO": "azure blob storage privado",
                        "recurso": account_name,
                        "status": "existe pero requiere autenticación",
                        "status_code": 403,
                        "poc": f"az storage blob list --account-name {account_name} --account-key <KEY>"
                    })
            except subprocess.TimeoutExpired:
                pass
            except Exception as e:
                pass

        return hallazgos

    def _search_gcp_storage(dominio):
        """Busca Google Cloud Storage usando gsutil"""
        hallazgos = []
        patrones_gcp = [
            dominio,
            f"{dominio}-backup",
            f"{dominio}-assets",
            f"{dominio}-storage",
            f"storage-{dominio}",
        ]

        for bucket_name in patrones_gcp:
            try:
                # Intenta listar bucket con gsutil
                result = subprocess.run(
                    ['gsutil', 'ls', f'gs://{bucket_name}'],
                    capture_output=True,
                    timeout=3,
                    text=True
                )

                if result.returncode == 0 and result.stdout.strip():
                    # Éxito = bucket listable
                    print(f"[recon_cloud] [GCP] ✓✓ ANÓNIMO: {bucket_name}")
                    hallazgos.append({
                        "HALLAZGO": "gcp storage anónimo",
                        "recurso": bucket_name,
                        "status": "listable sin credenciales",
                        "status_code": 200,
                        "poc": f"gsutil ls gs://{bucket_name}"
                    })
                elif 'does not exist' in result.stderr or 'not found' in result.stderr.lower():
                    pass  # No existe
                elif 'AccessDenied' in result.stderr or 'Forbidden' in result.stderr:
                    # Bucket existe pero no accesible
                    print(f"[recon_cloud] [GCP] ✓ PRIVADO: {bucket_name}")
                    hallazgos.append({
                        "HALLAZGO": "gcp storage privado",
                        "recurso": bucket_name,
                        "status": "existe pero requiere autenticación",
                        "status_code": 403,
                        "poc": f"gsutil ls gs://{bucket_name}"
                    })
            except subprocess.TimeoutExpired:
                pass
            except FileNotFoundError:
                pass  # gsutil no instalado
            except Exception as e:
                pass

        return hallazgos

    def _search_digitalocean_spaces(dominio):
        """Busca DigitalOcean Spaces - verifica acceso y listado"""
        hallazgos = []
        patrones_do = [
            dominio,
            f"{dominio}-backup",
            f"{dominio}-assets",
        ]

        for space_name in patrones_do:
            try:
                url = f"https://{space_name}.nyc3.digitaloceanspaces.com/"
                response = requests.get(url, timeout=3, allow_redirects=False)

                if response.status_code in [200, 201] and 'xml' in response.text.lower():
                    # Éxito = space listable sin credenciales
                    print(f"[recon_cloud] [DO] ✓✓ ANÓNIMO: {space_name}")
                    hallazgos.append({
                        "HALLAZGO": "digitalocean spaces anónimo",
                        "recurso": space_name,
                        "status": "listable sin credenciales",
                        "status_code": 200,
                        "poc": f"curl https://{space_name}.nyc3.digitaloceanspaces.com/"
                    })
                elif response.status_code == 403:
                    # Space existe pero protegido
                    print(f"[recon_cloud] [DO] ✓ PRIVADO: {space_name}")
                    hallazgos.append({
                        "HALLAZGO": "digitalocean spaces privado",
                        "recurso": space_name,
                        "status": "requiere credenciales",
                        "status_code": 403,
                        "poc": f"s3cmd ls s3://{space_name}/ (con credenciales DO)"
                    })
            except requests.exceptions.Timeout:
                pass
            except requests.exceptions.ConnectionError:
                pass
            except Exception as e:
                pass

        return hallazgos

    def _search_rds_endpoints(dominio):
        """Busca AWS RDS endpoints"""
        hallazgos = []
        patrones_rds = [
            (f"{dominio}-db.c9akciq32.us-east-1.rds.amazonaws.com", "us-east-1"),
            (f"{dominio}-db.c9akciq32.eu-west-1.rds.amazonaws.com", "eu-west-1"),
            (f"{dominio}-db.c9akciq32.ap-southeast-1.rds.amazonaws.com",
             "ap-southeast-1"),
            (f"{dominio}-database.c9akciq32.us-east-1.rds.amazonaws.com", "us-east-1"),
            (f"db-{dominio}.c9akciq32.us-east-1.rds.amazonaws.com", "us-east-1"),
            (f"mysql-{dominio}.c9akciq32.us-east-1.rds.amazonaws.com", "us-east-1"),
            (f"postgres-{dominio}.c9akciq32.us-east-1.rds.amazonaws.com", "us-east-1"),
        ]

        for patron, region in patrones_rds:
            if _check_dns(patron):
                print(f"[recon_cloud] [RDS] ✓ ENCONTRADO: {patron}")
                hallazgos.append({
                    "HALLAZGO": "aws rds database",
                    "recurso": patron,
                    "region": region,
                    "status": "requiere credenciales (típico)",
                    "poc": f"mysql -h {patron} -u admin -p (probar credenciales comunes)"
                })

        return hallazgos

    def _search_api_gateway(dominio):
        """Busca AWS API Gateway endpoints - solo públicos y privados (403)"""
        hallazgos = []
        patrones_apigw = [
            f"api-{dominio}.execute-api.us-east-1.amazonaws.com",
            f"api-{dominio}.execute-api.eu-west-1.amazonaws.com",
            f"{dominio}-api.execute-api.us-east-1.amazonaws.com",
            f"{dominio}.execute-api.us-east-1.amazonaws.com",
        ]

        for patron in patrones_apigw:
            if _check_dns(patron):
                url = f"https://{patron}/prod"
                status = _get_status(url)

                if status in [200, 301, 302]:
                    print(f"[recon_cloud] [API-GW] ✓✓ ACCESIBLE: {patron}")
                    hallazgos.append({
                        "HALLAZGO": "aws api gateway accesible",
                        "recurso": patron,
                        "status": "accesible",
                        "status_code": status,
                        "poc": f"curl https://{patron}/prod"
                    })
                elif status == 403:
                    print(f"[recon_cloud] [API-GW] ✓ PRIVADO: {patron}")
                    hallazgos.append({
                        "HALLAZGO": "aws api gateway privado",
                        "recurso": patron,
                        "status": "requiere autenticación",
                        "status_code": 403,
                        "poc": f"curl https://{patron}/prod"
                    })

        return hallazgos

    def _search_lambda_urls(dominio):
        """Busca AWS Lambda URLs públicas - solo públicos y privados (403)"""
        hallazgos = []
        patrones_lambda = [
            f"{dominio}-lambda.execute-api.us-east-1.amazonaws.com",
            f"lambda-{dominio}.execute-api.us-east-1.amazonaws.com",
        ]

        for patron in patrones_lambda:
            if _check_dns(patron):
                url = f"https://{patron}"
                status = _get_status(url)

                if status in [200, 301, 302]:
                    print(f"[recon_cloud] [LAMBDA] ✓✓ ACCESIBLE: {patron}")
                    hallazgos.append({
                        "HALLAZGO": "aws lambda url accesible",
                        "recurso": patron,
                        "status": "accesible",
                        "status_code": status,
                        "poc": f"curl -X POST https://{patron}"
                    })
                elif status == 403:
                    print(f"[recon_cloud] [LAMBDA] ✓ PRIVADO: {patron}")
                    hallazgos.append({
                        "HALLAZGO": "aws lambda url privado",
                        "recurso": patron,
                        "status": "requiere autenticación",
                        "status_code": 403,
                        "poc": f"curl -X POST https://{patron}"
                    })

        return hallazgos

    def _search_gcp_functions(dominio):
        """Busca Google Cloud Functions - solo públicos y privados (403)"""
        hallazgos = []
        regiones = ['us-central1', 'europe-west1', 'asia-northeast1']

        for region in regiones:
            patrones_gcf = [
                f"{dominio}-function-{region}.cloudfunctions.net",
                f"function-{dominio}-{region}.cloudfunctions.net",
            ]

            for patron in patrones_gcf:
                if _check_dns(patron):
                    url = f"https://{patron}"
                    status = _get_status(url)

                    if status in [200, 301, 302]:
                        print(f"[recon_cloud] [GCF] ✓✓ ACCESIBLE: {patron}")
                        hallazgos.append({
                            "HALLAZGO": "gcp cloud function accesible",
                            "recurso": patron,
                            "region": region,
                            "status": "accesible",
                            "status_code": status,
                            "poc": f"curl https://{patron}"
                        })
                    elif status == 403:
                        print(f"[recon_cloud] [GCF] ✓ PRIVADO: {patron}")
                        hallazgos.append({
                            "HALLAZGO": "gcp cloud function privado",
                            "recurso": patron,
                            "region": region,
                            "status": "requiere autenticación",
                            "status_code": 403,
                            "poc": f"curl https://{patron}"
                        })

        return hallazgos

    def _search_firebase(dominio):
        """Busca Google Firebase Realtime DB - obtiene datos reales"""
        hallazgos = []
        patrones_firebase = [
            f"{dominio}.firebaseio.com",
            f"{dominio}-db.firebaseio.com",
            f"{dominio}-rtdb.firebaseio.com",
        ]

        for db_name in patrones_firebase:
            try:
                url = f"https://{db_name}/.json"
                response = requests.get(url, timeout=3, allow_redirects=False)

                if response.status_code in [200, 201]:
                    # Éxito = DB listable sin credenciales
                    print(f"[recon_cloud] [FIREBASE] ✓✓ ANÓNIMO: {db_name}")
                    hallazgos.append({
                        "HALLAZGO": "firebase realtime db anónimo",
                        "recurso": db_name,
                        "status": "datos accesibles sin autenticación",
                        "status_code": 200,
                        "poc": f"curl https://{db_name}/.json | jq ."
                    })
                elif response.status_code == 403:
                    # DB existe pero protegido
                    print(f"[recon_cloud] [FIREBASE] ✓ PRIVADO: {db_name}")
                    hallazgos.append({
                        "HALLAZGO": "firebase realtime db privado",
                        "recurso": db_name,
                        "status": "requiere autenticación",
                        "status_code": 403,
                        "poc": f"curl https://{db_name}/.json"
                    })
            except requests.exceptions.Timeout:
                pass
            except requests.exceptions.ConnectionError:
                pass
            except Exception as e:
                pass

        return hallazgos

    def _search_azure_functions(dominio):
        """Busca Azure Functions - solo públicos y privados (403)"""
        hallazgos = []
        patrones_azure_func = [
            f"{dominio}func.azurewebsites.net",
            f"{dominio}-function.azurewebsites.net",
            f"func-{dominio}.azurewebsites.net",
        ]

        for patron in patrones_azure_func:
            if _check_dns(patron):
                url = f"https://{patron}"
                status = _get_status(url)

                if status in [200, 301, 302]:
                    print(f"[recon_cloud] [AZURE-FUNC] ✓✓ ACCESIBLE: {patron}")
                    hallazgos.append({
                        "HALLAZGO": "azure functions accesible",
                        "recurso": patron,
                        "status": "accesible",
                        "status_code": status,
                        "poc": f"curl https://{patron}"
                    })
                elif status == 403:
                    print(f"[recon_cloud] [AZURE-FUNC] ✓ PRIVADO: {patron}")
                    hallazgos.append({
                        "HALLAZGO": "azure functions privado",
                        "recurso": patron,
                        "status": "requiere autenticación",
                        "status_code": 403,
                        "poc": f"curl https://{patron}"
                    })

        return hallazgos

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
                "No hay dominios para escanear")

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
        # BÚSQUEDA DE RECURSOS POR PROVEEDOR
        # ═══════════════════════════════════════════════════════════════════════
        proveedores = [
            {'nombre': 'AWS S3', 'id': 'aws_s3', 'categoria': 'storage'},
            {'nombre': 'Azure Blob Storage',
                'id': 'azure_blob', 'categoria': 'storage'},
            {'nombre': 'Google Cloud Storage',
                'id': 'gcp_storage', 'categoria': 'storage'},
            {'nombre': 'DigitalOcean Spaces',
                'id': 'do_spaces', 'categoria': 'storage'},
            {'nombre': 'Backblaze B2', 'id': 'b2_cloud', 'categoria': 'storage'},
            {'nombre': 'AWS RDS', 'id': 'aws_rds', 'categoria': 'database'},
            {'nombre': 'Azure Database', 'id': 'azure_database',
                'categoria': 'database'},
            {'nombre': 'Google Cloud SQL',
                'id': 'gcp_cloudsql', 'categoria': 'database'},
            {'nombre': 'DigitalOcean Managed DB',
                'id': 'do_database', 'categoria': 'database'},
            {'nombre': 'AWS ElastiCache',
                'id': 'aws_elasticache', 'categoria': 'cache'},
            {'nombre': 'Azure Cache for Redis',
                'id': 'azure_cache', 'categoria': 'cache'},
            {'nombre': 'Google Cloud Memorystore',
                'id': 'gcp_memorystore', 'categoria': 'cache'},
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

        hallazgos_totales = []

        print(
            f"[recon_cloud] Iniciando escaneo de {len(proveedores)} proveedores...")

        # EXTRAER DOMINIO RAÍZ PARA CONSTRUCCIÓN DE PATRONES
        dominio_raiz_construccion = None
        if dominios_principales:
            primer_dominio = dominios_principales[0]
            partes = primer_dominio.replace('www.', '').split('.')
            if len(partes) >= 2:
                # ej: "ater" de "ater.gob.ar"
                dominio_raiz_construccion = partes[0]
            else:
                dominio_raiz_construccion = partes[0]

        # COMBINAR: dominios principales + subdominios descubiertos
        todos_los_dominios = list(
            set(dominios_principales + dominios_descubiertos))
        # Limitar a 10 dominios totales
        dominios_a_escanear = todos_los_dominios[:10]

        print(f"[recon_cloud] Dominios a escanear: {len(dominios_a_escanear)}")

        # Escanear cada dominio (principal + subdominios)
        for dom in dominios_a_escanear:
            partes_dom = dom.replace('www.', '').split('.')
            primera_parte = partes_dom[0]  # ej: "vpn" de "vpn.ater.gob.ar"

            # Si es el dominio principal, usar el dominio COMPLETO
            # Si es un subdominio, combinar: subdomain-domainroot
            if primera_parte == dominio_raiz_construccion:
                # ej: "flaws.cloud" o "ater.gob.ar"
                dominio_base = dom.replace('www.', '')
            else:
                # ej: "vpn-ater"
                dominio_base = f"{primera_parte}-{dominio_raiz_construccion}"

            print(
                f"\n[recon_cloud] ═══ Escaneando: {dom} (patrón: {dominio_base}) ═══")

            try:
                # S3
                print(f"[recon_cloud] [STORAGE] Escaneando AWS S3...")
                hallazgos_totales.extend(_search_s3(dominio_base))

                # Azure Blob
                print(f"[recon_cloud] [STORAGE] Escaneando Azure Blob Storage...")
                hallazgos_totales.extend(_search_azure_blob(dominio_base))

                # GCP Storage
                print(f"[recon_cloud] [STORAGE] Escaneando Google Cloud Storage...")
                hallazgos_totales.extend(_search_gcp_storage(dominio_base))

                # DigitalOcean Spaces
                print(f"[recon_cloud] [STORAGE] Escaneando DigitalOcean Spaces...")
                hallazgos_totales.extend(
                    _search_digitalocean_spaces(dominio_base))

                # RDS
                print(f"[recon_cloud] [DATABASE] Escaneando AWS RDS...")
                hallazgos_totales.extend(_search_rds_endpoints(dominio_base))

                # API Gateway
                print(f"[recon_cloud] [API] Escaneando AWS API Gateway...")
                hallazgos_totales.extend(_search_api_gateway(dominio_base))

                # Lambda URLs
                print(f"[recon_cloud] [SERVERLESS] Escaneando AWS Lambda URLs...")
                hallazgos_totales.extend(_search_lambda_urls(dominio_base))

                # GCP Functions
                print(
                    f"[recon_cloud] [SERVERLESS] Escaneando Google Cloud Functions...")
                hallazgos_totales.extend(_search_gcp_functions(dominio_base))

                # Firebase
                print(f"[recon_cloud] [DATABASE] Escaneando Google Firebase...")
                hallazgos_totales.extend(_search_firebase(dominio_base))

                # Azure Functions
                print(f"[recon_cloud] [SERVERLESS] Escaneando Azure Functions...")
                hallazgos_totales.extend(_search_azure_functions(dominio_base))

            except Exception as e:
                print(f"[recon_cloud] Error escaneando {dom}: {e}")

        print(f"\n[recon_cloud] ═══ ESCANEO COMPLETADO ═══")
        print(f"[recon_cloud] Total hallazgos: {len(hallazgos_totales)}")

        return {
            "tipo": "recon_cloud_extendido",
            "dominio_scope": dominio_scope,
            "total_dominios_scope": len(dominios_config),
            "total_dominios_from_ips": len(dominios_from_ips),
            "total_subdominios_descubiertos": len(dominios_descubiertos),
            "total_dominios_buscados": len(dominios_principales),
            "total_proveedores_escaneados": len(proveedores),
            "total_hallazgos": len(hallazgos_totales),
            "proveedores": [p['nombre'] for p in proveedores],
            "hallazgos": hallazgos_totales
        }

    return _run_osint_job(ejecucion_id, job)


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
        dominios_descubiertos = OsintEjecucion.get_discovered_subdomains(
            proyecto_id)
        if dominios_descubiertos:
            print(
                f"[escaneo_repositorios] Subdominios descubiertos (solo info): {len(dominios_descubiertos)}")

        # 4. Buscar SOLO dominios raíz (config + mapeo_ips)
        dominios_para_buscar = list(set(dominios_config + dominios_from_ips))

        if not dominios_para_buscar:
            raise Exception(
                "No hay dominios raíz para escanear")

        print(
            f"[escaneo_repositorios] Dominios raíz a buscar: {len(dominios_para_buscar)}")

        hallazgos_raw = []
        for dom in dominios_para_buscar:
            hallazgos_raw.extend(_search_github(dom))

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

    return _run_osint_job(ejecucion_id, job)


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
            domain_base = '.'.join(dom_parts[1:])
        else:
            domain_base = dominio

        domain_parts = domain_base.split('.')
        keyword = domain_parts[0]  # 'ater' de 'ater.gob.ar'

        searches = [
            # 1. Búsquedas por palabra clave en archivos de credenciales
            f'filename:.env {keyword}',
            f'filename:.env.example {keyword}',
            f'filename:config.json {keyword}',
            f'filename:secrets.json {keyword}',
            f'filename:credentials.json {keyword}',
            f'filename:.postman_collection.json {keyword}',
            f'filename:docker-compose.yml {keyword}',

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
            f'"{keyword}apps"',
            f'"{keyword}-api"',
            f'"customer-{keyword}"',
            f'{keyword}-api',
            f'customer-{keyword}',

            # 4. Búsquedas por dominio COMPLETO + palabras sensibles
            f'"{domain_base}"',
            f'"{domain_base}" secret',
            f'"{domain_base}" password',
            f'"{domain_base}" token',
            f'"{domain_base}" api',
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
    """Genera todas las variantes posibles de uno o múltiples dominios"""
    variants = set()

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

        # Agregar cada palabra individual
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
        domain_variants = {
            v for v in domain_variants if '.' in v or len(v) > 3}

    for item in hallazgos_raw:
        if item.get('tipo') != 'github_repo':
            continue

        repo = item.get('repo', '').replace(
            '[', '').replace('](', '/').replace(')', '')
        if not repo:
            continue

        repo_lower = repo.lower()

        # Filtro 1: El nombre del repo DEBE contener una variante del dominio
        if domain_variants:
            has_variant = any(var in repo_lower for var in domain_variants)
            if not has_variant:
                continue

        # Filtro 2: Remover repos no relacionados
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
            'status': status,
            'queries_encontradas': len(data['queries']),
            'queries': sorted(list(data['queries'])),
            'archivos': sorted(list(data['archivos']))
        })

    return resultado


def analisis_dns(ejecucion_id, proyecto_id):
    """Análisis de registros DNS - Optimizado"""
    print(f"[OSINT-DNS] Handler iniciado para ejecución {ejecucion_id}")

    def job():

        # 1. Obtener TODO el scope
        scope = OsintEjecucion.get_scope_completo(proyecto_id)
        todos_los_dominios = scope['dominio'] + \
            scope['subdominio'] + scope['servicios']

        # 2. Agregar subdominios descubiertos
        subdominios_descubiertos = OsintEjecucion.get_discovered_subdomains(
            proyecto_id)
        todos_los_dominios.extend(subdominios_descubiertos)

        # 3. Fallback: dominios de mapeo_ips
        if not todos_los_dominios:
            dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(
                proyecto_id)
            todos_los_dominios.extend(dominios_from_ips)

        if not todos_los_dominios:
            raise Exception("No hay dominios para analizar")

        # Deduplicar y ordenar
        todos_los_dominios = sorted(list(set(todos_los_dominios)))

        registros = {}
        tipos = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

        print(f"[analisis_dns] Analizando {len(todos_los_dominios)} dominios")

        for dom in todos_los_dominios:
            registros[dom] = {}
            
            # UNA sola consulta por dominio en lugar de 7
            for tipo in tipos:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 5
                    resolver.lifetime = 5
                    
                    answers = resolver.resolve(dom, tipo, raise_on_no_answer=False)
                    
                    if answers:
                        registros[dom][tipo] = [str(rdata) for rdata in answers]
                    
                except DNSException as e:
                    print(f"[dns] {tipo} {dom}: {type(e).__name__}")
                except Exception as e:
                    print(f"[dns] Error {tipo} {dom}: {e}")

        return {
            "tipo": "analisis_dns",
            "total_dominios_analizados": len(todos_los_dominios),
            "dominios_scope": len(scope['dominio']) + len(scope['subdominio']) + len(scope['servicios']),
            "subdominios_descubiertos": len(subdominios_descubiertos),
            "tipos_registros": tipos,
            "registros": registros
        }

    return _run_osint_job(ejecucion_id, job)


def busqueda_endpoints(ejecucion_id, proyecto_id):
    """Búsqueda de endpoints - múltiples estrategias"""
    def job():
        # 1. DOMINIO del scope
        dominios_scope = OsintEjecucion.get_dominio_from_config(proyecto_id)

        # 2. SIEMPRE agregar subdominios descubiertos
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

        for dom in todos_los_dominios:
            endpoints.update(_search_waybackurls(dom))

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
            "endpoints": endpoints_200
        }

    return _run_osint_job(ejecucion_id, job)


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
            f"[waybackurls] No instalado")
    except subprocess.TimeoutExpired:
        print(f"[waybackurls] Timeout")
    except Exception as e:
        print(f"[waybackurls] Error: {e}")

    return endpoints


def urls_historicas(ejecucion_id, proyecto_id):
    """Búsqueda de URLs históricas con GAU"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio_config = config.get('DOMINIO', '').strip()
        ips_config = config.get('IPS', '').strip()  # ← NUEVO

        # 1. Obtener dominios del scope
        dominios_scope = _parse_multiline_config(
            dominio_config) if dominio_config else []
        if dominios_scope:
            print(f"[gau] Dominios del scope: {dominios_scope}")

        # 1b. Obtener IPs del scope ← NUEVO
        ips_scope = _parse_multiline_config(ips_config) if ips_config else []
        if ips_scope:
            print(f"[gau] IPs del scope: {ips_scope}")

        # 2. Fallback: Obtener dominios descubiertos por reverse DNS
        dominios_from_ips = OsintEjecucion.get_discovered_domains_from_ips(
            proyecto_id)
        if dominios_from_ips:
            print(f"[gau] Dominios descubiertos: {dominios_from_ips}")

        # 3. Fallback: Obtener subdominios descubiertos
        subdominios_descubiertos = OsintEjecucion.get_discovered_subdomains(
            proyecto_id)
        if subdominios_descubiertos:
            print(f"[gau] Subdominios descubiertos: {len(subdominios_descubiertos)}")

        # 4. Combinar todas las fuentes de dominios
        todos_los_dominios = list(
            set(dominios_scope + dominios_from_ips + subdominios_descubiertos))

        # 5. Validar que hay algo para escanear
        if not todos_los_dominios and not ips_scope:
            raise Exception("No hay dominios ni IPs para escanear")

        urls = set()

        # 6. Buscar URLs de dominios
        if todos_los_dominios:
            print(f"[gau] Buscando URLs en {len(todos_los_dominios)} dominios...")
            for dom in todos_los_dominios:
                print(f"[gau] Escaneando: {dom}...")
                urls.update(_search_gau(dom))

        # 7. Buscar URLs de IPs CON MÚLTIPLES PUERTOS
        if ips_scope:
            urls_from_ips = []
            puertos = ["", "8080", "8443", "3000", "3001", "5000", "8000"]
            protocolos = ["http", "https"]
            
            for ip in ips_scope:
                for protocolo in protocolos:
                    for puerto in puertos:
                        if puerto:
                            url = f"{protocolo}://{ip}:{puerto}"
                        else:
                            url = f"{protocolo}://{ip}"
                        urls_from_ips.append(url)
            
            print(f"[gau] Buscando URLs en {len(ips_scope)} IPs con puertos ({len(urls_from_ips)} URLs)...")
            for url in urls_from_ips:
                print(f"[gau] Escaneando: {url}...")
                urls.update(_search_gau(url))

        urls = sorted(list(filter(None, urls)))

        return {
            "tipo": "busqueda_urls_historicas",
            "dominios_scope": dominios_scope,
            "ips_scope": ips_scope,
            "dominios_from_ips": dominios_from_ips,
            "subdominios_descubiertos": subdominios_descubiertos,
            "total_dominios": len(todos_los_dominios),
            "total_ips": len(ips_scope),
            "total_urls_ips_generadas": len(urls_from_ips) if ips_scope else 0,
            "total": len(urls),
            "urls": urls
        }

    return _run_osint_job(ejecucion_id, job)


def _get_valid_ips_from_mapeo(proyecto_id):
    """Obtiene IPs válidas del resultado de mapeo_ips"""
    try:
        resultado = OsintEjecucion.get_latest_resultado(
            proyecto_id, 'mapeo_ips')
        if not resultado:
            return []

        ips_success = resultado.get('ips_success', [])
        ips = [ip_data['ip']
               for ip_data in ips_success if ip_data.get('valido')]
        return ips
    except Exception as e:
        print(f"[mapeo_ips] Error obteniendo IPs válidas: {e}")
        return []


def _search_gau(target):
    """Busca URLs históricas usando GAU"""
    urls = set()
    try:
        print(f"[gau] Buscando URLs históricas de {target}...")

        gau_path = _find_gau_path()
        if not gau_path:
            print(f"[gau] ❌ GAU NO ENCONTRADO en PATH")
            return urls

        print(f"[gau] ✅ GAU encontrado en: {gau_path}")

        result = subprocess.run(
            [gau_path, '--blacklist',
                'svg,css,js,woff,woff2,ttf,eot,otf,ico,map', target],
            capture_output=True,
            text=True,
            timeout=300
        )

        print(f"[gau] Return code: {result.returncode}")
        print(f"[gau] Stdout chars: {len(result.stdout)}")

        if result.returncode == 0 and result.stdout.strip():
            urls_raw = result.stdout.strip().split('\n')
            urls.update([url for url in urls_raw if url])
            print(f"[gau] ✅ Encontradas {len(urls)} URLs para {target}")
            return urls
        else:
            print(
                f"[gau] ⚠️ GAU no devolvió URLs (return_code={result.returncode})")

    except subprocess.TimeoutExpired:
        print(f"[gau] ⏱️ TIMEOUT para {target} (>300s)")
    except Exception as e:
        print(f"[gau] ❌ EXCEPTION: {type(e).__name__}: {e}")

    return urls


def google_dorking(ejecucion_id, proyecto_id):
    """Google Dorking - búsquedas especializadas con resultados reales"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio_config = config.get('DOMINIO', '').strip()

        # 1. Obtener dominios del scope inicial
        dominios_scope = _parse_multiline_config(
            dominio_config) if dominio_config else []
        if dominios_scope:
            print(
                f"[google_dorking] Dominios del scope encontrados: {dominios_scope}")
        else:
            print(f"[google_dorking] Sin dominios configurados en DOMINIO")

        # 2. Fallback: Obtener dominios descubiertos por reverse DNS
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
                "No hay dominios para escanear")

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

    return _run_osint_job(ejecucion_id, job)


def _ejecutar_google_dork(dominio, dork_query):
    """Ejecuta un dork en Google y obtiene resultados"""
    resultados = []
    try:
        print(f"[google] Ejecutando dork: {dork_query}")

        # Usar curl con User-Agent para simular navegador
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        # Construir URL de búsqueda
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
        resultados.append({
            'dork': dork_query,
            'dominio': dominio,
            'url': None,
            'tipo': 'google_search_result',
            'error': str(e)
        })

    return resultados


# ════════════════════════════════════════════════════════════════════════════════
# SENSITIVE DATA EXTRACTION - ADAPTADO CON MEJORAS
# ════════════════════════════════════════════════════════════════════════════════
PALABRAS_CLAVE = [
    # CRÍTICOS - API & Tokens
    'api_key', 'apikey', 'access_token', 'auth_token',
    'bearer', 'x-api-key',

    # CRÍTICOS - Contraseñas & Secretos
    'password', 'passwd', 'secret', 'secret_key',

    # CRÍTICOS - Cloud
    'aws_access_key', 'aws_secret', 'AKIA',
    'firebase_key', 'stripe_key', 'github_token',
    'slack_token', 'discord_token',

    # CRÍTICOS - Bases de Datos
    'database_url', 'mongodb', 'postgresql',
    'mysql_url', 'redis_url', 'connection_string',

    # CRÍTICOS - Auth & JWT
    'jwt', 'jwt_token', 'oauth_token', 'client_secret',

    # CRÍTICOS - Encriptación
    'private_key', 'public_key', 'certificate',
    'ssh_key', 'ssh_private_key', 'rsa_private_key',
    'openssh_key', 'private_pem', 'id_rsa',

    # NUEVO - Configuración & Sesión (Moodle, PHP, etc.)
    'sesskey', 'csrf_token', 'csrf', 'apibase', 'api_url',
    'admin_token', 'admin_key', 'root_token', 'root_key',
    'session_id', 'session_token', 'sso_token',
    'wwwroot', 'base_url', 'site_url', 'app_key',
    'encryption_key', 'hmac_key', 'signing_key'
]

PATRONES_VULNERABILIDADES = {
    'reverse_shell_bash': {
        'patron': r'bash\s+-i\s+>(&|\|)\s*/dev/tcp',
        'nivel_recomendado': 'CRITICAL',
        'descripcion': 'Reverse shell bash detectado'
    },
    'reverse_shell_netcat': {
        'patron': r'nc\s+(-e|--exec)\s+/bin/(sh|bash)',
        'nivel_recomendado': 'CRITICAL',
        'descripcion': 'Reverse shell netcat detectado'
    },
    'eval_dinamico': {
        'patron': r'\beval\s*\(',
        'nivel_recomendado': 'HIGH',
        'descripcion': 'Código dinámico ejecutado con eval()'
    },
    'hardcoded_credentials': {
        'patron': r'(?:user|pass|password)\s*[:=]\s*["\'](?!password["\'])[^\s\"\'{}\[\]]{8,}["\']',
        'nivel_recomendado': 'CRITICAL',
        'descripcion': 'Credenciales hardcodeadas'
    }
}


# ════════════════════════════════════════════════════════════════════════════════
# FUNCIONES AUXILIARES
# ════════════════════════════════════════════════════════════════════════════════

def _obtener_severidad_real(nivel_recomendado, mapa_severidades):
    """
    ✨ NUEVO: Mapea nivel recomendado a severidad REAL de la BD

    Intenta encontrar la severidad en este orden:
    1. Exacta: Busca el nombre exacto
    2. Aproximada: Si dice CRITICAL, busca CRITICO/CRITICAL
    3. Default: Si no encuentra, usa la primera severidad disponible
    """
    if not mapa_severidades:
        return 'MEDIUM'  # Fallback si no hay severidades

    # 1. Búsqueda exacta
    if nivel_recomendado in mapa_severidades:
        return nivel_recomendado

    # 2. Búsqueda aproximada (ignorar acentos)
    nivel_limpio = nivel_recomendado.upper()
    for sev_nombre in mapa_severidades.keys():
        if sev_nombre.upper() == nivel_limpio:
            return sev_nombre

    # 3. Mapeo por similitud
    mapeo_aproximado = {
        'CRITICAL': ['CRITICO', 'CRÍTICO', 'CRITICAL', 'GRAVE', 'SEVERO'],
        'HIGH': ['ALTO', 'HIGH', 'IMPORTANTE', 'SERIO'],
        'MEDIUM': ['MEDIO', 'MEDIUM', 'MODERADO', 'NORMAL'],
        'LOW': ['BAJO', 'LOW', 'MENOR', 'TRIVIAL'],
        'INFO': ['INFO', 'INFORMATIVO', 'INFORMACIÓN']
    }

    for nivel, variantes in mapeo_aproximado.items():
        if nivel_recomendado.upper() in variantes:
            for variante in variantes:
                if variante in mapa_severidades:
                    return variante

    # 4. Fallback: primera severidad disponible
    return list(mapa_severidades.keys())[0]


def _parse_multiline_config(texto):
    """Parsea configuración multilinea"""
    if not texto:
        return []
    items = [linea.strip() for linea in texto.split('\n') if linea.strip()]
    return items


def _es_ip(texto):
    """Detectar si es una IP (IPv4) - MEJORADO"""
    if not texto:
        return False

    texto_limpio = texto.strip().split(':')[0]
    patron_ip = r'^(\d{1,3}\.){3}\d{1,3}$'

    if re.match(patron_ip, texto_limpio):
        try:
            octetos = [int(x) for x in texto_limpio.split('.')]
            return all(0 <= oct <= 255 for oct in octetos)
        except:
            return False
    return False


def _generar_urls_para_ip(ip_texto):
    """Genera URLs variantes para una IP"""
    urls_dict = {}
    ip_texto = ip_texto.strip()

    if ':' in ip_texto:
        ip, puerto = ip_texto.rsplit(':', 1)
    else:
        ip = ip_texto
        puerto = None

    if not _es_ip(ip):
        return urls_dict

    if puerto:
        try:
            puerto_num = int(puerto)
            if 1 <= puerto_num <= 65535:
                urls_dict[f"http://{ip}:{puerto}"] = f"{ip}:{puerto}"
                urls_dict[f"https://{ip}:{puerto}"] = f"{ip}:{puerto}"
        except:
            pass
    else:
        urls_dict[f"http://{ip}"] = ip
        urls_dict[f"https://{ip}"] = ip
        urls_dict[f"http://{ip}:8080"] = f"{ip}:8080"
        urls_dict[f"https://{ip}:8443"] = f"{ip}:8443"
        urls_dict[f"http://{ip}:3000"] = f"{ip}:3000"
        urls_dict[f"http://{ip}:3001"] = f"{ip}:3001"
        urls_dict[f"http://{ip}:5000"] = f"{ip}:5000"
        urls_dict[f"http://{ip}:8000"] = f"{ip}:8000"

    return urls_dict


def _procesar_ips_scope(texto_ips):
    """Parsea IPs del scope y genera URLs variantes"""
    urls_ips = {}

    if not texto_ips:
        return urls_ips

    items = [item.strip() for item in texto_ips.split('\n') if item.strip()]

    for item in items:
        if item.startswith('#') or item.startswith('//'):
            continue

        if _es_ip(item):
            urls_variantes = _generar_urls_para_ip(item)
            urls_ips.update(urls_variantes)

    return urls_ips


# ════════════════════════════════════════════════════════════════════════════════
# VALIDACIÓN MEJORADA DE SECRETOS (SIN FALSOS POSITIVOS)
# ════════════════════════════════════════════════════════════════════════════════

def _es_asignacion_legit(linea, palabra_clave):
    """
    VALIDACIÓN MEJORADA: Detecta SOLO asignaciones REALES de credenciales
    ✅ Filtra: función unmaskPassword(), pw.type="password", etc.
    """
    linea_limpia = linea.strip()

    # Ignorar comentarios
    if linea_limpia.startswith('//') or linea_limpia.startswith('#'):
        return False
    if '/*' in linea_limpia or '*/' in linea_limpia:
        return False
    if '//' in linea_limpia:
        antes_comentario = linea_limpia.split('//')[0]
        if palabra_clave.lower() not in antes_comentario.lower():
            return False
        linea_limpia = antes_comentario

    # Ignorar definiciones de tipos
    if re.search(r':\s*(string|boolean|number|any|void|String|Boolean|Number)', linea_limpia):
        return False
    if re.search(r'\binterface\s+|\btype\s+|\benum\s+', linea_limpia):
        return False

    # Ignorar nombres de funciones
    if re.search(rf'\b(function|const|let|var)\s+\w*{re.escape(palabra_clave)}\s*\(',
                 linea_limpia, re.IGNORECASE):
        return False
    if re.search(rf'\.([a-z]*{re.escape(palabra_clave)}|{re.escape(palabra_clave)})\s*\(',
                 linea_limpia, re.IGNORECASE):
        return False

    # Ignorar asignaciones de tipo
    if re.search(r'\.type\s*=\s*["\']password["\']', linea_limpia, re.IGNORECASE):
        return False
    if re.search(r'type\s*=\s*["\']password["\']', linea_limpia, re.IGNORECASE):
        return False

    # La palabra debe ser palabra completa
    patron_palabra = r'\b' + re.escape(palabra_clave) + r'\b'
    match = re.search(patron_palabra, linea_limpia, re.IGNORECASE)
    if not match:
        return False

    # Patrones de asignación REAL

    # Patrón 1: var/let/const password = "valor"
    patron_var_assign = r'^(var|let|const|private|public|protected|static)?\s*\w*' + \
        re.escape(palabra_clave) + r'\s*[:=]\s*["\']'
    if re.search(patron_var_assign, linea_limpia, re.IGNORECASE):
        valor_match = re.search(
            patron_var_assign + r'([^"\']+)', linea_limpia, re.IGNORECASE)
        if valor_match:
            valor = valor_match.group(valor_match.lastindex)
            if valor.lower() != palabra_clave.lower():
                return True
        return False

    # Patrón 2: password: "valor" (objeto JS)
    patron_obj = r'\b' + re.escape(palabra_clave) + r'\s*:\s*["\']'
    if re.search(patron_obj, linea_limpia, re.IGNORECASE):
        valor_match = re.search(
            patron_obj + r'([^"\']+)', linea_limpia, re.IGNORECASE)
        if valor_match:
            valor = valor_match.group(1)
            if valor.lower() != palabra_clave.lower() and len(valor) > 3:
                return True
        return False

    # Patrón 3: password="valor" (atributo HTML)
    patron_html = r'\b' + re.escape(palabra_clave) + r'\s*=\s*["\']'
    if re.search(patron_html, linea_limpia, re.IGNORECASE):
        valor_match = re.search(
            patron_html + r'([^"\']+)', linea_limpia, re.IGNORECASE)
        if valor_match:
            valor = valor_match.group(1)
            if valor.lower() != palabra_clave.lower() and len(valor) > 3:
                return True
        return False

    # Patrón 4: this.password = "valor"
    if re.search(r'(this|self|obj)\.' + re.escape(palabra_clave) + r'\s*=\s*["\']',
                 linea_limpia, re.IGNORECASE):
        valor_match = re.search(r'(this|self|obj)\.' + re.escape(palabra_clave) + r'\s*=\s*["\']' + r'([^"\']+)',
                                linea_limpia, re.IGNORECASE)
        if valor_match:
            valor = valor_match.group(valor_match.lastindex)
            if valor.lower() != palabra_clave.lower() and len(valor) > 3:
                return True
        return False

    # Patrón 5: tokens/keys sin comillas
    patron_sin_comillas = r'\b' + \
        re.escape(palabra_clave) + r'\s*[:=]\s*([a-zA-Z0-9_\-\.]{16,})'
    match_sin_comillas = re.search(
        patron_sin_comillas, linea_limpia, re.IGNORECASE)
    if match_sin_comillas:
        valor = match_sin_comillas.group(1)
        if not re.match(r'^(string|number|boolean|any|void)$', valor, re.IGNORECASE):
            return True

    # Anti-ruido
    if re.search(r'@\w+|typeof|instanceof|\.prototype', linea_limpia):
        return False

    return False


def _buscar_secretos_en_contenido(contenido, url_origen):
    """Buscar secretos con validación MEJORADA"""
    secretos = []
    lineas = contenido.split('\n')
    palabras_encontradas = set()

    for num_linea, linea in enumerate(lineas, 1):
        for palabra_clave in PALABRAS_CLAVE:
            if palabra_clave in palabras_encontradas:
                continue

            # USAR VALIDACIÓN MEJORADA
            if _es_asignacion_legit(linea, palabra_clave):
                secretos.append({
                    'url': url_origen,
                    'palabra_clave': palabra_clave,
                    'linea': linea[:250],
                    'numero_linea': num_linea,
                    'severidad': 'MEDIUM',
                    'metodo': 'grep'
                })
                palabras_encontradas.add(palabra_clave)

    # ✨ NUEVO: Buscar patrones específicos de configuración JS
    secretos_config = _buscar_config_javascript(contenido, url_origen)
    secretos.extend(secretos_config)

    return secretos


def _buscar_config_javascript(contenido, url_origen):
    """
    ✨ NUEVO: Busca configuración expuesta en variables globales
    Detecta: M.cfg = {...}, config = {...}, etc.
    """
    secretos = []

    # Patrones de configuración comunes
    patrones_config = {
        'sesskey': {
            'patron': r'["\']?sesskey["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{8,})["\']',
            'severidad': 'HIGH',
            'razon': 'Token de sesión expuesto (CSRF risk)'
        },
        'csrf_token': {
            'patron': r'["\']?csrf(?:_token)?["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{8,})["\']',
            'severidad': 'HIGH',
            'razon': 'Token CSRF expuesto'
        },
        'apibase': {
            'patron': r'["\']?apibase["\']?\s*[:=]\s*["\']([^"\']{10,})["\']',
            'severidad': 'MEDIUM',
            'razon': 'URL de API expuesta'
        },
        'api_key_config': {
            'patron': r'["\']?api[_]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            'severidad': 'HIGH',
            'razon': 'API Key expuesta en configuración'
        },
        'admin_token': {
            'patron': r'["\']?admin[_]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{10,})["\']',
            'severidad': 'CRITICAL',
            'razon': 'Token de admin expuesto'
        },
        'wwwroot': {
            'patron': r'["\']?wwwroot["\']?\s*[:=]\s*["\']([^"\']{10,})["\']',
            'severidad': 'LOW',
            'razon': 'URL raíz de aplicación expuesta (información de sistema)'
        },
    }

    for patron_nombre, config_patron in patrones_config.items():
        try:
            matches = re.finditer(
                config_patron['patron'], contenido, re.IGNORECASE)
            for match in matches:
                valor = match.group(1)

                # Filtrar valores triviales
                if len(valor) < 5 or valor.lower() in ['password', 'token', 'key', 'value']:
                    continue

                secretos.append({
                    'url': url_origen,
                    'palabra_clave': patron_nombre,
                    'linea': f'{patron_nombre} = {valor[:80]}',
                    'numero_linea': contenido[:match.start()].count('\n') + 1,
                    'severidad': config_patron['severidad'],
                    'metodo': 'js_config_pattern',
                    'razon': config_patron['razon']
                })
        except Exception as e:
            pass

    return secretos


# ════════════════════════════════════════════════════════════════════════════════
# DETECCIÓN HTML SENSIBLE (NUEVO)
# ════════════════════════════════════════════════════════════════════════════════

def _analizar_valor_sensible(valor):
    """Analiza si un valor es potencialmente sensible"""
    if not valor or len(valor) < 8:
        return None

    valor_limpio = valor.strip()

    # JWT
    jwt_pattern = r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
    if re.match(jwt_pattern, valor_limpio):
        return {
            'tipo_valor': 'jwt_like',
            'descripcion': 'JWT token detectado',
            'severidad': 'CRITICAL'
        }

    # Base64 largo
    base64_pattern = r'^[A-Za-z0-9+/]{32,}={0,2}$'
    if re.match(base64_pattern, valor_limpio):
        return {
            'tipo_valor': 'base64_largo',
            'descripcion': 'Base64 largo (probablemente encriptado/token)',
            'severidad': 'MEDIUM'
        }

    # Hex largo
    hex_pattern = r'^[a-f0-9]{32,}$'
    if re.match(hex_pattern, valor_limpio):
        return {
            'tipo_valor': 'hex_largo',
            'descripcion': 'Hexadecimal largo (hash o encriptado)',
            'severidad': 'MEDIUM'
        }

    # UUID
    uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    if re.match(uuid_pattern, valor_limpio):
        return {
            'tipo_valor': 'uuid',
            'descripcion': 'UUID detectado',
            'severidad': 'LOW'
        }

    return None


def _buscar_inputs_hidden(contenido_html, url_origen):
    """Busca inputs hidden y elementos HTML sensibles - DETECCIÓN GENÉRICA"""
    hallazgos = []

    try:
        soup = BeautifulSoup(contenido_html, 'html.parser')

        # Inputs hidden - REGLA SIMPLE: Cualquier input con valor = hallazgo potencial
        inputs_hidden = soup.find_all('input', {'type': 'hidden'})

        for input_tag in inputs_hidden:
            nombre = input_tag.get('name', 'sin_nombre').lower()
            valor = input_tag.get('value', '').strip()

            # ✨ GENÉRICO: Detectar CUALQUIER input hidden con valor no vacío
            if not valor:
                continue

            # Analizar el valor para determinar severidad
            analisis_valor = _analizar_valor_sensible(valor)

            # Determinar severidad basado en:
            # 1. Análisis del valor (Base64, Hex, JWT, UUID)
            # 2. Longitud del valor
            # 3. Nombre del input (si contiene palabras sensibles)

            severidad = 'LOW'
            razon = ''

            # Opción 1: Si el análisis detecta patrón → usar su severidad
            if analisis_valor:
                severidad = analisis_valor['severidad']
                razon = analisis_valor['descripcion']
            # Opción 2: Si es muy largo → probablemente estado/token encriptado
            elif len(valor) >= 50:
                severidad = 'HIGH'
                razon = f'Input hidden con valor muy largo ({len(valor)} chars) - probable estado/token'
            # Opción 3: Si es medianamente largo → potencial valor sensible
            elif len(valor) >= 20:
                severidad = 'MEDIUM'
                razon = f'Input hidden con valor largo ({len(valor)} chars) - potencial estado/credencial'
            # Opción 4: Si tiene nombre sensible
            else:
                palabras_sensibles = [
                    'token', 'csrf', 'auth', 'session', 'nonce',
                    'secret', 'key', 'state', 'payload'
                ]
                for palabra in palabras_sensibles:
                    if palabra in nombre:
                        severidad = 'MEDIUM'
                        razon = f'Input hidden con nombre sensible: "{nombre}"'
                        break

                # Si no tiene nombre sensible pero tiene valor → LOW priority
                if not razon:
                    severidad = 'LOW'
                    razon = f'Input hidden: {nombre} (requiere análisis manual)'

            # Crear hallazgo
            hallazgos.append({
                'url': url_origen,
                'tipo': 'hidden_input',
                'nombre_input': nombre,
                'valor': valor[:100],
                'longitud_valor': len(valor),
                'severidad': severidad,
                'razon': razon,
                'analisis_valor': analisis_valor,
                'metodo': 'html_parsing'
            })

        # Meta tags sensibles
        metas_sensibles = soup.find_all('meta', {'name': re.compile(
            r'(csrf|token|nonce|auth|user|session|api)', re.IGNORECASE)})

        for meta in metas_sensibles:
            nombre = meta.get('name', '')
            contenido = meta.get('content', '').strip()

            if contenido and len(contenido) > 5:
                analisis = _analizar_valor_sensible(contenido)
                hallazgos.append({
                    'url': url_origen,
                    'tipo': 'meta_sensible',
                    'nombre_meta': nombre,
                    'contenido': contenido[:100],
                    'longitud': len(contenido),
                    'severidad': 'HIGH',
                    'razon': f'Meta tag con nombre sensible: {nombre}',
                    'analisis_valor': analisis,
                    'metodo': 'html_parsing'
                })

        # Data attributes
        elementos_data = soup.find_all(attrs={'data-token': True})
        elementos_data += soup.find_all(attrs={'data-auth': True})
        elementos_data += soup.find_all(attrs={'data-user': True})
        elementos_data += soup.find_all(attrs={'data-session': True})

        for elemento in elementos_data:
            for attr, valor in elemento.attrs.items():
                if attr.startswith('data-'):
                    if isinstance(valor, str) and len(valor) > 8:
                        analisis = _analizar_valor_sensible(valor)
                        hallazgos.append({
                            'url': url_origen,
                            'tipo': 'data_attribute',
                            'atributo': attr,
                            'valor': valor[:100],
                            'longitud_valor': len(valor),
                            'severidad': 'MEDIUM',
                            'razon': f'Data attribute "{attr}" con valor potencialmente sensible',
                            'analisis_valor': analisis,
                            'metodo': 'html_parsing'
                        })

    except Exception as e:
        print(f"  [ERROR] Parsing HTML sensible: {type(e).__name__}")

    return hallazgos


# ════════════════════════════════════════════════════════════════════════════════
# VULNERABILIDADES (SIN CAMBIOS)
# ════════════════════════════════════════════════════════════════════════════════

def _es_potencial_vulnerabilidad_linea(linea, nombre_patron):
    """Filtro anti-ruido SIMPLE para vulnerabilidades"""
    linea_limpia = linea.strip()

    # Ignorar comentarios
    if linea_limpia.startswith('//') or linea_limpia.startswith('#'):
        return False

    # Ignorar TypeScript types
    if re.search(r':\s*(string|boolean|number|any|void)', linea_limpia):
        return False

    # Ignorar definiciones de tipos/interfaces
    if re.search(r'interface\s+|type\s+|enum\s+', linea_limpia):
        return False

    # Para credenciales: NO si es "password" literal
    if nombre_patron == 'hardcoded_credentials':
        if re.search(r'password\s*[:=]\s*["\']password["\']', linea_limpia):
            return False

    return True


def _deteccion_de_vulnerabilidades(contenido, url_origen, mapa_severidades):
    """Detecta vulnerabilidades críticas - USA SEVERIDADES DE LA BD"""
    vulnerabilidades = []

    for nombre_patron, config in PATRONES_VULNERABILIDADES.items():
        try:
            # ✨ MEJORADO: Usar severidad REAL de la BD
            nivel_recomendado = config['nivel_recomendado']
            severidad_real = _obtener_severidad_real(
                nivel_recomendado, mapa_severidades)

            regex = re.compile(config['patron'], re.IGNORECASE | re.MULTILINE)

            for i, linea in enumerate(contenido.split('\n'), 1):
                linea_limpia = linea.strip()

                if linea_limpia.startswith('//') or linea_limpia.startswith('#'):
                    continue

                if not _es_potencial_vulnerabilidad_linea(linea, nombre_patron):
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


# ════════════════════════════════════════════════════════════════════════════════
# EXTRACCIÓN DE EMAILS HARDCODEADOS (alimenta al handler data_emails / holehe)
# ════════════════════════════════════════════════════════════════════════════════

# Regex de email para contenido descargado (no anclado: busca dentro del texto)
_EMAIL_CONTENIDO_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
# Extensiones que generan falsos positivos (foo@2x.png, sprite@3x.jpg, etc.)
_EMAIL_BASURA_EXT = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.css', '.js', '.ico')


def _extraer_emails_de_contenido(contenido, url_origen, dominios_scope=None):
    """Extrae emails hardcodeados del contenido descargado (HTML o JS).

    Si dominios_scope está dado, marca (no descarta) los del dominio objetivo.
    Devuelve: [{'email', 'url', 'en_scope'}, ...]
    """
    encontrados = []
    vistos = set()
    for m in _EMAIL_CONTENIDO_RE.finditer(contenido or ""):
        email = m.group(0).strip().lower()
        if email in vistos:
            continue
        if email.endswith(_EMAIL_BASURA_EXT):
            continue
        dominio_email = email.split('@')[-1]
        # descartar cosas tipo version@1.2.3 o dominios sin punto / solo numéricos
        if '.' not in dominio_email or dominio_email.replace('.', '').isdigit():
            continue
        vistos.add(email)
        en_scope = bool(dominios_scope) and any(
            dominio_email == d or dominio_email.endswith('.' + d) for d in dominios_scope
        )
        encontrados.append({"email": email, "url": url_origen, "en_scope": en_scope})
    return encontrados


# ════════════════════════════════════════════════════════════════════════════════
# EXTRACCIÓN DE TELÉFONOS (alimenta al handler phone_intelligence)
# ════════════════════════════════════════════════════════════════════════════════

# Región por defecto para interpretar números sin prefijo internacional
_TEL_REGION_DEFAULT = "AR"
_TIPO_TEL = {
    PhoneNumberType.FIXED_LINE: "fijo",
    PhoneNumberType.MOBILE: "movil",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fijo/movil",
    PhoneNumberType.VOIP: "voip",
    PhoneNumberType.TOLL_FREE: "gratuito",
    PhoneNumberType.PREMIUM_RATE: "premium",
    PhoneNumberType.SHARED_COST: "costo_compartido",  # 0810 en Argentina
    PhoneNumberType.UAN: "numero_universal",           # 0800/0810 corporativos
    PhoneNumberType.PERSONAL_NUMBER: "personal",
    PhoneNumberType.PAGER: "pager",
    PhoneNumberType.VOICEMAIL: "voicemail",
}


def _extraer_telefonos_de_contenido(contenido, url_origen, region=_TEL_REGION_DEFAULT):
    """Extrae números de teléfono VÁLIDOS del contenido (HTML o JS) con phonenumbers.

    Usa PhoneNumberMatcher + is_valid_number para evitar los falsos positivos de
    un regex crudo (IDs, fechas, ViewState). Normaliza a E.164 y deduplica.
    Devuelve: [{'telefono': E164, 'tipo': str, 'url': str}, ...]
    """
    encontrados = []
    if not contenido:
        return encontrados
    vistos = set()
    try:
        for match in phonenumbers.PhoneNumberMatcher(contenido, region):
            num = match.number
            if not phonenumbers.is_valid_number(num):
                continue
            # Filtro de calidad: descartar números de tipo desconocido, que son
            # casi siempre secuencias de dígitos que "parecen" teléfono (tracking, IDs)
            tipo_num = phonenumbers.number_type(num)
            if tipo_num == PhoneNumberType.UNKNOWN:
                continue
            e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
            if e164 in vistos:
                continue
            vistos.add(e164)
            encontrados.append({
                "telefono": e164,
                "tipo": _TIPO_TEL.get(tipo_num, "desconocido"),
                "url": url_origen,
            })
    except Exception as e:
        print(f"[_extraer_telefonos] Error en {url_origen}: {type(e).__name__}")
    return encontrados


def _host_de_url(url):
    """Devuelve el host (minúscula) de una URL, o '' si no se puede parsear."""
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _host_en_scope(url, dominios_root, hosts_scope):
    """True si el host de la URL pertenece al scope (dominio raíz, subdominio
    del objetivo o host explícito de la lista de scope)."""
    h = _host_de_url(url)
    if not h:
        return False
    if h in hosts_scope:
        return True
    return any(h == d or h.endswith('.' + d) for d in dominios_root if d)


# ════════════════════════════════════════════════════════════════════════════════
# FUNCIÓN PRINCIPAL - MEJORADA CON IPs + HTML + VALIDACIÓN
# ════════════════════════════════════════════════════════════════════════════════

def sensitive_data_extraction(ejecucion_id, proyecto_id):
    """Extracción de datos sensibles - VERSIÓN MEJORADA"""
    print(
        f"[OSINT-SENSITIVE-DATA] Handler iniciado para ejecución {ejecucion_id}")

    def job():
        severidades = Proyecto.get_severidades()
        mapa_severidades = {sev['nombre']: sev for sev in severidades}

        config = Proyecto.get_osint_config(proyecto_id)
        urls_scope = {}

        # FASE 1: URLs desde SCOPE
        dominio = config.get('DOMINIO', '').strip() if config else ''
        subdominio = config.get('SUBDOMINIO', '').strip() if config else ''
        servicio = config.get('SERVICIOS', '').strip() if config else ''
        ips = config.get('IPS', '').strip() if config else ''  # ✨ NUEVO

        # Dominios
        for dom in _parse_multiline_config(dominio):
            if not _es_ip(dom):
                urls_scope[f"http://{dom}"] = dom
                urls_scope[f"https://{dom}"] = dom

        # Subdominios
        for subdom in _parse_multiline_config(subdominio):
            if not _es_ip(subdom):
                urls_scope[f"http://{subdom}"] = subdom
                urls_scope[f"https://{subdom}"] = subdom

        # Servicios
        for srv in _parse_multiline_config(servicio):
            if not _es_ip(srv):
                if ':' in srv:
                    host, puerto = srv.rsplit(':', 1)
                    protocolo = 'https' if puerto == '443' else 'http'
                    urls_scope[f"{protocolo}://{host}:{puerto}"] = host
                else:
                    urls_scope[f"http://{srv}"] = srv
                    urls_scope[f"https://{srv}"] = srv

        # ✨ NUEVO: Procesar IPs
        if ips:
            urls_ips = _procesar_ips_scope(ips)
            urls_scope.update(urls_ips)

        # FASE 2: ✨ MEJORADO - Agregar Discovery Subdominios + evitar duplicados
        urls_fase2 = {}
        subdominios_scope = set()

        # Recolectar dominios/subdominios ya en scope (para evitar duplicados)
        for url in urls_scope.keys():
            # Extraer dominio de "http://ejemplo.com" o "https://ejemplo.com"
            if "://" in url:
                # Quita protocolo y puerto
                dominio_part = url.split("://", 1)[1].split(":")[0]
                subdominios_scope.add(dominio_part.lower())

        try:
            subdominios_desc = OsintEjecucion.get_discovered_subdomains(
                proyecto_id)
            if subdominios_desc:
                for subdom in subdominios_desc[:20]:
                    subdom_lower = subdom.lower()

                    # ✨ NUEVO: Solo agregar si NO existe en scope
                    if subdom_lower not in subdominios_scope:
                        urls_fase2[f"http://{subdom}"] = subdom
                        urls_fase2[f"https://{subdom}"] = subdom
                        print(
                            f"[sensitive_data] Discovery subdominio agregado: {subdom}")
                    else:
                        print(
                            f"[sensitive_data] Subdominio ya en scope, omitido: {subdom}")
        except Exception as e:
            print(
                f"[sensitive_data] Error al obtener subdominios descubiertos: {type(e).__name__}")

        # Merge: Scope (FASE 1) + Discovery (FASE 2) sin duplicados
        # Prioridad: scope (se agrega primero)
        todas_las_urls = {**urls_scope, **urls_fase2}
        fase_usada = 'FASE 1+2' if urls_fase2 else 'FASE 1'

        if not todas_las_urls:
            raise Exception("No hay URLs")

        print(
            f"[sensitive_data] Total URLs: {len(todas_las_urls)} ({fase_usada})")

        # ⚠️ LÍMITE: máx 200 URLs (aumentado para cobertura completa: IPs + puertos + subdominios)
        urls_a_analizar = list(todas_las_urls.keys())[:200]
        urls_a_analizar = [url for url in urls_a_analizar
                           if '.min.js' not in url.lower()]

        print(
            f"[sensitive_data] URLs después de filtrar minificados: {len(urls_a_analizar)}")

        hallazgos_secretos = {}
        hallazgos_vulnerabilidades = {}
        hallazgos_html_sensibles = {}  # ✨ NUEVO
        hallazgos_emails = {}  # ✨ NUEVO: emails hardcodeados por URL
        hallazgos_telefonos = {}  # ✨ NUEVO: teléfonos por URL
        total_telefonos = 0  # ✨ NUEVO
        total_secretos = 0
        total_vulnerabilidades = 0
        total_html_sensibles = 0  # ✨ NUEVO
        total_emails = 0  # ✨ NUEVO
        # Dominios raíz del scope para marcar emails institucionales
        dominios_scope_email = [d.lower() for d in _parse_multiline_config(dominio)] if dominio else []
        # Hosts del scope (todas las URLs que vamos a analizar SON del scope):
        # se usa para NO minar teléfonos/emails de JS de terceros (google, CDNs, etc.)
        hosts_scope = set()
        for _u in urls_a_analizar:
            _h = _host_de_url(_u)
            if _h:
                hosts_scope.add(_h)

        for url in urls_a_analizar:
            try:
                print(f"[sensitive_data] Analizando: {url}")

                # DESCARGA con timeout + límite de tamaño
                try:
                    response = requests.get(
                        url,
                        timeout=10,
                        verify=False,
                        allow_redirects=True,
                        headers={'User-Agent': 'Mozilla/5.0'},
                        stream=True
                    )

                    # ⚠️ LÍMITE DE TAMAÑO: máx 5MB
                    if int(response.headers.get('content-length', 0)) > 5242880:
                        print(f"[sensitive_data] SKIP {url} (>5MB)")
                        continue

                    response.raise_for_status()
                    contenido = response.content[:5242880].decode(
                        'utf-8', errors='ignore')

                    # ✨ MEJORADO: Capturar URL final después de redirects
                    final_url = response.url
                    if final_url != url:
                        print(
                            f"[sensitive_data] Redirigido: {url} → {final_url}")

                except requests.Timeout:
                    print(f"[sensitive_data] TIMEOUT {url}")
                    continue
                except requests.RequestException as e:
                    print(f"[sensitive_data] ERROR {url}: {type(e).__name__}")
                    continue

                try:
                    soup = BeautifulSoup(contenido, 'html.parser')

                    # ✨ NUEVO: Análisis de elementos HTML sensibles
                    # Usar final_url (la URL después de redirects) para reportar hallazgos
                    elementos_sensibles = _buscar_inputs_hidden(
                        contenido, final_url)
                    if elementos_sensibles:
                        hallazgos_html_sensibles[final_url] = elementos_sensibles
                        total_html_sensibles += len(elementos_sensibles)
                        print(
                            f"  [HALLAZGO] {len(elementos_sensibles)} elementos HTML sensibles")

                    # ✨ NUEVO: extraer emails hardcodeados del HTML
                    emails_html = _extraer_emails_de_contenido(
                        contenido, final_url, dominios_scope_email)
                    if emails_html:
                        hallazgos_emails[final_url] = emails_html
                        total_emails += len(emails_html)
                        print(f"  [HALLAZGO] {len(emails_html)} emails en HTML")

                    # ✨ NUEVO: extraer teléfonos del HTML
                    telefonos_html = _extraer_telefonos_de_contenido(contenido, final_url)
                    if telefonos_html:
                        hallazgos_telefonos[final_url] = telefonos_html
                        total_telefonos += len(telefonos_html)
                        print(f"  [HALLAZGO] {len(telefonos_html)} teléfonos en HTML")

                    # Scripts externos - ⚠️ LÍMITE: 5 scripts por URL
                    for script in soup.find_all('script', src=True)[:5]:
                        js_url = script['src']

                        # ✅ MEJORADO: Chequear .min en cualquier parte
                        if '.min.js' in js_url.lower():
                            print(f"  [SKIP] {js_url} (minificado)")
                            continue

                        if not js_url.startswith('http'):
                            js_url = urljoin(final_url, js_url)

                        try:
                            js_response = requests.get(
                                js_url,
                                timeout=10,
                                verify=False,
                                headers={'User-Agent': 'Mozilla/5.0'},
                                stream=True
                            )

                            # ⚠️ LÍMITE: máx 5MB por script
                            if int(js_response.headers.get('content-length', 0)) > 5242880:
                                continue

                            js_response.raise_for_status()
                            js_contenido = js_response.content[:5242880].decode(
                                'utf-8', errors='ignore')

                            # ✨ Emails/teléfonos SOLO de JS del scope (no de terceros: google, CDNs)
                            js_en_scope = _host_en_scope(js_url, dominios_scope_email, hosts_scope)
                            if not js_en_scope:
                                print(f"  [SKIP PII] {js_url} (JS de tercero, fuera de scope)")

                            if js_en_scope:
                                # ✨ NUEVO: extraer emails hardcodeados del JS
                                emails_js = _extraer_emails_de_contenido(
                                    js_contenido, js_url, dominios_scope_email)
                                if emails_js:
                                    hallazgos_emails.setdefault(js_url, []).extend(emails_js)
                                    total_emails += len(emails_js)

                                # ✨ NUEVO: extraer teléfonos del JS
                                telefonos_js = _extraer_telefonos_de_contenido(js_contenido, js_url)
                                if telefonos_js:
                                    hallazgos_telefonos.setdefault(js_url, []).extend(telefonos_js)
                                    total_telefonos += len(telefonos_js)

                            secretos = _buscar_secretos_en_contenido(
                                js_contenido, js_url)
                            total_secretos += len(secretos)
                            if secretos:
                                hallazgos_secretos[js_url] = secretos

                            vulnerabilidades = _deteccion_de_vulnerabilidades(
                                js_contenido, js_url, mapa_severidades)
                            total_vulnerabilidades += len(vulnerabilidades)
                            if vulnerabilidades:
                                hallazgos_vulnerabilidades[js_url] = vulnerabilidades

                        except requests.Timeout:
                            print(f"  [TIMEOUT] {js_url}")
                        except Exception as e:
                            print(f"  [ERROR] {js_url}: {type(e).__name__}")

                    # Scripts inline - ⚠️ LÍMITE: 10 inline scripts
                    for i, script in enumerate(soup.find_all('script')[:10]):
                        if not script.get('src') and script.string:
                            contenido_inline = script.string.strip()
                            if len(contenido_inline) > 50:
                                # ✨ MEJORADO: Usar final_url (después de redirects)
                                inline_url = f"{final_url}#inline-{i}"
                                secretos = _buscar_secretos_en_contenido(
                                    contenido_inline, inline_url)
                                if secretos:
                                    hallazgos_secretos[inline_url] = secretos
                                    total_secretos += len(secretos)

                                vulnerabilidades = _deteccion_de_vulnerabilidades(
                                    contenido_inline, inline_url, mapa_severidades)
                                if vulnerabilidades:
                                    hallazgos_vulnerabilidades[inline_url] = vulnerabilidades
                                    total_vulnerabilidades += len(
                                        vulnerabilidades)

                except Exception as e:
                    print(f"  [WARN] Parsing {url}: {type(e).__name__}")

            except Exception as e:
                print(f"[sensitive_data] Error {url}: {str(e)[:60]}")
                continue

        # RESULTADOS
        vulnerabilidades_por_severidad = {}
        for severidad in severidades:
            nombre_sev = severidad['nombre']
            count = len([v for vv in hallazgos_vulnerabilidades.values()
                        for v in vv if v.get('severidad') == nombre_sev])
            vulnerabilidades_por_severidad[nombre_sev] = count

        return {
            "tipo": "sensitive_data_extraction",
            "fase_usada": fase_usada,
            "total_urls_analizadas": len(urls_a_analizar),
            "total_secretos_encontrados": total_secretos,
            "total_vulnerabilidades_encontrados": total_vulnerabilidades,
            "total_html_sensibles_encontrados": total_html_sensibles,  # ✨ NUEVO
            "total_emails_encontrados": total_emails,  # ✨ NUEVO
            "total_telefonos_encontrados": total_telefonos,  # ✨ NUEVO
            "secretos": hallazgos_secretos,
            "vulnerabilidades": hallazgos_vulnerabilidades,
            "elementos_html_sensibles": hallazgos_html_sensibles,  # ✨ NUEVO
            "emails_encontrados": hallazgos_emails,  # ✨ NUEVO
            "telefonos_encontrados": hallazgos_telefonos,  # ✨ NUEVO
            "resumen": {
                "vulnerabilidades_por_severidad": vulnerabilidades_por_severidad,
                "tipos_html_sensibles": {  # ✨ NUEVO
                    'hidden_input': len([h for hh in hallazgos_html_sensibles.values() for h in hh if h.get('tipo') == 'hidden_input']),
                    'meta_sensible': len([h for hh in hallazgos_html_sensibles.values() for h in hh if h.get('tipo') == 'meta_sensible']),
                    'data_attribute': len([h for hh in hallazgos_html_sensibles.values() for h in hh if h.get('tipo') == 'data_attribute']),
                }
            }
        }

    try:
        return _run_osint_job(ejecucion_id, job)
    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        print(f"[OSINT-SENSITIVE-DATA] ERROR: {error_msg}")
        try:
            OsintEjecucion.mark_failed(ejecucion_id, error_msg)
        except:
            pass
        raise


# ══════════════════════════════════════════════════════════════════
# HANDLER DATA EMAILS
# ══════════════════════════════════════════════════════════════════
# Regex simple de validación de email
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
# Fuentes de theHarvester que NO requieren API key de pago
_THEHARVESTER_SOURCES = "crtsh,duckduckgo,yahoo,mojeek,rapiddns,otx,urlscan,certspotter,hackertarget,waybackarchive"
# Patrón de dominio/subdominio válido (descarta basura tipo entradas con Markdown)
_DOM_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")
# Tope de emails a verificar con holehe (holehe consulta ~120 sitios por email)
_HOLEHE_MAX_EMAILS = 40
def _harvest_emails(objetivo):
    """Corre theHarvester sobre un dominio/subdominio y devuelve lista de emails.

    Devuelve: [{'email': str, 'origen': objetivo, 'fuente': 'theHarvester'}, ...]
    """
    resultados = []
    tmp_path = None
    try:
        # theHarvester guarda en <archivo>.json
        fd, tmp_base = tempfile.mkstemp(prefix="th_", suffix="")
        os.close(fd)
        tmp_path = tmp_base + ".json"

        cmd = [
            "theHarvester",
            "-d", objetivo,
            "-b", _THEHARVESTER_SOURCES,
            "-f", tmp_base,
        ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
        # theHarvester devuelve rc=1 aunque una sola fuente falle (rate limit, etc.);
        # por eso NO se corta por returncode: si el JSON existe, se lee igual.
        if os.path.exists(tmp_path):
            with open(tmp_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            for email in data.get("emails", []) or []:
                email = email.strip().lower()
                if _EMAIL_RE.match(email):
                    resultados.append({
                        "email": email,
                        "origen": objetivo,
                        "fuente": "theHarvester",
                    })
        else:
            # Sin archivo = falla real; theHarvester escribe el error por stdout
            salida = (proc.stdout or "")[-300:] + " " + (proc.stderr or "")[-100:]
            print(f"[_harvest_emails] Sin salida para {objetivo} (rc={proc.returncode}): {salida.strip()}")
    except subprocess.TimeoutExpired:
        print(f"[_harvest_emails] Timeout en theHarvester para {objetivo}")
    except Exception as e:
        print(f"[_harvest_emails] Error en {objetivo}: {e}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        # theHarvester a veces también crea .xml
        xml_path = (tmp_path[:-5] + ".xml") if tmp_path else None
        if xml_path and os.path.exists(xml_path):
            try:
                os.remove(xml_path)
            except OSError:
                pass

    return resultados


def _deduplicate_emails(hallazgos_raw, objetivos):
    """Normaliza, valida y deduplica emails por dirección, agrupando orígenes/fuentes."""
    dedup = {}
    for h in hallazgos_raw:
        email = h.get("email", "").strip().lower()
        if not email or not _EMAIL_RE.match(email):
            continue
        if email not in dedup:
            dedup[email] = {
                "email": email,
                "origenes": set(),
                "fuentes": set(),
            }
        if h.get("origen"):
            dedup[email]["origenes"].add(h["origen"])
        if h.get("fuente"):
            dedup[email]["fuentes"].add(h["fuente"])

    # Convertir sets a listas para que sea serializable (JSON)
    salida = []
    for e in dedup.values():
        salida.append({
            "email": e["email"],
            "origenes": sorted(e["origenes"]),
            "fuentes": sorted(e["fuentes"]),
        })
    return salida


# Códigos de color ANSI (holehe colorea los marcadores [+]/[-]/[x])
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _holehe_lookup(email):
    """Ejecuta holehe sobre un email y devuelve los servicios donde está registrado."""
    servicios = []
    try:
        # Nota: no se usa --no-color porque no existe en todas las versiones de holehe
        # y haría fallar el proceso; en su lugar se filtran los códigos ANSI del stdout.
        cmd = ["holehe", "--only-used", email]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=180
        )
        for linea in proc.stdout.splitlines():
            linea = _ANSI_RE.sub("", linea).strip()
            # holehe marca los servicios con cuenta como: [+] servicio.com
            if linea.startswith("[+]"):
                servicio = linea[3:].strip()
                # Excluir la línea de leyenda "[+] Email used, [-] ..." y cualquier
                # cosa que no sea un dominio (los servicios reales no llevan espacios ni comas)
                if servicio and " " not in servicio and "," not in servicio:
                    servicios.append(servicio)
    except subprocess.TimeoutExpired:
        print(f"[_holehe_lookup] Timeout en holehe para {email}")
    except FileNotFoundError:
        print(f"[_holehe_lookup] holehe no está instalado / no está en el PATH")
    except Exception as e:
        print(f"[_holehe_lookup] Error con {email}: {e}")
    return servicios

def data_emails(ejecucion_id, proyecto_id):
    """Recolección de emails por dominio/subdominio + verificación con holehe.

    Scope inicial: dominios y subdominios de la configuración del proyecto.
    Fallback: subdominios descubiertos (discovery_subdominios).
    """
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio_scope = config.get('DOMINIO', '').strip() if config else ''
        subdominio_scope = config.get('SUBDOMINIO', '').strip() if config else ''

        # 1. Dominios y subdominios del scope inicial
        dominios_config = _parse_multiline_config(dominio_scope) if dominio_scope else []
        subdominios_config = _parse_multiline_config(subdominio_scope) if subdominio_scope else []

        if dominios_config:
            print(f"[discovery_email] Dominios del scope: {dominios_config}")
        if subdominios_config:
            print(f"[discovery_email] Subdominios del scope: {subdominios_config}")

        # 2. FALLBACK: subdominios descubiertos (solo si el scope no trae subdominios)
        subdominios_fallback = []
        if not subdominios_config:
            subdominios_fallback = OsintEjecucion.get_discovered_subdomains(proyecto_id)
            if subdominios_fallback:
                print(f"[discovery_email] Fallback a discovery_subdominios: {len(subdominios_fallback)} subdominios")
            else:
                print(f"[discovery_email] Sin subdominios en scope ni descubiertos")

        # 3. Consolidar y SANITIZAR objetivos (descarta entradas mal formadas)
        objetivos = list(set(dominios_config + subdominios_config + subdominios_fallback))
        objetivos_validos = [o.strip().lower() for o in objetivos if _DOM_RE.match(o.strip().lower())]
        descartados = [o for o in objetivos if o.strip().lower() not in objetivos_validos]
        if descartados:
            print(f"[discovery_email] Objetivos descartados por formato inválido: {descartados}")
        objetivos = objetivos_validos

        if not objetivos:
            raise Exception("No hay dominios ni subdominios válidos para buscar emails")

        # Dominios raíz del scope (para marcar emails institucionales / priorizar holehe)
        dominios_scope_email = [d.strip().lower() for d in dominios_config if d.strip()]

        print(f"[discovery_email] Objetivos a analizar: {len(objetivos)}")

        # 4a. Recolección con theHarvester por cada objetivo
        emails_raw = []
        total_obj = len(objetivos)
        for i, obj in enumerate(objetivos, 1):
            print(f"[discovery_email] [{i}/{total_obj}] theHarvester sobre {obj} ...")
            encontrados = _harvest_emails(obj)
            if encontrados:
                print(f"[discovery_email] [{i}/{total_obj}] {obj}: {len(encontrados)} emails")
            emails_raw.extend(encontrados)

        # 4b. Fusionar emails hardcodeados extraídos por Sensitive Data Extraction
        emails_sensitive = []
        try:
            # solo_scope=True: solo correos del dominio objetivo, para descartar
            # el ruido de librerías JS (autores tipo @google.com, @mozilla.org, etc.)
            emails_sensitive = OsintEjecucion.get_discovered_emails(proyecto_id, solo_scope=True)
        except Exception as e:
            print(f"[discovery_email] No se pudieron leer emails de sensitive_data: {type(e).__name__}: {e}")
        if emails_sensitive:
            print(f"[discovery_email] Emails de Sensitive Data Extraction: {len(emails_sensitive)}")
            for em in emails_sensitive:
                emails_raw.append({
                    "email": em,
                    "origen": "sensitive_data",
                    "fuente": "sensitive_data_extraction",
                })

        emails_dedup = _deduplicate_emails(emails_raw, objetivos)

        # 5. Enriquecimiento con holehe. Se prioriza a los emails del dominio objetivo
        #    (institucionales) y se aplica un tope para no disparar cientos de consultas.
        def _es_institucional(email):
            dom = email.split("@")[-1]
            return any(dom == d or dom.endswith("." + d) for d in dominios_scope_email)

        emails_ordenados = sorted(
            emails_dedup, key=lambda e: (not _es_institucional(e["email"]), e["email"])
        )

        print(f"[discovery_email] Emails únicos: {len(emails_dedup)}. Verificando con holehe...")
        verificados = 0
        for e in emails_ordenados:
            if verificados < _HOLEHE_MAX_EMAILS:
                print(f"[discovery_email] holehe [{verificados + 1}] {e['email']} ...")
                e['servicios_registrados'] = _holehe_lookup(e['email'])
                verificados += 1
            else:
                e['servicios_registrados'] = []
                e['holehe_omitido'] = True
        if len(emails_dedup) > _HOLEHE_MAX_EMAILS:
            print(f"[discovery_email] holehe limitado a {_HOLEHE_MAX_EMAILS} de {len(emails_dedup)} emails")

        return {
            "tipo": "discovery_email",
            "dominio_scope": dominio_scope,
            "subdominio_scope": subdominio_scope,
            "total_dominios_scope": len(dominios_config),
            "total_subdominios_scope": len(subdominios_config),
            "total_subdominios_fallback": len(subdominios_fallback),
            "total_objetivos": len(objetivos),
            "total_emails_theharvester": len([1 for h in emails_raw if h.get("fuente") == "theHarvester"]),
            "total_emails_sensitive_data": len(emails_sensitive),
            "total_emails_unicos": len(emails_dedup),
            "total_emails_verificados_holehe": verificados,
            "emails": emails_ordenados
        }

    return _run_osint_job(ejecucion_id, job)


# ══════════════════════════════════════════════════════════════════
# HANDLER PHONE INTELLIGENCE
# ══════════════════════════════════════════════════════════════════
# Tope de números a enriquecer (evita corridas eternas si hay muchos)
_PHONE_MAX = 40


def _enriquecer_telefono(e164, region=_TEL_REGION_DEFAULT):
    """Enriquece un número (E.164) con datos de phonenumbers + links OSINT.

    Devuelve: pais, operador, tipo, zona horaria, ubicación y URLs de investigación.
    """
    info = {
        "telefono": e164,
        "valido": False,
        "pais_iso": None,
        "codigo_pais": None,
        "operador": None,
        "tipo": "desconocido",
        "ubicacion": None,
        "zonas_horarias": [],
        "osint_links": {},
    }
    try:
        num = phonenumbers.parse(e164, region)
        info["valido"] = phonenumbers.is_valid_number(num)
        info["codigo_pais"] = num.country_code
        info["pais_iso"] = phonenumbers.region_code_for_number(num)
        info["operador"] = carrier.name_for_number(num, "es") or None
        info["ubicacion"] = geocoder.description_for_number(num, "es") or None
        info["zonas_horarias"] = list(timezone.time_zones_for_number(num))
        info["tipo"] = _TIPO_TEL.get(phonenumbers.number_type(num), "desconocido")

        # Links OSINT para investigación manual (sin consultar nada de pago)
        sin_mas = e164.lstrip("+")
        info["osint_links"] = {
            "google": f"https://www.google.com/search?q=%22{e164}%22",
            "whatsapp": f"https://wa.me/{sin_mas}",
            "truecaller": f"https://www.truecaller.com/search/{(info['pais_iso'] or 'ar').lower()}/{sin_mas}",
            "sync_me": f"https://sync.me/search/?number={sin_mas}",
        }
    except Exception as e:
        print(f"[_enriquecer_telefono] Error con {e164}: {type(e).__name__}")
    return info


def _phoneinfoga_lookup(e164):
    """Best-effort: corre PhoneInfoga si está instalado y devuelve su salida cruda.

    PhoneInfoga v2 no exporta JSON limpio por CLI, así que se captura el texto.
    Si el binario no está, se omite sin romper el handler.
    """
    try:
        proc = subprocess.run(
            ["phoneinfoga", "scan", "-n", e164],
            capture_output=True, text=True, timeout=120
        )
        salida = (proc.stdout or "").strip()
        return salida[:4000] if salida else None
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        print(f"[_phoneinfoga_lookup] Timeout con {e164}")
        return None
    except Exception as e:
        print(f"[_phoneinfoga_lookup] Error con {e164}: {type(e).__name__}")
        return None


def phone_intelligence(ejecucion_id, proyecto_id):
    """Inteligencia de teléfonos: lee los números extraídos por Sensitive Data
    Extraction y los enriquece (país, operador, tipo, links OSINT) + PhoneInfoga
    si está disponible.
    """
    def job():
        # 1. Números descubiertos por Sensitive Data Extraction
        telefonos = OsintEjecucion.get_discovered_phones(proyecto_id)
        if not telefonos:
            raise Exception("No hay teléfonos para analizar (ejecutá primero Sensitive Data Extraction)")

        print(f"[phone_intelligence] Teléfonos a analizar: {len(telefonos)}")

        # 2. ¿Está PhoneInfoga disponible? (se chequea una vez)
        phoneinfoga_ok = False
        try:
            chk = subprocess.run(["phoneinfoga", "version"], capture_output=True, text=True, timeout=20)
            phoneinfoga_ok = (chk.returncode == 0)
        except Exception:
            phoneinfoga_ok = False
        print(f"[phone_intelligence] PhoneInfoga disponible: {phoneinfoga_ok}")

        resultados = []
        analizados = 0
        for item in telefonos:
            # item = {'telefono': E164, 'origenes': [url, ...]}
            tel = item.get("telefono") if isinstance(item, dict) else str(item)
            origenes = item.get("origenes", []) if isinstance(item, dict) else []
            # Dominios de origen (para relacionar con el cliente/objetivo)
            dominios_origen = sorted({_host_de_url(u) for u in origenes if _host_de_url(u)})
            if analizados >= _PHONE_MAX:
                resultados.append({"telefono": tel, "origenes": origenes,
                                   "dominios_origen": dominios_origen,
                                   "analizado": False, "motivo": "tope alcanzado"})
                continue
            print(f"[phone_intelligence] [{analizados + 1}] {tel} ...")
            info = _enriquecer_telefono(tel)
            info["origenes"] = origenes
            info["dominios_origen"] = dominios_origen
            if phoneinfoga_ok:
                info["phoneinfoga"] = _phoneinfoga_lookup(tel)
            resultados.append(info)
            analizados += 1

        return {
            "tipo": "phone_intelligence",
            "total_telefonos": len(telefonos),
            "total_analizados": analizados,
            "phoneinfoga_disponible": phoneinfoga_ok,
            "telefonos": resultados,
        }

    return _run_osint_job(ejecucion_id, job)


# ══════════════════════════════════════════════════════════════════
# HANDLER DOCUMENT METADATA
# ══════════════════════════════════════════════════════════════════
import hashlib

# Extensiones de documentos/imágenes con metadata útil
_METADATA_EXTS = (
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.odt', '.ods', '.odp', '.rtf', '.jpg', '.jpeg', '.png', '.tiff', '.tif',
)

# Carpeta base para las descargas, relativa al repo (portable Win/Linux):
# <repo_root>/data/osint/documentosMetadata
_METADATA_BASE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "osint", "documentosMetadata"
)

# Campos de exiftool que interesan (todo lo demás es ruido)
_EXIF_CAMPOS_UTILES = [
    "Author", "Creator", "LastModifiedBy", "Company", "Manager",
    "Producer", "CreatorTool", "Software", "Application",
    "Title", "Subject", "Keywords", "Description", "Comment",
    "CreateDate", "ModifyDate", "MetadataDate",
    "GPSLatitude", "GPSLongitude", "GPSPosition", "GPSAltitude",
    "Make", "Model",
]
_EXIF_CAMPOS_AUTOR = ["Author", "Creator", "LastModifiedBy"]
_EXIF_CAMPOS_SOFTWARE = ["Producer", "CreatorTool", "Software", "Application"]

_METADATA_MAX_ARCHIVOS = 150
_METADATA_MAX_BYTES = 20 * 1024 * 1024  # 20 MB por archivo
# Rutas embebidas que revelan usuario del sistema (Windows/Unix)
_RUTA_USUARIO_RE = re.compile(r"(?:[A-Za-z]:\\Users\\|/Users/|/home/)([^\\/\s\"']{1,40})")


def _descargar_archivo(url, destino):
    """Descarga un archivo a 'destino' con límite de tamaño/timeout. True si OK."""
    try:
        resp = requests.get(url, timeout=20, verify=False, stream=True,
                            headers={'User-Agent': 'Mozilla/5.0'})
        resp.raise_for_status()
        cl = int(resp.headers.get('content-length', 0) or 0)
        if cl and cl > _METADATA_MAX_BYTES:
            return False
        escrito = 0
        with open(destino, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                escrito += len(chunk)
                if escrito > _METADATA_MAX_BYTES:
                    break
                f.write(chunk)
        if escrito == 0 or escrito > _METADATA_MAX_BYTES:
            if os.path.exists(destino):
                os.remove(destino)
            return False
        return True
    except Exception as e:
        print(f"[document_metadata] Error descargando {url}: {type(e).__name__}")
        try:
            if os.path.exists(destino):
                os.remove(destino)
        except OSError:
            pass
        return False


def _correr_exiftool(carpeta):
    """Corre exiftool -json sobre toda la carpeta. Devuelve (lista_dicts, disponible)."""
    try:
        proc = subprocess.run(
            ["exiftool", "-json", carpeta],
            capture_output=True, text=True, timeout=300
        )
        if proc.stdout.strip():
            return json.loads(proc.stdout), True
        return [], True
    except FileNotFoundError:
        print("[document_metadata] exiftool no está instalado / no está en el PATH")
        return [], False
    except subprocess.TimeoutExpired:
        print("[document_metadata] Timeout en exiftool")
        return [], True
    except Exception as e:
        print(f"[document_metadata] Error en exiftool: {type(e).__name__}: {e}")
        return [], True


def _decodificar_valor(val):
    """Decodifica cadenas UTF-16 que exiftool deja escapadas en octal (\\376\\377...).

    Ej: '\\376\\377\\000i\\000s...' -> 'is12133312'. Si no es UTF-16, devuelve el valor tal cual.
    """
    if not isinstance(val, str) or '\\' not in val:
        return val
    try:
        out = bytearray()
        i, n = 0, len(val)
        while i < n:
            if val[i] == '\\' and i + 3 < n + 1 and val[i+1:i+4].isdigit() and len(val[i+1:i+4]) == 3:
                out.append(int(val[i+1:i+4], 8) & 0xFF)
                i += 4
            else:
                out.append(ord(val[i]) & 0xFF)
                i += 1
        b = bytes(out)
        if b[:2] == b'\xfe\xff':
            return b.decode('utf-16-be').lstrip('﻿').strip()
        if b[:2] == b'\xff\xfe':
            return b.decode('utf-16-le').lstrip('﻿').strip()
    except Exception:
        pass
    return val


def _curar_metadata(raw_item):
    """Filtra un dict crudo de exiftool a los campos útiles + usuarios de rutas."""
    curado = {}
    for campo in _EXIF_CAMPOS_UTILES:
        val = raw_item.get(campo)
        if val not in (None, "", []):
            curado[campo] = val
    usuarios = set()
    for v in raw_item.values():
        if isinstance(v, str):
            for m in _RUTA_USUARIO_RE.finditer(v):
                usuarios.add(m.group(1))
    if usuarios:
        curado["usuarios_en_rutas"] = sorted(usuarios)
    return curado


def document_metadata(ejecucion_id, proyecto_id):
    """Extrae metadatos de documentos públicos (autores, usuarios, software, GPS).

    Fuente: URLs Historicas (servicio 9). Descarga los documentos a una carpeta
    hash, corre exiftool y devuelve un resumen curado (sin el ruido de exiftool).
    El crudo completo queda en <carpeta>/metadata.json.
    """
    def job():
        # 1. URLs de URLs Historicas, filtradas a documentos/imágenes
        urls = OsintEjecucion.get_discovered_urls(proyecto_id)
        docs = []
        vistos = set()
        for u in urls:
            base = u.split('?', 1)[0].split('#', 1)[0].lower()
            if base.endswith(_METADATA_EXTS) and u not in vistos:
                vistos.add(u)
                docs.append(u)
        if not docs:
            raise Exception("No hay documentos en URLs Historicas (ejecutá primero URLs Historicas)")
        docs = docs[:_METADATA_MAX_ARCHIVOS]
        print(f"[document_metadata] Documentos candidatos: {len(docs)}")

        # 2. Crear carpeta hash y registrarla en osint_ejecuciones_carpeta
        sello = f"{proyecto_id}-{ejecucion_id}-{datetime.now().isoformat()}"
        hash_carpeta = hashlib.sha1(sello.encode()).hexdigest()[:16]
        carpeta = os.path.join(_METADATA_BASE_PATH, hash_carpeta)
        os.makedirs(carpeta, exist_ok=True)
        OsintEjecucion.registrar_carpeta(ejecucion_id, hash_carpeta)
        print(f"[document_metadata] Carpeta: {carpeta}")

        # 3. Descargar
        descargados = []  # (nombre_local, url)
        for i, url in enumerate(docs):
            ext = os.path.splitext(url.split('?', 1)[0])[1][:10].lower() or ".bin"
            nombre_local = f"{i:03d}{ext}"
            destino = os.path.join(carpeta, nombre_local)
            print(f"[document_metadata] [{i+1}/{len(docs)}] descargando {url}")
            if _descargar_archivo(url, destino):
                descargados.append((nombre_local, url))
        print(f"[document_metadata] Descargados: {len(descargados)}")

        if not descargados:
            return {
                "tipo": "document_metadata",
                "carpeta": hash_carpeta,
                "total_candidatos": len(docs),
                "total_descargados": 0,
                "exiftool_disponible": None,
                "total_documentos_con_metadata": 0,
                "resumen": {"autores": [], "usuarios": [], "software": [], "con_gps": 0},
                "documentos": [],
            }

        # 4. exiftool sobre toda la carpeta
        raw, exif_ok = _correr_exiftool(carpeta)

        # 4a. Normalizar: decodificar cadenas UTF-16 escapadas por exiftool
        for item in raw:
            for k, v in list(item.items()):
                if isinstance(v, str):
                    item[k] = _decodificar_valor(v)

        # 4b. Guardar el crudo completo como respaldo en la carpeta
        try:
            with open(os.path.join(carpeta, "metadata.json"), "w", encoding="utf-8") as f:
                json.dump(raw, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            print(f"[document_metadata] No se pudo guardar metadata.json: {type(e).__name__}")

        # 5. Curar + mapear cada item a su URL de origen
        mapa_local_url = {nl: u for nl, u in descargados}
        documentos = []
        autores, usuarios, software = set(), set(), set()
        con_gps = 0
        for item in raw:
            src = os.path.basename(item.get("SourceFile", ""))
            curado = _curar_metadata(item)
            if not curado:
                continue
            for c in _EXIF_CAMPOS_AUTOR:
                if item.get(c):
                    autores.add(str(item[c]).strip())
            for c in _EXIF_CAMPOS_SOFTWARE:
                if item.get(c):
                    software.add(str(item[c]).strip())
            for us in curado.get("usuarios_en_rutas", []):
                usuarios.add(us)
            if any(k.startswith("GPS") for k in curado):
                con_gps += 1
            documentos.append({
                "url": mapa_local_url.get(src, src),
                "archivo": src,
                "metadata": curado,
            })

        print(f"[document_metadata] Documentos con metadata: {len(documentos)} | autores: {len(autores)} | usuarios: {len(usuarios)}")

        return {
            "tipo": "document_metadata",
            "carpeta": hash_carpeta,
            "total_candidatos": len(docs),
            "total_descargados": len(descargados),
            "exiftool_disponible": exif_ok,
            "total_documentos_con_metadata": len(documentos),
            "resumen": {
                "autores": sorted(autores),
                "usuarios": sorted(usuarios),
                "software": sorted(software),
                "con_gps": con_gps,
            },
            "documentos": documentos,
        }

    return _run_osint_job(ejecucion_id, job)


# ══════════════════════════════════════════════════════════════════
# HANDLER USERNAME ENUMERATION (Sherlock)
# ══════════════════════════════════════════════════════════════════
import shutil

# Tope de usernames a verificar (Sherlock consulta cientos de sitios por handle)
_USERNAME_MAX = 30


def _sherlock_lookup(username):
    """Corre Sherlock sobre un username y devuelve los perfiles encontrados.

    Devuelve: [{'sitio': str, 'url': str}, ...]
    """
    perfiles = []
    tmpdir = tempfile.mkdtemp(prefix="sherlock_")
    try:
        proc = subprocess.run(
            ["sherlock", username, "--print-found", "--no-color", "--timeout", "10"],
            capture_output=True, text=True, timeout=300, cwd=tmpdir
        )
        for linea in proc.stdout.splitlines():
            linea = _ANSI_RE.sub("", linea).strip()
            # formato: [+] Sitio: https://url
            if linea.startswith("[+]"):
                resto = linea[3:].strip()
                if ":" in resto:
                    sitio, url = resto.split(":", 1)
                    sitio, url = sitio.strip(), url.strip()
                    if url.startswith("http"):
                        perfiles.append({"sitio": sitio, "url": url})
    except subprocess.TimeoutExpired:
        print(f"[_sherlock_lookup] Timeout con {username}")
    except FileNotFoundError:
        print(f"[_sherlock_lookup] sherlock no está instalado / no está en el PATH")
    except Exception as e:
        print(f"[_sherlock_lookup] Error con {username}: {type(e).__name__}: {e}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return perfiles


def username_enumeration(ejecucion_id, proyecto_id):
    """Enumeración de usernames en plataformas online con Sherlock.

    Toma los usernames candidatos (Document Metadata + Data Emails) y por cada uno
    verifica en qué sitios existe una cuenta con ese handle.
    """
    def job():
        candidatos = OsintEjecucion.get_discovered_usernames(proyecto_id)
        if not candidatos:
            raise Exception("No hay usernames para analizar (ejecutá antes Document Metadata y/o Data Emails)")

        print(f"[username_enumeration] Usernames a analizar: {len(candidatos)}")

        # ¿Está Sherlock disponible?
        sherlock_ok = shutil.which("sherlock") is not None
        print(f"[username_enumeration] Sherlock disponible: {sherlock_ok}")
        if not sherlock_ok:
            raise Exception("Sherlock no está instalado en el worker (pip install sherlock-project)")

        resultados = []
        analizados = 0
        for c in candidatos:
            username = c.get("username")
            if analizados >= _USERNAME_MAX:
                resultados.append({"username": username, "fuentes": c.get("fuentes", []),
                                   "analizado": False, "motivo": "tope alcanzado"})
                continue
            print(f"[username_enumeration] [{analizados + 1}] {username} ...")
            perfiles = _sherlock_lookup(username)
            resultados.append({
                "username": username,
                "fuentes": c.get("fuentes", []),
                "total_perfiles": len(perfiles),
                "perfiles": perfiles,
            })
            analizados += 1

        total_perfiles = sum(r.get("total_perfiles", 0) for r in resultados)
        return {
            "tipo": "username_enumeration",
            "total_usernames": len(candidatos),
            "total_analizados": analizados,
            "total_perfiles_encontrados": total_perfiles,
            "usernames": resultados,
        }

    return _run_osint_job(ejecucion_id, job)