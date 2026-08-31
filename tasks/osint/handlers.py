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
    """Obtiene ASN usando DNS reverse a cymru.com (LOCAL)"""
    try:
        partes = ip.split('.')
        reversed_ip = '.'.join(reversed(partes))
        query_domain = f"{reversed_ip}.asn.cymru.com"

        # Usar dig para obtener TXT records
        resultado = subprocess.run(
            ['dig', query_domain, 'TXT', '+short'],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if resultado.returncode == 0 and resultado.stdout.strip():
            txt_record = resultado.stdout.strip().strip('"')
            if '|' in txt_record:
                partes_txt = txt_record.split('|')
                return {
                    'asn': partes_txt[0].strip() if len(partes_txt) > 0 else 'unknown',
                    'isp': partes_txt[1].strip() if len(partes_txt) > 1 else 'unknown'
                }
    except Exception:
        pass

    return {'asn': 'unknown', 'isp': 'unknown'}


def _get_geoip_info(ip):
    """Obtiene geolocalización usando geoip2 (LOCAL si está instalado)"""
    try:
        # Intenta usar geoip2-python si está instalado
        import geoip2.database

        # Rutas comunes de MaxMind GeoIP2
        db_paths = [
            '/usr/share/GeoIP/GeoLite2-City.mmdb',
            '/var/lib/GeoIP/GeoLite2-City.mmdb',
            '/opt/GeoIP/GeoLite2-City.mmdb'
        ]

        for db_path in db_paths:
            if os.path.exists(db_path):
                reader = geoip2.database.Reader(db_path)
                response = reader.city(ip)
                return {
                    'pais': response.country.iso_code or 'unknown',
                    'ciudad': response.city.name or 'unknown',
                    'latitud': response.location.latitude or 'unknown',
                    'longitud': response.location.longitude or 'unknown'
                }
    except Exception:
        pass

    # Fallback: retorna unknown
    return {
        'pais': 'unknown',
        'ciudad': 'unknown',
        'latitud': 'unknown',
        'longitud': 'unknown'
    }


def _get_whois_info(ip, timeout=5):
    """Obtiene WHOIS info (LOCAL usando comando whois)"""
    try:
        resultado = subprocess.run(
            ['whois', ip],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if resultado.returncode == 0:
            lineas = resultado.stdout.split('\n')
            info = {
                'organizacion': 'unknown',
                'pais': 'unknown',
                'red': 'unknown'
            }

            for linea in lineas:
                linea_lower = linea.lower()

                if 'organization' in linea_lower:
                    info['organizacion'] = linea.split(
                        ':')[1].strip() if ':' in linea else 'unknown'
                elif 'country' in linea_lower and info['pais'] == 'unknown':
                    info['pais'] = linea.split(
                        ':')[1].strip() if ':' in linea else 'unknown'
                elif 'netname' in linea_lower or 'network name' in linea_lower:
                    info['red'] = linea.split(
                        ':')[1].strip() if ':' in linea else 'unknown'

            return info
    except Exception:
        pass

    return {
        'organizacion': 'unknown',
        'pais': 'unknown',
        'red': 'unknown'
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
                    # ✨ NUEVO: Información enriquecida
                    'asn': asn_info['asn'],
                    'isp': asn_info['isp'],
                    'pais': geo_info['pais'],
                    'ciudad': geo_info['ciudad'],
                    'organizacion': whois_info['organizacion'],
                    'red': whois_info['red'],
                    # ✨ NUEVO: Reverse lookup
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
                    'red': 'unknown',
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
    """Análisis de registros DNS con dig"""
    print(f"[OSINT-DNS] Handler iniciado para ejecución {ejecucion_id}")

    def job():
        # 1. Obtener TODO el scope: DOMINIO + SUBDOMINIO + SERVICIOS
        scope = OsintEjecucion.get_scope_completo(proyecto_id)
        todos_los_dominios = scope['dominio'] + \
            scope['subdominio'] + scope['servicios']

        # 2. SIEMPRE obtener subdominios descubiertos si existen
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
                "No hay dominios para analizar")

        # Deduplicar y ordenar
        todos_los_dominios = sorted(list(set(todos_los_dominios)))

        registros = {}
        tipos = ['A', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

        print(f"[analisis_dns] Analizando {len(todos_los_dominios)} dominios")

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

        # 1. Obtener dominios del scope inicial
        dominios_scope = _parse_multiline_config(
            dominio_config) if dominio_config else []
        if dominios_scope:
            print(f"[gau] Dominios del scope encontrados: {dominios_scope}")
        else:
            print(f"[gau] Sin dominios configurados en DOMINIO")

        # 2. Fallback: Obtener dominios descubiertos por reverse DNS
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
                "No hay dominios ni IPs para escanear")

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
                'jpg,jpeg,png,gif,svg,css,js,woff,woff2,ttf,eot', target],
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

    # ✨ NUEVO - Configuración & Sesión (Moodle, PHP, etc.)
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
    patron_var_assign = r'^(var|let|const|private|public|protected|static)?\s*\w*' + re.escape(palabra_clave) + r'\s*[:=]\s*["\']'
    if re.search(patron_var_assign, linea_limpia, re.IGNORECASE):
        valor_match = re.search(patron_var_assign + r'([^"\']+)', linea_limpia, re.IGNORECASE)
        if valor_match:
            valor = valor_match.group(valor_match.lastindex)
            if valor.lower() != palabra_clave.lower():
                return True
        return False

    # Patrón 2: password: "valor" (objeto JS)
    patron_obj = r'\b' + re.escape(palabra_clave) + r'\s*:\s*["\']'
    if re.search(patron_obj, linea_limpia, re.IGNORECASE):
        valor_match = re.search(patron_obj + r'([^"\']+)', linea_limpia, re.IGNORECASE)
        if valor_match:
            valor = valor_match.group(1)
            if valor.lower() != palabra_clave.lower() and len(valor) > 3:
                return True
        return False

    # Patrón 3: password="valor" (atributo HTML)
    patron_html = r'\b' + re.escape(palabra_clave) + r'\s*=\s*["\']'
    if re.search(patron_html, linea_limpia, re.IGNORECASE):
        valor_match = re.search(patron_html + r'([^"\']+)', linea_limpia, re.IGNORECASE)
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
    patron_sin_comillas = r'\b' + re.escape(palabra_clave) + r'\s*[:=]\s*([a-zA-Z0-9_\-\.]{16,})'
    match_sin_comillas = re.search(patron_sin_comillas, linea_limpia, re.IGNORECASE)
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
            matches = re.finditer(config_patron['patron'], contenido, re.IGNORECASE)
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
            severidad_real = _obtener_severidad_real(nivel_recomendado, mapa_severidades)

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
# FUNCIÓN PRINCIPAL - MEJORADA CON IPs + HTML + VALIDACIÓN
# ════════════════════════════════════════════════════════════════════════════════

def sensitive_data_extraction(ejecucion_id, proyecto_id):
    """Extracción de datos sensibles - VERSIÓN MEJORADA"""
    print(f"[OSINT-SENSITIVE-DATA] Handler iniciado para ejecución {ejecucion_id}")

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
                dominio_part = url.split("://", 1)[1].split(":")[0]  # Quita protocolo y puerto
                subdominios_scope.add(dominio_part.lower())

        try:
            subdominios_desc = OsintEjecucion.get_discovered_subdomains(proyecto_id)
            if subdominios_desc:
                for subdom in subdominios_desc[:20]:
                    subdom_lower = subdom.lower()

                    # ✨ NUEVO: Solo agregar si NO existe en scope
                    if subdom_lower not in subdominios_scope:
                        urls_fase2[f"http://{subdom}"] = subdom
                        urls_fase2[f"https://{subdom}"] = subdom
                        print(f"[sensitive_data] Discovery subdominio agregado: {subdom}")
                    else:
                        print(f"[sensitive_data] Subdominio ya en scope, omitido: {subdom}")
        except Exception as e:
            print(f"[sensitive_data] Error al obtener subdominios descubiertos: {type(e).__name__}")

        # Merge: Scope (FASE 1) + Discovery (FASE 2) sin duplicados
        # Prioridad: scope (se agrega primero)
        todas_las_urls = {**urls_scope, **urls_fase2}
        fase_usada = 'FASE 1+2' if urls_fase2 else 'FASE 1'

        if not todas_las_urls:
            raise Exception("No hay URLs")

        print(f"[sensitive_data] Total URLs: {len(todas_las_urls)} ({fase_usada})")

        # ⚠️ LÍMITE: máx 200 URLs (aumentado para cobertura completa: IPs + puertos + subdominios)
        urls_a_analizar = list(todas_las_urls.keys())[:200]
        urls_a_analizar = [url for url in urls_a_analizar
                   if '.min.js' not in url.lower()]

        print(f"[sensitive_data] URLs después de filtrar minificados: {len(urls_a_analizar)}")

        hallazgos_secretos = {}
        hallazgos_vulnerabilidades = {}
        hallazgos_html_sensibles = {}  # ✨ NUEVO
        total_secretos = 0
        total_vulnerabilidades = 0
        total_html_sensibles = 0  # ✨ NUEVO

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
                    contenido = response.content[:5242880].decode('utf-8', errors='ignore')

                    # ✨ MEJORADO: Capturar URL final después de redirects
                    final_url = response.url
                    if final_url != url:
                        print(f"[sensitive_data] Redirigido: {url} → {final_url}")

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
                    elementos_sensibles = _buscar_inputs_hidden(contenido, final_url)
                    if elementos_sensibles:
                        hallazgos_html_sensibles[final_url] = elementos_sensibles
                        total_html_sensibles += len(elementos_sensibles)
                        print(f"  [HALLAZGO] {len(elementos_sensibles)} elementos HTML sensibles")

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
                            js_contenido = js_response.content[:5242880].decode('utf-8', errors='ignore')

                            secretos = _buscar_secretos_en_contenido(js_contenido, js_url)
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
                                    total_vulnerabilidades += len(vulnerabilidades)

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
            "secretos": hallazgos_secretos,
            "vulnerabilidades": hallazgos_vulnerabilidades,
            "elementos_html_sensibles": hallazgos_html_sensibles,  # ✨ NUEVO
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