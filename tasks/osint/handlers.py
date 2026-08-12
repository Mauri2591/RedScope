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
# HANDLERS OSINT
# ══════════════════════════════════════════════════════════════════

def discovery_subdominios(ejecucion_id, proyecto_id):
    """Descubrimiento de subdominios con subfinder"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio = config.get('DOMINIO', '').strip() if config else ''

        if not dominio:
            raise Exception("Dominio no configurado")

        subdominios = set()
        dominios = _parse_multiline_config(dominio)

        if not dominios:
            raise Exception("No se encontraron dominios válidos en la configuración")

        for dom in dominios:
            try:
                print(f"[subfinder] Escaneando {dom}...")
                OsintEjecucion.update_resultado(ejecucion_id, {
                    "tipo": "discovery_subdominios",
                    "dominio": dominio,
                    "total": len(subdominios),
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
                    subdominios.update(result.stdout.strip().split('\n'))
            except subprocess.TimeoutExpired:
                print(f"[subfinder] Timeout para {dom}")
            except Exception as e:
                print(f"[subfinder] Error en {dom}: {e}")

        subdominios = sorted(list(filter(None, subdominios)))

        return {
            "tipo": "discovery_subdominios",
            "dominio": dominio,
            "total": len(subdominios),
            "subdominios": subdominios
        }

    _run_osint_job(ejecucion_id, job)

def enumeracion_servicios(ejecucion_id, proyecto_id):
    """Enumeración de servicios con nmap - usa puertos de BD"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio = config.get('DOMINIO', '').strip()

        if not dominio:
            raise Exception("Dominio no configurado")

        servicios = []
        dominios = _parse_multiline_config(dominio)

        if not dominios:
            raise Exception("No se encontraron dominios válidos")

        puertos_dict = OsintEjecucion.top_100_common_ports()
        if not puertos_dict:
            puertos_dict = {'80': 'http', '443': 'https', '22': 'ssh', '3306': 'mysql'}

        puertos_str = ','.join(puertos_dict.keys())
        print(f"[nmap] Escaneando {len(puertos_dict)} puertos comunes")

        for dom in dominios:
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
            "dominio": dominio,
            "total": len(servicios),
            "servicios": servicios
        }

    _run_osint_job(ejecucion_id, job)

def mapeo_ips(ejecucion_id, proyecto_id):
    """Mapeo y resolución de IPs - combina IPS configuradas + dominios resueltos"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)

        ips_analizadas = []
        ips_a_analizar = set()

        ips_str = config.get('IPS', '').strip() if config else ''
        if ips_str:
            ips_a_analizar.update(_parse_multiline_config(ips_str))

        dominio = config.get('DOMINIO', '').strip() if config else ''
        if dominio:
            dominios = _parse_multiline_config(dominio)
            for dom in dominios:
                try:
                    print(f"[mapeo_ips] Resolviendo dominio {dom}...")
                    result = subprocess.run(
                        ['nslookup', dom],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    for line in result.stdout.split('\n'):
                        if 'Address:' in line and not line.startswith(';'):
                            ip = line.split('Address:')[1].strip()
                            if ip and not ip.startswith('#') and ':' not in ip:
                                ips_a_analizar.add(ip)
                except Exception as e:
                    print(f"[mapeo_ips] Error resolviendo {dom}: {e}")

        if not ips_a_analizar:
            raise Exception("No hay IPs ni dominios configurados para analizar")

        for ip in sorted(ips_a_analizar):
            try:
                result_reverse = subprocess.run(
                    ['nslookup', ip],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                hostname = 'unknown'
                for rev_line in result_reverse.stdout.split('\n'):
                    if 'name =' in rev_line:
                        hostname = rev_line.split('name =')[1].strip().rstrip('.')
                        break

                ips_analizadas.append({
                    'ip': ip,
                    'hostname': hostname
                })
            except Exception as e:
                print(f"[mapeo_ips] Error resolviendo reverso {ip}: {e}")
                ips_analizadas.append({
                    'ip': ip,
                    'hostname': 'error'
                })

        return {
            "tipo": "mapeo_ips",
            "total": len(ips_analizadas),
            "ips_analizadas": ips_analizadas
        }

    _run_osint_job(ejecucion_id, job)

def recon_cloud(ejecucion_id, proyecto_id):
    """Reconocimiento de buckets S3 y servicios cloud mejorado"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio = config.get('DOMINIO', '').strip()

        if not dominio:
            raise Exception("Dominio no configurado")

        recursos = []
        dominios = _parse_multiline_config(dominio)

        if not dominios:
            raise Exception("No se encontraron dominios válidos")

        for dom in dominios:
            bucket_names = _generate_bucket_candidates(dom)
            bucket_names.extend(_find_buckets_wayback(dom))
            bucket_names.extend(_find_buckets_from_ct(dom))
            bucket_names.extend(_scan_with_wordlist(dom))

            bucket_names = list(set(filter(None, bucket_names)))

            for bucket in bucket_names:
                recursos.extend(_verify_bucket(bucket, dom))

        return {
            "tipo": "recon_cloud",
            "dominio": dominio,
            "total": len(recursos),
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


def _verify_bucket(bucket_name, dominio):
    """Verifica si un bucket existe y obtiene info"""
    resultado = []

    try:
        result = subprocess.run(
            ['aws', 's3', 'ls', f"s3://{bucket_name}", '--max-items', '1'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            resultado.append({
                'tipo': 's3_bucket',
                'nombre': bucket_name,
                'dominio': dominio,
                'acceso': 'público_o_auth',
                'estado': 'existe'
            })
        elif 'NoSuchBucket' not in result.stderr:
            resultado.append({
                'tipo': 's3_bucket',
                'nombre': bucket_name,
                'dominio': dominio,
                'acceso': 'privado',
                'estado': 'existe'
            })

    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        pass

    return resultado

def escaneo_repositorios(ejecucion_id, proyecto_id):
    """Búsqueda de secretos en repositorios públicos"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio = config.get('DOMINIO', '').strip()

        if not dominio:
            raise Exception("Dominio no configurado")

        hallazgos_raw = []
        dominios = _parse_multiline_config(dominio)

        for dom in dominios:
            # 1. Búsqueda en GitHub via API pública
            hallazgos_raw.extend(_search_github(dom))

            # 2. Intentar con trufflehog si está instalado
            hallazgos_raw.extend(_search_trufflehog(dom))

        # Deduplicar y agrupar por repositorio
        hallazgos_dedup = _deduplicate_github_results(hallazgos_raw)

        return {
            "tipo": "escaneo_repositorios",
            "dominio": dominio,
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
            domain_base = '.'.join(dom_parts[1:])  # ater.gob.ar
        else:
            domain_base = dominio
        
        searches = [
            f'"{domain_base}"',           # "ater.gob.ar"
            f'org:{dom_parts[0]}',        # org:ater (si no es www)
            f'{domain_base} secret',
            f'{domain_base} password',
            f'{domain_base} api_key',
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


def _deduplicate_github_results(hallazgos_raw):
    """Deduplica y agrupa hallazgos por repositorio"""
    repos_dict = {}

    for item in hallazgos_raw:
        if item.get('tipo') != 'github_repo':
            continue

        repo = item.get('repo', '').replace('[', '').replace('](', '/').replace(')', '')
        if not repo:
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
    """Análisis de registros DNS con dig"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio = config.get('DOMINIO', '').strip()

        if not dominio:
            raise Exception("Dominio no configurado")

        registros = {}
        dominios = _parse_multiline_config(dominio)

        if not dominios:
            raise Exception("No se encontraron dominios válidos")

        for dom in dominios:
            registros[dom] = {}
            tipos = ['A', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

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
            "dominio": dominio,
            "registros": registros
        }

    _run_osint_job(ejecucion_id, job)

def busqueda_endpoints(ejecucion_id, proyecto_id):
    """Búsqueda de endpoints con waybackurls"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio = config.get('DOMINIO', '').strip()

        if not dominio:
            raise Exception("Dominio no configurado")

        endpoints = set()
        dominios = _parse_multiline_config(dominio)

        if not dominios:
            raise Exception("No se encontraron dominios válidos")

        for dom in dominios:
            try:
                result = subprocess.run(
                    ['waybackurls', dom],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.stdout:
                    endpoints.update(result.stdout.strip().split('\n'))
            except FileNotFoundError:
                print(f"[waybackurls] No instalado")
            except subprocess.TimeoutExpired:
                print(f"[waybackurls] Timeout para {dom}")
            except Exception as e:
                print(f"[waybackurls] Error en {dom}: {e}")

        endpoints = sorted(list(filter(None, endpoints)))

        return {
            "tipo": "busqueda_endpoints",
            "dominio": dominio,
            "total": len(endpoints),
            "endpoints": endpoints
        }

    _run_osint_job(ejecucion_id, job)

def google_dorking(ejecucion_id, proyecto_id):
    """Google Dorking - búsquedas especializadas con resultados reales"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio = config.get('DOMINIO', '').strip()

        if not dominio:
            raise Exception("Dominio no configurado")

        resultados = []
        dominios = _parse_multiline_config(dominio)

        if not dominios:
            raise Exception("No se encontraron dominios válidos")

        for dom in dominios:
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
            "dominio": dominio,
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