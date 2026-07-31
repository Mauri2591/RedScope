import json
from config import Config
from models.proyecto import Proyecto
from models.osint_ejecucion import OsintEjecucion
from db import get_db_connection
from datetime import datetime
import subprocess
import socket
import requests

# ══════════════════════════════════════════════════════════════════
# HELPERS GLOBALES OSINT
# ══════════════════════════════════════════════════════════════════

def _parse_multiline_config(value):
    """Limpia y parsea valores multilinea de configuración"""
    if not value:
        return []
    # Reemplazar \r\n por \n y split
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

        # Traer puertos comunes de la BD
        puertos_dict = OsintEjecucion.top_100_common_ports()
        if not puertos_dict:
            puertos_dict = {'80': 'http', '443': 'https', '22': 'ssh', '3306': 'mysql'}

        # Extraer solo números de puertos y hacer string para nmap
        puertos_str = ','.join(puertos_dict.keys())
        print(f"[nmap] Escaneando {len(puertos_dict)} puertos comunes")

        for dom in dominios:
            try:
                # Resolver IP primero
                result_ip = subprocess.run(
                    ['nslookup', dom],
                    capture_output=True,
                    text=True,
                    timeout=15
                )

                # Extraer IP
                ips = []
                for line in result_ip.stdout.split('\n'):
                    if 'Address:' in line and not line.startswith(';'):
                        ip = line.split('Address:')[1].strip()
                        if ip and not ip.startswith('#'):
                            ips.append(ip)

                # Escanear puertos desde BD
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
        ips_a_analizar = set()  # Usar set para evitar duplicados

        # Agregar IPS configuradas
        ips_str = config.get('IPS', '').strip() if config else ''
        if ips_str:
            ips_a_analizar.update(_parse_multiline_config(ips_str))

        # TAMBIÉN resolver dominios a IPS
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

        # Analizar las IPs (reverse DNS lookup)
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
            # 1. Buckets derivados del dominio (actual)
            bucket_names = _generate_bucket_candidates(dom)
            
            # 2. Buscar en Wayback (referencias históricas)
            bucket_names.extend(_find_buckets_wayback(dom))
            
            # 3. Buscar en CT logs (subdominios)
            bucket_names.extend(_find_buckets_from_ct(dom))
            
            # 4. Escanear con s3scanner si está disponible
            bucket_names.extend(_scan_with_s3scanner(dom))
            
            # Eliminar duplicados y escanear
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
        # Original + variaciones
        dominio,
        domain_clean,
        domain_nodots,
        f"{company}-bucket",
        f"bucket-{company}",
        f"{company}-aws",
        f"{company}-s3",
        f"s3-{company}",
        
        # Comunes
        f"{company}-data",
        f"{company}-assets",
        f"{company}-backup",
        f"{company}-files",
        f"{company}-media",
        f"{company}-logs",
        f"{company}-public",
        
        # Con extensión
        f"{company}-com-ar",
        f"{company}-{dominio.split('.')[-2]}",
    ]
    
    return candidates


def _find_buckets_wayback(dominio):
    """Busca referencias a buckets en Wayback Machine"""
    buckets = []
    try:
        print(f"[wayback] Buscando buckets en histórico de {dominio}...")
        
        # Descargar URLs del wayback para este dominio
        result = subprocess.run(
            ['waybackurls', dominio],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.stdout:
            urls = result.stdout.strip().split('\n')
            
            # Buscar patrones de S3
            for url in urls:
                # Patrones comunes en URLs
                if 's3' in url.lower():
                    # s3://bucket-name
                    if 's3://' in url:
                        bucket = url.split('s3://')[1].split('/')[0]
                        if bucket and '.' not in bucket:  # Buckets S3 no tienen .
                            buckets.append(bucket)
                    # amazonaws URLs
                    elif 'amazonaws' in url:
                        # bucket.s3.amazonaws.com
                        parts = url.split('/')
                        for part in parts:
                            if 's3' in part and 'amazonaws' in part:
                                bucket = part.split('.')[0]
                                if bucket:
                                    buckets.append(bucket)
    
    except FileNotFoundError:
        print("[wayback] waybackurls no instalado - skipping")
    except Exception as e:
        print(f"[wayback] Error: {e}")
    
    return buckets


def _find_buckets_from_ct(dominio):
    """Busca buckets en subdominios vía CT logs"""
    buckets = []
    try:
        print(f"[ct-logs] Buscando subdominios de {dominio}...")
        
        # Usar curl para consultar crt.sh
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
                
                # Convertir subdominios en candidatos de bucket
                for sub in subdomains:
                    buckets.append(sub.replace('.', '-'))
                    buckets.append(sub.replace('.', ''))
                    
            except json.JSONDecodeError:
                pass
    
    except Exception as e:
        print(f"[ct-logs] Error: {e}")
    
    return buckets


def _scan_with_s3scanner(dominio):
    """Usa s3scanner para escaneo más inteligente"""
    buckets = []
    try:
        print(f"[s3scanner] Escaneando con s3scanner...")
        
        # s3scanner mantiene listas de buckets comunes
        result = subprocess.run(
            ['s3scanner', 'scan', '-l', '/dev/stdin'],
            input=dominio,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.stdout:
            for line in result.stdout.split('\n'):
                if 'BucketExists' in line or 'Exists' in line.lower():
                    # Extraer nombre del bucket
                    parts = line.split()
                    if parts:
                        buckets.append(parts[0])
    
    except FileNotFoundError:
        print("[s3scanner] s3scanner no instalado")
    except Exception as e:
        print(f"[s3scanner] Error: {e}")
    
    return buckets


def _verify_bucket(bucket_name, dominio):
    """Verifica si un bucket existe y obtiene info"""
    resultado = []
    
    try:
        # Verificar si el bucket existe y es accesible
        result = subprocess.run(
            ['aws', 's3', 'ls', f"s3://{bucket_name}", '--max-items', '1'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            # Bucket es accesible
            resultado.append({
                'tipo': 's3_bucket',
                'nombre': bucket_name,
                'dominio': dominio,
                'acceso': 'público_o_auth',
                'estado': 'existe'
            })
        elif 'NoSuchBucket' not in result.stderr:
            # Existe pero no tiene permisos de lectura
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

        hallazgos = []
        dominios = _parse_multiline_config(dominio)

        # Búsquedas simples en GitHub (requiere token)
        # Por ahora solo placeholder
        for dom in dominios:
            print(f"[repos] Buscando en GitHub: {dom}")
            # Aquí iría integración con API de GitHub
            # Requiere: github token, trufflehog instalado, etc.

        return {
            "tipo": "escaneo_repositorios",
            "dominio": dominio,
            "total": len(hallazgos),
            "hallazgos": hallazgos,
            "nota": "Requiere configurar GitHub token para buscar secretos"
        }

    _run_osint_job(ejecucion_id, job)

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
                print(f"[waybackurls] No instalado. Instala: go install github.com/tomnomnom/waybackurls@latest")
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
    """Google Dorking - búsquedas especializadas"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio = config.get('DOMINIO', '').strip()

        if not dominio:
            raise Exception("Dominio no configurado")

        resultados = []
        dominios = _parse_multiline_config(dominio)

        if not dominios:
            raise Exception("No se encontraron dominios válidos")

        # Dorks comunes
        for dom in dominios:
            dorks = [
                f'site:{dom} inurl:admin',
                f'site:{dom} filetype:pdf',
                f'site:{dom} inurl:login',
                f'site:{dom} "password"',
                f'site:{dom} inurl:backup'
            ]

            for dork in dorks:
                resultados.append({
                    'dork': dork,
                    'dominio': dom,
                    'nota': 'Requiere API de Google Custom Search'
                })

        return {
            "tipo": "google_dorking",
            "dominio": dominio,
            "total": len(resultados),
            "resultados": resultados,
            "nota": "Requiere configurar Google Custom Search API"
        }

    _run_osint_job(ejecucion_id, job)
