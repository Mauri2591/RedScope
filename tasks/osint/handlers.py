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
        print(f"[OSINT] Config: {config}")
        dominio = config.get('DOMINIO', '').strip() if config else ''
        print(f"[OSINT] Dominio: {dominio}")

        if not dominio:
            raise Exception("Dominio no configurado")

        subdominios = set()
        dominios = [d.strip() for d in dominio.split(',')]
        print(f"[OSINT] Dominios a procesar: {dominios}")

        for dom in dominios:
            try:
                print(f"[subfinder] Ejecutando para {dom}...")
                result = subprocess.run(
                    ['subfinder', '-d', dom, '-silent'],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                print(f"[subfinder] stdout: {result.stdout}")
                print(f"[subfinder] stderr: {result.stderr}")
                print(f"[subfinder] returncode: {result.returncode}")
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
    """Enumeración de servicios con nmap"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio = config.get('DOMINIO', '').strip()

        if not dominio:
            raise Exception("Dominio no configurado")

        servicios = []
        dominios = [d.strip() for d in dominio.split(',')]

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

                # Escanear puertos comunes
                for ip in ips:
                    print(f"[nmap] Escaneando {dom} ({ip})...")
                    result = subprocess.run(
                        ['nmap', '-p', '80,443,22,21,25,53,3306,5432,8080,8443', '--open', ip],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )

                    for line in result.stdout.split('\n'):
                        if 'open' in line:
                            servicios.append({
                                'dominio': dom,
                                'ip': ip,
                                'puerto': line.split('/')[0].strip(),
                                'servicio': line.split('tcp')[0].strip() if 'tcp' in line else 'unknown'
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
    """Mapeo y resolución de IPs"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio = config.get('DOMINIO', '').strip()

        if not dominio:
            raise Exception("Dominio no configurado")

        ips_analizadas = []
        dominios = [d.strip() for d in dominio.split(',')]

        for dom in dominios:
            try:
                result = subprocess.run(
                    ['nslookup', dom],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                for line in result.stdout.split('\n'):
                    if 'Address:' in line and not line.startswith(';'):
                        ip = line.split('Address:')[1].strip()
                        if ip and not ip.startswith('#') and ':' not in ip:  # Filtrar IPv6
                            # Intenta reverse DNS
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
                                    'dominio': dom,
                                    'ip': ip,
                                    'hostname': hostname
                                })
                            except:
                                ips_analizadas.append({
                                    'dominio': dom,
                                    'ip': ip,
                                    'hostname': 'unknown'
                                })
            except Exception as e:
                print(f"[mapeo_ips] Error para {dom}: {e}")

        return {
            "tipo": "mapeo_ips",
            "dominio": dominio,
            "total": len(ips_analizadas),
            "ips_analizadas": ips_analizadas
        }

    _run_osint_job(ejecucion_id, job)

def recon_cloud(ejecucion_id, proyecto_id):
    """Reconocimiento de buckets S3 y servicios cloud"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio = config.get('DOMINIO', '').strip()

        if not dominio:
            raise Exception("Dominio no configurado")

        recursos = []
        dominios = [d.strip() for d in dominio.split(',')]

        for dom in dominios:
            try:
                # Buscar buckets S3 comunes
                bucket_names = [
                    dom.replace('.', '-'),
                    f"{dom.split('.')[0]}-bucket",
                    f"bucket-{dom.replace('.', '-')}",
                    f"{dom.replace('.', '')}"
                ]

                for bucket in bucket_names:
                    try:
                        result = subprocess.run(
                            ['aws', 's3', 'ls', f"s3://{bucket}"],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if result.returncode == 0:
                            recursos.append({
                                'tipo': 's3_bucket',
                                'nombre': bucket,
                                'dominio': dom
                            })
                    except:
                        pass
            except Exception as e:
                print(f"[recon_cloud] Error para {dom}: {e}")

        return {
            "tipo": "recon_cloud",
            "dominio": dominio,
            "total": len(recursos),
            "recursos": recursos
        }

    _run_osint_job(ejecucion_id, job)

def escaneo_repositorios(ejecucion_id, proyecto_id):
    """Búsqueda de secretos en repositorios públicos"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio = config.get('DOMINIO', '').strip()

        if not dominio:
            raise Exception("Dominio no configurado")

        hallazgos = []
        dominios = [d.strip() for d in dominio.split(',')]

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
        dominios = [d.strip() for d in dominio.split(',')]

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
        dominios = [d.strip() for d in dominio.split(',')]

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
        dominios = [d.strip() for d in dominio.split(',')]

        # Dorks comunes
        dorks = [
            f'site:{dominio} inurl:admin',
            f'site:{dominio} filetype:pdf',
            f'site:{dominio} inurl:login',
            f'site:{dominio} "password"',
            f'site:{dominio} inurl:backup'
        ]

        # Nota: Se requiere API de Google Custom Search o usar curl/wget
        # Por ahora solo placeholder
        for dom in dominios:
            resultados.append({
                'dork': f'site:{dom} inurl:admin',
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