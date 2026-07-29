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
    """Enumeración de servicios activos"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio = config.get('DOMINIO', '')
        
        if not dominio:
            raise Exception("Dominio no configurado")
        
        # TODO: Integrar nmap, masscan, etc.
        servicios = []
        
        return {
            "tipo": "enumeracion_servicios",
            "dominio": dominio,
            "total": len(servicios),
            "servicios": servicios
        }
    
    _run_osint_job(ejecucion_id, job)

def mapeo_ips(ejecucion_id, proyecto_id):
    """Mapeo de IPs"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        ips = config.get('IPS', '')
        
        if not ips:
            raise Exception("IPs no configuradas")
        
        # TODO: Procesar rangos de IPs
        analisis = []
        
        return {
            "tipo": "mapeo_ips",
            "total": len(analisis),
            "ips_analizadas": analisis
        }
    
    _run_osint_job(ejecucion_id, job)

def recon_cloud(ejecucion_id, proyecto_id):
    """Reconocimiento de servicios cloud"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        
        # TODO: Integrar cloud_enum, s3scanner, etc.
        recursos = []
        
        return {
            "tipo": "recon_cloud",
            "total": len(recursos),
            "recursos": recursos
        }
    
    _run_osint_job(ejecucion_id, job)

def escaneo_repositorios(ejecucion_id, proyecto_id):
    """Escaneo de repositorios públicos"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        
        # TODO: Integrar GitRob, TruffleHog, etc.
        hallazgos = []
        
        return {
            "tipo": "escaneo_repositorios",
            "total": len(hallazgos),
            "hallazgos": hallazgos
        }
    
    _run_osint_job(ejecucion_id, job)

def analisis_dns(ejecucion_id, proyecto_id):
    """Análisis de DNS"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio = config.get('DOMINIO', '')
        
        if not dominio:
            raise Exception("Dominio no configurado")
        
        registros = {}
        
        return {
            "tipo": "analisis_dns",
            "dominio": dominio,
            "registros": registros
        }
    
    _run_osint_job(ejecucion_id, job)

def busqueda_endpoints(ejecucion_id, proyecto_id):
    """Búsqueda de endpoints"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio = config.get('DOMINIO', '')
        
        if not dominio:
            raise Exception("Dominio no configurado")
        
        # TODO: Integrar waybackurls, hakrawler, etc.
        endpoints = []
        
        return {
            "tipo": "busqueda_endpoints",
            "dominio": dominio,
            "total": len(endpoints),
            "endpoints": endpoints
        }
    
    _run_osint_job(ejecucion_id, job)

def google_dorking(ejecucion_id, proyecto_id):
    """Google Dorking"""
    def job():
        config = Proyecto.get_osint_config(proyecto_id)
        dominio = config.get('DOMINIO', '')
        
        if not dominio:
            raise Exception("Dominio no configurado")
        
        # TODO: Implementar búsquedas dorking
        resultados = []
        
        return {
            "tipo": "google_dorking",
            "dominio": dominio,
            "total": len(resultados),
            "resultados": resultados
        }
    
    _run_osint_job(ejecucion_id, job)