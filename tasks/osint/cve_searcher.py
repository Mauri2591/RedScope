"""
Búsqueda híbrida de CVEs para herramientas IA.
Intenta primero BD local, luego NVD online.
"""

import json
import os
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Intentar importar nvdlib (opcional)
try:
    import nvdlib
    NVDLIB_AVAILABLE = True
except ImportError:
    NVDLIB_AVAILABLE = False
    print("[INFO] nvdlib no instalado. Usando solo BD offline.")
    print("[INFO] Instala con: pip install nvdlib")


class CVESearcher:
    """Busca CVEs en BD local y NVD online"""

    def __init__(self, cves_json_path: str = None):
        """
        Args:
            cves_json_path: Ruta al archivo cves_ia_tools.json
        """
        self.cves_locales = {}
        self.cache_online = {}
        self.cache_file = '/tmp/cve_cache.json'

        # Cargar BD local
        if cves_json_path and os.path.exists(cves_json_path):
            self.cargar_cves_offline(cves_json_path)

        # Cargar cache
        self._cargar_cache()

    def cargar_cves_offline(self, ruta: str):
        """Carga CVEs desde archivo JSON"""
        try:
            with open(ruta, 'r', encoding='utf-8') as f:
                self.cves_locales = json.load(f)
            print(f"[CVE] Cargadas {len(self.cves_locales)} herramientas IA con CVEs offline")
        except Exception as e:
            print(f"[ERROR] No se pudo cargar CVEs: {e}")

    def _cargar_cache(self):
        """Carga CVEs cacheados (máximo 24h)"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    cache_data = json.load(f)

                # Verificar que no sea más viejo que 24h
                timestamp = cache_data.get('timestamp', 0)
                if datetime.now().timestamp() - timestamp < 86400:  # 24h
                    self.cache_online = cache_data.get('cves', {})
                    print(f"[CVE] Cache cargado: {len(self.cache_online)} entradas")
            except Exception as e:
                print(f"[CVE] Error cargando cache: {e}")

    def _guardar_cache(self):
        """Guarda CVEs cacheados"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump({
                    'timestamp': datetime.now().timestamp(),
                    'cves': self.cache_online
                }, f)
        except Exception as e:
            print(f"[CVE] Error guardando cache: {e}")

    def buscar(self, ia_name: str) -> List[Dict]:
        """
        Busca CVEs para una herramienta IA.

        Flujo:
        1. BD local (rápido)
        2. Cache online (rápido)
        3. NVD online (lento, pero actual)

        Args:
            ia_name: Nombre de la herramienta IA

        Returns:
            Lista de CVEs
        """
        resultados = []

        # 1. Buscar en BD local
        if ia_name in self.cves_locales:
            resultados.extend(self.cves_locales[ia_name])
            print(f"[CVE] {ia_name}: Encontrados {len(resultados)} CVEs en BD local")

        # 2. Buscar en cache
        if ia_name in self.cache_online:
            resultados.extend(self.cache_online[ia_name])
            print(f"[CVE] {ia_name}: Encontrados {len(self.cache_online[ia_name])} CVEs en cache")

        # 3. Buscar en NVD si está disponible y no hay resultados
        if NVDLIB_AVAILABLE and len(resultados) == 0:
            print(f"[CVE] Buscando {ia_name} en NVD...")
            nvd_results = self._buscar_nvd(ia_name)
            if nvd_results:
                resultados.extend(nvd_results)
                self.cache_online[ia_name] = nvd_results
                self._guardar_cache()

        return resultados

    def _buscar_nvd(self, ia_name: str) -> List[Dict]:
        """
        Busca en NVD usando nvdlib.

        Limitaciones:
        - Sin autenticación: ~10 requests/min
        - Timeout: ~5 seg por request
        - Resultados parciales

        Args:
            ia_name: Nombre a buscar

        Returns:
            Lista de CVEs encontrados
        """
        if not NVDLIB_AVAILABLE:
            return []

        try:
            resultados = []

            # Buscar productos relacionados
            print(f"[CVE] Buscando productos para '{ia_name}'...")
            productos = nvdlib.searchCPE(
                keyword=ia_name,
                timeout=5,
                limit=5
            )

            if not productos:
                print(f"[CVE] No se encontraron productos para '{ia_name}'")
                return []

            # Por cada producto, buscar vulns
            for producto in productos[:3]:  # Máximo 3 productos
                try:
                    print(f"[CVE] Buscando vulnerabilidades para {producto.cpe}...")

                    vulns = nvdlib.searchCVE(
                        cpeName=producto.cpe,
                        timeout=5,
                        limit=5
                    )

                    for vuln in vulns:
                        resultado_vuln = {
                            'cve': vuln.id,
                            'nombre': vuln.title if hasattr(vuln, 'title') else 'Sin título',
                            'descripcion': self._extraer_descripcion(vuln),
                            'severidad': self._extraer_severidad(vuln),
                            'publicado': str(vuln.published) if hasattr(vuln, 'published') else '',
                            'referencias': self._extraer_referencias(vuln),
                            'fuente': 'NVD',
                            'poc': f"Consultar: https://nvd.nist.gov/vuln/detail/{vuln.id}",
                            'mitigacion': 'Actualizar paquete a versión sin vulnerabilidad'
                        }
                        resultados.append(resultado_vuln)

                except Exception as e:
                    print(f"[CVE] Error buscando vulns para {producto.cpe}: {e}")
                    continue

            return resultados

        except Exception as e:
            print(f"[CVE] Error en búsqueda NVD: {e}")
            return []

    def _extraer_descripcion(self, vuln) -> str:
        """Extrae descripción de CVE"""
        try:
            if hasattr(vuln, 'descriptions') and vuln.descriptions:
                return vuln.descriptions[0].value
            return 'Sin descripción disponible'
        except:
            return 'Sin descripción disponible'

    def _extraer_severidad(self, vuln) -> float:
        """Extrae score de severidad"""
        try:
            if hasattr(vuln, 'score') and vuln.score:
                return float(vuln.score[0].base_score)
            return 0.0
        except:
            return 0.0

    def _extraer_referencias(self, vuln) -> List[str]:
        """Extrae referencias"""
        try:
            if hasattr(vuln, 'references') and vuln.references:
                return [ref.url for ref in vuln.references]
            return []
        except:
            return []


def obtener_vulnerabilidades_ia(ia_name: str, cves_json_path: str = None) -> List[Dict]:
    """
    Función conveniente para obtener CVEs de una IA.

    Args:
        ia_name: Nombre de la herramienta IA
        cves_json_path: Ruta a cves_ia_tools.json (opcional)

    Returns:
        Lista de CVEs

    Ejemplo:
        vulns = obtener_vulnerabilidades_ia('OpenAI')
        for v in vulns:
            print(f"{v['cve']}: {v['nombre']} (Severidad: {v['severidad']})")
    """
    searcher = CVESearcher(cves_json_path)
    return searcher.buscar(ia_name)


if __name__ == '__main__':
    # Test
    searcher = CVESearcher('./cves_ia_tools.json')

    for ia in ['OpenAI', 'Claude', 'Cohere', 'API_Endpoint']:
        print(f"\n{'='*60}")
        print(f"Buscando CVEs para: {ia}")
        print('='*60)

        vulns = searcher.buscar(ia)
        for v in vulns[:3]:  # Mostrar máximo 3
            print(f"\n[{v['cve']}] {v['nombre']}")
            print(f"  Severidad: {v.get('severidad', 'N/A')}")
            print(f"  Descripción: {v.get('descripcion', 'N/A')[:100]}...")
            print(f"  POC: {v.get('poc', 'N/A')[:80]}...")
