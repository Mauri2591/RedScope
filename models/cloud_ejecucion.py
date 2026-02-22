from db import get_db_connection
import json

class CloudEjecucion:
    
    RISK_KEYWORDS = [
        "public",
        "exposed",
        "wildcard",
        "dangerous",
        "cross_account",
        "privilege",
        "ingress",
        "anonymous",
        "write"
    ]
     
    @staticmethod
    def mark_running(ejecucion_id):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            query = """
                UPDATE cloud_ejecuciones
                SET estado='RUNNING'
                WHERE id=%s
            """
            cursor.execute(query, (ejecucion_id,))
            conn.commit()
        except Exception as e:
            print(f"Error al marcar como 'RUNNING': {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def mark_completed(resultado_json, ejecucion_id):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            query = """
                UPDATE cloud_ejecuciones
                SET estado='COMPLETED',
                    resultado=%s,
                    fecha_fin=NOW()
                WHERE id=%s
            """
            cursor.execute(query, (resultado_json, ejecucion_id))
            conn.commit()
        except Exception as e:
            print(f"Error al marcar como 'COMPLETED': {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def mark_failed(error, ejecucion_id):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            query = """
                UPDATE cloud_ejecuciones
                SET estado='FAILED',
                    error=%s,
                    fecha_fin=NOW()
                WHERE id=%s
            """
            cursor.execute(query, (error, ejecucion_id))
            conn.commit()
        except Exception as e:
            print(f"Error al marcar como 'FAILED': {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def top_100_common_ports():
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT puertos_json
                FROM puertos_comunes
                WHERE nombre = 'TOP_100_COMMON_TCP'
                AND estado_id = 1
                LIMIT 1
            """)
            row = cursor.fetchone()
            if not row:
                return {}
            return json.loads(row["puertos_json"])
        except Exception as e:
            print(f"Error al obtener puertos comunes: {e}")
            return {}
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def versiones_deprecadas(tipo_proyecto_id, proveedor, servicio, categoria):
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT nombre_version
                FROM versiones_deprecadas
                WHERE tipo_proyecto_id = %s
                AND proveedor = %s
                AND servicio = %s
                AND categoria = %s
                AND estado_id = 1
            """, (tipo_proyecto_id, proveedor, servicio, categoria))
            rows = cursor.fetchall()
            return [row["nombre_version"] for row in rows]
        except Exception as e:
            print(f"Error al obtener versiones deprecadas: {e}")
            return []
        finally:
            cursor.close()
            conn.close()
            

    @staticmethod
    def extract_interesting(resultado):
        if isinstance(resultado, str):
            try:
                resultado = json.loads(resultado)
            except:
                return []

        interesting = []
        # 🔴 Si la ejecución falló por permisos
        if resultado.get("status") == "FAILED":
            error = resultado.get("error", "")
            if "AccessDenied" in error or "Unauthorized" in error:
                interesting.append({
                    "type": "ENUMERATION_BLOCKED",
                    "details": "Insufficient permissions to enumerate this service"
                })
            return interesting

        for r in resultado.get("resources", []):
            analysis = r.get("analysis", {})

            for key, value in analysis.items():

                if value is True:
                    key_lower = key.lower()

                    for keyword in CloudEjecucion.RISK_KEYWORDS:
                        if keyword in key_lower:
                            interesting.append({
                                "resource_id": r.get("resource_id"),
                                "flag": key
                            })
                            break
        return interesting
    