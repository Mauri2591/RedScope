from db import get_db_connection
import json
from datetime import datetime

class OsintEjecucion:

    @staticmethod
    def crear(proyecto_id, servicio_osint_id, usuario_id):
        """Crea o actualiza ejecución OSINT (evita duplicados)"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO osint_ejecuciones
                (proyecto_id, servicio_osint_id, usuario_id, estado, estado_id, fecha_creacion, fecha_inicio)
                VALUES (%s, %s, %s, 'QUEUED', 1, NOW(), NOW())
                ON DUPLICATE KEY UPDATE
                    usuario_id=%s,
                    estado='QUEUED',
                    resultado=NULL,
                    error=NULL,
                    fecha_creacion=NOW(),
                    fecha_inicio=NOW(),
                    fecha_fin=NULL
            """, (proyecto_id, servicio_osint_id, usuario_id, usuario_id))

            cursor.execute("SELECT id FROM osint_ejecuciones WHERE proyecto_id=%s AND servicio_osint_id=%s",
                          (proyecto_id, servicio_osint_id))
            result = cursor.fetchone()
            ejecucion_id = result[0] if result else None

            conn.commit()
            return ejecucion_id
        except Exception as e:
            print(f"Error al crear ejecución OSINT: {e}")
            return None
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def mark_running(ejecucion_id):
        """Marca ejecución como en proceso"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE osint_ejecuciones
                SET estado='RUNNING', fecha_inicio=NOW()
                WHERE id=%s
            """, (ejecucion_id,))

            conn.commit()
        except Exception as e:
            print(f"Error al marcar como RUNNING: {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_resultado(ejecucion_id, resultado_json):
        """Actualiza resultado parcial durante la ejecución"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            resultado_str = resultado_json if isinstance(resultado_json, str) else json.dumps(resultado_json, indent=2, default=str)

            cursor.execute("""
                UPDATE osint_ejecuciones
                SET resultado=%s
                WHERE id=%s
            """, (resultado_str, ejecucion_id))

            conn.commit()
        except Exception as e:
            print(f"Error al actualizar resultado: {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def mark_completed(ejecucion_id, resultado_json):
        """Marca ejecución como completada con resultado"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Convertir dict a JSON string si es necesario
            resultado_str = resultado_json if isinstance(resultado_json, str) else json.dumps(resultado_json, indent=2, default=str)

            cursor.execute("""
                UPDATE osint_ejecuciones
                SET estado='COMPLETED', resultado=%s, fecha_fin=NOW()
                WHERE id=%s
            """, (resultado_str, ejecucion_id))

            conn.commit()
        except Exception as e:
            print(f"Error al marcar como COMPLETED: {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def mark_failed(ejecucion_id, error_msg):
        """Marca ejecución como fallida con error"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE osint_ejecuciones
                SET estado='FAILED', error=%s, fecha_fin=NOW()
                WHERE id=%s
            """, (str(error_msg), ejecucion_id))

            conn.commit()
        except Exception as e:
            print(f"Error al marcar como FAILED: {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_ejecucion(ejecucion_id):
        """Obtiene datos de una ejecución"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute("""
                SELECT * FROM osint_ejecuciones
                WHERE id=%s
            """, (ejecucion_id,))

            return cursor.fetchone()
        except Exception as e:
            print(f"Error al obtener ejecución: {e}")
            return None
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_status(ejecucion_id):
        """Obtiene estado y resultado de una ejecución"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute("""
                SELECT id, estado, resultado, error, fecha_inicio, fecha_fin
                FROM osint_ejecuciones
                WHERE id=%s
            """, (ejecucion_id,))

            return cursor.fetchone()
        except Exception as e:
            print(f"Error al obtener estado: {e}")
            return None
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_ultimas_ejecuciones(proyecto_id, limit=10):
        """Obtiene últimas ejecuciones de un proyecto"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute("""
                SELECT oe.*, so.nombre as servicio_nombre
                FROM osint_ejecuciones oe
                LEFT JOIN servicios_osint so ON so.id = oe.servicio_osint_id
                WHERE oe.proyecto_id=%s
                ORDER BY oe.fecha_inicio DESC
                LIMIT %s
            """, (proyecto_id, limit))

            return cursor.fetchall()
        except Exception as e:
            print(f"Error al obtener ejecuciones: {e}")
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def top_100_common_ports():
        """Obtiene puertos comunes de la BD para escaneo"""
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
