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
    
    RISK_FALSE_KEYWORDS = [
    "lifecycle_enabled",
    "replication_enabled", 
    "encryption_enabled",
    "versioning_enabled",
    "logging_enabled",
    "mfa_enabled",
    "rotation_enabled"
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
            cursor.execute("""
                UPDATE cloud_ejecuciones
                SET estado='COMPLETED',
                    resultado=%s,
                    fecha_fin=NOW()
                WHERE id=%s
            """, (resultado_json, ejecucion_id))
            conn.commit()
        except Exception as e:
            print(f"Error al marcar como 'COMPLETED': {e}")
        finally:
            cursor.close()
            conn.close()

        # ✅ AUTO-INSERT findings luego de completar
        CloudEjecucion.auto_insert_findings(ejecucion_id, resultado_json)


    @staticmethod
    def auto_insert_findings(ejecucion_id, resultado_json):
        """
        Parsea el resultado del escaneo y auto-inserta un finding por cada
        check interesante detectado. security_rules_id queda NULL hasta que
        el usuario la complete manualmente.
        """
        try:
            # Obtener proyecto_id, usuario_id, provider y service de la ejecución
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT ce.proyecto_id, ce.usuario_id,
                    sa.nombre AS service_nombre
                FROM cloud_ejecuciones ce
                LEFT JOIN servicios_aws_acciones saa ON saa.id = ce.accion_id
                LEFT JOIN servicios_aws sa ON sa.id = saa.servicios_aws_id
                WHERE ce.id = %s
            """, (ejecucion_id,))
            ejecucion = cursor.fetchone()
            cursor.close()
            conn.close()

            if not ejecucion:
                return

            proyecto_id = ejecucion['proyecto_id']
            usuario_id  = ejecucion['usuario_id']

            # Parsear resultado para extraer checks interesantes
            resultado = resultado_json
            if isinstance(resultado, str):
                resultado = json.loads(resultado)

            interesting = CloudEjecucion.extract_interesting(resultado)
            if not interesting:
                return

            # Provider y service vienen del envelope del resultado
            provider = resultado.get('provider', 'aws').lower()
            service  = resultado.get('service', '').lower()

            conn = get_db_connection()
            cursor = conn.cursor()

            for item in interesting:
                resource_id = item.get('resource_id', '')
                check_id    = item.get('check_id', '')

                if not resource_id or not check_id:
                    continue

                cursor.execute("""
                    INSERT INTO findings (
                        proyecto_id,
                        usuario_id,
                        cloud_ejecucion_id,
                        security_rules_id,
                        check_id,
                        provider,
                        service,
                        resource_id,
                        severidad_id,
                        estados_findings_id,
                        estado_id
                    ) VALUES (%s,%s,%s,NULL,%s,%s,%s,%s,1,1,1)
                """, (
                    proyecto_id,
                    usuario_id,
                    ejecucion_id,
                    check_id,
                    provider,
                    service,
                    resource_id
                ))

            conn.commit()
            cursor.close()
            conn.close()

        except Exception as e:
            print(f"[auto_insert_findings] Error: {e}")

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
            added_keys = set()  # evitar duplicados por recurso

            for key, value in analysis.items():
                key_lower = key.lower()

                # ✅ Hallazgo cuando algo riesgoso ES True
                if value is True:
                    for keyword in CloudEjecucion.RISK_KEYWORDS:
                        if keyword in key_lower:
                            if key not in added_keys:
                                interesting.append({
                                    "resource_id": r.get("resource_id"),
                                    "check_id": key
                                })
                                added_keys.add(key)
                            break

                # ✅ Hallazgo cuando algo importante NO está habilitado
                if value is False:
                    for keyword in CloudEjecucion.RISK_FALSE_KEYWORDS:
                        if keyword in key_lower:
                            if key not in added_keys:
                                interesting.append({
                                    "resource_id": r.get("resource_id"),
                                    "check_id": key
                                })
                                added_keys.add(key)
                            break

        return interesting
    
    @staticmethod
    def get_display_name(check_id):
        for keyword in CloudEjecucion.RISK_FALSE_KEYWORDS:
            if keyword in check_id.lower():
                base = check_id.replace("_enabled", "").replace("_", " ").upper()
                return f"{base} Disabled"
        return check_id.replace("_", " ").title()