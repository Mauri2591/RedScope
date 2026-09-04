from config import Config
import os
import base64
import uuid
from db import get_db_connection
import json
from helpers.prowler_parser import ProwlerDataExtractor
from helpers.scoutsuite_parser import ScoutSuiteDataExtractor

class Proyecto:
    @staticmethod
    def get_tipo_proyectos():
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = """
        SELECT tipo_proyecto.id, tipo_proyecto.nombre AS tipo, estados.nombre AS estado,tipo_proyecto.descripcion 
        FROM tipo_proyecto 
        INNER JOIN estados 
        ON estados.id=tipo_proyecto.estado_id WHERE tipo_proyecto.estado_id=1
        """
        cursor.execute(query,)
        proyecto = cursor.fetchall()
        cursor.close()
        conn.close()
        return proyecto

    @staticmethod
    def get_tipos_servicio(tipo_proyecto_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = """
        SELECT id, nombre FROM tipos_servicio WHERE tipo_proyecto_id=%s AND estado_id=1
        """
        cursor.execute(query,(tipo_proyecto_id,))
        tipos_servicio = cursor.fetchall()
        cursor.close()
        conn.close()
        return tipos_servicio

    @staticmethod
    def insert_proyecto(titulo, cliente_id, sector_id, usuario_creador_id, tipo_proyecto, tipo_servicio, autenticado, estado_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        query = """
            INSERT INTO proyectos (titulo, cliente_id, sector_id, usuario_creador_id, tipo_proyecto_id, tipo_servicio_id, autenticado, estado_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (titulo, cliente_id, sector_id, usuario_creador_id, tipo_proyecto, tipo_servicio, autenticado, estado_id))
        conn.commit()
        cursor.close()
        conn.close()
    
    @staticmethod
    def get_proyectos(sector_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT 
            p.id,
            p.titulo,
            u.email,
            IF(tp.nombre IS NULL, 'N/A', tp.nombre) AS tipo_proyecto,
            IF(ts.nombre IS NULL, 'N/A', ts.nombre) AS tipo_servicio,

            e.nombre AS estado

            FROM proyectos p

            INNER JOIN usuarios u
                ON p.usuario_creador_id = u.id

            LEFT JOIN tipos_servicio ts
                ON p.tipo_servicio_id = ts.id

            LEFT JOIN tipo_proyecto tp
                ON p.tipo_proyecto_id = tp.id


            INNER JOIN estados e
                ON p.estado_id = e.id

            WHERE p.sector_id = %s AND p.estado_id != 2;
        """
        cursor.execute(query, (sector_id,))
        get_proyectos = cursor.fetchall()
        conn.commit()
        cursor.close()
        conn.close()
        return get_proyectos

    @staticmethod
    def get_by_id(proyecto_id, sector_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT 
                p.id,
                p.titulo,
                clientes.nombre AS cliente,
                u.email,
                IF(ts.nombre IS NULL, 'N/A', ts.nombre) AS tipo_servicio,
                ts.id AS tipo_servicio_id,
                tp.nombre AS tipo_proyecto,
                e.nombre AS estado_proyecto,
                CASE 
                    WHEN tp.nombre = 'CLOUD' AND sc.estado_id = 1 THEN 'CLOUD_CONFIGURADO'
                    WHEN tp.nombre = 'CLOUD' THEN 'CLOUD_NO_CONFIGURADO'
                    WHEN tp.nombre = 'OSINT' AND poc.estado_id = 1 THEN 'OSINT_CONFIGURADO'
                    WHEN tp.nombre = 'OSINT' THEN 'OSINT_NO_CONFIGURADO'
                    ELSE 'NO_CONFIGURADO'
                END AS configuracion
            FROM proyectos p
            INNER JOIN usuarios u ON p.usuario_creador_id = u.id
            LEFT JOIN tipos_servicio ts ON p.tipo_servicio_id = ts.id
            INNER JOIN estados e ON p.estado_id = e.id
            INNER JOIN tipo_proyecto tp ON tp.id = p.tipo_proyecto_id
            LEFT JOIN proyecto_cloud_config sc ON sc.proyecto_id = p.id
            LEFT JOIN proyecto_osint_config poc ON poc.proyecto_id = p.id
            LEFT JOIN clientes ON clientes.id=p.cliente_id
            WHERE p.id = %s
            AND p.sector_id = %s
            AND p.estado_id != 2
            LIMIT 1;
        """
        cursor.execute(query, (proyecto_id, sector_id))
        proyecto = cursor.fetchone()
        cursor.close()
        conn.close()
        return proyecto


    @staticmethod
    def guardar_cloud_config(
        proyecto_id,
        auth_method,
        access_key,
        secret_key,
        role_arn,
        external_id,
        region,
        aws_account_id
    ):
        conn = get_db_connection()
        cursor = conn.cursor()
        query = """
            INSERT INTO proyecto_cloud_config
            (proyecto_id, auth_method, access_key, secret_key, role_arn, external_id, region, aws_account_id, estado_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1)
            ON DUPLICATE KEY UPDATE
                auth_method = VALUES(auth_method),
                access_key = VALUES(access_key),
                secret_key = VALUES(secret_key),
                role_arn = VALUES(role_arn),
                external_id = VALUES(external_id),
                region = VALUES(region),
                aws_account_id = VALUES(aws_account_id),
                estado_id = 1
        """
        cursor.execute(query, (
            proyecto_id,
            auth_method,
            access_key,
            secret_key,
            role_arn,
            external_id,
            region,
            aws_account_id
        ))
        conn.commit()
        cursor.close()
        conn.close()

        
    @staticmethod
    def get_servicios_aws_by_id(tipo_servicio_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query="""
        SELECT servicios_aws.id,servicios_aws.nombre,servicios_aws.descripcion FROM servicios_aws WHERE tipos_servicio_id=%s;
        """
        cursor.execute(query,(tipo_servicio_id,))
        servicios_aws=cursor.fetchall()
        cursor.close()
        conn.close()
        return servicios_aws
    
    
    @staticmethod
    def get_servicios_aws_acciones(servicios_aws_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query="""
        SELECT id,accion_key,nombre_ui,descripcion,handler,requiere_parametros,orden FROM servicios_aws_acciones WHERE servicios_aws_id=%s
        """
        cursor.execute(query,(servicios_aws_id,))
        servicios_aws=cursor.fetchall()
        cursor.close()
        conn.close()
        return servicios_aws
    
    
    @staticmethod
    def get_cloud_config(proyecto_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT auth_method, access_key, secret_key, role_arn, external_id, region
            FROM proyecto_cloud_config
            WHERE proyecto_id=%s
            AND estado_id=1
        """, (proyecto_id,))
        config = cursor.fetchone()
        cursor.close()
        conn.close()
        return config


    @staticmethod
    def get_accion_by_id(accion_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, handler
            FROM servicios_aws_acciones
            WHERE id=%s AND estado_id=1
        """, (accion_id,))

        accion = cursor.fetchone()

        cursor.close()
        conn.close()

        return accion

    @staticmethod
    def get_data_ejecucion_cloud(proyecto_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT 
            saa.nombre_ui,
            ce.id,
            ce.estado,
            ce.resultado,
            ce.error,
            ce.fecha_fin,
            (SELECT COUNT(*) 
            FROM findings f 
            WHERE f.cloud_ejecucion_id = ce.id
            AND f.estado_id = 1) AS total_hallazgos,
            (SELECT COUNT(*) 
            FROM findings f
            LEFT JOIN security_rules sr 
                ON sr.check_id = f.check_id 
                AND sr.service = f.service 
                AND sr.provider = f.provider
                AND sr.estado_id = 1
            WHERE f.cloud_ejecucion_id = ce.id 
            AND f.estado_id = 1
            AND sr.id IS NULL) AS hallazgos_sin_clasificar,
            (SELECT COUNT(*)
            FROM findings f
            WHERE f.cloud_ejecucion_id = ce.id
            AND f.estado_id = 1
            AND (f.verificado IS NULL OR f.verificado != 'SI')) AS hallazgos_sin_verificar
        FROM cloud_ejecuciones ce
        LEFT JOIN servicios_aws_acciones saa
            ON saa.id = ce.accion_id
        WHERE ce.proyecto_id = %s
        AND ce.estado_id != 2
        ORDER BY ce.id ASC
        """, (proyecto_id,))

        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        data = {}
        for row in rows:
            data[row["nombre_ui"]] = {
                "id": row['id'],
                "estado": row["estado"],
                "resultado": row["resultado"],
                "error": row["error"],
                "fecha_fin": str(row["fecha_fin"]) if row["fecha_fin"] else None,
                "total_hallazgos": row["total_hallazgos"],
                "hallazgos_sin_clasificar": row["hallazgos_sin_clasificar"],
                "hallazgos_sin_verificar": row["hallazgos_sin_verificar"]
            }
        return data

    @staticmethod
    def get_data_ejecuciones_para_analisis(proyecto_id, cloud_ejecuciones_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = """
    SELECT 
    saa.nombre_ui,
    saa.descripcion,
    sa.nombre AS servicio,
    ce.id AS cloud_ejecuciones_id,
    ce.estado,
    ce.error,
    ce.fecha_creacion AS creacion,
    ce.resultado,
    p.titulo
    FROM cloud_ejecuciones ce
    INNER JOIN servicios_aws_acciones saa
        ON ce.accion_id = saa.id
    INNER JOIN servicios_aws sa
        ON sa.id = saa.servicios_aws_id
    INNER JOIN proyectos p
        ON p.id = ce.proyecto_id
    WHERE ce.proyecto_id = %s
    AND ce.id = %s;
            """
        cursor.execute(query, (proyecto_id, cloud_ejecuciones_id))
        accion = cursor.fetchone()
        cursor.close()
        conn.close()
        return accion
        
    @staticmethod
    def insert_cloud_findings(ejecucion_id, findings):
        if not findings:
            return
        conn = get_db_connection()
        cursor = conn.cursor()
        data = []
        for f in findings:
            data.append((
                ejecucion_id,
                f.get("resource_id"),
                f.get("check_id")
            ))
        cursor.executemany("""
            INSERT INTO cloud_ejecucion_findings
            (cloud_ejecucion_id, resource_id, check_id)
            VALUES (%s, %s, %s)
        """, data)
        conn.commit()
        conn.close()
    
    @staticmethod
    def get_security_rules(check_id):

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = """
        SELECT *
        FROM security_rules
        WHERE check_id = %s
        AND estado_id = 1
        """

        cursor.execute(query, (check_id,))
        data = cursor.fetchone()

        cursor.close()
        conn.close()

        return data

    @staticmethod
    def get_severidades():
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = """
        SELECT id, nombre, color, score, orden 
        FROM severidades 
        WHERE estado_id = 1 
        ORDER BY orden
        """
        cursor.execute(query)
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        return data

    @staticmethod
    def get_combo_estados_findings():
        conn=get_db_connection()
        cursor=conn.cursor(dictionary=True)
        query="""
        SELECT * FROM estados_findings WHERE estado_id=1
        """
        cursor.execute(query)
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        return data
    
    @staticmethod
    def insert_security_rule(data, usuario_id):
        """Path manual — el pentester carga o edita desde el form. Siempre valida."""
        conn = get_db_connection()
        cursor = conn.cursor()

        query = """
        INSERT INTO security_rules
        (provider, service, check_id, title, description, severidad_id,
        condition_logic, remediation, reference, estado_id, validado_por, validado_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s,CURRENT_TIMESTAMP)
        ON DUPLICATE KEY UPDATE
            title = VALUES(title),
            description = VALUES(description),
            severidad_id = VALUES(severidad_id),
            condition_logic = VALUES(condition_logic),
            remediation = VALUES(remediation),
            reference = VALUES(reference),
            validado_por = VALUES(validado_por),
            validado_at = CURRENT_TIMESTAMP,
            actualizacion = CURRENT_TIMESTAMP
        """
        cursor.execute(query, (
            data['provider'], data['service'], data['check_id'],
            data['title'], data['description'], data['severidad_id'],
            data['condition_logic'], data['remediation'], data['reference'],
            usuario_id
        ))

        conn.commit()
        rule_id = cursor.lastrowid
        cursor.close()
        conn.close()
        return rule_id
    
    @staticmethod
    def insert_security_rule_ia(data):
        """Path automático — llamado por tasks/cloud/security_rules_ia.py. Nunca toca validado_por."""
        conn = get_db_connection()
        cursor = conn.cursor()

        query = """
        INSERT INTO security_rules
        (provider, service, check_id, title, description, severidad_id,
        condition_logic, remediation, reference, estado_id, creado_por_ia)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,1,1)
        ON DUPLICATE KEY UPDATE
            estado_id = 1,
            creado_por_ia = 1,
            check_id = check_id
        """
        cursor.execute(query, (
            data['provider'], data['service'], data['check_id'],
            data['title'], data['description'], data['severidad_id'],
            data['condition_logic'], data['remediation'], data['reference']
        ))

        conn.commit()
        rule_id = cursor.lastrowid
        cursor.close()
        conn.close()
        return rule_id
    
    @staticmethod
    def insert_evidences(finding_id, evidencias):
        import os, base64, uuid
        from config import Config

        if not evidencias:
            return

        conn = get_db_connection()
        cursor = conn.cursor()

        path_dir = os.path.join(Config.BASE_DIR, "uploads", "findings")
        os.makedirs(path_dir, exist_ok=True)

        for img in evidencias:
            if not img.startswith("data:image"):
                continue

            header, encoded = img.split(",", 1)
            binary = base64.b64decode(encoded)

            # Nombre único por imagen
            filename = f"{uuid.uuid4()}.png"
            path = os.path.join(path_dir, filename)

            # Guardar en disco
            with open(path, "wb") as f:
                f.write(binary)

            relative_path = f"uploads/findings/{filename}"

            # Insertar directamente en DB
            cursor.execute("""
                INSERT INTO findings_evidence(finding_id, file_path, estado_id)
                VALUES (%s, %s, 1)
            """, (finding_id, relative_path))

        conn.commit()
        cursor.close()
        conn.close()
        
    @staticmethod
    def insert_finding(data, usuario_id):
        conn = get_db_connection()
        cursor = conn.cursor()

        check_id = data['check_id'].strip()
        resource_id = data['resource_id'].strip()
        cloud_ejecucion_id = data.get('cloud_ejecucion_id')
        proyecto_id = data['proyecto_id']

        # ========================
        # BUSCAR SI YA EXISTE
        # ========================
        cursor.execute("""
            SELECT id, herramienta FROM findings
            WHERE proyecto_id = %s 
            AND check_id = %s 
            AND resource_id = %s 
            AND estado_id = 1
            LIMIT 1
        """, (proyecto_id, check_id, resource_id))
        
        existe = cursor.fetchone()

        if existe:
            # ========================
            # UPDATE (preservar herramienta original)
            # ========================
            finding_id = existe[0]
            
            cursor.execute("""
                UPDATE findings SET
                    usuario_id = %s,
                    security_rules_id = %s,
                    severidad_id = %s,
                    estados_findings_id = %s,
                    finding_comment = %s,
                    inventory_data = %s,
                    region = %s,
                    actualizacion = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (
                usuario_id,
                data.get('security_rules_id'),
                data['severidad_id'],
                data['estados_findings_id'],
                data.get('finding_comment'),
                data.get('inventory_data'),
                data.get('region', ''),
                finding_id
            ))
        else:
            # ========================
            # INSERT (nuevo finding)
            # ========================
            cursor.execute("""
                INSERT INTO findings(
                    proyecto_id,
                    usuario_id,
                    cloud_ejecucion_id,
                    security_rules_id,
                    check_id,
                    provider,
                    service,
                    resource_id,
                    region,
                    severidad_id,
                    estados_findings_id,
                    inventory_data,
                    finding_comment,
                    herramienta,
                    estado_id
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1)
            """, (
                proyecto_id,
                usuario_id,
                data.get('cloud_ejecucion_id'),
                data.get('security_rules_id'),
                check_id,
                data['provider'],
                data['service'],
                resource_id,
                data.get('region', ''),
                data['severidad_id'],
                data['estados_findings_id'],
                data.get('inventory_data'),
                data.get('finding_comment'),
                data.get('herramienta')  # ← Preservar herramienta
            ))
            
            finding_id = cursor.lastrowid

        conn.commit()
        cursor.close()
        conn.close()

        return finding_id

    @staticmethod
    def get_estado_reglas(check_ids):
        """Devuelve dict {check_id: {'existe': bool, 'creado_por_ia': bool, 'validado_por': int|None}}"""
        if not check_ids:
            return {}
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        format_strings = ','.join(['%s'] * len(check_ids))
        cursor.execute(f"""
            SELECT check_id, creado_por_ia, validado_por, origen
            FROM security_rules
            WHERE check_id IN ({format_strings})
            AND estado_id = 1
        """, list(check_ids))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return {
            r['check_id']: {
                'existe': True,
                'creado_por_ia': bool(r['creado_por_ia']),
                'validado_por': r['validado_por'],
                'origen': r['origen']
            }
            for r in rows
        }
        
    # @staticmethod lo borré por el de arriba get_estado_reglas
    # def get_check_ids_con_regla(check_ids):
    #     """Devuelve el set de check_id que ya tienen una security_rule activa en el catálogo."""
    #     if not check_ids:
    #         return set()
    #     conn = get_db_connection()
    #     cursor = conn.cursor(dictionary=True)
    #     format_strings = ','.join(['%s'] * len(check_ids))
    #     cursor.execute(f"""
    #         SELECT DISTINCT check_id FROM security_rules
    #         WHERE check_id IN ({format_strings})
    #         AND estado_id = 1
    #     """, list(check_ids))
    #     rows = cursor.fetchall()
    #     cursor.close()
    #     conn.close()
    #     return {r['check_id'] for r in rows}
    
    @staticmethod
    def get_finding(check_id, proyecto_id, resource_id=None, cloud_ejecucion_id=None):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        query = """
            SELECT id, estados_findings_id, finding_comment, security_rules_id
            FROM findings
            WHERE proyecto_id = %s
            AND check_id = %s
            AND estado_id = 1
        """
        params = [proyecto_id, check_id]

        if resource_id:
            query += " AND resource_id = %s"
            params.append(resource_id)

        if cloud_ejecucion_id:
            query += " AND cloud_ejecucion_id = %s"
            params.append(int(cloud_ejecucion_id))

        query += " LIMIT 1"
        
        cursor.execute(query, params)
        data = cursor.fetchone()
        cursor.close()
        conn.close()
        return data

    @staticmethod
    def enrich_findings_with_ids(findings, proyecto_id, ejecucion_id):
        if not findings:
            return findings

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        enriched = []
        for f in findings:
            cursor.execute("""
                SELECT id, security_rules_id, estados_findings_id, finding_comment, verificado
                FROM findings
                WHERE proyecto_id = %s
                AND cloud_ejecucion_id = %s
                AND resource_id = %s
                AND check_id = %s
                AND estado_id = 1
                ORDER BY security_rules_id DESC, id DESC
                LIMIT 1
            """, (proyecto_id, ejecucion_id, f['resource_id'], f['check_id']))
            row = cursor.fetchone()
            f['finding_id'] = row['id'] if row else None
            f['security_rules_id'] = row['security_rules_id'] if row else None
            f['verificado'] = row['verificado'] if row else None
            enriched.append(f)

        cursor.close()
        conn.close()
        return enriched

    @staticmethod
    def delete_finding(finding_id, herramienta=None):
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if herramienta:
            cursor.execute("UPDATE findings SET estado_id=2 WHERE id=%s AND herramienta=%s", (finding_id, herramienta))
        else:
            cursor.execute("UPDATE findings SET estado_id=2 WHERE id=%s", (finding_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
    
    @staticmethod
    def get_finding_by_id(finding_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, proyecto_id, cloud_ejecucion_id, security_rules_id,
                check_id, provider, service, resource_id, region, severidad_id,
                estados_findings_id, finding_comment, inventory_data, referencias_data
            FROM findings
            WHERE id = %s AND estado_id = 1
        """, (finding_id,))
        data = cursor.fetchone()
        cursor.close()
        conn.close()
        return data
    
    @staticmethod
    def get_resultado_ejecucion(cloud_ejecucion_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT resultado
            FROM cloud_ejecuciones
            WHERE id = %s
        """, (cloud_ejecucion_id,))
        data = cursor.fetchone()
        cursor.close()
        conn.close()
        return data['resultado'] if data else None

    @staticmethod
    def get_finding_evidencias(finding_id):
        """
        Devuelve todas las evidencias activas de un hallazgo
        """
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT file_path
            FROM findings_evidence
            WHERE finding_id=%s AND estado_id=1
            ORDER BY id
        """
        cursor.execute(query, (finding_id,))
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        return data
    
    @staticmethod
    def get_finding_evidencias_img(finding_id):
        """
        Devuelve todas las evidencias activas de un hallazgo
        """
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT id, file_path
            FROM findings_evidence
            WHERE finding_id=%s AND estado_id=1
            ORDER BY id
        """
        cursor.execute(query, (finding_id,))
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        return data
    
    @staticmethod
    def delete_evidences(ids):
        if not ids:
            return
        conn = get_db_connection()
        cursor = conn.cursor()
        format_strings = ','.join(['%s'] * len(ids))
        query = f"""
            UPDATE findings_evidence 
            SET estado_id = %s 
            WHERE id IN ({format_strings})
        """
        cursor.execute(query, tuple([2] + ids))
        conn.commit()
        cursor.close()
        conn.close()


# *****************************  Reportes  ***************************
#------------- CSV ------------
    @staticmethod
    def get_data_reporte(proyecto_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = """
        SELECT
            p.titulo AS proyecto_titulo,
            f.id AS finding_id,
            f.provider AS proveedor,
            f.service AS servicio,
            f.check_id,
            f.region,
            sr.title AS titulo,
            sr.description AS descripcion,
            sev.id AS severidad_id,
            sev.nombre AS severidad,
            sr.condition_logic AS condicion_logica,
            sr.remediation AS remediacion,
            sr.reference AS referencia,
            f.resource_id,
            f.inventory_data,
            f.referencias_data,
            f.finding_comment,
            GROUP_CONCAT(fe.file_path ORDER BY fe.id SEPARATOR '|') AS imagenes
        FROM findings f
        INNER JOIN proyectos p
            ON p.id = f.proyecto_id
        LEFT JOIN cloud_ejecuciones ce
            ON ce.id = f.cloud_ejecucion_id
        LEFT JOIN (
            SELECT accion_id, MAX(id) AS ultima_ejecucion_id
            FROM cloud_ejecuciones
            WHERE proyecto_id = %s
            AND estado_id != 2
            GROUP BY accion_id
        ) ultima
            ON ultima.accion_id = ce.accion_id
            AND ultima.ultima_ejecucion_id = ce.id
        LEFT JOIN security_rules sr
            ON sr.check_id = f.check_id
            AND sr.service = f.service
            AND sr.provider = f.provider
        LEFT JOIN severidades sev
            ON sev.id = sr.severidad_id
        LEFT JOIN findings_evidence fe
            ON fe.finding_id = f.id AND fe.estado_id = 1
        WHERE f.proyecto_id = %s
        AND f.estado_id = 1
        AND (f.cloud_ejecucion_id IS NULL OR ultima.ultima_ejecucion_id IS NOT NULL)
        GROUP BY f.id
        ORDER BY sev.orden DESC;
        """
        cursor.execute(query, (proyecto_id, proyecto_id))
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        return data
    
    
    
    @staticmethod
    def get_reporte_tema():
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT uso, hex FROM reporte_tema WHERE estado_id=1
        """)
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        # Retorna dict { 'fondo_primario': '#1E1B4B', 'acento': '#00B4D8', ... }
        return {row['uso']: row['hex'] for row in rows}

    @staticmethod
    def get_reporte_estructura(proveedor='aws'):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT clave, subtitulo, tipo, pagina_ref, orden, es_dinamico
            FROM reporte_estructura_cloud
            WHERE proveedor = %s AND estado_id = 1
            ORDER BY orden ASC
        """, (proveedor,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    
    @staticmethod
    def get_contenido_secciones(tipo_servicio: str) -> dict:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM reporte_contenido_secciones
            WHERE LOWER(tipo_servicio) = LOWER(%s) AND estado_id = 1
            LIMIT 1
        """, (tipo_servicio,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return result or {}
    
    
    @staticmethod
    def get_todas_las_acciones(tipo_servicio_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT saa.id, saa.nombre_ui, saa.handler
            FROM servicios_aws_acciones saa
            INNER JOIN servicios_aws sa ON sa.id = saa.servicios_aws_id
            WHERE sa.tipos_servicio_id = %s
            AND saa.estado_id = 1
            ORDER BY sa.id ASC, saa.orden ASC
        """, (tipo_servicio_id,))
        acciones = cursor.fetchall()
        cursor.close()
        conn.close()
        return acciones
    
    #---------------------------------------------------------------------------#
    #-------------------------------- Importar archivos de findings de herramientas ------------#
    @staticmethod
    def import_findings(proyecto_id, herramienta, data, usuario_id):
        if herramienta == 'prowler_cli':
            return Proyecto._import_prowler_cli(proyecto_id, data, usuario_id)
        elif herramienta == 'prowler_web':
            return Proyecto._import_prowler_web(proyecto_id, data, usuario_id)
        elif herramienta == 'scoutsuite_cli':
            return Proyecto._import_scoutsuite_cli(proyecto_id, data, usuario_id)
        elif herramienta == 'scoutsuite_web':
            return Proyecto._import_scoutsuite_web(proyecto_id, data, usuario_id)
        return 0

    @staticmethod
    def get_imported_findings_by_proyecto(proyecto_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT f.herramienta AS origen, COUNT(DISTINCT f.id) as total
            FROM findings f
            WHERE f.proyecto_id = %s AND f.cloud_ejecucion_id IS NULL AND f.estado_id = 1
            GROUP BY f.herramienta
        """, (proyecto_id,))
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        return data

    # ============================================================================
# REEMPLAZAR ESTOS MÉTODOS EN models/proyecto.py
# ============================================================================

    @staticmethod
    def _normalize_prowler_data(data):
        """
        Normaliza la entrada de Prowler a una lista de items.
        Prowler puede retornar:
        - Array directo: [{ CheckID: ..., Status: ... }, ...]
        - Objeto con clave 'findings': { findings: [...] }
        - Otros formatos
        """
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            # Intenta extraer array de keys comunes
            for key in ['findings', 'Findings', 'checks', 'Checks', 'data', 'Data']:
                if key in data and isinstance(data[key], list):
                    return data[key]
            # Si es un dict con CheckID, envolver en array
            if 'CheckID' in data:
                return [data]
        return []

    @staticmethod
    def _import_prowler_cli(proyecto_id, data, usuario_id):
        """Importa findings desde Prowler CLI (formato JSON plano)"""
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        importados = 0
        
        # Normalizar entrada
        items = Proyecto._normalize_prowler_data(data)
        if not items:
            cursor.close()
            conn.close()
            return 0
        
        severidades = Proyecto.get_severidades()
        severidad_map = {s['nombre'].lower(): s['id'] for s in severidades}
        
        try:
            for idx, item in enumerate(items):
                check_id = item.get('CheckID', '').strip()
                status = item.get('Status', '').upper()
                
                # Debug
                print(f"[PROWLER_CLI] idx={idx} CheckID={check_id} Status={status}")
                
                # Solo importar FAIL
                if status != 'FAIL':
                    continue
                
                if not check_id:
                    print(f"[PROWLER_CLI] Saltando item sin CheckID en índice {idx}")
                    continue
                
                provider = item.get('Provider', 'aws').lower()
                service = item.get('ServiceName', '').lower()
                resource_id = item.get('ResourceId', '')
                region = item.get('Region', '')

                # Mapear severity text a ID (Prowler devuelve 'high', 'medium', 'critical', 'low')
                severity_text = str(item.get('Severity', 'medium')).lower()
                severidad_id = severidad_map.get(severity_text, 3)
                
                # ========================
                # Guardar o actualizar security_rule
                # ========================
                cursor.execute("""
                    INSERT INTO security_rules 
                    (provider, service, check_id, title, description, severidad_id, 
                    remediation, reference, origen, estado_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'prowler', 1)
                    ON DUPLICATE KEY UPDATE 
                        reference = COALESCE(NULLIF(VALUES(reference), ''), reference),
                        origen = COALESCE(NULLIF(VALUES(origen), ''), origen),
                        estado_id = 1
                """, (
                    provider,
                    service,
                    check_id,
                    item.get('CheckTitle', check_id)[:200],
                    item.get('Risk', '')[:500],
                    severidad_id,
                    item.get('Remediation', {}).get('Recommendation', {}).get('Text', '')[:500] if isinstance(item.get('Remediation'), dict) else '',
                    item.get('RelatedUrl', item.get('Remediation', {}).get('Recommendation', {}).get('Url') if isinstance(item.get('Remediation'), dict) else None)
                ))
                
                # Obtener ID de la rule
                cursor.execute("SELECT id FROM security_rules WHERE check_id = %s LIMIT 1", (check_id,))
                rule_row = cursor.fetchone()
                security_rule_id = rule_row['id'] if rule_row else None
                
                # ========================
                # Verificar si el finding ya existe
                # ========================
                cursor.execute("""
                    SELECT id FROM findings 
                    WHERE proyecto_id = %s 
                    AND check_id = %s 
                    AND resource_id = %s 
                    AND herramienta = 'prowler_cli'
                    AND cloud_ejecucion_id IS NULL 
                    AND estado_id = 1
                    LIMIT 1
                """, (proyecto_id, check_id, resource_id))
                
                existe = cursor.fetchone()
                if existe:
                    print(f"[PROWLER_CLI] ⏭️  Ya existe: check_id={check_id} resource={resource_id}")
                    continue
                
                # ========================
                # Separar datos: inventory vs referencias (igual que Prowler Web)
                # ========================
                # inventory_data: SOLO salida de la herramienta (status + account)
                inventory_json = json.dumps({
                    "status_code": status,
                    "account_id": item.get('AccountId', '')
                }, ensure_ascii=False)

                # referencias_data: compliance, remediation, etc.
                referencias_json = json.dumps({
                    "compliance": item.get('Compliance', {}),
                    "remediation": item.get('Remediation', {}).get('Recommendation', {}).get('Text', ''),
                    "remediation_url": item.get('RelatedUrl', item.get('Remediation', {}).get('Recommendation', {}).get('Url') if isinstance(item.get('Remediation'), dict) else None),
                    "risk_details": item.get('Risk', ''),
                    "referencias": [
                        {
                            "title": "Remediation",
                            "url": item.get('RelatedUrl', item.get('Remediation', {}).get('Recommendation', {}).get('Url') if isinstance(item.get('Remediation'), dict) else '')
                        }
                    ] if item.get('RelatedUrl') or (isinstance(item.get('Remediation'), dict) and item.get('Remediation', {}).get('Recommendation', {}).get('Url')) else []
                }, ensure_ascii=False)

                cursor.execute("""
                    INSERT INTO findings
                    (proyecto_id, usuario_id, security_rules_id, check_id,
                    provider, service, resource_id, region, severidad_id,
                    estados_findings_id, inventory_data, referencias_data, herramienta, estado_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 1, %s, %s, 'prowler_cli', 1)
                """, (
                    proyecto_id, usuario_id, security_rule_id, check_id,
                    provider, service, resource_id, region, severidad_id,
                    inventory_json, referencias_json
                ))

                importados += 1
                print(f"[PROWLER_CLI] Importado: {check_id} - {resource_id}")
            
            conn.commit()
        
        except Exception as e:
            conn.rollback()
            print(f"[PROWLER_CLI ERROR] {str(e)}")
            import traceback
            traceback.print_exc()
        
        finally:
            cursor.close()
            conn.close()
        
        print(f"[PROWLER_CLI] Total importados: {importados}")
        return importados

    @staticmethod
    def _import_prowler_web(proyecto_id, data, usuario_id):
        """Importa findings desde Prowler Web (JSON-OCSF)"""
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        importados = 0
        
        items = Proyecto._normalize_prowler_data(data)
        if not items:
            cursor.close()
            conn.close()
            return 0
        
        severidades = Proyecto.get_severidades()
        severidad_map = {s['nombre'].lower(): s['id'] for s in severidades}
        
        try:
            for idx, item in enumerate(items):
                # OCSF structure
                status_code = item.get('status_code', '').upper()
                check_id = item.get('metadata', {}).get('event_code', '').strip()

                print(f"[PROWLER_WEB] idx={idx} CheckID={check_id} Status={status_code}")

                if status_code != 'FAIL':
                    continue

                if not check_id:
                    print(f"[PROWLER_WEB] Sin CheckID en idx {idx}")
                    continue

                # Extraer datos
                provider = item.get('cloud', {}).get('provider', 'aws').lower()
                region = item.get('cloud', {}).get('region', '')
                account_id = item.get('cloud', {}).get('account', {}).get('uid', '')

                # Recurso: primera del array
                resources = item.get('resources', [])
                resource_id = resources[0].get('uid', '') if resources else ''
                service = resources[0].get('group', {}).get('name', '') if resources else ''

                # Mapear severity text a ID (OCSF puede devolver 'high', 'medium', 'critical', 'low')
                severity_text = str(item.get('severity_id', item.get('severity', 'medium'))).lower()
                severidad_id = severidad_map.get(severity_text, 3)
                
                # Usar parser para extraer datos correctamente
                parsed = ProwlerDataExtractor.parse_prowler_item(item)

                # Guardar security_rule (usando datos parseados)
                cursor.execute("""
                    INSERT INTO security_rules
                    (provider, service, check_id, title, description, severidad_id,
                    remediation, reference, condition_logic, origen, estado_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'prowler_web', 1)
                    ON DUPLICATE KEY UPDATE
                        reference = COALESCE(NULLIF(VALUES(reference), ''), reference),
                        condition_logic = COALESCE(NULLIF(VALUES(condition_logic), ''), condition_logic),
                        origen = COALESCE(NULLIF(VALUES(origen), ''), origen),
                        estado_id = 1
                """, (
                    provider,
                    service,
                    check_id,
                    parsed.get('title', check_id)[:200],
                    parsed.get('description', '')[:500],
                    severidad_id,
                    parsed.get('remediation', '')[:500],
                    parsed.get('remediation_url', ''),
                    parsed.get('condition_logic', '')[:500]  # Condición Lógica (extraída del parser)
                ))
                
                cursor.execute("SELECT id FROM security_rules WHERE check_id = %s LIMIT 1", (check_id,))
                rule_row = cursor.fetchone()
                security_rule_id = rule_row['id'] if rule_row else None
                
                # Verificar duplicado
                cursor.execute("""
                SELECT id FROM findings 
                WHERE proyecto_id = %s 
                AND check_id = %s 
                AND resource_id = %s 
                AND herramienta = 'prowler_web'
                AND cloud_ejecucion_id IS NULL 
                AND estado_id = 1
                LIMIT 1
            """, (proyecto_id, check_id, resource_id))
                
                if cursor.fetchone():
                    print(f"[PROWLER_WEB] ⏭️  Ya existe: {check_id} - {resource_id}")
                    continue
                
                # Usar parser ya creado arriba para separar datos
                inventory_json = ProwlerDataExtractor.generate_inventory_json(parsed)
                referencias_json = ProwlerDataExtractor.generate_referencias_json(parsed)

                cursor.execute("""
                    INSERT INTO findings
                    (proyecto_id, usuario_id, security_rules_id, check_id,
                    provider, service, resource_id, region, severidad_id,
                    estados_findings_id, inventory_data, referencias_data, herramienta, estado_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 1, %s, %s, 'prowler_web', 1)
                """, (
                    proyecto_id, usuario_id, security_rule_id, check_id,
                    provider, service, resource_id, region, severidad_id,
                    inventory_json, referencias_json
                ))
                
                importados += 1
                print(f"[PROWLER_WEB] Importado: {check_id}")
            
            conn.commit()
        
        except Exception as e:
            conn.rollback()
            print(f"[PROWLER_WEB ERROR] {str(e)}")
            import traceback
            traceback.print_exc()
        
        finally:
            cursor.close()
            conn.close()
        
        print(f"[PROWLER_WEB] Total: {importados}")
        return importados

    @staticmethod
    def _import_scoutsuite_cli(proyecto_id, data, usuario_id):
        """Importa findings desde ScoutSuite"""
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        importados = 0

        # Extraer account_id del JSON
        account_id = data.get('account_id', '')
        print(f"[SCOUTSUITE_CLI] Account ID: {account_id}")
        print(f"[SCOUTSUITE_CLI] Data keys: {list(data.keys())}")

        if not account_id:
            print(f"[SCOUTSUITE_CLI] ERROR: No account_id en JSON")
            cursor.close()
            conn.close()
            return 0

        severidades = Proyecto.get_severidades()
        severidad_map = {s['nombre'].lower(): s['id'] for s in severidades}

        try:
            # Iterar sobre servicios
            services = data.get('services', {})
            print(f"[SCOUTSUITE_CLI] Services encontrados: {list(services.keys())}")

            for service_name, service_data in services.items():
                # Procesar findings del servicio
                findings = service_data.get('findings', {})

                for finding_id, finding_data in findings.items():
                    # Saltar si no hay items flagged
                    if finding_data.get('flagged_items', 0) == 0:
                        continue

                    level = finding_data.get('level', 'warning').lower()
                    severity_name = 'critical' if level == 'danger' else ('medium' if level == 'warning' else 'low')
                    severidad_id = severidad_map.get(severity_name, 3)

                    print(f"[SCOUTSUITE_CLI] Finding={finding_id} Level={level} Service={service_name}")

                    # Parsear el finding (genera multiple items, uno por recurso)
                    parsed_items = ScoutSuiteDataExtractor.parse_scoutsuite_finding(
                        finding_id, finding_data, account_id
                    )

                    if not parsed_items:
                        continue

                    # Guardar security_rule (una vez por finding)
                    description = finding_data.get('description') or ''
                    remediation = finding_data.get('remediation') or ''
                    references = finding_data.get('references') or []
                    reference_url = references[0] if references and isinstance(references, list) else ''

                    cursor.execute("""
                        INSERT INTO security_rules
                        (provider, service, check_id, title, description, severidad_id,
                        remediation, reference, condition_logic, origen, estado_id)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'scoutsuite_cli', 1)
                        ON DUPLICATE KEY UPDATE
                            reference = COALESCE(NULLIF(VALUES(reference), ''), reference),
                            condition_logic = COALESCE(NULLIF(VALUES(condition_logic), ''), condition_logic),
                            origen = COALESCE(NULLIF(VALUES(origen), ''), origen),
                            estado_id = 1
                    """, (
                        'aws',
                        service_name.lower(),
                        finding_id,
                        (description or '')[:200],
                        (description or '')[:500],
                        severidad_id,
                        (remediation or '')[:500],
                        reference_url,
                        ''
                    ))

                    cursor.execute("SELECT id FROM security_rules WHERE check_id = %s LIMIT 1", (finding_id,))
                    rule_row = cursor.fetchone()
                    security_rule_id = rule_row['id'] if rule_row else None

                    # Importar cada item parseado como un finding
                    for parsed in parsed_items:
                        check_id = parsed['check_id']
                        resource_id = parsed['resource_id']
                        region = parsed['region']

                        # Verificar duplicado
                        cursor.execute("""
                            SELECT id FROM findings
                            WHERE proyecto_id = %s
                            AND check_id = %s
                            AND resource_id = %s
                            AND herramienta = 'scoutsuite_cli'
                            AND cloud_ejecucion_id IS NULL
                            AND estado_id = 1
                            LIMIT 1
                        """, (proyecto_id, check_id, resource_id))

                        if cursor.fetchone():
                            print(f"[SCOUTSUITE_CLI] ⏭️  Ya existe: {check_id} - {resource_id}")
                            continue

                        # Generar JSONs
                        inventory_json = ScoutSuiteDataExtractor.generate_inventory_json(parsed)
                        referencias_json = ScoutSuiteDataExtractor.generate_referencias_json(parsed)

                        # Insertar finding
                        cursor.execute("""
                            INSERT INTO findings
                            (proyecto_id, usuario_id, security_rules_id, check_id,
                            provider, service, resource_id, region, severidad_id,
                            estados_findings_id, inventory_data, referencias_data, herramienta, estado_id)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 1, %s, %s, 'scoutsuite_cli', 8, 1)
                        """, (
                            proyecto_id, usuario_id, security_rule_id, check_id,
                            'aws', service_name.lower(), resource_id, region, severidad_id,
                            inventory_json, referencias_json
                        ))

                        importados += 1
                        print(f"[SCOUTSUITE_CLI] ✓ Importado: {check_id} - {resource_id}")

            conn.commit()

        except Exception as e:
            conn.rollback()
            print(f"[SCOUTSUITE ERROR] {str(e)}")
            import traceback
            traceback.print_exc()

        finally:
            cursor.close()
            conn.close()

        print(f"[SCOUTSUITE_CLI] Total importados: {importados}")
        return importados

    @staticmethod
    def _import_scoutsuite_web(proyecto_id, data, usuario_id):
        """
        Importa findings desde ScoutSuite Web (versión paga)
        Implementación futura cuando se tenga acceso a la versión Web
        """
        print("[SCOUTSUITE_WEB] No implementado aún")
        return 0

    @staticmethod
    def get_findings_importados(proyecto_id, herramienta):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT f.id as finding_id, f.check_id, f.resource_id, f.region,
                f.severidad_id, f.estados_findings_id, f.finding_comment,
                f.verificado, f.inventory_data, f.security_rules_id,
                f.provider, f.service, f.cloud_ejecucion_id, f.herramienta,
                sr.origen AS rule_origen
            FROM findings f
            LEFT JOIN security_rules sr ON f.security_rules_id = sr.id
            WHERE f.proyecto_id = %s 
            AND f.cloud_ejecucion_id IS NULL
            AND f.estado_id = 1
            AND f.herramienta = %s
        """, (proyecto_id, herramienta))
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        return data
    
    @staticmethod
    def verificar_findings_masivo(ids):
        if not ids: return
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        format_strings = ','.join(['%s'] * len(ids))
        cursor.execute(f"UPDATE findings SET verificado='SI' WHERE id IN ({format_strings})", ids)
        conn.commit()
        cursor.close()
        conn.close()

    @staticmethod
    def eliminar_findings_masivo(ids, herramienta=None):
        if not ids: return
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        format_strings = ','.join(['%s'] * len(ids))
        
        if herramienta:
            cursor.execute(f"UPDATE findings SET estado_id=2 WHERE id IN ({format_strings}) AND herramienta = %s", ids + [herramienta])
        else:
            cursor.execute(f"UPDATE findings SET estado_id=2 WHERE id IN ({format_strings})", ids)
        
        conn.commit()
        cursor.close()
        conn.close()
        
    @staticmethod
    def get_findings_con_inventory(proyecto_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT f.id, f.check_id, f.resource_id, f.service, 
                f.severidad_id, f.inventory_data
            FROM findings f
            WHERE f.proyecto_id = %s 
            AND f.estado_id = 1
            AND f.inventory_data IS NOT NULL
        """, (proyecto_id,))
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        return data
    
    
    #-----------------   OSINT ---------------------
    @staticmethod
    def get_osint_config_tipos():
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM osint_config_tipos WHERE activo = 1")
        datos = cursor.fetchall()
        cursor.close()
        conn.close()
        return datos

    @staticmethod
    def guardar_osint_config(proyecto_id, config_data):
        """config_data es dict: {config_tipo_id: valor, ...}"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Limpiar config anterior
        cursor.execute("DELETE FROM proyecto_osint_config WHERE proyecto_id = %s", (proyecto_id,))
        
        # Insertar nueva config
        for config_tipo_id, valor in config_data.items():
            if valor.strip():
                cursor.execute("""
                    INSERT INTO proyecto_osint_config (proyecto_id, config_tipo_id, valor, estado_id)
                    VALUES (%s, %s, %s, 1)
                """, (proyecto_id, config_tipo_id, valor))
        
        conn.commit()
        cursor.close()
        conn.close()
        
    @staticmethod
    def get_osint_config(proyecto_id):
        """Retorna dict con config OSINT del proyecto"""
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT ct.nombre, poc.valor
            FROM proyecto_osint_config poc
            INNER JOIN osint_config_tipos ct ON ct.id = poc.config_tipo_id
            WHERE poc.proyecto_id = %s AND poc.estado_id = 1
        """, (proyecto_id,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return {row['nombre']: row['valor'] for row in rows}
    
    @staticmethod
    def get_servicios_osint_pasivo():
        """Retorna servicios OSINT disponibles"""
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, nombre, descripcion, tipo_analisis, orden
            FROM servicios_osint
            WHERE tipos_servicio_id = 4 AND tipo_analisis = 'PASIVO' AND estado_id = 1
            ORDER BY (orden IS NULL), orden ASC, id ASC;
        """)
        servicios = cursor.fetchall()
        cursor.close()
        conn.close()
        return servicios

   