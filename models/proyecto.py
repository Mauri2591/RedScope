from config import Config
import os
import base64
import uuid
from db import get_db_connection

class Proyecto:
    @staticmethod
    def get_tipo_proyectos():
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = """
        SELECT tipo_proyecto.id, tipo_proyecto.nombre AS tipo, estados.nombre AS estado 
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
    def get_tipos_servicio():
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = """
        SELECT id, nombre FROM tipos_servicio WHERE estado_id=1
        """
        cursor.execute(query,)
        tipos_servicio = cursor.fetchall()
        cursor.close()
        conn.close()
        return tipos_servicio

    @staticmethod
    def insert_proyecto(titulo, cliente, sector_id, usuario_creador_id, tipo_proyecto, tipo_servicio, autenticado, estado_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        query = """
            INSERT INTO proyectos (titulo, cliente, sector_id, usuario_creador_id, tipo_proyecto_id, tipo_servicio_id,autenticado, estado_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (titulo, cliente, sector_id,
                       usuario_creador_id, tipo_proyecto, tipo_servicio, autenticado, estado_id))
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
            p.cliente,
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
            p.cliente,
            u.email,
            pcc.aws_account_id AS cuenta_id,
            IF(ts.nombre IS NULL, 'N/A', ts.nombre) AS tipo_servicio,
            ts.id AS tipo_servicio_id,
            tp.nombre AS tipo_proyecto,
            e.nombre AS estado_proyecto,

            IF (sc.estado_id = 1, 'CLOUD_CONFIGURADO','CLOUD_NO_CONFIGURADO') AS configuracion

        FROM proyectos p

        INNER JOIN usuarios u
            ON p.usuario_creador_id = u.id

        LEFT JOIN tipos_servicio ts
            ON p.tipo_servicio_id = ts.id

        INNER JOIN estados e
            ON p.estado_id = e.id

        LEFT JOIN proyecto_cloud_config sc
            ON sc.proyecto_id = p.id
            INNER JOIN tipo_proyecto tp ON tp.id=p.tipo_proyecto_id
        LEFT JOIN proyecto_cloud_config AS pcc on pcc.proyecto_id=p.id
        WHERE p.id = %s
        AND p.sector_id = %s
        AND p.estado_id != 2;
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
                ce.fecha_fin
            FROM cloud_ejecuciones ce
            LEFT JOIN servicios_aws_acciones saa
                ON saa.id = ce.accion_id
            WHERE ce.proyecto_id = %s
            AND ce.estado_id != 2
        """, (proyecto_id,))

        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        # Lo dejamos como nombre_ui : resultado
        data = {}

        for row in rows:
            data[row["nombre_ui"]] = {
                "id":row['id'],
                "estado": row["estado"],
                "resultado": row["resultado"],
                "error": row["error"],
                "fecha_fin": str(row["fecha_fin"]) if row["fecha_fin"] else None
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
    ce.id AS cloud_ejecuciones_id,
    ce.estado,
    ce.error,
    ce.fecha_creacion AS creacion,
    ce.resultado,
    p.titulo,
    p.cliente
    FROM cloud_ejecuciones ce
    INNER JOIN servicios_aws_acciones saa
        ON ce.accion_id = saa.id
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
        conn=get_db_connection()
        cursor=conn.cursor(dictionary=True)
        query="""
        SELECT * FROM severidades WHERE estado_id = 1
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
    def insert_security_rule(data):

        conn = get_db_connection()
        cursor = conn.cursor()

        query = """
        INSERT INTO security_rules
        (
        provider,
        service,
        check_id,
        title,
        description,
        severidad_id,
        condition_logic,
        remediation,
        reference,
        estado_id
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,1)

        ON DUPLICATE KEY UPDATE

        title = VALUES(title),
        description = VALUES(description),
        severidad_id = VALUES(severidad_id),
        condition_logic = VALUES(condition_logic),
        remediation = VALUES(remediation),
        reference = VALUES(reference),
        actualizacion = CURRENT_TIMESTAMP
        """

        cursor.execute(query,(
            data['provider'],
            data['service'],
            data['check_id'],
            data['title'],
            data['description'],
            data['severidad_id'],
            data['condition_logic'],
            data['remediation'],
            data['reference']
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
        """
        Inserta un hallazgo o actualiza si ya existe.
        Luego inserta las evidencias asociadas en uploads/findings/
        """
        conn = get_db_connection()
        cursor = conn.cursor()

        check_id = data['check_id'].strip()
        resource_id = data['resource_id'].strip()

        # Verificar si ya existe el finding exacto
        cursor.execute("""
            SELECT id FROM findings
            WHERE proyecto_id = %s
            AND cloud_ejecucion_id = %s
            AND security_rules_id = %s
            AND resource_id = %s
            AND check_id = %s
        """, (
            data['proyecto_id'],
            data['cloud_ejecucion_id'],
            data['security_rules_id'],
            resource_id,
            check_id
        ))
        row = cursor.fetchone()

        if row:
            # Actualizar hallazgo existente
            finding_id = row[0]
            cursor.execute("""
                UPDATE findings
                SET
                    usuario_id = %s,
                    severidad_id = %s,
                    estados_findings_id = %s,
                    finding_comment = %s,
                    inventory_data = %s,
                    actualizacion = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (
                usuario_id,
                data['severidad_id'],
                data['estados_findings_id'],
                data.get('finding_comment'),
                data.get('inventory_data'),
                finding_id
            ))
        else:
            # Insertar nuevo hallazgo
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
                    severidad_id,
                    estados_findings_id,
                    inventory_data,
                    finding_comment,
                    estado_id
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1)
            """, (
                data['proyecto_id'],
                usuario_id,
                data['cloud_ejecucion_id'],
                data['security_rules_id'],
                check_id,
                data['provider'],
                data['service'],
                resource_id,
                data['severidad_id'],
                data['estados_findings_id'],
                data.get('inventory_data'),
                data.get('finding_comment')
            ))
            finding_id = cursor.lastrowid

        conn.commit()
        cursor.close()
        conn.close()

        return finding_id

    
    @staticmethod
    def get_finding(check_id, proyecto_id):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT findings.id, findings.estados_findings_id, findings.finding_comment
            FROM findings
            WHERE findings.proyecto_id=%s
            AND findings.check_id=%s AND findings.estado_id=1;
        """
        cursor.execute(query, (proyecto_id, check_id))
        data = cursor.fetchone()
        cursor.close()
        conn.close()
        return data

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