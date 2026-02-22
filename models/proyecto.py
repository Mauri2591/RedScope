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

        