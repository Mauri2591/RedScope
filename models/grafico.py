from db import get_db_connection

class Grafico:
    @staticmethod
    def get_servicios_con_totales():
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Obtén servicios
        sql_servicios = """
        SELECT tipo_proyecto.nombre AS servicio, tipo_proyecto.id AS tipo_proyecto_id, 
            tipos_servicio.nombre AS tipo, tipos_servicio.id AS id_tipo_servicio, 
            tipo_proyecto.descripcion AS descripcion 
        FROM tipo_proyecto 
        INNER JOIN tipos_servicio ON tipos_servicio.tipo_proyecto_id=tipo_proyecto.id 
        WHERE tipo_proyecto.estado_id=1 AND tipos_servicio.estado_id=1
        """
        cursor.execute(sql_servicios)
        servicios = cursor.fetchall()
        
        # Obtén totales
        sql_totales = """
        SELECT tipos_servicio.id, COUNT(proyectos.id) AS total 
        FROM proyectos 
        INNER JOIN tipos_servicio ON tipos_servicio.id=proyectos.tipo_servicio_id 
        GROUP BY tipos_servicio.id
        """
        cursor.execute(sql_totales)
        totales = {row['id']: row['total'] for row in cursor.fetchall()}
        
        # Combina datos
        for servicio in servicios:
            servicio['total'] = totales.get(servicio['id_tipo_servicio'], 0)
        
        cursor.close()
        conn.close()
        return servicios
        
        