from db import get_db_connection

class Servicio:
    @staticmethod
    def alta(nombre, descripcion):
        conn = get_db_connection()
        cursor = conn.cursor()
        sql = "INSERT INTO tipo_proyecto (nombre, descripcion, estado_id) VALUES (%s, %s, 1)"
        params = (nombre, descripcion)
        cursor.execute(sql, params)
        conn.commit()
        cursor.close()
        conn.close()
        
    @staticmethod
    def inhabilitar(id):
        conn = get_db_connection()
        cursor = conn.cursor()
        sql = "UPDATE tipo_proyecto SET estado_id = 2 WHERE id = %s"
        cursor.execute(sql, (id,))
        conn.commit()
        cursor.close()
        conn.close()