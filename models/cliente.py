from db import get_db_connection

class Cliente:
    
    @staticmethod
    def get_all():
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT c.id, c.nombre, c.cuit, c.referencia, e.nombre AS estado
            FROM clientes c
            JOIN estados e ON c.estado_id = e.id
            WHERE c.estado_id = 1
        """)
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        return data
    
    @staticmethod
    def alta(nombre, cuit, referencia):
        conn = get_db_connection()
        cursor = conn.cursor()
        sql = "INSERT INTO clientes (nombre, cuit, referencia, estado_id) VALUES (%s, %s, %s, 1)"
        params = (nombre, cuit, referencia)
        cursor.execute(sql, params)
        conn.commit()
        cursor.close()
        conn.close()
        
    @staticmethod
    def inhabilitar_cliente(id):
        conn = get_db_connection()
        cursor = conn.cursor()
        sql = "UPDATE clientes SET estado_id=2 WHERE id=%s AND estado_id=1"
        params = (id,)
        cursor.execute(sql, params)
        conn.commit()
        cursor.close()
        conn.close()