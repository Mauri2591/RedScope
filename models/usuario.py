from db import get_db_connection
from werkzeug.security import generate_password_hash


class Usuario:
    @staticmethod
    def get_email(email):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        query = """
        SELECT
        u.id,
        u.email,
        u.password_hash,
        r.nombre AS rol,
        s.nombre AS sector,
        s.id AS sector_id,
        e.nombre AS estado
        FROM usuarios u
        JOIN roles r ON u.rol_id = r.id
        JOIN sectores s ON u.sector_id = s.id
        JOIN estados e ON u.estado_id = e.id
        WHERE u.email = %s;
        """
        cursor.execute(query, (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        return user

    @staticmethod
    def update_usuario(user_id, email, password=None):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            if password:
                hashed_password = generate_password_hash(password)

                cursor.execute("""
                    UPDATE usuarios
                    SET email=%s, password_hash=%s
                    WHERE id=%s
                """, (email, hashed_password, user_id))
            else:
                cursor.execute("""
                    UPDATE usuarios
                    SET email=%s
                    WHERE id=%s
                """, (email, user_id))

            conn.commit()

        finally:
            cursor.close()
            conn.close()

        
        