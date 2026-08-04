"""
Endpoint temporal para debuggear conclusiones dinámicas
"""
from flask import Blueprint, jsonify
from db import get_db_connection

debug_bp = Blueprint('debug', __name__, url_prefix='/debug')

@debug_bp.route('/conclusiones', methods=['GET'])
def debug_conclusiones():
    """Muestra información sobre conclusiones en BD"""
    data = {
        'estructura_cloud': [],
        'contenido_secciones': {},
        'diagnostico': []
    }

    # 1. Obtener estructura de reporte_estructura_cloud
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT clave, subtitulo, tipo, orden, es_dinamico
            FROM reporte_estructura_cloud
            WHERE proveedor = 'aws' AND estado_id = 1
            ORDER BY orden
        """)
        data['estructura_cloud'] = cursor.fetchall()

        # 2. Buscar específicamente conclusiones
        cursor.execute("""
            SELECT clave, subtitulo, tipo, orden, es_dinamico
            FROM reporte_estructura_cloud
            WHERE proveedor = 'aws' AND clave = 'conclusiones'
        """)
        conclusiones_row = cursor.fetchone()

        if conclusiones_row:
            data['diagnostico'].append(f"✅ Conclusiones encontrada en reporte_estructura_cloud")
            data['diagnostico'].append(f"   - es_dinamico: {conclusiones_row['es_dinamico']}")

            if conclusiones_row['es_dinamico'] == 1:
                data['diagnostico'].append(f"✅ es_dinamico está correctamente en 1")
            else:
                data['diagnostico'].append(f"❌ PROBLEMA: es_dinamico NO está en 1 (valor: {conclusiones_row['es_dinamico']})")
        else:
            data['diagnostico'].append(f"❌ PROBLEMA: Conclusiones NO encontrada en reporte_estructura_cloud")

        # 3. Contar hallazgos en proyectos
        cursor.execute("""
            SELECT p.id, p.titulo, COUNT(f.id) as total_hallazgos
            FROM proyectos p
            LEFT JOIN findings f ON p.id = f.proyecto_id
            GROUP BY p.id
            HAVING COUNT(f.id) > 0
            ORDER BY total_hallazgos DESC
            LIMIT 3
        """)
        proyectos = cursor.fetchall()

        if proyectos:
            data['diagnostico'].append(f"\n📊 Proyectos con hallazgos:")
            for p in proyectos:
                data['diagnostico'].append(f"   - Proyecto {p['id']}: {p['titulo']} ({p['total_hallazgos']} hallazgos)")

    except Exception as e:
        data['diagnostico'].append(f"❌ ERROR EN QUERY: {str(e)}")
    finally:
        cursor.close()
        conn.close()

    return jsonify(data)
