#!/usr/bin/env python3
"""
Script para debuggear la sección de conclusiones
Verifica: es_dinamico, datos en BD, función siendo llamada
"""
import sys
sys.path.insert(0, 'C:\\xampp\\htdocs\\RedScoe')

from models.database import get_db

# Conectarse a la BD
db = get_db()
cursor = db.cursor(dictionary=True)

print("\n" + "="*60)
print("DEBUG: Verificando configuración de conclusiones en BD")
print("="*60)

# Consulta 1: Ver todas las secciones de reporte_contenido_secciones
print("\n1. TODAS LAS SECCIONES EN BD:")
cursor.execute("SELECT id, clave, subtitulo, es_dinamico FROM reporte_contenido_secciones ORDER BY orden")
for row in cursor.fetchall():
    print(f"  [{row['id']}] {row['clave']:30} | dinámico: {row['es_dinamico']}")

# Consulta 2: Específicamente conclusiones
print("\n2. SECCIÓN CONCLUSIONES:")
cursor.execute("SELECT * FROM reporte_contenido_secciones WHERE clave = 'conclusiones'")
result = cursor.fetchone()
if result:
    print(f"  ID: {result.get('id')}")
    print(f"  Clave: {result.get('clave')}")
    print(f"  Subtítulo: {result.get('subtitulo')}")
    print(f"  Es Dinámico: {result.get('es_dinamico')}")
    print(f"  Tipo: {result.get('tipo')}")
    print(f"  Contenido: {result.get('contenido')[:100] if result.get('contenido') else 'VACÍO'}...")
else:
    print("  ❌ NO ENCONTRADA EN BD!")

# Consulta 3: Contar hallazgos en un proyecto
print("\n3. CONTEO DE HALLAZGOS EN PROYECTOS:")
cursor.execute("""
    SELECT p.id, p.titulo, COUNT(f.id) as total_hallazgos
    FROM proyectos p
    LEFT JOIN findings f ON p.id = f.proyecto_id
    GROUP BY p.id
    HAVING COUNT(f.id) > 0
    ORDER BY total_hallazgos DESC
    LIMIT 5
""")
for row in cursor.fetchall():
    print(f"  Proyecto {row['id']:3} | {row['titulo']:30} | {row['total_hallazgos']:3} hallazgos")

cursor.close()
db.close()

print("\n" + "="*60)
print("✅ Verificación completada")
print("="*60)
