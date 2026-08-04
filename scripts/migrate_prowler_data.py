#!/usr/bin/env python3
"""
Script de migración: Actualizar inventory_data de Prowler a nueva estructura
Uso: python migrate_prowler_data.py --proyecto_id 27
"""
import sys
import json
import argparse
from pathlib import Path

# Agregar root al path
sys.path.insert(0, str(Path(__file__).parent.parent))

from db import get_db_connection
from helpers.prowler_parser import ProwlerDataExtractor


def migrate_proyecto(proyecto_id):
    """Migra todos los findings de un proyecto a la nueva estructura con referencias_data separado"""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    print(f"\n🔄 Migrando proyecto_id={proyecto_id}...")

    try:
        # Obtener todos los findings con inventory_data
        cursor.execute("""
            SELECT id, inventory_data, herramienta
            FROM findings
            WHERE proyecto_id = %s
            AND inventory_data IS NOT NULL
            AND estado_id = 1
            AND herramienta IN ('prowler_web', 'prowler_cli')
        """, (proyecto_id,))

        findings = cursor.fetchall()
        total = len(findings)
        migratos = 0
        errores = 0

        for idx, finding in enumerate(findings, 1):
            finding_id = finding['id']
            inventory_str = finding['inventory_data']
            herramienta = finding['herramienta']

            try:
                # Parsear JSON antiguo
                if isinstance(inventory_str, str):
                    inventory = json.loads(inventory_str)
                else:
                    inventory = inventory_str

                # Separar en dos estructuras
                # inventory_data: solo status_code + account_id
                new_inventory = {
                    "status_code": inventory.get("status_code", "UNKNOWN"),
                    "account_id": inventory.get("account_id", "")
                }

                # referencias_data: compliance + links
                new_referencias = {
                    "compliance": inventory.get("compliance", {}),
                    "referencias": inventory.get("links", [])
                }

                # Actualizar en DB ambos campos
                inventory_json = json.dumps(new_inventory, ensure_ascii=False)
                referencias_json = json.dumps(new_referencias, ensure_ascii=False)

                cursor.execute("""
                    UPDATE findings
                    SET inventory_data = %s, referencias_data = %s, actualizacion = CURRENT_TIMESTAMP
                    WHERE id = %s
                """, (inventory_json, referencias_json, finding_id))

                migratos += 1
                if idx % 10 == 0:
                    print(f"  ✓ {idx}/{total} migratos...")

            except Exception as e:
                errores += 1
                print(f"  ✗ Error en finding {finding_id}: {str(e)}")
                continue

        # Commit
        conn.commit()
        print(f"\n Migración completada:")
        print(f"   - Total procesados: {total}")
        print(f"   - Migratos: {migratos}")
        print(f"   - Errores: {errores}")

    except Exception as e:
        conn.rollback()
        print(f"\n Error en migración: {str(e)}")
        import traceback
        traceback.print_exc()

    finally:
        cursor.close()
        conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="Migrar findings de Prowler a nueva estructura"
    )
    parser.add_argument(
        "--proyecto_id",
        type=int,
        help="ID del proyecto a migrar (ej: 27)",
        required=False
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Migrar TODOS los proyectos"
    )

    args = parser.parse_args()

    if args.all:
        print("🔄 Migrando TODOS los proyectos...")
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT DISTINCT proyecto_id
            FROM findings
            WHERE inventory_data IS NOT NULL
            AND herramienta IN ('prowler_web', 'prowler_cli')
            AND estado_id = 1
        """)

        proyectos = cursor.fetchall()
        cursor.close()
        conn.close()

        for row in proyectos:
            migrate_proyecto(row['proyecto_id'])

    elif args.proyecto_id:
        migrate_proyecto(args.proyecto_id)

    else:
        parser.print_help()
        sys.exit(1)

    print("\n✨ ¡Migración completada!")


if __name__ == "__main__":
    main()
