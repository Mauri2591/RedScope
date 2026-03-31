from io import BytesIO
from datetime import datetime
import re
import csv
import io
from openpyxl import Workbook
from openpyxl.styles import Alignment, PatternFill, Font

class ReportService:
    
    @staticmethod
    def _normalizar_color(color: str) -> str | None:
        """
        Convierte color CSS (#RGB o #RRGGBB) a formato aRGB requerido por openpyxl (FFRRGGBB).
        Retorna None si el formato no es válido.
        """
        if not color:
            return None
        
        color = color.strip().lstrip('#')
        
        # Expandir shorthand #RGB -> #RRGGBB
        if len(color) == 3:
            color = ''.join(c * 2 for c in color)
        
        if len(color) == 6:
            return f"FF{color.upper()}"  # Agregar alpha FF (opaco)
        
        if len(color) == 8:
            return color.upper()  # Ya viene en aRGB    
        return None  # Formato inválido


    @staticmethod
    def construir_mapa_severidad(severidades):
        return {
            row["nombre"].upper(): row["color"]
            for row in severidades
        }

    @staticmethod
    def _limpiar(texto):
        if not texto:
            return "sin_valor"
        return re.sub(r'[^a-zA-Z0-9_-]', '_', str(texto))

    @staticmethod
    def generar_nombre_archivo(data, proyecto_id, extension="xlsx"):
        if data:
            titulo = ReportService._limpiar(data[0].get('proyecto_titulo'))
            proveedores = {row.get('proveedor', 'sin_proveedor') for row in data}
            proveedor = ReportService._limpiar("_".join(proveedores))
        else:
            titulo = f"proyecto_{proyecto_id}"
            proveedor = "sin_proveedor"

        return f"{titulo}_{proveedor}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{extension}"

    @staticmethod
    def generar_xlsx(data, severidades):
        wb = Workbook()
        ws = wb.active
        ws.title = "Findings"

        headers = [
            'proveedor','servicio','check_id','titulo','descripcion',
            'riesgo','condicion logica','remediacion','referencia',
            'resource_id','estado'
        ]

        ws.append(headers)

        wrap = Alignment(wrap_text=True, vertical="top")

        header_fill = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
        header_font = Font(color="FFFFFF", bold=True)

        severity_colors = ReportService.construir_mapa_severidad(severidades)

        for cell in ws[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = wrap

        for row in data:
            fila = [
                row.get('proveedor', ''),
                row.get('servicio', ''),
                row.get('check_id', ''),
                row.get('titulo', ''),
                row.get('descripcion', ''),
                row.get('severidad', ''),
                row.get('condicion_logica', ''),
                row.get('remediacion', ''),
                row.get('referencia', ''),
                row.get('resource_id', ''),
                row.get('estado', '')
            ]

            ws.append(fila)
            current_row = ws.max_row

            for col_idx, value in enumerate(fila, start=1):
                cell = ws.cell(row=current_row, column=col_idx)
                cell.alignment = wrap

                if col_idx == 6:
                    sev = str(value).upper()
                    raw_color = severity_colors.get(sev)
                    color = ReportService._normalizar_color(raw_color)  # ← fix

                    if color:
                        cell.fill = PatternFill(
                            start_color=color,
                            end_color=color,
                            fill_type="solid"
                        )

        ws.auto_filter.ref = ws.dimensions
        ws.freeze_panes = "A2"

        for col in ws.columns:
            max_length = 0
            col_letter = col[0].column_letter

            for cell in col:
                if cell.value:
                    max_length = max(max_length, len(str(cell.value)))

            ws.column_dimensions[col_letter].width = min(max_length + 2, 50)

        output = BytesIO()
        wb.save(output)
        output.seek(0)

        return output
        
    @staticmethod
    def generar_csv_vulma(data):
        output = io.StringIO(newline='')

        writer = csv.DictWriter(
            output,
            fieldnames=[
                "Vulnerabilidad",
                "Descripcion",
                "Impacto",
                "Solucion",
                "Target",
                "Severidad",
                "CVSS",
                "CVSS_Vector",
                "Referencias",
                "CVE",
                "Exploits",
                "Output",
                "Protocolo",
                "Puerto",
                "URI"
            ],
            delimiter=',',             
            quotechar='"',              
            quoting=csv.QUOTE_MINIMAL
        )

        writer.writeheader()

        for row in data:
            resource = row.get("resource_id", "")

            writer.writerow({
                "Vulnerabilidad": row.get("titulo", ""),
                "Descripcion": row.get("descripcion", ""),
                "Impacto": row.get("condicion_logica", ""),
                "Solucion": row.get("remediacion", ""),
                "Target": resource,  # 🔥 clave
                "Severidad": row.get("severidad", ""),
                "CVSS": "",
                "CVSS_Vector": "",
                "Referencias": row.get("referencia", ""),
                "CVE": "",
                "Exploits": "",
                "Output": "",
                "Protocolo": "",
                "Puerto": "",
                "URI": ""
            })

        # encoding correcto para Vulma / Excel
        csv_content = output.getvalue()
        output.close()

        final_output = io.BytesIO()
        final_output.write(csv_content.encode("utf-8-sig"))
        final_output.seek(0)

        return final_output