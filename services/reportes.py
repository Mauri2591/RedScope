from io import BytesIO
from datetime import datetime
import re
import csv
import io

from openpyxl import Workbook
from openpyxl.styles import Alignment, PatternFill, Font

from docx import Document
from docx.shared import Pt, Cm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement


# ══════════════════════════════════════════════════════════════════
# HELPERS XML (internos, no exponer fuera del módulo)
# ══════════════════════════════════════════════════════════════════
def _set_row_height(row, height_cm: float):
    """Fija la altura mínima de una fila en cm."""
    tr   = row._tr
    trPr = tr.get_or_add_trPr()
    for old in trPr.findall(qn('w:trHeight')):
        trPr.remove(old)
    trH = OxmlElement('w:trHeight')
    trH.set(qn('w:val'),   str(int(height_cm * 567)))
    trH.set(qn('w:hRule'), 'atLeast')
    trPr.append(trH)
def _hex_to_rgb(hex_color: str) -> RGBColor:
    """Convierte '#1E1B4B' o '1E1B4B' a RGBColor."""
    h = hex_color.strip().lstrip('#')
    return RGBColor(int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))


def _set_cell_bg(cell, hex_color: str):
    """Relleno sólido de celda."""
    h    = hex_color.strip().lstrip('#')
    tc   = cell._tc
    tcPr = tc.get_or_add_tcPr()
    # eliminar shd previo si existe
    for old in tcPr.findall(qn('w:shd')):
        tcPr.remove(old)
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'),   'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'),  h.upper())
    tcPr.append(shd)


def _set_cell_borders(cell, hex_color: str = 'CCCCCC', size: str = '4'):
    """Bordes finos en todas las caras de la celda."""
    h    = hex_color.strip().lstrip('#').upper()
    tc   = cell._tc
    tcPr = tc.get_or_add_tcPr()
    for old in tcPr.findall(qn('w:tcBorders')):
        tcPr.remove(old)
    tcBorders = OxmlElement('w:tcBorders')
    for side in ('top', 'left', 'bottom', 'right'):
        el = OxmlElement(f'w:{side}')
        el.set(qn('w:val'),   'single')
        el.set(qn('w:sz'),    size)
        el.set(qn('w:space'), '0')
        el.set(qn('w:color'), h)
        tcBorders.append(el)
    tcPr.append(tcBorders)


def _set_cell_margin(cell, top=80, bottom=80, left=120, right=120):
    """Padding interno de celda en twips."""
    tc   = cell._tc
    tcPr = tc.get_or_add_tcPr()
    for old in tcPr.findall(qn('w:tcMar')):
        tcPr.remove(old)
    mar = OxmlElement('w:tcMar')
    for side, val in (('top', top), ('bottom', bottom), ('left', left), ('right', right)):
        el = OxmlElement(f'w:{side}')
        el.set(qn('w:w'),    str(val))
        el.set(qn('w:type'), 'dxa')
        mar.append(el)
    tcPr.append(mar)


def _add_hr(doc, hex_color: str = '00B4D8', size: int = 10):
    """Línea horizontal decorativa debajo de un párrafo."""
    h = hex_color.strip().lstrip('#').upper()
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after  = Pt(10)
    pPr  = p._p.get_or_add_pPr()
    pBdr = OxmlElement('w:pBdr')
    bot  = OxmlElement('w:bottom')
    bot.set(qn('w:val'),   'single')
    bot.set(qn('w:sz'),    str(size))
    bot.set(qn('w:space'), '1')
    bot.set(qn('w:color'), h)
    pBdr.append(bot)
    pPr.append(pBdr)
    return p


def _page_break(doc):
    p  = doc.add_paragraph()
    r  = p.add_run()
    br = OxmlElement('w:br')
    br.set(qn('w:type'), 'page')
    r._r.append(br)


def _remove_table_borders(table):
    """Quita el estilo de borde por defecto de una tabla."""
    tbl   = table._tbl
    tblPr = tbl.tblPr
    for tag in ('w:tblStyle', 'w:tblBorders'):
        el = tblPr.find(qn(tag))
        if el is not None:
            tblPr.remove(el)


def _campo_pagina(run):
    """Inserta campo PAGE de Word en un run."""
    fldChar1 = OxmlElement('w:fldChar')
    fldChar1.set(qn('w:fldCharType'), 'begin')
    instr = OxmlElement('w:instrText')
    instr.text = 'PAGE'
    fldChar2 = OxmlElement('w:fldChar')
    fldChar2.set(qn('w:fldCharType'), 'end')
    run._r.append(fldChar1)
    run._r.append(instr)
    run._r.append(fldChar2)


# ══════════════════════════════════════════════════════════════════
# REPORT SERVICE
# ══════════════════════════════════════════════════════════════════

class ReportService:

    # ─────────────────────────────────────────────────────────────
    # Helpers de color
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _normalizar_color(color: str) -> str | None:
        if not color:
            return None
        color = color.strip().lstrip('#')
        if len(color) == 3:
            color = ''.join(c * 2 for c in color)
        if len(color) == 6:
            return f"FF{color.upper()}"
        if len(color) == 8:
            return color.upper()
        return None

    @staticmethod
    def construir_mapa_severidad(severidades):
        return {row["nombre"].upper(): row["color"] for row in severidades}

    @staticmethod
    def _limpiar(texto):
        if not texto:
            return "sin_valor"
        return re.sub(r'[^a-zA-Z0-9_-]', '_', str(texto))

    @staticmethod
    def generar_nombre_archivo(data, proyecto_id, extension="xlsx"):
        if data:
            titulo      = ReportService._limpiar(data[0].get('proyecto_titulo'))
            proveedores = {row.get('proveedor', 'sin_proveedor') for row in data}
            proveedor   = ReportService._limpiar("_".join(proveedores))
        else:
            titulo    = f"proyecto_{proyecto_id}"
            proveedor = "sin_proveedor"
        return f"{titulo}_{proveedor}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{extension}"

    # ─────────────────────────────────────────────────────────────
    # XLSX
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def generar_xlsx(data, severidades):
        wb = Workbook()
        ws = wb.active
        ws.title = "Findings"

        headers = [
            'proveedor', 'servicio', 'check_id', 'titulo', 'descripcion',
            'riesgo', 'condicion logica', 'remediacion', 'referencia',
            'resource_id', 'estado'
        ]
        ws.append(headers)

        wrap        = Alignment(wrap_text=True, vertical="top")
        header_fill = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
        header_font = Font(color="FFFFFF", bold=True)
        sev_colors  = ReportService.construir_mapa_severidad(severidades)

        for cell in ws[1]:
            cell.fill      = header_fill
            cell.font      = header_font
            cell.alignment = wrap

        for row in data:
            fila = [
                row.get('proveedor', ''),      row.get('servicio', ''),
                row.get('check_id', ''),       row.get('titulo', ''),
                row.get('descripcion', ''),    row.get('severidad', ''),
                row.get('condicion_logica', ''), row.get('remediacion', ''),
                row.get('referencia', ''),     row.get('resource_id', ''),
                row.get('estado', '')
            ]
            ws.append(fila)
            current_row = ws.max_row

            for col_idx, value in enumerate(fila, start=1):
                cell           = ws.cell(row=current_row, column=col_idx)
                cell.alignment = wrap
                if col_idx == 6:
                    raw   = sev_colors.get(str(value).upper())
                    color = ReportService._normalizar_color(raw)
                    if color:
                        cell.fill = PatternFill(start_color=color, end_color=color, fill_type="solid")

        ws.auto_filter.ref = ws.dimensions
        ws.freeze_panes    = "A2"

        for col in ws.columns:
            max_len    = max((len(str(c.value)) for c in col if c.value), default=0)
            col_letter = col[0].column_letter
            ws.column_dimensions[col_letter].width = min(max_len + 2, 50)

        output = BytesIO()
        wb.save(output)
        output.seek(0)
        return output

    # ─────────────────────────────────────────────────────────────
    # CSV VULMA
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def generar_csv_vulma(data):
        output = io.StringIO(newline='')
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "Vulnerabilidad", "Descripcion", "Impacto", "Solucion",
                "Target", "Severidad", "CVSS", "CVSS_Vector", "Referencias",
                "CVE", "Exploits", "Output", "Protocolo", "Puerto", "URI"
            ],
            delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL
        )
        writer.writeheader()
        for row in data:
            writer.writerow({
                "Vulnerabilidad": row.get("titulo", ""),
                "Descripcion":    row.get("descripcion", ""),
                "Impacto":        row.get("condicion_logica", ""),
                "Solucion":       row.get("remediacion", ""),
                "Target":         row.get("resource_id", ""),
                "Severidad":      row.get("severidad", ""),
                "CVSS": "", "CVSS_Vector": "",
                "Referencias":    row.get("referencia", ""),
                "CVE": "", "Exploits": "", "Output": "",
                "Protocolo": "", "Puerto": "", "URI": ""
            })
        csv_content  = output.getvalue()
        output.close()
        final_output = io.BytesIO()
        final_output.write(csv_content.encode("utf-8-sig"))
        final_output.seek(0)
        return final_output

    # ─────────────────────────────────────────────────────────────
    # DOCX — bloques internos
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _doc_base(proyecto, tema):
        """Crea el documento con márgenes, header y footer."""
        doc = Document()
        sec = doc.sections[0]
        sec.top_margin    = Cm(2.5)
        sec.bottom_margin = Cm(2.5)
        sec.left_margin   = Cm(2.5)
        sec.right_margin  = Cm(2.5)

        # Fuente base
        doc.styles['Normal'].font.name       = 'Arial'
        doc.styles['Normal'].font.size       = Pt(10)
        doc.styles['Normal'].font.color.rgb  = _hex_to_rgb(tema.get('texto_oscuro', '#111827'))

        # ── Header ──
        header = sec.header
        header.is_linked_to_previous = False
        hp = header.paragraphs[0]
        hp.clear()

        r1 = hp.add_run(f"RedScope  |  {proyecto.get('titulo', '')}")
        r1.font.name      = 'Arial'
        r1.font.size      = Pt(8)
        r1.font.color.rgb = _hex_to_rgb(tema.get('borde', '#CCCCCC'))

        hp.add_run('\t')

        r2 = hp.add_run('CONFIDENCIAL')
        r2.font.name      = 'Arial'
        r2.font.size      = Pt(8)
        r2.font.bold      = True
        r2.font.color.rgb = _hex_to_rgb(tema.get('acento', '#00B4D8'))

        # Línea baja header
        pPr  = hp._p.get_or_add_pPr()
        pBdr = OxmlElement('w:pBdr')
        bot  = OxmlElement('w:bottom')
        bot.set(qn('w:val'),   'single')
        bot.set(qn('w:sz'),    '6')
        bot.set(qn('w:space'), '1')
        bot.set(qn('w:color'), tema.get('fondo_secundario', '#2D2A6E').lstrip('#'))
        pBdr.append(bot)
        pPr.append(pBdr)

        # ── Footer ──
        footer = sec.footer
        footer.is_linked_to_previous = False
        fp = footer.paragraphs[0]
        fp.clear()

        rf = fp.add_run(f"{proyecto.get('cliente', '')}  ·  {datetime.now().strftime('%d/%m/%Y')}")
        rf.font.name      = 'Arial'
        rf.font.size      = Pt(8)
        rf.font.color.rgb = _hex_to_rgb(tema.get('borde', '#CCCCCC'))

        fp.add_run('\t')

        rp = fp.add_run('Página ')
        rp.font.name      = 'Arial'
        rp.font.size      = Pt(8)
        rp.font.color.rgb = _hex_to_rgb(tema.get('borde', '#CCCCCC'))

        rnum = fp.add_run()
        rnum.font.name      = 'Arial'
        rnum.font.size      = Pt(8)
        rnum.font.color.rgb = _hex_to_rgb(tema.get('borde', '#CCCCCC'))
        _campo_pagina(rnum)

        return doc

    @staticmethod
    def _bloque_portada(doc, proyecto, tema):
        """Portada: bloque de color + datos del proyecto."""
        color_primario    = tema.get('fondo_primario',   '#1E1B4B').lstrip('#')
        color_secundario  = tema.get('fondo_secundario', '#2D2A6E').lstrip('#')
        color_acento      = tema.get('acento',           '#00B4D8').lstrip('#')
        color_texto_claro = tema.get('texto_claro',      '#FFFFFF').lstrip('#')
        proveedor         = proyecto.get('tipo_servicio', 'Cloud').upper()
        cliente           = proyecto.get('cliente', '').upper()

        # ── Bloque hero ──
        t = doc.add_table(rows=1, cols=1)
        _remove_table_borders(t)
        c = t.cell(0, 0)
        _set_cell_bg(c, color_primario)
        _set_cell_margin(c, 600, 500, 400, 400)
        _set_row_height(t.rows[0], 8)

        # Nombre empresa pequeño arriba
        p0 = c.paragraphs[0]
        p0.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r0 = p0.add_run('P E R S O N A L')
        r0.font.name      = 'Arial'
        r0.font.size      = Pt(11)
        r0.font.bold      = True
        r0.font.color.rgb = _hex_to_rgb(color_acento)

        # H1 — Pentest Cloud — AWS
        p1 = c.add_paragraph()
        p1.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p1.paragraph_format.space_before = Pt(18)
        r1 = p1.add_run(f'Pentest Cloud — {proveedor}')
        r1.font.name      = 'Arial'
        r1.font.size      = Pt(28)
        r1.font.bold      = True
        r1.font.color.rgb = _hex_to_rgb(color_texto_claro)

        # Subtítulo — nombre del cliente
        p2 = c.add_paragraph()
        p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p2.paragraph_format.space_before = Pt(10)
        r2 = p2.add_run(cliente)
        r2.font.name      = 'Arial'
        r2.font.size      = Pt(20)
        r2.font.bold      = True
        r2.font.color.rgb = _hex_to_rgb(color_acento)

        # ── Banda acento cyan ──
        banda = doc.add_table(rows=1, cols=1)
        _remove_table_borders(banda)
        bc = banda.cell(0, 0)
        _set_cell_bg(bc, color_acento)
        _set_row_height(banda.rows[0], 0.35)
        bc.paragraphs[0].add_run('')

        doc.add_paragraph()

        # ── Tabla de datos del proyecto ──
        campos = [
            ('Cliente',   proyecto.get('cliente',   '')),
            ('Proyecto',  proyecto.get('titulo',    '')),
            ('Proveedor', proveedor),
            ('Cuenta',    proyecto.get('cuenta_id', 'N/A')),
            ('Fecha',     datetime.now().strftime('%d de %B de %Y')),
        ]

        info = doc.add_table(rows=len(campos), cols=2)
        _remove_table_borders(info)
        info.alignment = WD_TABLE_ALIGNMENT.CENTER

        for i, (label, valor) in enumerate(campos):
            # Label
            lc = info.rows[i].cells[0]
            lc.width = Cm(4)
            _set_cell_bg(lc, color_secundario)
            _set_cell_borders(lc, 'FFFFFF', '2')
            _set_cell_margin(lc, 100, 100, 160, 120)
            lp = lc.paragraphs[0]
            lp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            lr = lp.add_run(label)
            lr.font.name      = 'Arial'
            lr.font.size      = Pt(10)
            lr.font.bold      = True
            lr.font.color.rgb = _hex_to_rgb(color_acento)
            lc.vertical_alignment = WD_ALIGN_VERTICAL.CENTER

            # Valor
            vc = info.rows[i].cells[1]
            vc.width = Cm(10)
            _set_cell_bg(vc, color_primario)
            _set_cell_borders(vc, 'FFFFFF', '2')
            _set_cell_margin(vc, 100, 100, 160, 120)
            vp = vc.paragraphs[0]
            vr = vp.add_run(str(valor))
            vr.font.name      = 'Arial'
            vr.font.size      = Pt(10)
            vr.font.color.rgb = _hex_to_rgb(color_texto_claro)
            vc.vertical_alignment = WD_ALIGN_VERTICAL.CENTER

        _page_break(doc)

    @staticmethod
    def _bloque_toc(doc, estructura, tema):
        """Tabla de contenidos manual desde reporte_estructura_cloud."""
        color_primario = tema.get('fondo_primario', '#1E1B4B')
        color_acento   = tema.get('acento',         '#00B4D8')
        color_oscuro   = tema.get('texto_oscuro',   '#111827')
        color_borde    = tema.get('borde',          '#CCCCCC')

        p = doc.add_paragraph()
        r = p.add_run('Tabla de Contenidos')
        r.font.name      = 'Arial'
        r.font.size      = Pt(18)
        r.font.bold      = True
        r.font.color.rgb = _hex_to_rgb(color_primario)

        _add_hr(doc, color_acento.lstrip('#'), 12)

        for item in estructura:
            if item['tipo'] in ('portada', 'toc'):
                continue

            toc_p = doc.add_paragraph()
            toc_p.paragraph_format.space_before = Pt(3)
            toc_p.paragraph_format.space_after  = Pt(3)

            rn = toc_p.add_run(item['subtitulo'])
            rn.font.name      = 'Arial'
            rn.font.size      = Pt(10)
            rn.font.color.rgb = _hex_to_rgb(
                color_borde if item['tipo'] == 'anexo' else color_oscuro
            )
            if item['tipo'] == 'anexo':
                rn.font.italic = True

            # Puntos líderes
            dots = toc_p.add_run(' ' + ('.' * 90) + ' ')
            dots.font.name      = 'Arial'
            dots.font.size      = Pt(10)
            dots.font.color.rgb = _hex_to_rgb('#DDDDDD')

            rp = toc_p.add_run(str(item.get('pagina_ref') or ''))
            rp.font.name      = 'Arial'
            rp.font.size      = Pt(10)
            rp.font.bold      = True
            rp.font.color.rgb = _hex_to_rgb(color_primario)

        _page_break(doc)

    @staticmethod
    def _seccion_titulo(doc, texto, tema):
        """Título de sección con línea decorativa."""
        color_primario = tema.get('fondo_primario', '#1E1B4B')
        color_acento   = tema.get('acento',         '#00B4D8')

        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(8)
        p.paragraph_format.space_after  = Pt(2)
        r = p.add_run(texto)
        r.font.name      = 'Arial'
        r.font.size      = Pt(15)
        r.font.bold      = True
        r.font.color.rgb = _hex_to_rgb(color_primario)

        _add_hr(doc, color_acento.lstrip('#'), 10)

    @staticmethod
    def _bloque_seccion_vacia(doc, subtitulo, tema):
        """Sección estática — el analista la completa a mano."""
        ReportService._seccion_titulo(doc, subtitulo, tema)
        p = doc.add_paragraph()
        r = p.add_run('[Completar por el analista]')
        r.font.name      = 'Arial'
        r.font.size      = Pt(10)
        r.font.italic    = True
        r.font.color.rgb = _hex_to_rgb(tema.get('borde', '#CCCCCC'))
        doc.add_paragraph()

    @staticmethod
    def _bloque_resumen(doc, findings, tema, severidades):
        """Tabla resumen de hallazgos por severidad."""
        ReportService._seccion_titulo(doc, 'Resumen de Hallazgos', tema)

        color_primario    = tema.get('fondo_primario',      '#1E1B4B')
        color_texto_claro = tema.get('texto_claro',         '#FFFFFF')
        color_fila_par    = tema.get('fondo_tabla_fila_par','#E8EAF6')
        color_oscuro      = tema.get('texto_oscuro',        '#111827')

        # Mapa severidad → color desde DB
        sev_map = {s['nombre'].upper(): s['color'].lstrip('#') for s in severidades}

        # Conteo
        conteo = {s['nombre'].upper(): 0 for s in severidades}
        for f in findings:
            sev = str(f.get('severidad', '')).upper()
            if sev in conteo:
                conteo[sev] += 1

        total = sum(conteo.values())

        # Intro
        intro = doc.add_paragraph()
        ri = intro.add_run(
            f"Durante la evaluación se identificaron {total} hallazgo(s) distribuidos "
            f"en las siguientes categorías de riesgo:"
        )
        ri.font.name      = 'Arial'
        ri.font.size      = Pt(10)
        ri.font.color.rgb = _hex_to_rgb(color_oscuro)
        intro.paragraph_format.space_after = Pt(8)

        # Tabla
        table = doc.add_table(rows=1, cols=3)
        _remove_table_borders(table)

        # Header
        for ci, txt in enumerate(['Severidad', 'Cantidad', 'Porcentaje']):
            c = table.rows[0].cells[ci]
            _set_cell_bg(c, color_primario.lstrip('#'))
            _set_cell_borders(c, 'FFFFFF', '2')
            _set_cell_margin(c)
            p = c.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            r = p.add_run(txt)
            r.font.name      = 'Arial'
            r.font.size      = Pt(10)
            r.font.bold      = True
            r.font.color.rgb = _hex_to_rgb(color_texto_claro)
            c.vertical_alignment = WD_ALIGN_VERTICAL.CENTER

        for sev, qty in conteo.items():
            if qty == 0:
                continue
            pct      = f"{(qty / total * 100):.0f}%" if total > 0 else "0%"
            sev_hex  = sev_map.get(sev, 'CCCCCC')
            row      = table.add_row()

            # Severidad
            sc = row.cells[0]
            _set_cell_bg(sc, sev_hex)
            _set_cell_borders(sc, 'FFFFFF', '2')
            _set_cell_margin(sc)
            sp = sc.paragraphs[0]
            sp.alignment = WD_ALIGN_PARAGRAPH.CENTER
            sr = sp.add_run(sev)
            sr.font.name      = 'Arial'
            sr.font.size      = Pt(10)
            sr.font.bold      = True
            sr.font.color.rgb = _hex_to_rgb(color_texto_claro)
            sc.vertical_alignment = WD_ALIGN_VERTICAL.CENTER

            # Cantidad
            qc = row.cells[1]
            _set_cell_bg(qc, color_fila_par.lstrip('#'))
            _set_cell_borders(qc, 'CCCCCC', '2')
            _set_cell_margin(qc)
            qp = qc.paragraphs[0]
            qp.alignment = WD_ALIGN_PARAGRAPH.CENTER
            qr = qp.add_run(str(qty))
            qr.font.name      = 'Arial'
            qr.font.size      = Pt(10)
            qr.font.bold      = True
            qr.font.color.rgb = _hex_to_rgb(color_oscuro)
            qc.vertical_alignment = WD_ALIGN_VERTICAL.CENTER

            # Porcentaje
            pc = row.cells[2]
            _set_cell_bg(pc, color_fila_par.lstrip('#'))
            _set_cell_borders(pc, 'CCCCCC', '2')
            _set_cell_margin(pc)
            pp = pc.paragraphs[0]
            pp.alignment = WD_ALIGN_PARAGRAPH.CENTER
            pr = pp.add_run(pct)
            pr.font.name      = 'Arial'
            pr.font.size      = Pt(10)
            pr.font.color.rgb = _hex_to_rgb(color_oscuro)
            pc.vertical_alignment = WD_ALIGN_VERTICAL.CENTER

        doc.add_paragraph()

    @staticmethod
    def _bloque_tabla_hallazgos(doc, findings, tema, severidades):
        """Tabla índice de todos los hallazgos."""
        ReportService._seccion_titulo(doc, 'Hallazgos', tema)

        color_primario    = tema.get('fondo_primario',       '#1E1B4B')
        color_texto_claro = tema.get('texto_claro',          '#FFFFFF')
        color_fila_par    = tema.get('fondo_tabla_fila_par', '#E8EAF6')
        color_oscuro      = tema.get('texto_oscuro',         '#111827')
        sev_map           = {s['nombre'].upper(): s['color'].lstrip('#') for s in severidades}

        cols    = ['#', 'Título', 'Servicio', 'Recurso', 'Severidad']
        widths  = [1.0, 5.5, 2.5, 5.0, 2.5]

        table = doc.add_table(rows=1, cols=len(cols))
        _remove_table_borders(table)

        # Header
        for ci, (txt, w) in enumerate(zip(cols, widths)):
            c = table.rows[0].cells[ci]
            c.width = Cm(w)
            _set_cell_bg(c, color_primario.lstrip('#'))
            _set_cell_borders(c, 'FFFFFF', '2')
            _set_cell_margin(c)
            p = c.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            r = p.add_run(txt)
            r.font.name      = 'Arial'
            r.font.size      = Pt(9)
            r.font.bold      = True
            r.font.color.rgb = _hex_to_rgb(color_texto_claro)
            c.vertical_alignment = WD_ALIGN_VERTICAL.CENTER

        for idx, f in enumerate(findings, start=1):
            sev     = str(f.get('severidad', '')).upper()
            sev_hex = sev_map.get(sev, 'CCCCCC')
            bg      = color_fila_par.lstrip('#') if idx % 2 == 0 else 'FFFFFF'
            row     = table.add_row()

            valores = [
                str(idx),
                f.get('titulo', ''),
                f.get('servicio', ''),
                f.get('resource_id', ''),
                sev,
            ]

            for ci, (val, w) in enumerate(zip(valores, widths)):
                c = row.cells[ci]
                c.width = Cm(w)
                _set_cell_margin(c)
                c.vertical_alignment = WD_ALIGN_VERTICAL.CENTER

                if ci == 4:  # Severidad
                    _set_cell_bg(c, sev_hex)
                    _set_cell_borders(c, 'FFFFFF', '2')
                    p = c.paragraphs[0]
                    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    r = p.add_run(val)
                    r.font.name      = 'Arial'
                    r.font.size      = Pt(9)
                    r.font.bold      = True
                    r.font.color.rgb = _hex_to_rgb(color_texto_claro)
                else:
                    _set_cell_bg(c, bg)
                    _set_cell_borders(c, 'DDDDDD', '2')
                    p = c.paragraphs[0]
                    p.alignment = WD_ALIGN_PARAGRAPH.CENTER if ci == 0 else WD_ALIGN_PARAGRAPH.LEFT
                    r = p.add_run(val)
                    r.font.name      = 'Arial'
                    r.font.size      = Pt(9)
                    r.font.color.rgb = _hex_to_rgb(color_oscuro)

        doc.add_paragraph()

    @staticmethod
    def _bloque_detalle_hallazgos(doc, findings, tema, severidades):
        """Una ficha completa por cada finding."""
        ReportService._seccion_titulo(doc, 'Detalle de Hallazgos', tema)

        color_primario    = tema.get('fondo_primario',       '#1E1B4B')
        color_secundario  = tema.get('fondo_secundario',     '#2D2A6E')
        color_acento      = tema.get('acento',               '#00B4D8')
        color_texto_claro = tema.get('texto_claro',          '#FFFFFF')
        color_fila_par    = tema.get('fondo_tabla_fila_par', '#E8EAF6')
        color_oscuro      = tema.get('texto_oscuro',         '#111827')
        color_borde       = tema.get('borde',                '#CCCCCC')
        sev_map           = {s['nombre'].upper(): s['color'].lstrip('#') for s in severidades}

        for idx, f in enumerate(findings, start=1):
            sev     = str(f.get('severidad', '')).upper()
            sev_hex = sev_map.get(sev, 'CCCCCC')

            # ── Encabezado finding ──────────────────────────────
            enc = doc.add_table(rows=1, cols=2)
            _remove_table_borders(enc)

            tc_titulo = enc.rows[0].cells[0]
            tc_titulo.width = Cm(13)
            _set_cell_bg(tc_titulo, color_primario.lstrip('#'))
            _set_cell_borders(tc_titulo, 'FFFFFF', '2')
            _set_cell_margin(tc_titulo, 120, 120, 160, 160)
            tp = tc_titulo.paragraphs[0]
            tp.paragraph_format.space_before = Pt(4)
            rn = tp.add_run(f'#{idx}  ')
            rn.font.name      = 'Arial'
            rn.font.size      = Pt(11)
            rn.font.bold      = True
            rn.font.color.rgb = _hex_to_rgb(color_acento)
            rt = tp.add_run(f.get('titulo', ''))
            rt.font.name      = 'Arial'
            rt.font.size      = Pt(11)
            rt.font.bold      = True
            rt.font.color.rgb = _hex_to_rgb(color_texto_claro)
            tc_titulo.vertical_alignment = WD_ALIGN_VERTICAL.CENTER

            tc_sev = enc.rows[0].cells[1]
            tc_sev.width = Cm(4)
            _set_cell_bg(tc_sev, sev_hex)
            _set_cell_borders(tc_sev, 'FFFFFF', '2')
            _set_cell_margin(tc_sev)
            sp = tc_sev.paragraphs[0]
            sp.alignment = WD_ALIGN_PARAGRAPH.CENTER
            sr = sp.add_run(sev)
            sr.font.name      = 'Arial'
            sr.font.size      = Pt(11)
            sr.font.bold      = True
            sr.font.color.rgb = _hex_to_rgb(color_texto_claro)
            tc_sev.vertical_alignment = WD_ALIGN_VERTICAL.CENTER

            # ── Metadata ────────────────────────────────────────
            meta = doc.add_table(rows=1, cols=3)
            _remove_table_borders(meta)

            meta_campos = [
                ('Servicio', f.get('servicio', ''),    3.0),
                ('Recurso',  f.get('resource_id', ''), 9.5),
                ('Estado',   f.get('estado', 'ABIERTO'), 4.5),
            ]

            for mi, (ml, mv, mw) in enumerate(meta_campos):
                mc = meta.rows[0].cells[mi]
                mc.width = Cm(mw)
                _set_cell_bg(mc, color_fila_par.lstrip('#'))
                _set_cell_borders(mc, 'CCCCCC', '2')
                _set_cell_margin(mc)
                mp = mc.paragraphs[0]
                mr_label = mp.add_run(f'{ml}: ')
                mr_label.font.name      = 'Arial'
                mr_label.font.size      = Pt(9)
                mr_label.font.bold      = True
                mr_label.font.color.rgb = _hex_to_rgb(color_secundario)
                mr_val = mp.add_run(str(mv))
                mr_val.font.name      = 'Arial'
                mr_val.font.size      = Pt(9)
                mr_val.font.color.rgb = _hex_to_rgb(color_oscuro)
                mc.vertical_alignment = WD_ALIGN_VERTICAL.CENTER

            # ── Campos del finding ──────────────────────────────
            ficha_campos = [
                ('Descripción',    f.get('descripcion',    '')),
                ('Condición',      f.get('condicion_logica', '')),
                ('Remediación',    f.get('remediacion',    '')),
                ('Referencia',     f.get('referencia',     '')),
            ]

            ficha = doc.add_table(rows=len(ficha_campos), cols=2)
            _remove_table_borders(ficha)

            for fi, (fl, fv) in enumerate(ficha_campos):
                bg = color_fila_par.lstrip('#') if fi % 2 == 0 else 'FFFFFF'

                # Label
                lc = ficha.rows[fi].cells[0]
                lc.width = Cm(3.5)
                _set_cell_bg(lc, color_secundario.lstrip('#'))
                _set_cell_borders(lc, 'FFFFFF', '2')
                _set_cell_margin(lc)
                lp = lc.paragraphs[0]
                lp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
                lr = lp.add_run(fl)
                lr.font.name      = 'Arial'
                lr.font.size      = Pt(9)
                lr.font.bold      = True
                lr.font.color.rgb = _hex_to_rgb(color_acento)
                lc.vertical_alignment = WD_ALIGN_VERTICAL.TOP

                # Valor
                vc = ficha.rows[fi].cells[1]
                vc.width = Cm(13.5)
                _set_cell_bg(vc, bg)
                _set_cell_borders(vc, 'DDDDDD', '2')
                _set_cell_margin(vc)
                vp = vc.paragraphs[0]
                vr = vp.add_run(str(fv))
                vr.font.name      = 'Arial'
                vr.font.size      = Pt(9)
                vr.font.color.rgb = _hex_to_rgb(color_oscuro)
                vc.vertical_alignment = WD_ALIGN_VERTICAL.TOP

            doc.add_paragraph()

            # Salto de página entre findings (excepto el último)
            if idx < len(findings):
                _page_break(doc)

    # ─────────────────────────────────────────────────────────────
    # DOCX — punto de entrada público
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def generar_docx(data, proyecto, tema, estructura, severidades):
        """
        Genera el reporte Word completo.

        Parámetros:
            data        → lista de findings (get_data_reporte)
            proyecto    → dict del proyecto (get_by_id)
            tema        → dict { uso: hex } (get_reporte_tema)
            estructura  → lista de secciones (get_reporte_estructura)
            severidades → lista de severidades (get_severidades)

        Retorna:
            BytesIO con el archivo .docx listo para descargar.
        """
        doc = ReportService._doc_base(proyecto, tema)

        # ── Portada ──
        ReportService._bloque_portada(doc, proyecto, tema)

        # ── TOC ──
        ReportService._bloque_toc(doc, estructura, tema)

        # ── Secciones dinámicas según reporte_estructura_cloud ──
        for seccion in estructura:
            tipo       = seccion['tipo']
            clave      = seccion['clave']
            subtitulo  = seccion['subtitulo']
            dinamico   = seccion['es_dinamico']

            if tipo in ('portada', 'toc'):
                continue

            if dinamico:
                # Secciones que se generan con datos de findings
                if clave == 'resumen_hallazgos':
                    ReportService._bloque_resumen(doc, data, tema, severidades)

                elif clave == 'hallazgos':
                    ReportService._bloque_tabla_hallazgos(doc, data, tema, severidades)

                elif clave == 'detalle_hallazgos':
                    ReportService._bloque_detalle_hallazgos(doc, data, tema, severidades)

            else:
                # Sección estática — el analista la completa a mano
                ReportService._bloque_seccion_vacia(doc, subtitulo, tema)

            # Salto de página entre secciones (excepto la última)
            if seccion != estructura[-1]:
                _page_break(doc)

        output = BytesIO()
        doc.save(output)
        output.seek(0)
        return output