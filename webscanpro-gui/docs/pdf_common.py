"""
docs/pdf_common.py

Plantilla y estilos compartidos para los manuales de WebScan Pro GUI
(Sr.Robot Labs). Un módulo común para que ambos documentos (usuario y
técnico) tengan la misma identidad visual.
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, Table,
    TableStyle, Image, HRFlowable, PageBreak, KeepTogether, ListFlowable,
    ListItem,
)
from reportlab.pdfgen import canvas as pdfcanvas

# ─── Paleta (Sr.Robot Labs: cian oscuro sobre fondo claro, legible en
# impresión y pantalla) ──────────────────────────────────────────────
CYAN_DARK = colors.HexColor("#0e7c86")
CYAN = colors.HexColor("#17a2b8")
NAVY = colors.HexColor("#0d1b2a")
GREY_TEXT = colors.HexColor("#333333")
GREY_LIGHT = colors.HexColor("#6e7681")
BG_CODE = colors.HexColor("#0d1117")
CODE_TEXT = colors.HexColor("#58a6ff")
RED = colors.HexColor("#c0392b")
ORANGE = colors.HexColor("#d68910")
YELLOW = colors.HexColor("#b7950b")
GREEN = colors.HexColor("#1e8449")
BLUE = colors.HexColor("#2874a6")
TABLE_HEADER_BG = colors.HexColor("#0e7c86")
TABLE_ALT_BG = colors.HexColor("#f2f7f8")


def build_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        "CoverTitle", parent=styles["Title"], fontSize=30, leading=34,
        textColor=NAVY, spaceAfter=6, alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        "CoverSubtitle", parent=styles["Normal"], fontSize=15, leading=19,
        textColor=CYAN_DARK, alignment=TA_CENTER, spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        "CoverMeta", parent=styles["Normal"], fontSize=10.5, leading=14,
        textColor=GREY_LIGHT, alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        "H1", parent=styles["Heading1"], fontSize=18, leading=22,
        textColor=NAVY, spaceBefore=6, spaceAfter=10,
        borderColor=CYAN, borderWidth=0, borderPadding=0,
    ))
    styles.add(ParagraphStyle(
        "H2", parent=styles["Heading2"], fontSize=13.5, leading=17,
        textColor=CYAN_DARK, spaceBefore=14, spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "H3", parent=styles["Heading3"], fontSize=11.5, leading=15,
        textColor=NAVY, spaceBefore=10, spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        "Body", parent=styles["Normal"], fontSize=10, leading=14.5,
        textColor=GREY_TEXT, spaceAfter=6, alignment=TA_LEFT,
    ))
    styles.add(ParagraphStyle(
        "BodyBold", parent=styles["Body"], fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "BulletBody", parent=styles["Body"], leftIndent=14, bulletIndent=2,
        spaceAfter=3,
    ))
    styles.add(ParagraphStyle(
        "Callout", parent=styles["Body"], backColor=colors.HexColor("#fff8e1"),
        borderColor=YELLOW, borderWidth=0.75, borderPadding=8,
        spaceBefore=6, spaceAfter=10,
    ))
    styles.add(ParagraphStyle(
        "CalloutDanger", parent=styles["Body"], backColor=colors.HexColor("#fdecea"),
        borderColor=RED, borderWidth=0.75, borderPadding=8,
        spaceBefore=6, spaceAfter=10,
    ))
    styles.add(ParagraphStyle(
        "CalloutInfo", parent=styles["Body"], backColor=colors.HexColor("#eaf6f8"),
        borderColor=CYAN, borderWidth=0.75, borderPadding=8,
        spaceBefore=6, spaceAfter=10,
    ))
    styles.add(ParagraphStyle(
        "CodeBlock", parent=styles["Code"], fontSize=8.6, leading=11.5,
        backColor=BG_CODE, textColor=CODE_TEXT, borderPadding=8,
        spaceBefore=4, spaceAfter=10, fontName="Courier",
    ))
    styles.add(ParagraphStyle(
        "Caption", parent=styles["Normal"], fontSize=8.5, leading=11,
        textColor=GREY_LIGHT, alignment=TA_CENTER, spaceBefore=3, spaceAfter=12,
    ))
    styles.add(ParagraphStyle(
        "TOCEntry", parent=styles["Normal"], fontSize=11, leading=18,
        textColor=GREY_TEXT,
    ))
    styles.add(ParagraphStyle(
        "TableCell", parent=styles["Normal"], fontSize=8.8, leading=11.5,
        textColor=GREY_TEXT,
    ))
    styles.add(ParagraphStyle(
        "TableCellHeader", parent=styles["Normal"], fontSize=9, leading=12,
        textColor=colors.white, fontName="Helvetica-Bold",
    ))
    return styles


def _header_footer(canvas: pdfcanvas.Canvas, doc, title: str):
    canvas.saveState()
    w, h = A4
    # Franja superior
    canvas.setFillColor(NAVY)
    canvas.rect(0, h - 0.9 * cm, w, 0.9 * cm, stroke=0, fill=1)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 8.5)
    canvas.drawString(1.6 * cm, h - 0.62 * cm, "SR.ROBOT LABS")
    canvas.setFont("Helvetica", 8.5)
    canvas.drawRightString(w - 1.6 * cm, h - 0.62 * cm, title)
    # Pie de página
    canvas.setFillColor(GREY_LIGHT)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(1.6 * cm, 1.1 * cm, "WebScan Pro GUI — Sr.Robot Labs")
    canvas.drawRightString(w - 1.6 * cm, 1.1 * cm, f"Página {doc.page}")
    canvas.setStrokeColor(CYAN)
    canvas.setLineWidth(0.6)
    canvas.line(1.6 * cm, 1.35 * cm, w - 1.6 * cm, 1.35 * cm)
    canvas.restoreState()


def make_doc(path: str, title: str):
    """Crea el BaseDocTemplate con cabecera/pie en todas las páginas
    salvo la portada (que se maneja aparte, sin franjas)."""
    doc = BaseDocTemplate(
        path, pagesize=A4,
        topMargin=1.7 * cm, bottomMargin=1.8 * cm,
        leftMargin=1.8 * cm, rightMargin=1.8 * cm,
        title=title, author="Sr.Robot Labs",
    )
    frame_cover = Frame(
        doc.leftMargin, doc.bottomMargin, doc.width, doc.height,
        id="cover",
    )
    frame_body = Frame(
        doc.leftMargin, doc.bottomMargin, doc.width, doc.height,
        id="body",
    )

    def _on_page(canvas, d):
        _header_footer(canvas, d, title)

    doc.addPageTemplates([
        PageTemplate(id="Cover", frames=[frame_cover]),
        PageTemplate(id="Body", frames=[frame_body], onPage=_on_page),
    ])
    return doc


def cover_page(story, styles, subtitle, doc_label, version="1.0", date_str=""):
    story.append(Spacer(1, 5.5 * cm))
    story.append(Paragraph("WEBSCAN PRO GUI", styles["CoverTitle"]))
    story.append(Paragraph(subtitle, styles["CoverSubtitle"]))
    story.append(Spacer(1, 0.4 * cm))
    story.append(HRFlowable(width="40%", thickness=1.2, color=CYAN, hAlign="CENTER", spaceAfter=10))
    story.append(Paragraph(doc_label, styles["CoverMeta"]))
    story.append(Spacer(1, 6 * cm))
    story.append(Paragraph("Sr.Robot Labs", styles["CoverMeta"]))
    story.append(Paragraph(f"Versión {version}" + (f" · {date_str}" if date_str else ""), styles["CoverMeta"]))
    story.append(PageBreak())


def screenshot(path, caption, styles, width=15.5 * cm):
    from PIL import Image as PILImage
    with PILImage.open(path) as im:
        iw, ih = im.size
    ratio = ih / iw
    img = Image(path, width=width, height=width * ratio)
    img.hAlign = "CENTER"
    return KeepTogether([
        Spacer(1, 4),
        img,
        Paragraph(caption, styles["Caption"]),
    ])


def code_block(text, style):
    """Bloque de código con salto de línea REAL (Preformatted respeta
    saltos de línea y espacios tal cual; Paragraph con '\\n' literal
    los ignora y todo queda comprimido en una sola línea)."""
    from reportlab.platypus import Preformatted
    return Preformatted(text, style)


def bullet_list(items, styles, style_name="BulletBody"):
    return ListFlowable(
        [ListItem(Paragraph(it, styles[style_name]), leftIndent=12, value="•") for it in items],
        bulletType="bullet", start="•", leftIndent=10,
    )


def simple_table(header, rows, styles, col_widths=None):
    data = [[Paragraph(h, styles["TableCellHeader"]) for h in header]]
    for row in rows:
        data.append([Paragraph(str(c), styles["TableCell"]) for c in row])
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), TABLE_HEADER_BG),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, TABLE_ALT_BG]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t
