"""Excel and PDF exports of a finished scan."""
import io
from datetime import datetime
from xml.sax.saxutils import escape

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from scanner import CRITICAL_DAYS, WARNING_DAYS

STATUS_LABEL = {
    "expired": "Expired",
    "critical": f"Expires in {CRITICAL_DAYS} days or less",
    "warning": f"Expires in {WARNING_DAYS} days or less",
    "ok": "Healthy",
    "error": "No SSL / unreachable",
}
# (fill, text) colours per status
XLSX_COLORS = {"expired": ("F8D7D4", "8C1C13"), "critical": ("FBE0CF", "9A3A0B"),
               "warning": ("FFF1C2", "7A5A00"), "ok": ("D4EFE2", "13613F"), "error": ("E6E9ED", "4A5560")}
PDF_COLORS = {"expired": ("#F8D7D4", "#8C1C13"), "critical": ("#FBE0CF", "#9A3A0B"),
              "warning": ("#FFF1C2", "#7A5A00"), "ok": ("#D4EFE2", "#13613F"), "error": ("#E6E9ED", "#4A5560")}


def _dt(iso):
    return datetime.fromisoformat(iso).replace(tzinfo=None) if iso else None


def _note(r):
    if r["status"] == "error":
        return r["error"]
    if r["trusted"] is False:
        return f"Not trusted: {r['trust_error']}"
    return ""


def _days_text(r):
    d = r["days_left"]
    if d is None:
        return ""
    return f"{-d} days ago" if d < 0 else f"{d}"


def build_xlsx(snap):
    rows, summary = snap["results"], snap["summary"]
    wb = Workbook()
    ws = wb.active
    ws.title = "SSL expiry"
    headers = ["#", "Hostname", "Status", "Days left", "Expires on (UTC)", "Issued on (UTC)",
               "Issuer", "Certificate name", "IP address", "Notes"]
    ws.append(headers)
    head_fill = PatternFill("solid", fgColor="12202B")
    for c in ws[1]:
        c.font, c.fill = Font(bold=True, color="FFFFFF"), head_fill
        c.alignment = Alignment(vertical="center")
    thin = Side(style="thin", color="D8DEE4")
    for i, r in enumerate(rows, 1):
        ws.append([i, r["host"], STATUS_LABEL[r["status"]], r["days_left"], _dt(r["expires_at"]),
                   _dt(r["issued_at"]), r["issuer"], r["common_name"], r["ip"], _note(r)])
        row = ws[i + 1]
        fill, text = XLSX_COLORS[r["status"]]
        row[2].fill, row[2].font = PatternFill("solid", fgColor=fill), Font(bold=True, color=text)
        row[4].number_format = row[5].number_format = "yyyy-mm-dd"
        for c in row:
            c.border = Border(bottom=thin)
            c.alignment = Alignment(vertical="top", wrap_text=(c.column == 10))
    widths = [5, 38, 28, 11, 17, 17, 26, 30, 17, 48]
    for idx, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(idx)].width = w
    ws.freeze_panes = "C2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{max(len(rows) + 1, 2)}"

    s = wb.create_sheet("Summary")
    s.append(["SSL certificate expiry report"]); s["A1"].font = Font(bold=True, size=14)
    s.append(["Domain", snap["domain"]])
    s.append(["Scanned (UTC)", _dt(snap["finished_at"])]); s["B3"].number_format = "yyyy-mm-dd hh:mm"
    s.append([])
    s.append(["Status", "Hostnames"]); s["A5"].font = s["B5"].font = Font(bold=True)
    for key in ("expired", "critical", "warning", "ok", "error"):
        s.append([STATUS_LABEL[key], summary[key]])
        fill, text = XLSX_COLORS[key]
        s.cell(s.max_row, 1).fill = PatternFill("solid", fgColor=fill)
        s.cell(s.max_row, 1).font = Font(bold=True, color=text)
    s.append(["Total", summary["total"]]); s.cell(s.max_row, 1).font = Font(bold=True)
    s.column_dimensions["A"].width = 34; s.column_dimensions["B"].width = 26
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def build_pdf(snap):
    rows, summary = snap["results"], snap["summary"]
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=12 * mm, rightMargin=12 * mm,
                            topMargin=12 * mm, bottomMargin=14 * mm,
                            title=f"SSL expiry report - {snap['domain']}")
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontSize=18, alignment=0, spaceAfter=2, textColor=colors.HexColor("#12202B"))
    meta = ParagraphStyle("meta", parent=ss["Normal"], fontSize=9, textColor=colors.HexColor("#5B6874"))
    cell = ParagraphStyle("cell", parent=ss["Normal"], fontSize=7.8, leading=9.6)
    cellb = ParagraphStyle("cellb", parent=cell, fontName="Helvetica-Bold")

    finished = _dt(snap["finished_at"])
    story = [Paragraph(f"SSL certificate expiry report: {escape(snap['domain'])}", h1),
             Paragraph(f"Scanned {finished:%Y-%m-%d %H:%M} UTC &nbsp;|&nbsp; {summary['total']} hostnames &nbsp;|&nbsp; "
                       f"{summary['expired']} expired &nbsp;|&nbsp; {summary['critical']} within {CRITICAL_DAYS} days &nbsp;|&nbsp; "
                       f"{summary['warning']} within {WARNING_DAYS} days &nbsp;|&nbsp; {summary['ok']} healthy &nbsp;|&nbsp; "
                       f"{summary['error']} without SSL", meta),
             Spacer(1, 5 * mm)]

    data = [[Paragraph(f"<b>{h}</b>", cell) for h in ["#", "Hostname", "Status", "Expires (UTC)", "Days left", "Issuer", "IP address"]]]
    style = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D8DEE4")),
             ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#D8DEE4")),
             ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    for i, r in enumerate(rows, 1):
        issuer = escape(r["issuer"] or "")
        note = _note(r)
        if r["status"] == "error":
            issuer = f"<i>{escape(note)}</i>"
        elif note:
            issuer += f"<br/><font color='#8C1C13'>{escape(note)}</font>"
        exp = _dt(r["expires_at"])
        data.append([Paragraph(str(i), cell), Paragraph(escape(r["host"]), cellb), Paragraph(STATUS_LABEL[r["status"]], cellb),
                     Paragraph(f"{exp:%Y-%m-%d}" if exp else "-", cell), Paragraph(_days_text(r) or "-", cell),
                     Paragraph(issuer or "-", cell), Paragraph(escape(r["ip"] or "-"), cell)])
        bg, fg = PDF_COLORS[r["status"]]
        style += [("BACKGROUND", (2, i), (2, i), colors.HexColor(bg)), ("TEXTCOLOR", (2, i), (2, i), colors.HexColor(fg))]
    # status text colour: re-render those paragraphs with colour
    for i, r in enumerate(rows, 1):
        fg = PDF_COLORS[r["status"]][1]
        data[i][2] = Paragraph(f"<font color='{fg}'><b>{STATUS_LABEL[r['status']]}</b></font>", cell)

    widths = [9 * mm, 78 * mm, 48 * mm, 26 * mm, 22 * mm, 58 * mm, 24 * mm]
    scale = (landscape(A4)[0] - 24 * mm) / sum(widths)
    t = Table(data, colWidths=[w * scale for w in widths], repeatRows=1)
    t.setStyle(TableStyle(style))
    story.append(t)

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#5B6874"))
        canvas.drawString(12 * mm, 8 * mm, f"{snap['domain']} - SSL certificate expiry report")
        canvas.drawRightString(landscape(A4)[0] - 12 * mm, 8 * mm, f"Page {d.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
