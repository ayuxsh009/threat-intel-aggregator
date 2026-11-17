"""PDF report generation (in memory) and email delivery."""

from __future__ import annotations

import io
import smtplib
from collections import Counter
from datetime import datetime
from email.message import EmailMessage

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from .config import APP_NAME, RISK_COLORS, RISK_ORDER

_INK = (15, 23, 42)
_MUTED = (100, 116, 139)
_ACCENT = (99, 102, 241)
_LINE = (226, 232, 240)


def _latin(text, limit: int | None = None) -> str:
    """Core PDF fonts only cover Latin-1; replace anything else instead of crashing."""
    s = "" if text is None else str(text)
    s = s.replace("–", "-").replace("—", "-").replace("…", "...")
    if limit and len(s) > limit:
        s = s[: limit - 3] + "..."
    return s.encode("latin-1", "replace").decode("latin-1")


def _rgb(hex_color: str) -> tuple[int, int, int]:
    h = hex_color.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


class _ReportPDF(FPDF):
    def __init__(self, subtitle: str):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.subtitle = subtitle
        self.set_margins(14, 14, 14)
        self.set_auto_page_break(True, margin=18)

    def header(self):
        self.set_fill_color(*_INK)
        self.rect(0, 0, self.w, 20, "F")
        self.set_fill_color(*_ACCENT)
        self.rect(0, 20, self.w, 1.2, "F")
        self.set_xy(14, 6)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(255, 255, 255)
        self.cell(90, 8, _latin(APP_NAME))
        self.set_xy(self.w - 104, 6)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(165, 180, 252)
        self.cell(90, 8, _latin(self.subtitle, 60), align="R")
        self.set_y(28)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*_MUTED)
        self.cell(0, 6, "Confidential - for internal security use", align="L")
        self.set_x(14)
        self.cell(0, 6, f"Page {self.page_no()} of {{nb}}", align="R")


_COLS = [("Indicator", 60), ("Type", 18), ("Risk", 24), ("Score", 14), ("VT", 16), ("Abuse %", 20), ("Scanned", 30)]


def _table_header(pdf: _ReportPDF) -> None:
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(241, 245, 249)
    pdf.set_text_color(*_INK)
    pdf.set_draw_color(*_LINE)
    for name, w in _COLS:
        pdf.cell(w, 8, name, border="B", fill=True)
    pdf.ln(8)


def build_pdf(results: list[dict], *, title: str, author: str, chart_png: bytes | None = None) -> bytes:
    counts = Counter(r.get("risk", "Unknown") for r in results)
    now = datetime.now()
    pdf = _ReportPDF(subtitle=title)
    pdf.set_title(_latin(title))
    pdf.set_creator(APP_NAME)
    pdf.add_page()

    # Title block
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*_INK)
    pdf.cell(0, 10, _latin(title, 70), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*_MUTED)
    pdf.cell(0, 6, _latin(f"Generated {now:%d %b %Y, %H:%M} by {author}  |  {len(results)} indicators"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)

    # Summary tiles
    tile_w, gap = 33.2, 3
    y = pdf.get_y()
    for i, risk in enumerate(RISK_ORDER):
        x = 14 + i * (tile_w + gap)
        pdf.set_fill_color(248, 250, 252)
        pdf.set_draw_color(*_LINE)
        pdf.rect(x, y, tile_w, 20, "DF")
        pdf.set_fill_color(*_rgb(RISK_COLORS[risk]))
        pdf.rect(x, y, 1.6, 20, "F")
        pdf.set_xy(x + 4, y + 3)
        pdf.set_font("Helvetica", "B", 15)
        pdf.set_text_color(*_INK)
        pdf.cell(tile_w - 6, 7, str(counts.get(risk, 0)))
        pdf.set_xy(x + 4, y + 11)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*_MUTED)
        pdf.cell(tile_w - 6, 5, risk.upper())
    pdf.set_y(y + 26)

    if chart_png:
        pdf.image(io.BytesIO(chart_png), x=(pdf.w - 120) / 2, w=120)
        pdf.ln(4)

    # Key findings
    flagged = [r for r in results if r.get("risk") in ("High", "Medium")]
    if flagged:
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(*_INK)
        pdf.cell(0, 8, "Key findings", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        for r in flagged[:15]:
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*_rgb(RISK_COLORS[r["risk"]]))
            pdf.cell(18, 5.5, r["risk"].upper())
            pdf.set_text_color(*_INK)
            pdf.cell(0, 5.5, _latin(r.get("ioc"), 90), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", "", 8.5)
            pdf.set_text_color(*_MUTED)
            pdf.set_x(32)
            pdf.multi_cell(0, 4.5, _latin("; ".join(r.get("reasons", [])), 220),
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(1)
        if len(flagged) > 15:
            pdf.set_font("Helvetica", "I", 8.5)
            pdf.cell(0, 5, f"... and {len(flagged) - 15} more in the table below.",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

    # Full table
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*_INK)
    pdf.cell(0, 8, "All indicators", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    _table_header(pdf)
    for r in results:
        if pdf.get_y() > pdf.h - 26:
            pdf.add_page()
            _table_header(pdf)
        vt = r.get("vt") or {}
        abuse = r.get("abuse") or {}
        risk = r.get("risk", "Unknown")
        cells = [
            _latin(r.get("ioc"), 31),
            _latin(r.get("type")),
            risk,
            str(r["score"]) if isinstance(r.get("score"), int) else "-",
            str(vt.get("malicious", "-")) if vt.get("ok") else "-",
            f"{abuse.get('confidence')}%" if abuse.get("ok") else "-",
            _latin(str(r.get("timestamp", "")).replace("T", " ")[:16]),
        ]
        pdf.set_draw_color(*_LINE)
        for (name, w), value in zip(_COLS, cells):
            if name == "Risk":
                pdf.set_font("Helvetica", "B", 8.5)
                pdf.set_text_color(*_rgb(RISK_COLORS.get(risk, "#64748b")))
            else:
                pdf.set_font("Courier" if name == "Indicator" else "Helvetica", "", 8.5)
                pdf.set_text_color(*_INK)
            pdf.cell(w, 7, value, border="B")
        pdf.ln(7)

    errored = [r for r in results if r.get("errors")]
    if errored:
        pdf.ln(5)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*_INK)
        pdf.cell(0, 7, "Lookup problems", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*_MUTED)
        for r in errored:
            pdf.multi_cell(0, 4.5, _latin(f"{r.get('ioc')}: " + "; ".join(r["errors"]), 300),
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    return bytes(pdf.output())


def send_email(pdf_bytes: bytes, filename: str, *, recipient: str, sender: str, password: str,
               host: str = "smtp.gmail.com", port: int = 465, subject: str = "Threat intelligence report") -> None:
    """Send the PDF as an attachment. Raises on failure."""
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    msg.set_content("Attached is the latest threat intelligence report.")
    msg.add_attachment(pdf_bytes, maintype="application", subtype="pdf", filename=filename)
    if int(port) == 465:
        with smtplib.SMTP_SSL(host, int(port), timeout=30) as smtp:
            smtp.login(sender, password)
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(host, int(port), timeout=30) as smtp:
            smtp.starttls()
            smtp.login(sender, password)
            smtp.send_message(msg)
