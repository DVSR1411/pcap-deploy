from datetime import datetime
from fpdf import FPDF

# ── Colours (exact from reference PDF) ───────────────────────────────────────
C_NAVY      = (31,  41,  59)
C_BLUE      = (37,  97, 235)
C_ROW_GREY  = (245, 247, 250)
C_LABEL_BG  = (99, 115, 139)
C_WHITE     = (255, 255, 255)
C_BLACK     = (0,   0,   0)
C_BORDER    = (199, 199, 199)
C_GREY_TEXT = (80,  80,  80)
C_META_TEXT = (100, 116, 139)

# ── Layout (1 pt = 0.3528 mm) ─────────────────────────────────────────────────
# All values derived from pdfplumber measurements of reference PDF
MARGIN   = 14.1    # 40pt  — table left/right margin
COV_X    = 30.0    # 85pt  — cover text left edge
ROW_H    = 6.78   # 19.2pt — table row height
INNER_W  = 181.5   # 515.28pt — usable table width
COL1     = 50.0    # 141.73pt — label column
COL2     = INNER_W - COL1
SEC_H    = 7.1     # ~20pt — section bar height

# IP page header: full-width navy bar = 99.2pt = 35.0mm
# "IP INTELLIGENCE FOR" top = 8.5mm, height = 10.8mm  (baseline 30.5pt=10.8mm)
# "[#001] ip"            top = 21.8mm, height = 13.0mm (baseline 61.9pt=21.8mm)
IP_HDR_H   = 35.0
IP_L1_TOP  = 6.8
IP_L1_H    = 10.8
IP_L2_H    = 15.5   # tuned: ref IP line y=61.9pt, L1_TOP+L1_H = 17.6mm = 49.9pt, need +12pt more

# Gap between IP header bottom and first section bar = 133.8pt - 99.2pt = 34.6pt = 12.2mm, tuned
IP_HDR_GAP = 10.4

# KV header gap: ref 161.4pt - 133.8pt = 27.6pt = 9.75mm (sec_h=7.1 + header_row=6.78 = 13.88mm)
# difference absorbed by _kv_header having no top border — add explicit top pad
KV_HDR_TOP_PAD = 2.5   # extra mm before PARAMETER/VALUE header row

# Gap between sections = ~2.8mm (from reference rect tops)
SEC_GAP    = 2.8

_UNICODE_MAP = {
    "\u2014": "-", "\u2013": "-", "\u2012": "-",
    "\u2018": "'", "\u2019": "'",
    "\u201c": '"', "\u201d": '"',
    "\u2026": "...",
}


def _san(text):
    if text is None:
        return "N/A"
    s = str(text)
    for uc, asc in _UNICODE_MAP.items():
        s = s.replace(uc, asc)
    return s.encode("latin-1", errors="replace").decode("latin-1")


def _val(v):
    s = _san(v)
    return s if s not in ("", "-", "N/A", "None") else "N/A"


class ReportPDF(FPDF):
    def __init__(self, generated_on=""):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.set_auto_page_break(auto=True, margin=14)
        self.set_margins(MARGIN, 0, MARGIN)
        self._current_ip_header = None
        self._ip_first_page = True
        self._generated_on = generated_on

    def header(self):
        if self.page_no() == 1 or self._current_ip_header is None or self._ip_first_page:
            return
        idx, ip = self._current_ip_header
        self.set_fill_color(*C_NAVY)
        self.rect(0, 0, self.w, IP_HDR_H, style="F")
        self.set_xy(MARGIN, IP_L1_TOP)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(150, 150, 150)
        self.cell(INNER_W, IP_L1_H, "IP INTELLIGENCE FOR (CONTINUED)", ln=True)
        self.set_x(MARGIN)
        self.set_font("Helvetica", "B", 22)
        self.set_text_color(*C_WHITE)
        self.cell(INNER_W, IP_L2_H, f"[#{idx:03d}] {_san(ip)}", ln=True)
        self.set_text_color(*C_BLACK)
        self.set_y(IP_HDR_H + IP_HDR_GAP)

    # ── Footer ────────────────────────────────────────────────────────────────
    def footer(self):
        if self.page_no() == 1:
            self.set_fill_color(*C_NAVY)
            self.rect(0, self.h - 11, self.w, 11, style="F")
            self.set_y(self.h - 7.5)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*C_WHITE)
            self.set_x(MARGIN)
            self.cell(INNER_W, 5, "CDAC-Hyderabad", align="L")
            self.set_text_color(*C_BLACK)
            return
        self.set_fill_color(*C_NAVY)
        self.rect(0, self.h - 11, self.w, 11, style="F")
        self.set_y(self.h - 7.5)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C_WHITE)
        self.set_x(MARGIN)
        self.cell(INNER_W / 2, 5, f"Report Generated: {self._generated_on}", align="L")
        self.set_x(MARGIN + INNER_W / 2)
        self.cell(INNER_W / 2, 5, f"Page {self.page_no() - 1}", align="R")
        self.set_text_color(*C_BLACK)

    # ── Section bar ───────────────────────────────────────────────────────────
    def _sec_bar(self, title):
        # Keep section bar + at least one row together
        if self.get_y() + SEC_H + ROW_H > self.h - self.b_margin:
            self.add_page()
        self.set_fill_color(*C_BLUE)
        self.set_text_color(*C_WHITE)
        self.set_font("Helvetica", "B", 10)
        self.set_x(MARGIN)
        self.cell(INNER_W, SEC_H, "  " + title, fill=True, ln=True)
        self.set_text_color(*C_BLACK)

    # ── KV table ──────────────────────────────────────────────────────────────
    def _kv_header(self, col1_label="PARAMETER", col2_label="VALUE"):
        self.ln(KV_HDR_TOP_PAD)
        # Keep header + at least one data row together
        if self.get_y() + ROW_H * 2 > self.h - self.b_margin:
            self.add_page()
            self.ln(KV_HDR_TOP_PAD)
        self.set_fill_color(*C_LABEL_BG)
        self.set_text_color(*C_WHITE)
        self.set_font("Helvetica", "B", 8)
        self.set_draw_color(*C_BORDER)
        self.set_x(MARGIN)
        self.cell(COL1, ROW_H, "  " + col1_label, border=0, fill=True)
        self.cell(COL2, ROW_H, "  " + col2_label, border=0, fill=True, ln=True)
        self.set_text_color(*C_BLACK)

    def _kv_row(self, label, value, even):
        if self.get_y() + ROW_H > self.h - self.b_margin:
            self.add_page()
        y = self.get_y()
        self.set_draw_color(*C_BORDER)

        # Label cell
        self.set_fill_color(*C_LABEL_BG)
        self.set_text_color(*C_WHITE)
        self.set_font("Helvetica", "B", 8)
        self.set_xy(MARGIN, y)
        self.cell(COL1, ROW_H, "  " + label.upper(), border=1, fill=True)

        # Value cell
        self.set_fill_color(*C_ROW_GREY if even else C_WHITE)
        self.set_text_color(*C_GREY_TEXT)
        self.set_font("Helvetica", "", 8)
        val = _val(value)
        self.set_xy(MARGIN + COL1, y)
        if self.get_string_width(val) <= COL2 - 4:
            self.cell(COL2, ROW_H, "  " + val, border=1, fill=True, ln=True)
        else:
            self.multi_cell(COL2, ROW_H, "  " + val, border=1, fill=True,
                            max_line_height=ROW_H)
        self.set_text_color(*C_BLACK)

    def _kv_table(self, rows, col1_label="PARAMETER", col2_label="VALUE"):
        # If the header + all rows don't fit, start a new page
        needed = KV_HDR_TOP_PAD + ROW_H * (1 + len(rows))
        if self.get_y() + needed > self.h - self.b_margin:
            self.add_page()
        self._kv_header(col1_label, col2_label)
        for i, (label, value) in enumerate(rows):
            self._kv_row(label, value, i % 2 == 0)

    # ── Multi-column table ────────────────────────────────────────────────────
    def _tbl_header(self, headers, col_widths):
        if self.get_y() + ROW_H * 2 > self.h - self.b_margin:
            self.add_page()
        self.set_fill_color(*C_LABEL_BG)
        self.set_text_color(*C_WHITE)
        self.set_draw_color(*C_BORDER)
        self.set_font("Helvetica", "B", 8)
        self.set_x(MARGIN)
        for h, w in zip(headers, col_widths):
            self.cell(w, ROW_H, "  " + h, border=1, fill=True)
        self.ln()
        self.set_text_color(*C_BLACK)

    def _tbl_row(self, cells, col_widths, even):
        if self.get_y() + ROW_H > self.h - self.b_margin:
            self.add_page()
        self.set_fill_color(*C_ROW_GREY if even else C_WHITE)
        self.set_text_color(*C_GREY_TEXT)
        self.set_draw_color(*C_BORDER)
        self.set_font("Helvetica", "", 8)
        self.set_x(MARGIN)
        for cell, w in zip(cells, col_widths):
            self.cell(w, ROW_H, "  " + _val(cell), border=1, fill=True)
        self.ln()
        self.set_text_color(*C_BLACK)

    # ── Contact row ───────────────────────────────────────────────────────────
    def _contact_row(self, role, c, even, cw):
        if self.get_y() + ROW_H > self.h - self.b_margin:
            self.add_page()
        y = self.get_y()
        self.set_draw_color(*C_BORDER)
        self.set_fill_color(*C_LABEL_BG)
        self.set_text_color(*C_WHITE)
        self.set_font("Helvetica", "", 7)
        self.set_xy(MARGIN, y)
        self.cell(cw[0], ROW_H, "  " + role.upper(), border=1, fill=True)
        self.set_fill_color(*C_ROW_GREY if even else C_WHITE)
        self.set_text_color(*C_GREY_TEXT)
        for val, w in zip([c.get("name"), c.get("email"), c.get("phone")], cw[1:]):
            self.cell(w, ROW_H, "  " + _val(val), border=1, fill=True)
        self.ln()
        self.set_text_color(*C_BLACK)

    # ── Cover page ────────────────────────────────────────────────────────────
    def cover(self, title, subtitle, generated, total, meta_pairs):
        self.add_page()
        self.set_fill_color(*C_NAVY)
        self.rect(0, 0, self.w, self.h, style="F")

        # "REPORT" — 118pt = 41.7mm, size 12, Bold, white
        self.set_xy(COV_X, 41.7)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*C_WHITE)
        self.cell(0, 6, _san(subtitle).upper(), ln=True)

        # Title — 174.5pt = 61.6mm, size 48, Bold, white
        self.set_xy(COV_X, 61.6)
        self.set_font("Helvetica", "B", 48)
        self.multi_cell(self.w - COV_X * 2, 20, _san(title).upper(), align="L")

        # Meta — 401.5pt = 141.7mm, size 12, Bold, grey
        self.set_xy(COV_X, 141.7)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*C_META_TEXT)
        self.cell(0, 7, f"GENERATED ON: {generated}", ln=True)
        self.set_x(COV_X)
        self.cell(0, 7, f"TOTAL IDENTIFIERS: {total}", ln=True)
        for label, value in (meta_pairs or []):
            if value is not None:
                self.set_x(COV_X)
                self.cell(0, 7, f"{_san(str(label)).upper()}: {_san(str(value))}", ln=True)

        # "CDAC-Hyderabad" — 748.9pt = 264.4mm, size 10, Bold, blue
        self.set_xy(COV_X, 264.4)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*C_BLUE)
        self.cell(0, 6, "CDAC-Hyderabad")

    # ── IP page ───────────────────────────────────────────────────────────────
    def ip_page(self, idx, ip, intel):
        geo   = intel.get("geo")     if isinstance(intel.get("geo"),     dict) else {}
        whois = intel.get("whois")   if isinstance(intel.get("whois"),   dict) else {}
        dnsbl = intel.get("dnsbl")   if isinstance(intel.get("dnsbl"),   dict) else {}
        os_i  = intel.get("os_info") if isinstance(intel.get("os_info"), dict) else {}
        ports = intel.get("ports")   if isinstance(intel.get("ports"),   list) else []

        listed = "LISTED / AT RISK" if dnsbl.get("listed") else "CLEAN"
        lat = geo.get("latitude")  or (intel.get("location") or {}).get("lat")
        lon = geo.get("longitude") or (intel.get("location") or {}).get("lon")
        coords = f"{lat}, {lon}" if lat and lon else "N/A"

        self._current_ip_header = (idx, ip)
        self._ip_first_page = True
        self.add_page()
        self._ip_first_page = False

        # Navy header bar — full width, 35mm tall
        self.set_fill_color(*C_NAVY)
        self.rect(0, 0, self.w, IP_HDR_H, style="F")

        # "IP INTELLIGENCE FOR" — size 8, grey (150), at y=8.5mm
        self.set_xy(MARGIN, IP_L1_TOP)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(150, 150, 150)
        self.cell(INNER_W, IP_L1_H, "IP INTELLIGENCE FOR", ln=True)

        # "[#001] ip" — size 22, white, at y=IP_L1_TOP+IP_L1_H
        self.set_x(MARGIN)
        self.set_font("Helvetica", "B", 22)
        self.set_text_color(*C_WHITE)
        self.cell(INNER_W, IP_L2_H, f"[#{idx:03d}] {_san(ip)}", ln=True)
        self.set_text_color(*C_BLACK)

        # Gap to first section bar = 133.8pt - 99.2pt = 34.6pt = 12.2mm
        self.set_y(IP_HDR_H + IP_HDR_GAP)

        # Section 1
        self._sec_bar("HOST IDENTITY & NETWORK ORIGIN")
        self._kv_table([
            ("AUTONOMOUS SYSTEM NUMBER", intel.get("asn")),
            ("OS MATCH",                 os_i.get("best_match")),
            ("OS CONFIDENCE",            f"{os_i.get('confidence')}%" if os_i.get("confidence") else "N/A"),
            ("SYSTEM STATUS",            str(intel.get("status", "N/A")).upper()),
            ("DNSBL REPUTATION",         listed),
            ("rDNS / HOSTNAME",          intel.get("rdns")),
            ("PROXY TYPE",               intel.get("proxy_type")),
        ])
        self.ln(SEC_GAP)

        # Section 2
        self._sec_bar("ACTIVE NETWORK SERVICES")
        headers = ["PORT", "SERVICE / APPLICATION", "PROTOCOL", "STATE", "REASON"]
        col_w   = [INNER_W * w for w in (0.119, 0.387, 0.204, 0.128, 0.162)]
        self._tbl_header(headers, col_w)
        if ports:
            for i, p in enumerate(ports):
                self._tbl_row(
                    [p.get("port"), p.get("service"), p.get("protocol"),
                     p.get("state"), p.get("reason")],
                    col_w, i % 2 == 0
                )
        else:
            self._tbl_row(["-", "-", "-", "-", "-"], col_w, True)
        self.ln(SEC_GAP)

        # Section 3
        self._sec_bar("GEOGRAPHIC INTEL")
        self._kv_table([
            ("CITY / REGION", geo.get("city")),
            ("COUNTRY",       geo.get("country")),
            ("ISP",           geo.get("isp")),
            ("COORDINATES",   coords),
        ], col1_label="METADATA", col2_label="VALUE")
        self.ln(SEC_GAP)

        # Section 4
        self._sec_bar("OWNERSHIP DETAILS")
        w = whois if isinstance(whois, dict) else {}
        raw_contacts = w.get("contacts")
        contacts = raw_contacts if isinstance(raw_contacts, (dict, list)) else {}

        cw = [INNER_W * x for x in (0.252, 0.300, 0.252, 0.196)]
        self._tbl_header(["CONTACT TYPE", "NAME", "EMAIL", "PHONE"], cw)
        row_i = 0
        for role in ("administrative", "abuse", "technical", "registrant"):
            entries = _get_contacts(contacts, role)
            if not entries:
                entries = [{}]
            for c in entries:
                self._contact_row(role, c, row_i % 2 == 0, cw)
                row_i += 1
        self.ln(SEC_GAP)

        self._kv_table([
            ("ORGANIZATION",               w.get("org") or w.get("name")),
            ("NETWORK OWNER",              w.get("network_owner")),
            ("CIDR RANGE",                 w.get("cidr")),
            ("REGISTRAR",                  w.get("registrar")),
            ("TOP LEVEL DOMAIN / WEBSITE", f"{w.get('tld', 'N/A')} / {w.get('website', 'N/A')}"),
            ("REGISTERED DATE",            w.get("registered")),
        ])
        self._current_ip_header = None


def _get_contacts(contacts, role):
    if isinstance(contacts, dict):
        val = contacts.get(role)
        if isinstance(val, dict): return [val]
        if isinstance(val, list): return [c for c in val if isinstance(c, dict)]
        return []
    if isinstance(contacts, list):
        return [c for c in contacts if isinstance(c, dict) and c.get("type", "").lower() == role]
    return []


def build_pdf(title: str, subtitle: str, meta_pairs: list, ip_rows: list,
              section_title: str = "IP Intelligence Details",
              password: str = "") -> bytes:
    from zoneinfo import ZoneInfo
    ist = ZoneInfo("Asia/Kolkata")
    now_ist = datetime.now(ist)
    generated = now_ist.strftime("%d/%m/%Y, %I:%M:%S %p IST")
    pdf = ReportPDF(generated_on=generated)
    pdf.cover(title, subtitle, generated, len(ip_rows), meta_pairs)
    for idx, row in enumerate(ip_rows, start=1):
        pdf.ip_page(idx, row.get("ip", "Unknown"), row)
    if password:
        pdf.set_encryption(owner_password=password, user_password=password)
    return bytes(pdf.output())
