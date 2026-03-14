import textwrap
from fpdf import FPDF
from datetime import datetime


class ReconPDF(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 18)
        self.set_text_color(0, 51, 102)
        self.cell(0, 10, 'CTF RECON - SECURITY ASSESSMENT REPORT', border=False, ln=True, align='C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()} / {{nb}}', align='C')

    def chapter_title(self, title):
        self.set_font('helvetica', 'B', 14)
        self.set_fill_color(240, 240, 240)
        self.set_text_color(0, 0, 0)
        self.cell(0, 10, title, border=False, ln=True, fill=True)
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('helvetica', '', 11)
        self.cell(0, 8, body, ln=True)
        self.ln(4)


def safe_str(value, max_chars=200):
    """
    Convert any value to a safe string for FPDF.
    Handles lists, dicts, datetime objects, etc.
    Limits to max_chars to avoid overflow.
    """
    if isinstance(value, list):
        # Join list items as comma-separated, each item as safe string
        value = ", ".join(safe_str(item, max_chars=60) for item in value)
    elif isinstance(value, dict):
        value = str(value)
    elif hasattr(value, 'isoformat'):
        # Handle datetime objects
        value = value.isoformat()
    else:
        value = str(value)

    value = value.replace('\r', '').strip()

    if len(value) > max_chars:
        value = value[:max_chars] + "..."

    return value


def safe_lines(value, max_chars=200, width=80):
    """
    Convert a value to a list of safe, width-limited strings for FPDF cell printing.
    Breaks long lines at `width` characters.
    """
    text = safe_str(value, max_chars)
    result = []
    for line in text.split('\n'):
        if not line:
            result.append('')
            continue
        # Break into chunks of `width` chars to guarantee it fits in the cell
        for i in range(0, max(1, len(line)), width):
            result.append(line[i:i+width])
    return result if result else ['']


def print_kv(pdf, key, value, key_width=50, font_size=9):
    """Print a key-value pair safely, with multi-line wrapping for long values."""
    lines = safe_lines(value, max_chars=300, width=80)
    pdf.set_font('helvetica', '', font_size)
    pdf.cell(key_width, 6, str(key) + ":")
    if lines:
        pdf.cell(0, 6, lines[0], ln=True)
        for line in lines[1:]:
            if line:
                pdf.cell(key_width, 6, "")
                pdf.cell(0, 6, line, ln=True)
    else:
        pdf.ln()


def generate_pdf_report(report_dict, output_path):
    """
    Takes the aggregated report dictionary from FullRecon and generates a clean PDF.
    """
    target = report_dict.get("target", "Unknown")
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    pdf = ReconPDF()
    pdf.alias_nb_pages()
    pdf.add_page()

    # Overview Section
    pdf.set_font('helvetica', '', 11)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 8, f"Target Domain/IP: {target}", ln=True)
    pdf.cell(0, 8, f"Scan Date: {date_str}", ln=True)
    pdf.ln(10)

    # ----- 1. Port Scan -----
    ps = report_dict.get("port_scan", [])
    pdf.chapter_title("1. Open Ports / Services")
    if not ps:
        pdf.chapter_body("No open ports found in scanned range.")
    else:
        pdf.set_font('helvetica', 'B', 11)
        pdf.cell(30, 8, "Port", border=1, align="C")
        pdf.cell(60, 8, "Service", border=1, align="C")
        pdf.cell(30, 8, "State", border=1, align="C")
        pdf.ln()

        pdf.set_font('helvetica', '', 11)
        for p in ps:
            pdf.cell(30, 8, str(p.get("port", ""))[:10], border=1, align="C")
            pdf.cell(60, 8, str(p.get("service", ""))[:30], border=1, align="C")
            pdf.cell(30, 8, "OPEN", border=1, align="C")
            pdf.ln()
    pdf.ln(8)

    # ----- 2. Subdomains -----
    sds = report_dict.get("subdomains", [])
    pdf.chapter_title("2. Discovered Subdomains")
    if not sds:
        pdf.chapter_body("No subdomains discovered.")
    else:
        pdf.set_font('helvetica', 'B', 11)
        pdf.cell(100, 8, "Subdomain", border=1)
        pdf.cell(60, 8, "IP Address", border=1)
        pdf.ln()

        pdf.set_font('helvetica', '', 11)
        for sd in sds:
            if isinstance(sd, dict):
                sub = str(sd.get("subdomain", ""))[:50]
                ip  = str(sd.get("ip", ""))[:30]
            else:
                sub = str(sd[0])[:50]
                ip  = str(sd[1])[:30]
            pdf.cell(100, 8, sub, border=1)
            pdf.cell(60, 8, ip, border=1)
            pdf.ln()
    pdf.ln(8)

    # ----- 3. WHOIS / Geo -----
    # The web API returns keys "geo" and "whois"; CLI stores as "geo_data"/"whois_data"
    whois_dict = report_dict.get("whois", {}) or {}
    geo = whois_dict.get("geo") or whois_dict.get("geo_data") or {}
    wd  = whois_dict.get("whois") or whois_dict.get("whois_data") or {}

    pdf.add_page()
    pdf.chapter_title("3. Target Geolocation & WHOIS")

    if geo:
        pdf.set_font('helvetica', 'B', 11)
        pdf.cell(0, 8, "Geolocation Info:", ln=True)
        for k, v in geo.items():
            print_kv(pdf, str(k).capitalize(), v, key_width=40, font_size=10)
        pdf.ln(4)

    if wd:
        pdf.set_font('helvetica', 'B', 11)
        pdf.cell(0, 8, "WHOIS Info:", ln=True)
        for k, v in wd.items():
            if v:
                print_kv(pdf, k, v, key_width=45, font_size=9)
        pdf.ln(4)

    if not geo and not wd:
        pdf.chapter_body("No WHOIS or Geolocation data could be retrieved.")

    pdf.ln(4)

    # ----- 4. Directories -----
    dirs = report_dict.get("directories", [])
    pdf.chapter_title("4. Discovered Directories/Files")
    if not dirs:
        pdf.chapter_body("No hidden files or directories found.")
    else:
        pdf.set_font('helvetica', 'B', 11)
        pdf.cell(20, 8, "Code", border=1, align="C")
        pdf.cell(130, 8, "URL Path", border=1)
        pdf.cell(40, 8, "Status", border=1)
        pdf.ln()

        pdf.set_font('helvetica', '', 10)
        for d in dirs:
            code = str(d.get("status", ""))[:6]
            url = str(d.get("url", ""))[:60]
            meaning = str(d.get("meaning", ""))[:20]

            pdf.cell(20, 8, code, border=1, align="C")
            pdf.cell(130, 8, url, border=1)
            pdf.cell(40, 8, meaning, border=1)
            pdf.ln()

    # Output to file
    pdf.output(output_path)
    return output_path
