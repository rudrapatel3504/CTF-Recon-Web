import textwrap
from fpdf import FPDF
from datetime import datetime

class ReconPDF(FPDF):
    def header(self):
        # Logo / Title
        self.set_font('helvetica', 'B', 18)
        self.set_text_color(0, 51, 102)  # Dark Blue
        self.cell(0, 10, 'CTF RECON - SECURITY ASSESSMENT REPORT', border=False, ln=True, align='C')
        self.ln(5)

    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        # Page number
        self.cell(0, 10, f'Page {self.page_no()} / {{nb}}', align='C')

    def chapter_title(self, title):
        self.set_font('helvetica', 'B', 14)
        self.set_fill_color(240, 240, 240) # Light grey
        self.set_text_color(0, 0, 0)
        self.cell(0, 10, title, border=False, ln=True, fill=True)
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('helvetica', '', 11)
        self.multi_cell(0, 6, body)
        self.ln(4)

def force_wrap(text, width=70):
    """
    Forcefully wraps text to a specific width, even if there are no spaces.
    This prevents FPDF from throwing "Not enough horizontal space" errors.
    """
    text = str(text).replace('\r', '')
    lines = text.split('\n')
    wrapped_lines = []
    for line in lines:
        if not line:
            wrapped_lines.append('')
            continue
        
        # Manually chunk the line into 'width' character pieces if no spaces are found
        # to ensure it fits in a cell.
        chunks = []
        words = line.split(' ')
        for word in words:
            if len(word) > width:
                # Chunk long contiguous string
                for i in range(0, len(word), width):
                    chunks.append(word[i:i+width])
            else:
                chunks.append(word)
        
        rejoined = ' '.join(chunks)
        wrapped_lines.extend(textwrap.wrap(rejoined, width))
        
    return '\n'.join(wrapped_lines)

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

    # 1. Port Scan
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
            pdf.cell(30, 8, str(p.get("port", "")), border=1, align="C")
            pdf.cell(60, 8, str(p.get("service", "")), border=1, align="C")
            pdf.cell(30, 8, "OPEN", border=1, align="C")
            pdf.ln()
    pdf.ln(8)

    # 2. Subdomains
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
            sub = str(sd[0])[:50] # Limit length for table
            ip = str(sd[1])
            pdf.cell(100, 8, sub, border=1)
            pdf.cell(60, 8, ip, border=1)
            pdf.ln()
    pdf.ln(8)

    # 3. WHOIS / Geo
    whois_dict = report_dict.get("whois", {})
    geo = whois_dict.get("geo_data", {})
    wd = whois_dict.get("whois_data", {})
    
    pdf.add_page()
    pdf.chapter_title("3. Target Geolocation & WHOIS")
    
    if geo:
        pdf.set_font('helvetica', 'B', 11)
        pdf.cell(0, 8, "Geolocation Info:", ln=True)
        pdf.set_font('helvetica', '', 11)
        for k, v in geo.items():
            pdf.cell(40, 6, str(k).capitalize() + ":")
            pdf.multi_cell(0, 6, str(v))
        pdf.ln(4)
    
    if wd:
        pdf.set_font('helvetica', 'B', 11)
        pdf.cell(0, 8, "WHOIS Info:", ln=True)
        pdf.set_font('helvetica', '', 9)
        for k, v in wd.items():
            if v:
                if isinstance(v, list):
                    v = ", ".join([str(item) for item in v])
                elif isinstance(v, dict):
                    v = str(v)
                
                # Use our robust wrapper
                val_str = force_wrap(v, 75)
                if len(val_str) > 2000:
                    val_str = val_str[:2000] + "..."
                    
                pdf.cell(40, 6, str(k) + ":")
                # Indent subsequent lines if any
                first = True
                for line in val_str.split('\n'):
                    if not first:
                        pdf.cell(40, 6, "")
                    pdf.cell(0, 6, line, ln=True)
                    first = False
        pdf.ln(4)
        
    if not geo and not wd:
        pdf.chapter_body("No WHOIS or Geolocation data could be retrieved.")
        
    pdf.ln(4)

    # 4. Directories
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
            code = str(d.get("status", ""))
            url = str(d.get("url", ""))[:70] # Truncate if too long
            meaning = str(d.get("meaning", ""))[:20]
            
            pdf.cell(20, 8, code, border=1, align="C")
            pdf.cell(130, 8, url, border=1)
            pdf.cell(40, 8, meaning, border=1)
            pdf.ln()

    # Output to File
    pdf.output(output_path)
    return output_path
