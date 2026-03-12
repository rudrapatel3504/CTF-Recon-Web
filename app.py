"""
CTF Recon Tool - Flask Web App
"""

from flask import Flask, render_template, request, jsonify, stream_with_context, Response, send_file
import io
import socket
import concurrent.futures
import json
import urllib.request
import urllib.error
import threading
import queue
import time
import os
import re
import shutil
import subprocess
import tempfile
from datetime import date, timedelta
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB max upload

# Always return JSON errors (never HTML)
@app.errorhandler(400)
def bad_request(e):    return jsonify(error=str(e)), 400

@app.errorhandler(413)
def too_large(e):      return jsonify(error="File too large. Max 50MB."), 413

@app.errorhandler(500)
def server_error(e):   return jsonify(error=f"Internal server error: {e}"), 500

PDF_WORDLIST = "/tmp/pdf_dates_wordlist.txt"
ALLOWED_EXTENSIONS = {'pdf'}
ALLOWED_WORDLIST_EXTENSIONS = {'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_wordlist(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_WORDLIST_EXTENSIONS

def load_wordlist(uploaded_file, default_path):
    """Load wordlist from uploaded file or fall back to default path."""
    if uploaded_file and uploaded_file.filename and allowed_wordlist(uploaded_file.filename):
        content = uploaded_file.read().decode("utf-8", errors="ignore")
        words = [l.strip() for l in content.splitlines() if l.strip()]
        return words, f"custom ({len(words)} entries)"
    with open(default_path) as f:
        words = [l.strip() for l in f if l.strip()]
    return words, "default"


# ─── Helpers ──────────────────────────────────────────────────────────────────

COMMON_PORTS = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
    110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",3306:"MySQL",
    3389:"RDP",5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",
}

INTERESTING_CODES = {
    200:"OK",201:"Created",204:"No Content",301:"Redirect",
    302:"Found",401:"Unauthorized",403:"Forbidden",500:"Server Error",
}

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

# ── Port Scanner ──────────────────────────────────────────────────────────────

@app.route("/api/portscan", methods=["POST"])
def portscan():
    data = request.json
    target = data.get("target", "").strip()
    start  = int(data.get("start", 1))
    end    = int(data.get("end", 1024))

    if not target:
        return jsonify({"error": "No target provided"}), 400

    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((target, port)) == 0:
                    return port
        except Exception:
            pass
        return None

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return jsonify({"error": f"Cannot resolve {target}"}), 400

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=150) as ex:
        results = ex.map(scan_port, range(start, end + 1))
    for p in results:
        if p:
            open_ports.append({"port": p, "service": COMMON_PORTS.get(p, "Unknown")})

    return jsonify({"ip": ip, "target": target, "open_ports": sorted(open_ports, key=lambda x: x["port"])})

# ── Subdomain Enum ────────────────────────────────────────────────────────────

@app.route("/api/subdomain", methods=["POST"])
def subdomain():
    domain = (request.form.get("domain") or (request.json or {}).get("domain", "")).strip().lower()

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    try:
        uploaded = request.files.get("wordlist")
        words, wl_source = load_wordlist(uploaded, "CTF_Recon/wordlists/subdomains.txt")
    except FileNotFoundError:
        return jsonify({"error": "Default wordlist not found"}), 500

    def check(word):
        sub = f"{word}.{domain}"
        try:
            ip = socket.gethostbyname(sub)
            return {"subdomain": sub, "ip": ip}
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        results = ex.map(check, words)
    found = [r for r in results if r]

    return jsonify({"domain": domain, "found": found, "wordlist": wl_source})

# ── WHOIS / IP Lookup ─────────────────────────────────────────────────────────

@app.route("/api/whois", methods=["POST"])
def whois_lookup():
    data   = request.json
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "No target provided"}), 400

    result = {"target": target, "geo": {}, "whois": {}}

    # Resolve IP
    try:
        ip = socket.gethostbyname(target)
        result["ip"] = ip
    except socket.gaierror:
        return jsonify({"error": f"Cannot resolve {target}"}), 400

    # Geo lookup
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}", timeout=5) as resp:
            geo = json.loads(resp.read().decode())
        if geo.get("status") == "success":
            result["geo"] = {k: geo.get(k) for k in ["country","regionName","city","isp","org","as","timezone"]}
    except Exception as e:
        result["geo_error"] = str(e)

    # WHOIS
    try:
        import whois
        w = whois.whois(target)
        result["whois"] = {
            "domain":      str(w.domain_name or ""),
            "registrar":   str(w.registrar or ""),
            "created":     str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date or ""),
            "expires":     str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date or ""),
            "nameservers": ", ".join(w.name_servers or [])[:100],
            "org":         str(w.org or ""),
            "emails":      str(w.emails[0] if isinstance(w.emails, list) else w.emails or ""),
        }
    except Exception as e:
        result["whois_error"] = str(e)

    return jsonify(result)

# ── Directory Brute-Force ─────────────────────────────────────────────────────

@app.route("/api/dirbrute", methods=["POST"])
def dirbrute():
    url  = (request.form.get("url") or (request.json or {}).get("url", "")).strip().rstrip("/")
    exts = ["", ".php", ".html", ".txt", ".bak"]

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        uploaded = request.files.get("wordlist")
        words, wl_source = load_wordlist(uploaded, "CTF_Recon/wordlists/dirs.txt")
    except FileNotFoundError:
        return jsonify({"error": "Default wordlist not found"}), 500

    targets = [f"{word}{ext}" for word in words for ext in exts]

    def probe(path):
        full = f"{url}/{path}"
        try:
            req = urllib.request.Request(full, method="HEAD")
            req.add_header("User-Agent", "CTFRecon/1.0")
            with urllib.request.urlopen(req, timeout=4) as resp:
                code = resp.status
                if code in INTERESTING_CODES:
                    return {"url": full, "status": code, "meaning": INTERESTING_CODES[code]}
        except urllib.error.HTTPError as e:
            if e.code in INTERESTING_CODES:
                return {"url": full, "status": e.code, "meaning": INTERESTING_CODES.get(e.code, "?")}
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        results = ex.map(probe, targets)
    found = [r for r in results if r]

    return jsonify({"url": url, "found": found, "wordlist": wl_source})

# ── PDF Unlocker ──────────────────────────────────────────────────────────────

def _build_pdf_wordlist():
    if os.path.exists(PDF_WORDLIST):
        return PDF_WORDLIST
    end_date = date.today()
    start_date = end_date - timedelta(days=120 * 365 + 30)
    with open(PDF_WORDLIST, "w") as f:
        cur = end_date
        while cur >= start_date:
            f.write(cur.strftime("%d%m%Y") + "\n")
            cur -= timedelta(days=1)
    return PDF_WORDLIST


@app.route("/api/pdfunlock", methods=["POST"])
def pdfunlock():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        f = request.files['file']
        if not f or not allowed_file(f.filename):
            return jsonify({"error": "Please upload a valid PDF file"}), 400

        # Check system tools — search PATH + common install locations
        extra_paths = ["/usr/local/bin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/sbin"]
        for tool in ("pdfcrack", "qpdf"):
            found = shutil.which(tool) or any(
                os.path.isfile(os.path.join(p, tool)) for p in extra_paths
            )
            if not found:
                return jsonify({"error": f"Server missing tool: {tool}. Install with: sudo yum install -y qpdf  (for pdfcrack: build from source)"}), 500

        with tempfile.TemporaryDirectory() as tmpdir:
            filename    = secure_filename(f.filename) or "upload.pdf"
            input_path  = os.path.join(tmpdir, filename)
            base, ext   = os.path.splitext(filename)
            output_path = os.path.join(tmpdir, f"{base}_unlocked{ext}")

            f.save(input_path)

            if not os.path.exists(input_path) or os.path.getsize(input_path) == 0:
                return jsonify({"error": "Failed to save uploaded file."}), 400

            # Build or load wordlist
            try:
                custom_wl = request.files.get("wordlist")
                if custom_wl and custom_wl.filename and allowed_wordlist(custom_wl.filename):
                    wl_path = os.path.join(tmpdir, "custom_wordlist.txt")
                    custom_wl.save(wl_path)
                    wordlist = wl_path
                    wl_source = f"custom ({sum(1 for _ in open(wl_path))} entries)"
                else:
                    wordlist = _build_pdf_wordlist()
                    wl_source = "default DDMMYYYY (120 years)"
            except Exception as e:
                return jsonify({"error": f"Failed to prepare wordlist: {e}"}), 500

            # Run pdfcrack
            try:
                result = subprocess.run(
                    ["pdfcrack", "-f", input_path, "-w", wordlist],
                    capture_output=True, text=True, timeout=360
                )
            except subprocess.TimeoutExpired:
                return jsonify({"error": "pdfcrack timed out after 6 minutes. Password not found."}), 422
            except Exception as e:
                return jsonify({"error": f"pdfcrack failed to run: {e}"}), 500

            match = re.search(r"found user-password:\s*'([^']*)'", result.stdout)
            if not match:
                detail = (result.stderr.strip() or result.stdout.strip() or "No output from pdfcrack.")[:300]
                return jsonify({"error": "Password not found. Not a DDMMYYYY date in the last 120 years.", "detail": detail}), 422

            password = match.group(1)

            # Decrypt with qpdf
            try:
                dec = subprocess.run(
                    ["qpdf", f"--password={password}", "--decrypt", input_path, output_path],
                    capture_output=True, text=True, timeout=60
                )
            except subprocess.TimeoutExpired:
                return jsonify({"error": f"Found password '{password}' but qpdf decryption timed out."}), 500
            except Exception as e:
                return jsonify({"error": f"qpdf failed to run: {e}"}), 500

            if dec.returncode != 0:
                err_detail = dec.stderr.strip() or "Unknown qpdf error."
                return jsonify({"error": f"Found password '{password}' but decryption failed: {err_detail}"}), 500

            if not os.path.exists(output_path):
                return jsonify({"error": f"Found password '{password}' but output file was not created."}), 500

            # Read bytes into memory BEFORE tempdir is deleted
            with open(output_path, 'rb') as pdf_file:
                pdf_bytes = io.BytesIO(pdf_file.read())

        # tempdir is now cleaned up — serve from memory
        pdf_bytes.seek(0)
        return send_file(
            pdf_bytes,
            as_attachment=True,
            download_name=f"{base}_unlocked{ext}",
            mimetype="application/pdf"
        )

    except Exception as e:
        # Catch-all: return JSON instead of Flask's HTML 500 page
        return jsonify({"error": f"Unexpected server error: {str(e)}"}), 500

# ─── Run ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True)