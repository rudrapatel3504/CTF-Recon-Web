"""
CTF Recon Tool - Flask Web App
"""

from flask import Flask, render_template, request, jsonify, stream_with_context, Response
import socket
import concurrent.futures
import json
import urllib.request
import urllib.error
import threading
import queue
import time

app = Flask(__name__)

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
    data   = request.json
    domain = data.get("domain", "").strip().lower()

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    try:
        with open("CTF_Recon/wordlists/subdomains.txt") as f:
            words = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return jsonify({"error": "Wordlist not found"}), 500

    def check(word):
        sub = f"{word}.{domain}"
        try:
            ip = socket.gethostbyname(sub)
            return {"subdomain": sub, "ip": ip}
        except Exception:
            return None

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        results = ex.map(check, words)
    found = [r for r in results if r]

    return jsonify({"domain": domain, "found": found})

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
    data = request.json
    url  = data.get("url", "").strip().rstrip("/")
    exts = ["", ".php", ".html", ".txt", ".bak"]

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        with open("CTF_Recon/wordlists/dirs.txt") as f:
            words = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return jsonify({"error": "Wordlist not found"}), 500

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

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        results = ex.map(probe, targets)
    found = [r for r in results if r]

    return jsonify({"url": url, "found": found})

# ─── Run ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True)
