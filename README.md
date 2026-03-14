# CTF Recon Tool - Web App

A dark hacker-style web interface for the CTF Recon Tool, built with Flask.

Web-App: https://ctf-recon-web.onrender.com/

## Features
- ⚡ **Full Automated Recon:** Runs Port Scan, Subdomain Enum, WHOIS, and Dir Brute-force concurrently
- ⬡ **Port Scanner:** Fast threaded TCP port scanning
- ◈ **Subdomain Enumerator:** DNS brute-force discovery
- ◎ **WHOIS / IP Lookup:** Domain WHOIS mapping and IP geolocation
- ▦ **Directory Brute-Forcer:** Discovery for hidden web paths
- 🔓 **PDF Unlocker:** Brute-force date-based passwords on encrypted PDFs
- 📝 **Wordlist Generator:** Generate personalized targeted wordlists

## Run Locally

```bash
git clone https://github.com/rudrapatel3504/CTF-Recon-Web
cd CTF-Recon-Web
pip install -r requirements.txt

# For the PDF Unlocker to work on linux/mac:
sudo apt install pdfcrack qpdf

python app.py
# Open http://localhost:5000
```

## Deploy to Render (Free)

1. Push this folder to a GitHub repo
2. Go to [render.com](https://render.com) → New → Web Service
3. Connect your GitHub repo
4. Set:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
5. Click Deploy — your app will be live in ~2 minutes!

*(Note: Render's native free tier might lack the `pdfcrack` and `qpdf` system binaries needed for PDF Unlocker unless you configure a Dockerfile deployment).*

## Project Structure

```
CTF-Recon-Web/
├── app.py                        # Flask backend API & app routing
├── requirements.txt
├── Procfile                      # For deployment
├── templates/
│   └── index.html                # Terminal UI frontend
└── CTF_Recon/
    ├── generator.py              # Logic for wordlist generator
    └── wordlists/
        ├── subdomains.txt
        └── dirs.txt
```

## ⚠️ Legal Disclaimer
This tool is intended **only** for use on systems you own or have explicit written permission to test. Unauthorized scanning is illegal. Use responsibly.
