<<<<<<< HEAD
# CTF Recon Tool - Web App

A dark hacker-style web interface for the CTF Recon Tool, built with Flask.

## Features
- ⬡ Port Scanner
- ◈ Subdomain Enumerator  
- ◎ WHOIS / IP Lookup
- ▦ Directory Brute-Forcer

## Run Locally

```bash
pip install -r requirements.txt
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

## Project Structure

```
ctf-webapp/
├── app.py                        # Flask backend
├── requirements.txt
├── Procfile                      # For deployment
├── templates/
│   └── index.html                # Terminal UI frontend
└── CTF_Recon/
    └── wordlists/
        ├── subdomains.txt
        └── dirs.txt
```

## ⚠️ Legal Disclaimer
Only use on systems you own or have explicit permission to test.
=======
# CTF-Recon-Web
>>>>>>> ee5c8539a049468d114ee201075625debdf2ade6
