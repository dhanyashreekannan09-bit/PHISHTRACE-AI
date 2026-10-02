# PHISHTRACE AI

AI-Powered Phishing Investigation & Digital Forensics Laboratory.

This is a self-contained local web application designed to run from VS Code.
It does not depend on a particular country, domain registrar, ISP, or timezone.

## Features

- Professional cybersecurity dashboard
- URL investigation without visiting the submitted website
- `.eml` email forensic parsing
- Sender / Reply-To / authentication-header extraction
- Suspicious URL and domain indicators
- Explainable risk scoring
- Evidence timeline
- Attack-chain visualization
- Case history stored in SQLite
- Downloadable PDF investigation report
- Demo sample email
- No API key required for the core application

## Important security design

The URL analyzer intentionally parses the URL instead of automatically opening it.
This reduces the risk of SSRF, malware delivery, redirects, credential theft, and accidental
interaction with hostile infrastructure.

The risk score is a heuristic investigation aid, not proof that a URL or email is malicious.

## Requirements

- Python 3.10+
- VS Code
- Internet is NOT required for the core application

## Windows setup

Open the project folder in VS Code terminal:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

Then open:

http://127.0.0.1:8000

## macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

Open:

http://127.0.0.1:8000

## Demo

Use the included:

`sample_data/phishing_sample.eml`

You can upload it from the Email Investigation panel.

## Project structure

```text
PHISHTRACE-AI/
├── app/
│   ├── main.py
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── app.js
│       └── style.css
├── sample_data/
│   └── phishing_sample.eml
├── .env.example
├── requirements.txt
└── README.md
```

## Production notes

For a real deployment, put the app behind HTTPS, add authentication, use PostgreSQL,
add structured logging, rate limits, background jobs, and a dedicated malware-analysis
sandbox. Do not execute attachments or visit suspicious URLs directly from the web server.

For threat-intelligence enrichment, integrate reputable providers separately and keep API
keys on the server. The included project intentionally remains functional without them.
