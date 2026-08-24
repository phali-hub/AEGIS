# AEGIS — AI-Powered Threat Intelligence & Cyber Defense Platform

A comprehensive cybersecurity platform combining real-time threat intelligence, AI-driven analysis, and autonomous vulnerability scanning under a single unified interface.

## Features

- **IP Threat Intelligence** — Query AbuseIPDB for abuse confidence scores, reports, and geo-ISP data with AI-generated threat assessments
- **URL Malware Scanning** — Cross-reference URLs against VirusTotal (70+ AV engines) and URLhaus (abuse.ch) for malicious payloads
- **Phishing Email Analyzer** — Parse raw emails, extract IOCs, check SPF/DKIM/DMARC authentication, and score phishing likelihood
- **AI-Powered Analysis** — Groq LLM (Llama 3.3 70B) provides analyst-grade threat assessments, MITRE ATT&CK TTP mapping, and actionable recommendations
- **AEGIS Vulnerability Scanner Suite** — 5 autonomous security agents (VANGUARD, SENTRY, AUTOPSY, ANGLER, HORIZON) with PDF report generation

## Architecture

```
Agent/
├── app.py                 # Flask web server — threat intelligence dashboard
├── config.py              # Environment-driven configuration (API keys)
├── intel.py               # AbuseIPDB, VirusTotal, URLhaus API integrations
├── email_analyzer.py      # Email parsing, IOC extraction, phishing scoring
├── groq_ai.py             # Groq LLM integration for AI threat analysis
├── checker.py             # Standalone URLhaus GUI checker (Tkinter)
├── templates/             # Web dashboard templates
├── static/                # CSS/JS assets
├── VulnerabilityScanner/  # AEGIS — Autonomous Cyber Defense Suite
│   ├── app.py             # Hub dashboard + 5 agent API endpoints
│   ├── agent/             # VANGUARD vulnerability scanner
│   ├── analysts/          # SENTRY, AUTOPSY, ANGLER, HORIZON agents
│   └── ...
└── requirements.txt
```

## Quick Start

### Prerequisites

- Python 3.10+
- API keys (optional but recommended):
  - [AbuseIPDB](https://www.abuseipdb.com/account/api) — IP reputation lookups
  - [VirusTotal](https://www.virustotal.com/gui/my-apikey) — URL/file scanning
  - [Groq](https://console.groq.com/keys) — AI-powered threat analysis

### Installation

```bash
cd Agent
python -m pip install -r requirements.txt
```

### Configuration

Create a `.env` file in the project root:

```
ABUSEIPDB_KEY=your_abuseipdb_key
VIRUSTOTAL_KEY=your_virustotal_key
GROQ_API_KEY=your_groq_api_key
```

### Run

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

### AEGIS Scanner Suite (optional)

```bash
cd VulnerabilityScanner
python -m pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000** for the AEGIS hub with all 5 agents.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/check-ip` | Check IP reputation via AbuseIPDB |
| `POST` | `/api/scan-url` | Scan URL via VirusTotal + URLhaus |
| `POST` | `/api/analyze-email` | Parse and analyze email for phishing |
| `GET`  | `/api/config-status` | Check which API keys are configured |

### Example Requests

**IP Check:**
```bash
curl -X POST http://localhost:5000/api/check-ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "8.8.8.8"}'
```

**URL Scan:**
```bash
curl -X POST http://localhost:5000/api/scan-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Email Analysis:**
```bash
curl -X POST http://localhost:5000/api/analyze-email \
  -H "Content-Type: application/json" \
  -d '{"raw_email": "From: sender@phish.com\nSubject: Urgent\n..."}'
```

## Tech Stack

- **Backend:** Python, Flask, Flask-CORS
- **AI Engine:** Groq API (Llama 3.3 70B Versatile)
- **Threat Intel:** AbuseIPDB, VirusTotal, URLhaus (abuse.ch)
- **Email Parsing:** Python `email` module with custom phishing heuristic scoring
- **Standalone GUI:** Tkinter (URLhaus checker)
- **AEGIS Suite:** Flask, fpdf2 (PDF reports), MySQL/SQLite, optional Anthropic Claude

## Disclaimer

This tool is intended for **defensive security research and authorized testing only**. Only scan or analyze systems you own or have explicit permission to assess. The authors are not responsible for misuse.

## License

Internal project — all rights reserved.
