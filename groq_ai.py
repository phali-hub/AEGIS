import json
import requests
import config


def _call_groq(system_prompt: str, user_prompt: str) -> str:
    if not config.GROQ_API_KEY:
        return "Groq API key not configured. Set GROQ_API_KEY in .env to enable AI analysis."
    try:
        resp = requests.post(
            config.GROQ_API_URL,
            headers={
                "Authorization": f"Bearer {config.GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": config.GROQ_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.1,
                "max_tokens": 1500,
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"AI analysis unavailable: {e}"


SYSTEM_THREAT = """You are a senior threat intelligence analyst with 25 years of experience in cybersecurity. 
Analyze the provided threat intelligence data and produce a concise, actionable assessment.

Structure your response:
1. **Threat Assessment**: Brief one-sentence verdict.
2. **Key Findings**: Bullet points of the most important indicators.
3. **Risk Level**: CRITICAL / HIGH / MEDIUM / LOW / CLEAN with justification.
4. **TTPs**: MITRE ATT&CK techniques or common threat patterns observed.
5. **Recommendations**: Specific actionable steps the analyst should take."""


def analyze_ip(data: dict) -> str:
    prompt = f"""Analyze this IP intelligence data from AbuseIPDB:

IP: {data.get('ip', 'N/A')}
Abuse Confidence Score: {data.get('abuse_score', 'N/A')}/100
Country: {data.get('country', 'N/A')}
ISP: {data.get('isp', 'N/A')}
Usage Type: {data.get('usage_type', 'N/A')}
Total Reports: {data.get('total_reports', 'N/A')}
Last Reported: {data.get('last_reported', 'N/A')}
Is Whitelisted: {data.get('is_whitelisted', 'N/A')}

Recent Reports:
{json.dumps(data.get('reports', [])[:5], indent=2) if data.get('reports') else 'No recent reports.'}

Provide a professional threat intelligence assessment of this IP address."""
    return _call_groq(SYSTEM_THREAT, prompt)


SYSTEM_URL = """You are a senior threat intelligence analyst with 25 years in cybersecurity.
Analyze URL scan results and provide a clear verdict on whether the URL is malicious.

Structure:
1. **Verdict**: Safe / Suspicious / Malicious with brief reasoning.
2. **Evidence**: What the scan data shows.
3. **Category**: If malicious, what type (phishing, malware, C2, etc.)
4. **Risk Level**: CRITICAL / HIGH / MEDIUM / LOW / CLEAN
5. **Recommendations**: Next steps for the analyst."""


def analyze_url(vt_data: dict, urlhaus_data: dict) -> str:
    prompt = f"""Analyze these URL scan results:

URL Scanned: {vt_data.get('url') or urlhaus_data.get('url', 'N/A')}

--- VirusTotal Results ---
Malicious Detections: {vt_data.get('malicious', 'N/A')}
Suspicious Detections: {vt_data.get('suspicious', 'N/A')}
Harmless: {vt_data.get('harmless', 'N/A')}
Total Engines: {vt_data.get('total', 'N/A')}
Malicious Engines: {json.dumps(vt_data.get('malicious_engines', []), indent=2)}

--- URLhaus Results ---
Found in URLhaus: {urlhaus_data.get('found', 'N/A')}
Status: {urlhaus_data.get('status', 'N/A')}
Threat Type: {urlhaus_data.get('threat', 'N/A')}
Tags: {urlhaus_data.get('tags', 'N/A')}
Date Added: {urlhaus_data.get('date_added', 'N/A')}
Payloads: {json.dumps(urlhaus_data.get('payloads', []), indent=2)}

Provide a professional threat intelligence assessment of this URL."""
    return _call_groq(SYSTEM_URL, prompt)


SYSTEM_EMAIL = """You are a senior phishing analyst with 25 years of experience. 
Analyze the parsed email data and determine if it's a phishing attempt.

Structure:
1. **Verdict**: Phishing / Suspicious / Legitimate with confidence level.
2. **Key Phishing Indicators**: List the most significant red flags.
3. **Threat Actor Profile**: If possible, infer the type of threat actor or campaign.
4. **Technical Analysis**: Authentication failures, header anomalies, URL analysis.
5. **User Impact**: What would happen if a user interacted with this email.
6. **Recommendations**: Specific actions (block sender, add to blocklist, train user, etc.)."""


def analyze_email(parsed: dict) -> str:
    prompt = f"""Analyze this parsed email for phishing indicators:

--- Email Metadata ---
From: {parsed.get('headers', {}).get('From', 'N/A')}
To: {parsed.get('headers', {}).get('To', 'N/A')}
Subject: {parsed.get('headers', {}).get('Subject', 'N/A')}
Date: {parsed.get('headers', {}).get('Date', 'N/A')}

--- Authentication Results ---
{json.dumps(parsed.get('auth_results', {}), indent=2)}

--- Phishing Indicator Score ---
Score: {parsed.get('phishing_score', 'N/A')}/100
Verdict: {parsed.get('verdict', 'N/A')}

--- Specific Indicators ---
{json.dumps(parsed.get('phishing_indicators', []), indent=2)}

--- URLs Found in Email ---
{json.dumps(parsed.get('urls', []), indent=2)}

--- Attachments ---
{json.dumps(parsed.get('attachments', []), indent=2)}

--- Body Preview ---
{parsed.get('body_preview', 'N/A')[:300]}

Provide a professional phishing analysis of this email."""
    return _call_groq(SYSTEM_EMAIL, prompt)
