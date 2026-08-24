import re
import email
from email import policy
from email.utils import parsedate_to_datetime

IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+|(?:www\.)[^\s<>\"']+", re.I)
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
DOMAIN_PATTERN = re.compile(r"(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:[/:\s]|$)")


def parse_email(raw_text: str) -> dict:
    try:
        msg = email.message_from_string(raw_text, policy=policy.default)
    except Exception:
        return {"error": "Failed to parse email. Ensure it's valid RFC 2822 format."}

    headers = {}
    for h in ["From", "To", "Subject", "Date", "Message-ID",
              "Return-Path", "Received-SPF", "DKIM-Signature",
              "Authentication-Results", "Reply-To", "X-Mailer"]:
        val = msg.get(h)
        if val:
            headers[h] = str(val)

    date_parsed = None
    if headers.get("Date"):
        try:
            date_parsed = parsedate_to_datetime(headers["Date"]).isoformat()
        except Exception:
            pass

    body_text = ""
    body_html = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                try:
                    body_text = part.get_content()
                except Exception:
                    pass
            elif ct == "text/html":
                try:
                    body_html = part.get_content()
                except Exception:
                    pass
    else:
        ct = msg.get_content_type()
        try:
            content = msg.get_content()
            if ct == "text/html":
                body_html = content
            else:
                body_text = content
        except Exception:
            pass

    body_text = body_text or ""
    body_html = body_html or ""

    urls = list(set(URL_PATTERN.findall(body_text + " " + body_html)))
    ips = list(set(IP_PATTERN.findall(raw_text)))
    domains = list(set(DOMAIN_PATTERN.findall(raw_text)))
    emails = list(set(EMAIL_PATTERN.findall(raw_text)))

    auth_results = {}
    auth_raw = headers.get("Authentication-Results", "")
    if auth_raw:
        for entry in re.findall(r"(\w+)=(pass|fail|softfail|neutral|none|temperror|permerror)", auth_raw, re.I):
            auth_results[entry[0]] = entry[1]

    received_chain = []
    for rec in msg.get_all("Received", []):
        rec_str = str(rec)
        ip_match = IP_PATTERN.search(rec_str)
        if ip_match:
            received_chain.append(ip_match.group())

    attachment_names = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                fn = part.get_filename()
                if fn:
                    attachment_names.append(fn)

    phishing_indicators = []
    total_score = 0

    if auth_results.get("spf") == "fail":
        phishing_indicators.append({"indicator": "SPF authentication failed", "severity": "high", "score": 25})
        total_score += 25

    if auth_results.get("dkim") == "fail":
        phishing_indicators.append({"indicator": "DKIM signature failed", "severity": "high", "score": 20})
        total_score += 20

    if auth_results.get("dmarc") == "fail":
        phishing_indicators.append({"indicator": "DMARC check failed", "severity": "high", "score": 25})
        total_score += 25

    body_lower = (body_text + " " + (re.sub(r"<[^>]+>", "", body_html) if body_html else "")).lower()

    suspicious_keywords = {
        "urgent": 10, "immediately": 8, "password": 15, "verify": 10,
        "account suspended": 15, "login": 8, "click here": 6,
        "bank": 10, "paypal": 10, "credit card": 15, "ssn": 20,
        "social security": 20, "unusual activity": 12, "unauthorized": 12,
        "confirm your account": 15, "update your information": 12,
        "security alert": 10, "suspended": 12, "limited": 8,
        "irs": 15, "tax refund": 12, "inheritance": 15, "lottery": 15,
        "free": 5, "act now": 8, "expires": 8, "deadline": 8,
    }
    for kw, score in suspicious_keywords.items():
        if kw in body_lower:
            phishing_indicators.append({"indicator": f"Suspicious phrase: '{kw}'", "severity": "medium" if score < 10 else "high", "score": score})
            total_score += score

    if urls:
        phishing_indicators.append({"indicator": f"Found {len(urls)} URL(s) in email body", "severity": "info", "score": 0})

    try:
        from_addr = headers.get("From", "")
        from_domain = from_addr.split("@")[-1].rstrip(">")
        for url_domain in domains:
            if url_domain and from_domain and url_domain != from_domain and url_domain not in from_domain and from_domain not in url_domain:
                phishing_indicators.append({"indicator": f"URL domain '{url_domain}' differs from From domain '{from_domain}'", "severity": "high", "score": 20})
                total_score += 20
                break
    except Exception:
        pass

    if attachment_names:
        phishing_indicators.append({"indicator": f"Found {len(attachment_names)} attachment(s): {', '.join(attachment_names[:5])}", "severity": "warning", "score": 5})
        for att in attachment_names:
            ext = att.lower().split(".")[-1] if "." in att else ""
            if ext in ("exe", "scr", "vbs", "js", "docm", "xlsm", "pptm", "zip", "rar"):
                phishing_indicators.append({"indicator": f"Dangerous attachment type: .{ext} ({att})", "severity": "high", "score": 25})
                total_score += 25

    total_score = min(total_score, 100)

    if total_score >= 60:
        verdict = "malicious"
    elif total_score >= 30:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "headers": headers,
        "date_parsed": date_parsed,
        "from_domain": from_addr.split("@")[-1].rstrip(">") if "From" in headers else "",
        "body_preview": body_text[:500] + ("..." if len(body_text) > 500 else "") if body_text else (body_html[:500] + "..." if len(body_html) > 500 else ""),
        "urls": urls,
        "ips_extracted": ips,
        "domains": domains,
        "email_addresses": emails,
        "auth_results": auth_results,
        "received_chain": received_chain,
        "attachments": attachment_names,
        "phishing_indicators": phishing_indicators,
        "phishing_score": total_score,
        "verdict": verdict,
    }
