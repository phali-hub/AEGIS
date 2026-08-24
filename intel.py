import requests
import json
import time
import config

session = requests.Session()
session.headers.update({"User-Agent": "ThreatAgent/1.0"})

def abuseipdb_check(ip: str) -> dict:
    if not config.ABUSEIPDB_KEY:
        return {"error": "AbuseIPDB API key not configured. Set ABUSEIPDB_KEY in .env"}
    try:
        resp = session.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": config.ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "ip": data.get("ipAddress"),
            "is_public": data.get("isPublic"),
            "is_whitelisted": data.get("isWhitelisted"),
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "total_reports": data.get("totalReports", 0),
            "last_reported": data.get("lastReportedAt"),
            "reports": data.get("reports", [])[:10],
        }
    except requests.exceptions.HTTPError as e:
        return {"error": f"AbuseIPDB HTTP {resp.status_code}: {e}"}
    except Exception as e:
        return {"error": f"AbuseIPDB error: {e}"}


def virustotal_scan_url(url: str) -> dict:
    if not config.VIRUSTOTAL_KEY:
        return {"error": "VirusTotal API key not configured. Set VIRUSTOTAL_KEY in .env"}
    try:
        resp = session.post(
            "https://www.virustotal.com/api/v3/urls",
            data={"url": url},
            headers={"x-apikey": config.VIRUSTOTAL_KEY},
            timeout=15,
        )
        resp.raise_for_status()
        analysis_link = resp.json().get("data", {}).get("links", {}).get("self", "")
        if not analysis_link:
            return {"error": "No analysis link returned"}
        time.sleep(3)
        report = session.get(
            analysis_link,
            headers={"x-apikey": config.VIRUSTOTAL_KEY},
            timeout=15,
        )
        report.raise_for_status()
        attrs = report.json().get("data", {}).get("attributes", {})
        stats = attrs.get("stats", {})
        results = attrs.get("results", {})
        malicious = []
        for engine, r in results.items():
            if r.get("category") == "malicious":
                malicious.append({"engine": engine, "result": r.get("result")})
        return {
            "url": url,
            "harmless": stats.get("harmless", 0),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "total": sum(stats.values()),
            "malicious_engines": malicious[:20],
            "scan_date": attrs.get("date"),
        }
    except requests.exceptions.HTTPError as e:
        return {"error": f"VirusTotal HTTP {e}"}
    except Exception as e:
        return {"error": f"VirusTotal error: {e}"}


def urlhaus_check(url: str) -> dict:
    try:
        resp = session.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        qs = data.get("query_status", "")
        if qs == "no_results":
            return {"found": False, "status": "clean", "url": url}
        if qs in ("is_url", "is_host", "available"):
            tags = data.get("tags") or []
            return {
                "found": True,
                "url": url,
                "status": data.get("url_status", "unknown"),
                "threat": data.get("threat", ""),
                "tags": tags,
                "date_added": data.get("date_added"),
                "reporter": data.get("reporter"),
                "reference": f"https://urlhaus.abuse.ch/url/{data.get('url_id', '')}/" if data.get("url_id") else None,
                "payloads": data.get("payloads") or [],
            }
        return {"found": False, "status": "unknown", "url": url}
    except Exception as e:
        return {"error": f"URLhaus error: {e}"}
