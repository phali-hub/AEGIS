import json
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

import config
import intel
import email_analyzer
import groq_ai

app = Flask(__name__)
CORS(app)


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/check-ip", methods=["POST"])
def check_ip():
    data = request.get_json()
    ip = (data or {}).get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    result = intel.abuseipdb_check(ip)
    if "error" in result:
        return jsonify(result), 502

    ai_analysis = groq_ai.analyze_ip(result) if config.GROQ_API_KEY else None
    return jsonify({"intel": result, "ai_analysis": ai_analysis})


@app.route("/api/scan-url", methods=["POST"])
def scan_url():
    data = request.get_json()
    url = (data or {}).get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    vt_result = intel.virustotal_scan_url(url)
    uh_result = intel.urlhaus_check(url)

    ai_analysis = None
    if config.GROQ_API_KEY and "error" not in vt_result:
        ai_analysis = groq_ai.analyze_url(vt_result, uh_result)

    return jsonify({
        "virustotal": vt_result,
        "urlhaus": uh_result,
        "ai_analysis": ai_analysis,
    })


@app.route("/api/analyze-email", methods=["POST"])
def analyze_email():
    data = request.get_json()
    raw_email = (data or {}).get("raw_email", "").strip()
    if not raw_email:
        return jsonify({"error": "Email content is required"}), 400

    parsed = email_analyzer.parse_email(raw_email)
    if "error" in parsed:
        return jsonify(parsed), 400

    ai_analysis = groq_ai.analyze_email(parsed) if config.GROQ_API_KEY else None
    return jsonify({"parsed": parsed, "ai_analysis": ai_analysis})


@app.route("/api/config-status", methods=["GET"])
def config_status():
    return jsonify({
        "abuseipdb": bool(config.ABUSEIPDB_KEY),
        "virustotal": bool(config.VIRUSTOTAL_KEY),
        "groq": bool(config.GROQ_API_KEY),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
