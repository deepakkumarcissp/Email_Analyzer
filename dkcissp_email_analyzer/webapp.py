"""Minimal local web UI for the DKCISSP Email Analyzer.

Run with:
    dkcissp-email-analyzer-web
or:
    python -m dkcissp_email_analyzer.webapp

Then open http://127.0.0.1:1008 and paste a suspicious email. Everything
runs locally — nothing is sent anywhere except the optional passive
VirusTotal / LLM lookups you explicitly configure via environment variables.
"""
from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request

from .engine import EmailAnalyzer

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    content = (data.get("content") or "").strip()
    if not content:
        return jsonify({"error": "No email content provided."}), 400

    org_domains_raw = (data.get("org_domains") or "").strip()
    org_domains = [d.strip() for d in org_domains_raw.split(",") if d.strip()] or None

    analyzer = EmailAnalyzer()
    try:
        result = analyzer.analyze(content, org_domains=org_domains)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {e}"}), 500
    return jsonify(result)


def main():
    port = int(os.environ.get("PORT", "1008"))
    host = os.environ.get("HOST", "127.0.0.1")
    debug = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
