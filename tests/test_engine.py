"""Deterministic (no LLM, no network-dependent assertions) tests for the
DKCISSP Email Analyzer engine."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dkcissp_email_analyzer import analyze_email


def test_benign_authenticated_email_is_benign():
    raw = (
        "From: Jane Doe <jane@example.com>\n"
        "To: bob@example.com\n"
        "Subject: Lunch tomorrow?\n"
        "Date: Mon, 1 Jan 2024 10:00:00 -0000\n"
        "Message-ID: <abc123@example.com>\n"
        "Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain\n\n"
        "Hey, are we still on for lunch tomorrow at noon?\n"
    )
    result = analyze_email(raw, use_llm=False)
    assert result["verdict"] == "benign"
    assert result["headers_available"] is True


def test_lookalike_domain_is_flagged():
    raw = (
        "From: IT Support <support@examp1e.com>\n"
        "Subject: Verify your account immediately\n\n"
        "Your account will be suspended. Verify your password now.\n"
    )
    result = analyze_email(raw, org_domains=["example.com"], use_llm=False)
    ids = {s["id"] for s in result["signals"]}
    assert "lookalike_domain" in ids
    assert result["verdict"] != "benign"


def test_bec_pattern_detected():
    raw = (
        "From: CEO <ceo.office@gmail.com>\n"
        "Reply-To: ceo.office2@gmail.com\n"
        "Subject: Urgent wire transfer needed\n\n"
        "I need you to process a wire transfer to our new beneficiary account today. "
        "Our bank details have changed, please use the new banking details I will send.\n"
    )
    result = analyze_email(raw, use_llm=False)
    ids = {s["id"] for s in result["signals"]}
    assert "bec_pattern" in ids or "bank_change_request" in ids
    assert result["verdict"] != "benign"


def test_brand_impersonation_detected():
    raw = (
        "From: DocuSign <notifications@docusign-secure.net>\n"
        "Subject: Document signed via DocuSign\n\n"
        "This is an automated message from DocuSign. Please review and sign the attached document.\n"
        'Click here: <a href="http://docusign-secure.net/sign">Review Document</a>\n'
    )
    result = analyze_email(raw, use_llm=False)
    ids = {s["id"] for s in result["signals"]}
    assert any(i.startswith("brand_impersonation") for i in ids)


def test_url_shortener_and_defang():
    raw = (
        "From: promo@example.com\n"
        "Subject: Check this out\n\n"
        "Click here: https://bit.ly/abc123\n"
    )
    result = analyze_email(raw, use_llm=False)
    assert len(result["urls"]) == 1
    u = result["urls"][0]
    assert u["is_shortener"] is True
    assert "[.]" in u["defanged"]


def test_cli_entrypoint_exists():
    from dkcissp_email_analyzer.cli import main
    assert callable(main)
