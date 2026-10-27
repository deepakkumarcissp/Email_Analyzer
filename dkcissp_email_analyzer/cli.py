"""Command-line interface for the DKCISSP Email Analyzer."""
from __future__ import annotations

import argparse
import json
import sys

from .engine import EmailAnalyzer


def _read_input(args: argparse.Namespace) -> str:
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    print("No input file given and stdin is a TTY — paste the email, then Ctrl-D:", file=sys.stderr)
    return sys.stdin.read()


def _print_human(result: dict) -> None:
    sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    print("=" * 70)
    print(f"VERDICT: {result['verdict'].upper()}  (risk: {result['risk']}, "
          f"confidence: {result['confidence']}, score: {result['score']})")
    print("=" * 70)
    print(result["summary"])
    print()
    sender = result["sender"]
    print(f"From:    {sender['display_name']} <{sender['address']}>")
    print(f"Subject: {result['subject']}")
    print(f"To:      {result['recipient']}")
    print(f"Headers available: {result['headers_available']}")
    print()
    if result["signals"]:
        print("Signals:")
        for s in result["signals"]:
            icon = sev_icon.get(s["severity"], "•")
            print(f"  {icon} [{s['severity'].upper():8s}] {s['title']}")
            print(f"           {s['detail']}")
    if result["urls"]:
        print("\nURLs found:")
        for u in result["urls"]:
            print(f"  - {u['defanged']}" + (f"  ({u['wrapper']})" if u.get("wrapper") else ""))
    print("\nRecommended actions:")
    for a in result["recommended_actions"]:
        print(f"  - {a}")
    print()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="dkcissp-email-analyzer",
        description="Analyze a suspicious email (.eml, Gmail 'Show original', or a pasted/forwarded "
                    "snippet) for phishing / spear-phishing / BEC indicators.")
    parser.add_argument("file", nargs="?", help="Path to a .eml file or text file. Omit to read stdin.")
    parser.add_argument("--org-domain", action="append", dest="org_domains", default=[],
                        help="Your own domain, for lookalike/cousin-domain detection. "
                             "May be given multiple times.")
    parser.add_argument("--json", action="store_true", help="Print the full result as JSON.")
    parser.add_argument("--no-llm", action="store_true",
                        help="Skip the optional LLM classification pass even if an API key is configured.")
    args = parser.parse_args(argv)

    content = _read_input(args)
    if not content.strip():
        print("error: no email content provided", file=sys.stderr)
        return 2

    analyzer = EmailAnalyzer()
    result = analyzer.analyze(content, org_domains=args.org_domains or None, use_llm=not args.no_llm)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_human(result)

    return 0 if result["verdict"] == "benign" else 1


if __name__ == "__main__":
    raise SystemExit(main())
