"""
DKCISSP Email Analyzer — defensive email forensics engine
===========================================================
Answers one question about an email someone received: "is this phishing /
spear-phishing / BEC, or benign?"

Input is deliberately forgiving (see EmailAnalyzer.analyze):
  * a full raw RFC-822 message / ".eml" / Gmail "Show original" dump
    (best — carries real Authentication-Results / Received / DKIM), OR
  * a plain pasted snippet / forwarded body (no real headers) — From /
    Subject / links are parsed from the text and the analysis leans on
    live domain recon + content + URL analysis, clearly flagging that
    header authentication was not available.

Deterministic checks (no API keys or LLM required, run first):
  - Header auth: SPF / DKIM / DMARC results from Authentication-Results,
    ARC-Authentication-Results, Received-SPF (raw messages only).
  - Sender identity: display-name-vs-address spoof, Reply-To / Return-Path
    mismatch, freemail, lookalike/cousin domain vs your own domain(s).
  - URLs: extract from HTML hrefs + plaintext, defang, unwrap/flag redirect
    wrappers (ESP click-trackers, ?url= style redirects, URL shorteners),
    and anchor-text-vs-target mismatch.
  - Sender-domain live recon: WHOIS age, DNS A/MX/SPF/DMARC presence.
  - Brand impersonation: body claims a brand (Adobe/DocuSign/Microsoft/IRS…)
    the sender domain does not own.
  - Lure language: financial / wire / credential / urgency keywords.
  - Reputation enrichment: VirusTotal (only if an API key is configured;
    passive lookup, never detonates the link).

An optional LLM pass can also classify the message (phishing / spear_phishing
/ bec / spam / benign) using the structured evidence, reconciled with the
deterministic score. It is OFF by default — set an API key to enable it.

Safety: this module NEVER requests the suspicious link/redirect target.
URL reputation is looked up by hostname via passive APIs only.
"""
from __future__ import annotations

import base64
import email
import email.policy
import html as _html
import os
import re
import subprocess
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import dns.resolver  # type: ignore
    _DNS = True
except Exception:
    _DNS = False

try:
    import requests  # type: ignore
    _REQ = True
except Exception:
    _REQ = False


# ── Reference data ────────────────────────────────────────────────────────

# Brand -> domains that legitimately send that brand's mail. If the body
# invokes the brand but the sender domain is not in this set, that's a
# high-signal impersonation indicator.
_BRANDS: Dict[str, Tuple[str, ...]] = {
    "adobe":      ("adobe.com", "adobesign.com", "echosign.com", "adobe-sign.com"),
    "docusign":   ("docusign.com", "docusign.net"),
    "microsoft":  ("microsoft.com", "office.com", "office365.com", "microsoftonline.com", "sharepoint.com"),
    "google":     ("google.com", "googleapis.com", "docs.google.com", "drive.google.com"),
    "dropbox":    ("dropbox.com", "dropboxmail.com"),
    "irs":        ("irs.gov",),
    "paypal":     ("paypal.com",),
    "amazon":     ("amazon.com", "amazonses.com"),
    "linkedin":   ("linkedin.com",),
    "wetransfer": ("wetransfer.com",),
    "zoom":       ("zoom.us",),
}

# Brand mentioned via any of these tokens (lowercased substring match on
# subject+body). Kept separate from the canonical key so "adobe acrobat",
# "adobe sign", "docu sign" etc. all resolve to the brand.
_BRAND_TOKENS: Dict[str, Tuple[str, ...]] = {
    "adobe":      ("adobe", "acrobat", "adobe sign"),
    "docusign":   ("docusign", "docu sign", "docu-sign"),
    "microsoft":  ("microsoft", "office 365", "office365", "onedrive", "sharepoint", "outlook"),
    "google":     ("google drive", "google docs", "google workspace"),
    "dropbox":    ("dropbox",),
    "irs":        ("irs", "internal revenue"),
    "paypal":     ("paypal",),
    "amazon":     ("amazon",),
    "linkedin":   ("linkedin",),
    "wetransfer": ("wetransfer", "we transfer"),
    "zoom":       ("zoom meeting", "zoom recording"),
}

_FREEMAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "yahoo.com",
    "yahoo.co.in", "aol.com", "icloud.com", "proton.me", "protonmail.com",
    "gmx.com", "mail.com", "zoho.com", "yandex.com", "live.com", "msn.com",
}

# ESP / marketing click-tracking hosts whose links hide the true destination
# behind an opaque token — abusing their good sending reputation is a common
# way to slip a phishing URL past reputation filters.
_ESP_REDIRECT_HOSTS = (
    "yotpo.com", "sendgrid.net", "sgrid.io", "mailchimp.com", "list-manage.com",
    "mandrillapp.com", "sparkpostmail.com", "hubspotlinks.com", "hs-sending.com",
    "rs6.net", "constantcontact.com", "mailgun.org", "sendinblue.com", "sib.email",
    "klclick.com", "ct.sendgrid.net", "url.emailprotection.link", "clicks.aweber.com",
    "go.pardot.com", "email.mg", "e.customeriomail.com",
)

# Query-param redirect wrappers whose target IS decodable from the URL.
_REDIRECT_PARAMS = ("url", "u", "redirect", "redir", "target", "dest", "destination",
                    "link", "q", "r", "next", "continue", "goto", "out")

_URL_SHORTENERS = (
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in",
    "adf.ly", "bl.ink", "t.ly",
)

_LURE_KEYWORDS = {
    "financial": ("wire transfer", "wire the", "bank details", "banking details",
                  "invoice", "payment", "remittance", "gift card", "purchase order",
                  "account details", "ach", "swift", "beneficiary", "refund",
                  "tax", "irs", "w-2", "w2", "1099", "direct deposit", "payroll"),
    "credential": ("verify your account", "confirm your password", "password expire",
                   "re-authenticate", "reactivate", "unlock your account",
                   "sign in to view", "log in to view", "validate your", "verify your identity"),
    "urgency": ("urgent", "immediately", "within 24 hours", "action required",
                "final notice", "your account will be", "suspended", "deactivat",
                "last warning", "expires today", "act now"),
    "esign": ("has been signed", "document you were sent", "review and sign",
              "signature requested", "please sign", "completed", "esignature",
              "digitally signed"),
}

_DANGEROUS_ATTACH = (".htm", ".html", ".iso", ".img", ".zip", ".rar", ".7z",
                     ".js", ".vbs", ".lnk", ".scr", ".exe", ".bat", ".cmd",
                     ".docm", ".xlsm", ".pptm", ".jar", ".hta", ".ace", ".gz")

_BRAND_DISPLAY = {"adobe": "Adobe", "docusign": "DocuSign", "microsoft": "Microsoft",
                  "google": "Google", "dropbox": "Dropbox", "irs": "IRS", "paypal": "PayPal",
                  "amazon": "Amazon", "linkedin": "LinkedIn", "wetransfer": "WeTransfer", "zoom": "Zoom"}

_SEV_WEIGHT = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 0}
_URL_RE = re.compile(r'https?://[^\s"\'<>)\]]+', re.IGNORECASE)
_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
_ANCHOR_RE = re.compile(r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
_EMAIL_RE = re.compile(r'([A-Z0-9._%+\-]+)@([A-Z0-9.\-]+\.[A-Z]{2,})', re.IGNORECASE)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _defang(u: str) -> str:
    return u.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def _domain_of(addr: str) -> str:
    addr = (addr or "").strip().strip("<>").lower()
    if "@" in addr:
        return addr.rsplit("@", 1)[-1].strip()
    return addr


def _reg_domain(host: str) -> str:
    """Best-effort registrable domain (last two labels). Good enough for the
    equality/lookalike comparisons here without pulling in a PSL dependency."""
    host = (host or "").strip().lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # crude handling of common 2-level ccTLD suffixes
    two_level = {"co.uk", "co.in", "com.au", "co.jp", "com.br", "co.nz", "org.uk", "gov.uk"}
    if ".".join(parts[-2:]) in two_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _kw_hits(text: str, kws) -> list:
    """Whole-word keyword matches — avoids substring false matches such as
    'ach' inside 'attached' or 'tax' inside 'syntax'."""
    return [kw for kw in kws if re.search(r'\b' + re.escape(kw) + r'\b', text)]


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# ── Data model ─────────────────────────────────────────────────────────────

@dataclass
class Signal:
    id: str
    title: str
    severity: str            # critical|high|medium|low|info
    detail: str
    category: str = "phishing"

    def as_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "severity": self.severity,
                "detail": self.detail, "category": self.category}


@dataclass
class ParsedEmail:
    raw_available: bool = False
    from_display: str = ""
    from_addr: str = ""
    from_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    subject: str = ""
    date: str = ""
    message_id: str = ""
    auth_results: str = ""      # raw Authentication-Results header value
    received: List[str] = field(default_factory=list)
    text_body: str = ""
    html_body: str = ""
    attachments: List[dict] = field(default_factory=list)

    def body_blob(self) -> str:
        return f"{self.subject}\n{self.text_body}\n{self.html_body}"


class EmailAnalyzer:
    """Analyze a raw .eml / pasted email and return a verdict dict.

    Configuration (all optional) via the ``cfg`` dict or environment
    variables:
      - org_domains: list[str] — your own domain(s), for lookalike/cousin
        domain detection. Env: EMAIL_ANALYZER_ORG_DOMAINS (comma-separated).
      - virustotal_api_key: str — enables passive domain reputation lookups.
        Env: EMAIL_ANALYZER_VT_API_KEY.
      - openai_api_key / openai_model: str — enables an optional LLM
        classification pass on top of the deterministic signals.
        Env: OPENAI_API_KEY, EMAIL_ANALYZER_OPENAI_MODEL.
    """

    def __init__(self, cfg: Optional[dict] = None):
        self.cfg = cfg or {}
        org_domains = self.cfg.get("org_domains")
        if not org_domains:
            env_domains = os.environ.get("EMAIL_ANALYZER_ORG_DOMAINS", "")
            org_domains = [d.strip() for d in env_domains.split(",") if d.strip()]
        self.org_domains = [d.lower() for d in org_domains if d]

    # ── Public API ─────────────────────────────────────────────────────
    def analyze(self, content: str, *, org_domains: Optional[List[str]] = None,
                use_llm: bool = True) -> dict:
        """Analyze a raw .eml OR a pasted snippet. Returns a verdict dict.
        use_llm=False runs the deterministic layer only (fast, offline,
        reproducible — the LLM pass is also a no-op unless an API key is
        configured, regardless of this flag)."""
        if org_domains:
            self.org_domains = [d.lower() for d in org_domains if d]

        content = content or ""
        parsed = self._parse(content)

        signals: List[Signal] = []
        urls = self._extract_urls(parsed)
        recon = self._domain_recon(parsed.from_domain) if parsed.from_domain else {}
        auth = self._parse_auth(parsed)

        signals += self._sig_auth(parsed, auth, recon)
        signals += self._sig_identity(parsed, recon)
        signals += self._sig_brand(parsed, urls)
        signals += self._sig_urls(parsed, urls)
        signals += self._sig_lure(parsed)
        signals += self._sig_attachments(parsed)
        signals += self._sig_reputation(parsed, urls)
        signals += self._sig_combo(parsed, signals, urls)

        score = sum(_SEV_WEIGHT.get(s.severity, 0) for s in signals)
        heur_verdict, heur_type = self._score_to_verdict(score, signals, parsed, urls)

        ai = self._llm_classify(parsed, signals, urls, recon, auth) if use_llm else {"ai_triage": False}

        verdict, threat_type, confidence, risk = self._reconcile(
            heur_verdict, heur_type, score, ai, signals, auth)

        result = {
            "verdict": verdict,                 # phishing|spear_phishing|bec|spam|suspicious|benign
            "threat_type": threat_type,
            "risk": risk,                       # critical|high|medium|low|info
            "confidence": confidence,           # HIGH|MEDIUM|LOW
            "score": score,
            "headers_available": parsed.raw_available,
            "sender": {
                "display_name": parsed.from_display,
                "address": parsed.from_addr,
                "domain": parsed.from_domain,
                "reply_to": parsed.reply_to,
                "return_path": parsed.return_path,
            },
            "subject": parsed.subject,
            "recipient": parsed.to,
            "date": parsed.date,
            "authentication": auth,
            "domain_recon": recon,
            "urls": urls,
            "signals": [s.as_dict() for s in signals],
            "iocs": self._iocs(parsed, urls, recon),
            "ai_analysis": ai,
            "summary": self._summary(verdict, threat_type, parsed, signals),
            "recommended_actions": self._actions(verdict, parsed, urls),
            "checks_performed": self._checks_summary(parsed, auth, recon, signals, urls, ai),
            "analyzed_at": _now(),
        }
        return result

    # ── Parsing ────────────────────────────────────────────────────────
    def _looks_raw(self, content: str) -> bool:
        head = content[:4000]
        # Headers injected by receiving/sending infrastructure that never
        # appear in a hand-forwarded body — any ONE means this is a real
        # message, not a snippet.
        if re.search(r'(?im)^(authentication-results|dkim-signature|arc-seal|arc-authentication-results|received-spf|x-received):\s', head):
            return True
        hdr_hits = sum(bool(re.search(rf'(?im)^{h}:\s', head)) for h in
                       ("received", "message-id", "return-path", "mime-version", "x-mailer", "list-unsubscribe"))
        return hdr_hits >= 2

    def _parse(self, content: str) -> ParsedEmail:
        if self._looks_raw(content):
            try:
                return self._parse_raw(content)
            except Exception:
                pass
        return self._parse_snippet(content)

    def _parse_raw(self, content: str) -> ParsedEmail:
        msg = email.message_from_string(content, policy=email.policy.default)
        p = ParsedEmail(raw_available=True)
        p.from_display, p.from_addr = self._split_addr(str(msg.get("From", "")))
        p.reply_to = self._addr_only(str(msg.get("Reply-To", "")))
        p.return_path = self._addr_only(str(msg.get("Return-Path", "")))
        p.to = str(msg.get("To", ""))
        p.subject = str(msg.get("Subject", ""))
        p.date = str(msg.get("Date", ""))
        p.message_id = str(msg.get("Message-ID", ""))
        p.auth_results = " || ".join(
            str(v) for k, v in msg.items()
            if k.lower() in ("authentication-results", "arc-authentication-results", "received-spf"))
        p.received = [str(v) for k, v in msg.items() if k.lower() == "received"]
        p.from_domain = _domain_of(p.from_addr)
        # bodies + attachments
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = str(part.get("Content-Disposition", ""))
                fn = part.get_filename()
                if fn or "attachment" in disp.lower():
                    p.attachments.append({"filename": fn or "(unnamed)",
                                          "content_type": ctype,
                                          "size": len(part.get_payload(decode=True) or b"")})
                    continue
                try:
                    payload = part.get_content()
                except Exception:
                    payload = ""
                if ctype == "text/plain" and not p.text_body:
                    p.text_body = payload if isinstance(payload, str) else ""
                elif ctype == "text/html" and not p.html_body:
                    p.html_body = payload if isinstance(payload, str) else ""
        else:
            try:
                body = msg.get_content()
            except Exception:
                body = str(msg.get_payload())
            if msg.get_content_type() == "text/html":
                p.html_body = body if isinstance(body, str) else ""
            else:
                p.text_body = body if isinstance(body, str) else ""
        return p

    def _parse_snippet(self, content: str) -> ParsedEmail:
        p = ParsedEmail(raw_available=False)
        # In forwarded snippets there can be several "From:" lines. Prefer the
        # LAST (innermost / original sender) — that's the actual sender being
        # judged, not the internal forwarder.
        froms = re.findall(r'(?im)^\s*From:\s*(.+)$', content)
        if froms:
            p.from_display, p.from_addr = self._split_addr(froms[-1].strip())
        if not p.from_addr:
            # fall back to any address in the header-ish region
            m = _EMAIL_RE.search(content[:1500])
            if m:
                p.from_addr = m.group(0)
        subs = re.findall(r'(?im)^\s*Subject:\s*(.+)$', content)
        if subs:
            p.subject = subs[-1].strip()
        tos = re.findall(r'(?im)^\s*To:\s*(.+)$', content)
        if tos:
            p.to = tos[-1].strip()
        dts = re.findall(r'(?im)^\s*Date:\s*(.+)$', content)
        if dts:
            p.date = dts[-1].strip()
        rt = re.findall(r'(?im)^\s*Reply-To:\s*(.+)$', content)
        if rt:
            p.reply_to = self._addr_only(rt[-1].strip())
        p.from_domain = _domain_of(p.from_addr)
        # Treat the whole thing as body for content/URL analysis; keep HTML if
        # it looks like HTML.
        if "<a " in content.lower() or "<html" in content.lower() or "href=" in content.lower():
            p.html_body = content
        else:
            p.text_body = content
        return p

    @staticmethod
    def _split_addr(raw: str) -> Tuple[str, str]:
        raw = (raw or "").strip()
        m = re.search(r'^(.*?)<([^>]+)>', raw)
        if m:
            return m.group(1).strip().strip('"'), m.group(2).strip().lower()
        m2 = _EMAIL_RE.search(raw)
        if m2:
            return "", m2.group(0).lower()
        return raw, ""

    @staticmethod
    def _addr_only(raw: str) -> str:
        _, a = EmailAnalyzer._split_addr(raw)
        return a

    # ── URL extraction / unwrap ─────────────────────────────────────────
    def _extract_urls(self, p: ParsedEmail) -> List[dict]:
        found: Dict[str, dict] = {}
        anchors = {}
        for href, text in _ANCHOR_RE.findall(p.html_body or ""):
            anchors[href.strip()] = _html.unescape(re.sub(r'<[^>]+>', '', text)).strip()

        raw_urls = set()
        raw_urls.update(_HREF_RE.findall(p.html_body or ""))
        raw_urls.update(_URL_RE.findall(p.html_body or ""))
        raw_urls.update(_URL_RE.findall(p.text_body or ""))
        # angle-bracket plaintext links <http://...>
        raw_urls.update(re.findall(r'<(https?://[^>]+)>', p.text_body or ""))

        for u in raw_urls:
            u = _html.unescape(u.strip()).rstrip('.,);]')
            if not u.lower().startswith(("http://", "https://")):
                continue
            try:
                parsed = urllib.parse.urlparse(u)
            except Exception:
                continue
            host = (parsed.hostname or "").lower()
            if not host:
                continue
            unwrapped, wrap_note = self._unwrap(u, parsed, host)
            entry = found.setdefault(u, {
                "url": u,
                "defanged": _defang(u),
                "host": host,
                "reg_domain": _reg_domain(host),
                "anchor_text": anchors.get(u, ""),
                "wrapper": wrap_note,
                "unwrapped": unwrapped,
                "is_shortener": any(host == s or host.endswith("." + s) for s in _URL_SHORTENERS),
            })
            # anchor text vs target mismatch
            at = entry["anchor_text"]
            at_host = ""
            m = _URL_RE.search(at or "")
            if m:
                at_host = (urllib.parse.urlparse(m.group(0)).hostname or "").lower()
            entry["anchor_domain_mismatch"] = bool(
                at_host and _reg_domain(at_host) != entry["reg_domain"])
        return list(found.values())

    def _unwrap(self, u: str, parsed, host: str) -> Tuple[str, str]:
        # ESP click-tracker with opaque token — cannot resolve offline.
        if any(host == h or host.endswith("." + h) for h in _ESP_REDIRECT_HOSTS) \
                or re.search(r'/ls/click\?upn=', u) or "/wf/click?upn=" in u:
            return "", f"ESP click-tracking redirect ({_reg_domain(host)}) — true destination hidden behind opaque token; detonate in sandbox"
        # decodable ?url= style redirect
        try:
            qs = urllib.parse.parse_qs(parsed.query)
        except Exception:
            qs = {}
        for pk in _REDIRECT_PARAMS:
            if pk in qs and qs[pk]:
                cand = urllib.parse.unquote(qs[pk][0])
                if cand.lower().startswith(("http://", "https://")):
                    return cand, f"open-redirect param ?{pk}= decoded to true destination"
        return "", ""

    # ── Sender-domain recon ─────────────────────────────────────────────
    def _domain_recon(self, domain: str) -> dict:
        out = {"domain": domain, "a": [], "mx": [], "spf": "", "dmarc": "",
               "dkim_selectors": [], "whois_created": "", "age_days": None,
               "registrar": ""}
        if not domain:
            return out
        if _DNS:
            r = dns.resolver.Resolver()
            r.lifetime = r.timeout = 4.0
            for rtype, key in (("A", "a"), ("MX", "mx")):
                try:
                    out[key] = [str(x).rstrip(".") for x in r.resolve(domain, rtype)]
                except Exception:
                    pass
            try:
                for x in r.resolve(domain, "TXT"):
                    txt = str(x).strip('"')
                    if txt.lower().startswith("v=spf1"):
                        out["spf"] = txt
            except Exception:
                pass
            try:
                for x in r.resolve(f"_dmarc.{domain}", "TXT"):
                    txt = str(x).strip('"')
                    if "v=dmarc1" in txt.lower():
                        out["dmarc"] = txt
            except Exception:
                pass
            for sel in ("default", "google", "selector1", "selector2", "s1", "k1"):
                try:
                    r.resolve(f"{sel}._domainkey.{domain}", "TXT")
                    out["dkim_selectors"].append(sel)
                except Exception:
                    pass
        # WHOIS creation date -> age (best-effort; requires the `whois` CLI)
        try:
            w = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=12)
            txt = w.stdout or ""
            m = re.search(r'(?im)^\s*(?:Creation Date|Created On|created|Registered on)\s*:?\s*(\S+)', txt)
            if m:
                out["whois_created"] = m.group(1)
                for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d", "%Y.%m.%d", "%d-%b-%Y"):
                    try:
                        dt = datetime.strptime(m.group(1).split("T")[0] if fmt in ("%Y-%m-%d", "%Y.%m.%d", "%d-%b-%Y") else m.group(1), fmt)
                        out["age_days"] = (datetime.now() - dt).days
                        break
                    except Exception:
                        continue
            mr = re.search(r'(?im)^\s*Registrar:\s*(.+)$', txt)
            if mr:
                out["registrar"] = mr.group(1).strip()
        except Exception:
            pass
        return out

    def _parse_auth(self, p: ParsedEmail) -> dict:
        auth = {"available": bool(p.auth_results), "spf": "unknown",
                "dkim": "unknown", "dmarc": "unknown", "raw": p.auth_results}
        if not p.auth_results:
            return auth
        blob = p.auth_results.lower()
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf'{mech}=(pass|fail|softfail|neutral|none|temperror|permerror|bestguesspass)', blob)
            if m:
                auth[mech] = m.group(1)
        return auth

    # ── Signal generators ───────────────────────────────────────────────
    def _sig_auth(self, p: ParsedEmail, auth: dict, recon: dict) -> List[Signal]:
        out = []
        if auth["available"]:
            for mech in ("spf", "dkim", "dmarc"):
                v = auth.get(mech)
                if v in ("fail", "softfail", "permerror"):
                    out.append(Signal(f"auth_{mech}_fail", f"{mech.upper()} {v}",
                                      "high" if mech == "dmarc" else "medium",
                                      f"Message failed {mech.upper()} ({v}) per Authentication-Results.",
                                      "authentication"))
                elif v == "none" and mech == "dmarc":
                    out.append(Signal("auth_dmarc_none", "No DMARC alignment", "medium",
                                      "DMARC evaluated to 'none' — the From domain is not DMARC-protected.",
                                      "authentication"))
        else:
            # No header auth (snippet/forward) — fall back to sender-domain
            # posture. These are WEAK on their own (plenty of small legitimate
            # domains lack SPF/DMARC), so they are low-severity context that
            # only matters combined with impersonation/reputation signals.
            if recon and recon.get("domain"):
                if not recon.get("spf"):
                    out.append(Signal("no_spf", "Sender domain publishes no SPF", "low",
                                      f"{recon['domain']} has no SPF record — its mail is unauthenticated and spoofable.",
                                      "authentication"))
                if not recon.get("dmarc"):
                    out.append(Signal("no_dmarc", "Sender domain publishes no DMARC", "low",
                                      f"{recon['domain']} has no DMARC policy — nothing rejects forged mail from this domain.",
                                      "authentication"))
                if recon.get("a") and not recon.get("mx"):
                    out.append(Signal("no_mx", "Sender domain has no MX record", "low",
                                      f"{recon['domain']} resolves (A record) but has no MX — not set up as a real mail domain, yet used as a sender.",
                                      "authentication"))
        return out

    def _sig_identity(self, p: ParsedEmail, recon: dict) -> List[Signal]:
        out = []
        fdom = p.from_domain
        # display-name spoof: a brand/person name in display, unrelated domain
        disp = (p.from_display or "").lower()
        for brand, toks in _BRAND_TOKENS.items():
            if any(t in disp for t in toks) and fdom and not self._is_brand_domain(brand, fdom):
                bname = _BRAND_DISPLAY.get(brand, brand.title())
                out.append(Signal("display_name_spoof", "Display name impersonates a brand", "high",
                                  f'From display name "{p.from_display}" invokes {bname}, but the address domain is {fdom}.',
                                  "impersonation"))
                break
        # reply-to mismatch
        if p.reply_to and fdom and _reg_domain(_domain_of(p.reply_to)) != _reg_domain(fdom):
            out.append(Signal("reply_to_mismatch", "Reply-To domain differs from From", "medium",
                              f"Reply-To ({p.reply_to}) points to a different domain than the sender ({fdom}) — replies are redirected to the attacker.",
                              "impersonation"))
        # return-path mismatch (raw only) — LOW: legitimate ESPs (SendGrid,
        # Mailchimp, Amazon SES…) routinely use their own bounce domain, so a
        # mismatch alone is normal; it only matters alongside other signals.
        if p.raw_available and p.return_path and fdom and \
                _reg_domain(_domain_of(p.return_path)) != _reg_domain(fdom):
            out.append(Signal("return_path_mismatch", "Envelope sender differs from From", "low",
                              f"Return-Path ({p.return_path}) is not aligned with the From domain ({fdom}).",
                              "impersonation"))
        # freemail
        if fdom in _FREEMAIL:
            out.append(Signal("freemail_sender", "Sent from a free webmail account", "low",
                              f"Sender uses a free webmail domain ({fdom}) — common for impersonation and BEC pretexting.",
                              "impersonation"))
        # lookalike / cousin domain vs your own configured domain(s)
        for od in self.org_domains:
            if not fdom or _reg_domain(fdom) == od:
                continue
            core_od = od.split(".")[0]
            core_fd = _reg_domain(fdom).split(".")[0]
            dist = _levenshtein(core_fd, core_od)
            if 0 < dist <= 2 or (core_od in core_fd and core_fd != core_od):
                out.append(Signal("lookalike_domain", "Look-alike / cousin domain of your organisation", "critical",
                                  f"Sender domain {fdom} closely resembles your domain {od} (edit distance {dist}) — a spoofing/cousin domain impersonating your organisation.",
                                  "impersonation"))
                break
        return out

    def _brand_claimed_as_sender(self, p: ParsedEmail, toks) -> bool:
        """True only when the brand is presented as the SENDER/originator of
        the message — not merely mentioned in passing. This is the key
        false-positive guard: a legit newsletter that says "open in Adobe
        Acrobat" must NOT be flagged as impersonating Adobe; a mail that says
        "automated message from Adobe Sign" or is From "Adobe Sign" must be."""
        disp = (p.from_display or "").lower()
        if any(t in disp for t in toks):
            return True
        text = f"{p.subject}\n{p.text_body}\n{p.html_body}".lower()
        for t in toks:
            et = re.escape(t)
            if re.search(r'(?:message|notification|email|mail|request)\s+(?:from|by|sent by|on behalf of)\s+' + et, text):
                return True
            if re.search(r'(?:from|by|on behalf of|regards,|thanks,|sincerely,|the)\s+' + et + r'\s+(?:team|support|sign|inc|group|notification)', text):
                return True
            if re.search(r'(?:automated|automatic|secure|do[- ]?not[- ]?reply)[^\n]{0,30}\b' + et, text):
                return True
            if re.search(et + r'\s+(?:sign|team|support|account team|customer support|notifications?)\b', text):
                return True
        return False

    def _sig_brand(self, p: ParsedEmail, urls: List[dict]) -> List[Signal]:
        out = []
        fdom = p.from_domain
        for brand, toks in _BRAND_TOKENS.items():
            if not self._brand_claimed_as_sender(p, toks):
                continue
            if fdom and not self._is_brand_domain(brand, fdom):
                bname = _BRAND_DISPLAY.get(brand, brand.title())
                out.append(Signal(f"brand_impersonation_{brand}", f"Impersonates {bname}", "high",
                                  f"The message presents itself as being from {bname} but was sent from {fdom}, "
                                  f"which is not an official {bname} domain.",
                                  "impersonation"))
        return out

    def _sig_urls(self, p: ParsedEmail, urls: List[dict]) -> List[Signal]:
        out = []
        for u in urls:
            # ESP click-trackers are used by huge numbers of LEGITIMATE bulk
            # senders — low on their own; the damning case (transactional
            # content routed through one) is caught as a combination in
            # _sig_combo.
            if u.get("wrapper"):
                out.append(Signal("redirect_wrapper", "Link routed through a redirect/click-tracker", "low",
                                  f"{u['defanged']} — {u['wrapper']}", "url"))
            if u.get("is_shortener"):
                out.append(Signal("url_shortener", "Link uses a URL shortener", "low",
                                  f"{u['defanged']} obscures its true destination via a shortener.", "url"))
            # Anchor text pointing to a different host than the real target is
            # genuine deception — kept HIGH.
            if u.get("anchor_domain_mismatch"):
                out.append(Signal("url_anchor_mismatch", "Link text disguises its real target", "high",
                                  f'Anchor text "{u.get("anchor_text","")}" does not match the actual link host {u["host"]}.',
                                  "url"))
        return out

    def _sig_lure(self, p: ParsedEmail) -> List[Signal]:
        out = []
        blob = p.body_blob().lower()
        hits = {cat: _kw_hits(blob, kws) for cat, kws in _LURE_KEYWORDS.items()}
        # Lure language is context, not proof (legit mail discusses invoices,
        # taxes, and password resets too) — low/medium, escalated by _sig_combo
        # when it co-occurs with a spoofed/freemail sender.
        if hits["financial"]:
            out.append(Signal("financial_lure", "Financial / payment topic", "low",
                              f"Financial / payment language present: {', '.join(hits['financial'][:4])}.", "lure"))
        if hits["credential"]:
            out.append(Signal("credential_lure", "Credential-harvest lure", "medium",
                              f"Language pushing the recipient to authenticate/verify: {', '.join(hits['credential'][:4])}.", "lure"))
        if hits["urgency"]:
            out.append(Signal("urgency", "Urgency / pressure tactics", "low",
                              f"Pressure language: {', '.join(hits['urgency'][:4])}.", "lure"))
        # Request to CHANGE/redirect payment destination — the single strongest
        # tell of invoice / vendor-email-compromise fraud. Legit "pay our usual
        # account" invoices do NOT contain this; a genuine bank change should
        # still be verified out-of-band, so flagging it is correct.
        _bankchg = ("bank account has changed", "banking details have changed", "updated banking",
                    "new bank", "change of bank", "new beneficiary", "account has changed",
                    "remit to the new", "changed our bank", "new banking", "account details have changed",
                    "bank details below", "update your records with")
        if _kw_hits(blob, _bankchg):
            out.append(Signal("bank_change_request", "Request to change/redirect payment details", "high",
                              "The message asks to send payment to new/changed bank or beneficiary details — the hallmark of "
                              "invoice / vendor-email-compromise fraud. Verify via a known-good phone number before paying.",
                              "impersonation"))
        return out

    def _sig_combo(self, p: ParsedEmail, signals: List[Signal], urls: List[dict]) -> List[Signal]:
        """Combination signals — individually-weak indicators that are strong
        TOGETHER. This is what separates a benign newsletter (ESP tracker
        alone) from a phish (impersonation + tracker), and catches link-less
        BEC that no single signal flags."""
        out = []
        ids = {s.id for s in signals}
        blob = p.body_blob().lower()
        freemail = "freemail_sender" in ids
        reply_mis = "reply_to_mismatch" in ids
        money = bool(_kw_hits(blob, ("wire transfer", "wire the", "bank details", "banking details",
                                     "beneficiary", "remit", "gift card", "change of bank",
                                     "updated banking", "new bank", "invoice", "outstanding")))
        # BEC / CEO-fraud / invoice-fraud: money movement + weak/off-domain
        # identity + little or no legitimate link content.
        if money and (freemail or reply_mis) and len(urls) <= 1:
            out.append(Signal("bec_pattern", "Business Email Compromise pattern", "high",
                              "A financial-action request is combined with a freemail/mismatched sender and little or no "
                              "legitimate link content — the classic BEC / CEO-fraud / invoice-fraud shape.",
                              "impersonation"))
        # Transactional (e-sign / document) notice delivered through a
        # bulk-marketing click-tracker — legit e-sign services link directly
        # to their own domain, so this mismatch is suspicious.
        esign = bool(_kw_hits(blob, _LURE_KEYWORDS["esign"]))
        if esign and "redirect_wrapper" in ids:
            out.append(Signal("transactional_via_bulk", "One-to-one document notice sent via bulk-mail redirect", "medium",
                              "A personal document / e-signature notification is routed through a bulk-marketing click-tracker — "
                              "legitimate e-sign services (Adobe, DocuSign) link directly to their own domain.",
                              "url"))
        return out

    def _sig_attachments(self, p: ParsedEmail) -> List[Signal]:
        out = []
        for a in p.attachments:
            fn = (a.get("filename") or "").lower()
            if any(fn.endswith(ext) for ext in _DANGEROUS_ATTACH):
                out.append(Signal("dangerous_attachment", "High-risk attachment type", "high",
                                  f"Attachment {a.get('filename')} ({a.get('content_type')}) is a type commonly used to deliver malware.",
                                  "attachment"))
        return out

    def _sig_reputation(self, p: ParsedEmail, urls: List[dict]) -> List[Signal]:
        out = []
        if not _REQ:
            return out
        vt_key = self.cfg.get("virustotal_api_key") or os.environ.get("EMAIL_ANALYZER_VT_API_KEY", "")
        if not vt_key:
            return out
        hosts = {u["host"] for u in urls}
        if p.from_domain:
            hosts.add(p.from_domain)
        checked = 0
        for host in list(hosts):
            if checked >= 6:
                break
            checked += 1
            try:
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/domains/{host}",
                    headers={"x-apikey": vt_key}, timeout=8)
                if r.status_code == 200:
                    stats = (r.json().get("data", {}).get("attributes", {})
                             .get("last_analysis_stats", {}))
                    mal = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
                    if mal > 0:
                        out.append(Signal("vt_reputation", "Flagged by threat-intel vendors", "critical",
                                          f"VirusTotal: {mal} security vendor(s) flag {host} as malicious/suspicious.",
                                          "reputation"))
            except Exception:
                pass
        return out

    # ── Verdict logic ────────────────────────────────────────────────────
    def _is_brand_domain(self, brand: str, domain: str) -> bool:
        rd = _reg_domain(domain)
        return any(rd == _reg_domain(b) for b in _BRANDS.get(brand, ()))

    def _score_to_verdict(self, score: int, signals: List[Signal],
                          p: ParsedEmail, urls: List[dict]) -> Tuple[str, str]:
        ids = {s.id for s in signals}
        # threat-type heuristic
        has_link = bool(urls)
        brand_imp = any(i.startswith("brand_impersonation") for i in ids) or "display_name_spoof" in ids
        if "bec_pattern" in ids or "bank_change_request" in ids:
            threat_type = "bec"
        elif p.to and "," not in p.to and ("impersonation" in {s.category for s in signals}) and not brand_imp and score >= 40:
            # single named recipient + non-brand impersonation -> targeted
            threat_type = "spear_phishing"
        else:
            threat_type = "phishing"

        if score >= 50:
            return "phishing", threat_type
        if score >= 24:
            return "suspicious", threat_type
        return "benign", "benign"

    def _llm_classify(self, p: ParsedEmail, signals: List[Signal],
                      urls: List[dict], recon: dict, auth: dict) -> dict:
        """Optional LLM classification pass, using an OpenAI-compatible chat
        completion API. Entirely opt-in: no-ops unless an API key is
        configured (OPENAI_API_KEY env var or cfg['openai_api_key']) and the
        `openai` package is installed."""
        api_key = self.cfg.get("openai_api_key") or os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            return {"ai_triage": False}
        try:
            from openai import OpenAI  # type: ignore
        except Exception:
            return {"ai_triage": False}

        model = self.cfg.get("openai_model") or os.environ.get("EMAIL_ANALYZER_OPENAI_MODEL", "gpt-4o-mini")
        evidence = {
            "from": f"{p.from_display} <{p.from_addr}>",
            "reply_to": p.reply_to, "subject": p.subject, "to": p.to,
            "headers_available": p.raw_available,
            "authentication": {k: auth.get(k) for k in ("spf", "dkim", "dmarc", "available")},
            "sender_domain_recon": {k: recon.get(k) for k in ("spf", "dmarc", "mx", "age_days", "registrar")},
            "urls": [{"host": u["host"], "wrapper": u.get("wrapper"), "anchor": u.get("anchor_text")} for u in urls][:8],
            "deterministic_signals": [f"[{s.severity}] {s.title}: {s.detail}" for s in signals],
            "body_excerpt": (p.text_body or re.sub(r'<[^>]+>', ' ', p.html_body or ''))[:1200],
        }
        import json as _json
        prompt = f"""You are a senior email-threat analyst. Deterministic pre-analysis has already been run; use it plus the raw evidence to reach a final classification.

EVIDENCE:
{_json.dumps(evidence, indent=2)[:3500]}

Classify the email. Respond ONLY with this exact JSON (no markdown):
{{
  "verdict": "<phishing|spear_phishing|bec|spam|suspicious|benign>",
  "confidence": "<HIGH|MEDIUM|LOW>",
  "threat_type": "<credential_harvest|malware_delivery|business_email_compromise|invoice_fraud|extortion|reconnaissance|marketing|legitimate>",
  "brand_impersonated": "<brand or empty>",
  "reasoning": "<2-3 sentences citing the strongest evidence>",
  "key_indicators": ["<indicator1>", "<indicator2>", "<indicator3>"],
  "recommended_actions": ["<action1>", "<action2>"]
}}"""
        try:
            client = OpenAI(api_key=api_key)
            resp = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=800,
                temperature=0,
            )
            raw = resp.choices[0].message.content or ""
            m = re.search(r'\{.*\}', raw, re.DOTALL)
            data = _json.loads(m.group(0) if m else raw)
            data["ai_triage"] = True
            return data
        except Exception as e:
            return {"ai_triage": False, "error": str(e)}

    def _reconcile(self, heur_verdict: str, heur_type: str, score: int,
                   ai: dict, signals=None, auth=None) -> Tuple[str, str, str, str]:
        signals = signals or []
        strong = any(s.severity in ("high", "critical") for s in signals)
        # ── False-positive guard ──
        # With essentially no deterministic evidence, do NOT let the LLM
        # escalate a clean (usually authenticated) message to a scary verdict.
        # This is what keeps legitimate mail classified as legitimate.
        dmarc_ok = bool(auth and auth.get("dmarc") == "pass")
        if not strong and (score < 12 or dmarc_ok):
            # DMARC pass = the From domain's owner authorised this mail; with no
            # high/critical indicator it is legitimate. Also covers near-zero-
            # evidence mail. Any real impersonation/lookalike/reputation/BEC
            # signal is high/critical -> `strong` -> this guard is skipped.
            return "benign", "benign", ("HIGH" if (score == 0 or dmarc_ok) else "MEDIUM"), "info"
        order = {"benign": 0, "spam": 1, "suspicious": 2, "bec": 3,
                 "spear_phishing": 3, "phishing": 3}
        av = (ai.get("verdict") or "").lower() if isinstance(ai, dict) else ""
        verdict = heur_verdict
        if av and order.get(av, 0) >= order.get(heur_verdict, 0):
            verdict = av
        threat_type = ai.get("threat_type") if isinstance(ai, dict) and ai.get("verdict") else heur_type
        threat_type = threat_type or heur_type
        # confidence: agreement between heuristic and AI raises it
        conf = (ai.get("confidence") or "").upper() if isinstance(ai, dict) else ""
        if score >= 50 or (av in ("phishing", "bec", "spear_phishing") and score >= 25):
            confidence = "HIGH"
        elif conf:
            confidence = conf
        else:
            confidence = "MEDIUM" if score >= 15 else "LOW"
        risk_map = {"phishing": "high", "bec": "high", "spear_phishing": "high",
                    "suspicious": "medium", "spam": "low", "benign": "info"}
        risk = risk_map.get(verdict, "medium")
        if verdict in ("phishing", "bec", "spear_phishing") and (score >= 65 or
                any(s for s in [ai] if isinstance(ai, dict) and ai.get("verdict") == "phishing" and score >= 50)):
            risk = "critical"
        return verdict, threat_type, confidence, risk

    # ── Output helpers ───────────────────────────────────────────────────
    def _iocs(self, p: ParsedEmail, urls: List[dict], recon: dict) -> List[dict]:
        iocs = []
        if p.from_addr:
            iocs.append({"type": "email", "value": p.from_addr})
        if p.from_domain:
            iocs.append({"type": "domain", "value": p.from_domain})
        for ip in recon.get("a", [])[:4]:
            iocs.append({"type": "ip", "value": ip})
        for u in urls:
            iocs.append({"type": "url", "value": u["defanged"]})
            if u.get("host"):
                iocs.append({"type": "domain", "value": u["host"]})
        # de-dup
        seen, out = set(), []
        for i in iocs:
            k = (i["type"], i["value"])
            if k not in seen:
                seen.add(k); out.append(i)
        return out

    def _checks_summary(self, p: ParsedEmail, auth: dict, recon: dict,
                        signals: List[Signal], urls: List[dict], ai: dict) -> List[dict]:
        """Always-populated, plain-English breakdown of every category this
        analyzer examines — shown regardless of verdict, so a 'benign' result
        visibly reflects real checks that came back clean rather than looking
        like nothing was done."""
        by_id = {s.id: s for s in signals}

        def flagged(ids):
            return [by_id[i] for i in ids if i in by_id]

        checks = []

        # 1) Header authentication
        if auth.get("available"):
            parts = [f"SPF {auth.get('spf','unknown')}", f"DKIM {auth.get('dkim','unknown')}",
                     f"DMARC {auth.get('dmarc','unknown')}"]
            auth_flagged = flagged(["auth_spf_fail", "auth_dkim_fail", "auth_dmarc_fail", "auth_dmarc_none"])
            checks.append({
                "id": "header_auth", "label": "Header authentication (SPF / DKIM / DMARC)",
                "status": "flagged" if auth_flagged else "clear",
                "detail": ("; ".join(parts) + " — read directly from the message's "
                          "Authentication-Results header." +
                          ("" if not auth_flagged else " Issue(s): " + "; ".join(s.detail for s in auth_flagged))),
            })
        else:
            no_auth_flagged = flagged(["no_spf", "no_dmarc", "no_mx"])
            checks.append({
                "id": "header_auth", "label": "Header authentication (SPF / DKIM / DMARC)",
                "status": "not_available" if not no_auth_flagged else "flagged",
                "detail": ("No original headers were supplied (forwarded snippet) — SPF/DKIM/DMARC "
                          "could not be read directly, so sender-domain posture was checked live instead." +
                          ("" if not no_auth_flagged else " Found: " + "; ".join(s.detail for s in no_auth_flagged))),
            })

        # 2) Sender identity
        id_flagged = flagged(["display_name_spoof", "reply_to_mismatch", "return_path_mismatch",
                              "freemail_sender", "lookalike_domain"])
        checks.append({
            "id": "sender_identity",
            "label": "Sender identity (display name, Reply-To, Return-Path, free-webmail, look-alike domain)",
            "status": "flagged" if id_flagged else "clear",
            "detail": ("; ".join(s.detail for s in id_flagged) if id_flagged else
                      "Display name, Reply-To, and Return-Path were compared against the From address"
                      + (f", and the sender domain ({p.from_domain}) was checked for look-alike similarity "
                         f"to {', '.join(self.org_domains)}" if self.org_domains else "")
                      + " — no spoofing indicators found."),
        })

        # 3) Brand impersonation
        brand_flagged = [s for s in signals if s.id.startswith("brand_impersonation")]
        brand_list = ", ".join(sorted(_BRAND_DISPLAY.values()))
        checks.append({
            "id": "brand_impersonation", "label": "Brand impersonation",
            "status": "flagged" if brand_flagged else "clear",
            "detail": ("; ".join(s.detail for s in brand_flagged) if brand_flagged else
                      f"Message content was checked against {len(_BRANDS)} commonly-impersonated "
                      f"brands ({brand_list}) — no impersonation detected."),
        })

        # 4) URL / link analysis
        url_flagged = flagged(["redirect_wrapper", "url_shortener", "url_anchor_mismatch"]) + \
                      [s for s in signals if s.id == "transactional_via_bulk"]
        if not urls:
            url_detail = "No links were found in this message."
            url_status = "not_available"
        elif url_flagged:
            url_detail = "; ".join(s.detail for s in url_flagged)
            url_status = "flagged"
        else:
            url_detail = (f"{len(urls)} link(s) found — extracted from HTML and plaintext, defanged, "
                          "checked for redirect wrappers/shorteners, and anchor-text-vs-target mismatch — "
                          "no deceptive links found.")
            url_status = "clear"
        checks.append({"id": "url_analysis", "label": f"URL / link analysis ({len(urls)} found)",
                       "status": url_status, "detail": url_detail})

        # 5) Lure language / social-engineering content
        lure_flagged = flagged(["financial_lure", "credential_lure", "urgency", "bank_change_request"])
        checks.append({
            "id": "lure_language", "label": "Lure language (financial, credential-harvest, urgency, payment-redirect)",
            "status": "flagged" if lure_flagged else "clear",
            "detail": ("; ".join(s.detail for s in lure_flagged) if lure_flagged else
                      "Message text was scanned for financial/wire-transfer, credential-harvest, urgency, "
                      "and payment-redirect language — none found."),
        })

        # 6) Combination / BEC pattern
        combo_flagged = flagged(["bec_pattern"])
        checks.append({
            "id": "bec_pattern", "label": "Business Email Compromise (BEC) pattern",
            "status": "flagged" if combo_flagged else "clear",
            "detail": ("; ".join(s.detail for s in combo_flagged) if combo_flagged else
                      "Checked whether a financial-action request co-occurs with a freemail/mismatched "
                      "sender and little or no legitimate link content — no BEC pattern detected."),
        })

        # 7) Attachments
        att_flagged = flagged(["dangerous_attachment"])
        if not p.attachments:
            att_detail, att_status = "No attachments were present in this message.", "not_available"
        elif att_flagged:
            att_detail, att_status = "; ".join(s.detail for s in att_flagged), "flagged"
        else:
            att_detail = f"{len(p.attachments)} attachment(s) checked against known high-risk file types — none flagged."
            att_status = "clear"
        checks.append({"id": "attachments", "label": f"Attachments ({len(p.attachments)} found)",
                       "status": att_status, "detail": att_detail})

        # 8) Sender-domain live recon (DNS / WHOIS)
        if recon and recon.get("domain"):
            bits = []
            bits.append("MX record present" if recon.get("mx") else "no MX record")
            bits.append("SPF record present" if recon.get("spf") else "no SPF record")
            bits.append("DMARC record present" if recon.get("dmarc") else "no DMARC record")
            if recon.get("age_days") is not None:
                bits.append(f"registered ~{recon['age_days']} days ago")
            checks.append({"id": "domain_recon", "label": f"Live sender-domain recon ({recon['domain']})",
                           "status": "info", "detail": "; ".join(bits) + "."})
        else:
            checks.append({"id": "domain_recon", "label": "Live sender-domain recon",
                           "status": "not_available", "detail": "No sender domain could be determined to look up."})

        # 9) Reputation (VirusTotal) — optional
        vt_flagged = flagged(["vt_reputation"])
        vt_key = self.cfg.get("virustotal_api_key") or os.environ.get("EMAIL_ANALYZER_VT_API_KEY", "")
        if not vt_key:
            checks.append({"id": "reputation", "label": "Threat-intel reputation (VirusTotal)",
                           "status": "skipped",
                           "detail": "Not enabled — no VirusTotal API key configured (set EMAIL_ANALYZER_VT_API_KEY to turn this on)."})
        elif vt_flagged:
            checks.append({"id": "reputation", "label": "Threat-intel reputation (VirusTotal)",
                           "status": "flagged", "detail": "; ".join(s.detail for s in vt_flagged)})
        else:
            checks.append({"id": "reputation", "label": "Threat-intel reputation (VirusTotal)",
                           "status": "clear",
                           "detail": "Sender domain and link host(s) checked against VirusTotal — no vendors flagged them."})

        # 10) Optional LLM classification pass
        if not isinstance(ai, dict) or not ai.get("ai_triage"):
            checks.append({"id": "llm_pass", "label": "AI classification pass",
                           "status": "skipped",
                           "detail": "Not enabled — no OPENAI_API_KEY configured. This verdict is based entirely on the deterministic checks above."})
        else:
            checks.append({"id": "llm_pass", "label": "AI classification pass",
                           "status": "info",
                           "detail": ai.get("reasoning") or f"AI verdict: {ai.get('verdict', 'n/a')} (confidence {ai.get('confidence', 'n/a')})."})

        return checks

    def _summary(self, verdict: str, threat_type: str, p: ParsedEmail,
                 signals: List[Signal]) -> str:
        top = [s.title for s in sorted(signals, key=lambda s: -_SEV_WEIGHT.get(s.severity, 0))][:4]
        vt = {"phishing": "a phishing email", "bec": "a business email compromise (BEC) attempt",
              "spear_phishing": "a targeted spear-phishing email", "suspicious": "a suspicious email",
              "spam": "spam / bulk mail", "benign": "most likely legitimate"}.get(verdict, verdict)
        base = f'This message ("{p.subject or "(no subject)"}" from {p.from_addr or "unknown"}) is assessed as {vt}.'
        if top and verdict not in ("benign",):
            base += " Primary indicators: " + "; ".join(top) + "."
        if not p.raw_available and verdict not in ("benign",):
            base += (" NOTE: analysis was performed on a forwarded snippet without original "
                     "headers — SPF/DKIM/DMARC results could not be read directly and were "
                     "inferred from live sender-domain posture. For header-level proof, supply the "
                     "original .eml ('Show original' → download).")
        return base

    def _actions(self, verdict: str, p: ParsedEmail, urls: List[dict]) -> List[str]:
        if verdict in ("benign",):
            return ["No action required. If unexpected, verify with the sender via a known-good channel."]
        acts = [
            "Do NOT click any link or open any attachment in this message.",
            f"Delete/quarantine the message from the recipient mailbox ({p.to or 'affected user'}).",
        ]
        if urls:
            acts.append("Block the sender domain and the link host(s) at the mail gateway, proxy, and DNS; "
                        "detonate the URL in a sandbox to recover the final landing domain and block it too.")
        acts += [
            "Search all mailboxes at the gateway/admin level for the same sender/subject/link to gauge blast radius, and purge matches.",
            "If anyone clicked or entered credentials: force password reset + revoke sessions and scan the endpoint.",
            "Report to the abuse contacts of the sending infrastructure and, for tax lures, to phishing@irs.gov.",
        ]
        return acts


def analyze_email(content: str, cfg: Optional[dict] = None, **kw) -> dict:
    """Convenience function: EmailAnalyzer(cfg).analyze(content, **kw)."""
    return EmailAnalyzer(cfg or {}).analyze(content, **kw)
