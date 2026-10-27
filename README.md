# DKCISSP Email Analyzer

Got a suspicious email? Paste it in, get an instant verdict — **phishing, spear-phishing,
business email compromise (BEC), spam, or benign** — with the exact evidence behind it.
Runs entirely on your own machine. No account, no cloud service, no data leaves your
computer unless you explicitly turn on an optional lookup.

## Why

Most people forward a suspicious email to IT and wait. This tool gives anyone — individuals,
small teams, students, security folks — an immediate, defensible first read on an email,
using the same kind of deterministic forensic checks a SOC analyst would run by hand.

## What it checks

All of the following run **offline, for free, with zero API keys required**:

- **Header authentication** — SPF / DKIM / DMARC results from `Authentication-Results`
  (when you supply the full raw message / `.eml`).
- **Sender identity** — display-name-vs-address spoofing, Reply-To / Return-Path mismatch,
  free webmail senders, look-alike / cousin domains of your own domain.
- **URLs** — extraction from HTML and plaintext, defanging, unwrapping common redirect
  wrappers (ESP click-trackers, `?url=`-style open redirects, URL shorteners), and
  anchor-text-vs-real-target mismatch.
- **Live sender-domain recon** — DNS A / MX / SPF / DMARC presence, WHOIS registration age.
- **Brand impersonation** — the body claims to be Adobe, DocuSign, Microsoft, Google, PayPal,
  the IRS, etc. but the sending domain doesn't belong to that brand.
- **Lure language** — financial/wire-transfer, credential-harvest, urgency, and
  payment-redirect ("our bank details have changed") keyword patterns.
- **Dangerous attachments** — high-risk file types commonly used to deliver malware.

Two things are **optional and off by default**:

- **VirusTotal domain reputation** — passive lookup only (never fetches the link), enabled by
  setting `EMAIL_ANALYZER_VT_API_KEY`.
- **LLM classification pass** — an additional AI-based verdict reconciled with the
  deterministic signals above, enabled by setting `OPENAI_API_KEY`.

**Safety guarantee:** this tool never opens, fetches, or detonates the suspicious link. All
URL analysis is done by parsing the text — nothing is requested from the attacker's
infrastructure.

## Quick start — one click

1. [Download the repo](https://github.com/deepakkumarcissp/Email_Analyzer/archive/refs/heads/main.zip) and unzip it (or `git clone` it).
2. Double-click the launcher for your OS:
   - **Windows:** `run.bat`
   - **macOS:** `run.command`
   - **Linux:** `run.sh`
3. Your browser opens automatically at `http://127.0.0.1:1008` — paste an email and click **Analyze Email**.

That's it — no manual `pip install`, no virtual environment setup. The first run takes about a
minute to quietly set itself up; every run after that starts instantly. The only prerequisite is
**Python 3.9+** installed on your machine (the launcher tells you if it's missing, with a link to
get it). Nothing you paste into the tool ever leaves your computer.

## Install manually (for developers / the CLI / scripting)

```bash
pip install -e .
# or, for the local web UI too:
pip install -e ".[web]"
```

(Not published to PyPI yet — install from a local clone for now.)

## Use it — command line

```bash
dkcissp-email-analyzer suspicious.eml
```

Or pipe a pasted/forwarded snippet in:

```bash
cat suspicious.eml | dkcissp-email-analyzer
```

Add your own domain(s) so look-alike/cousin-domain spoofing is detected:

```bash
dkcissp-email-analyzer suspicious.eml --org-domain example.com
```

Get machine-readable JSON output (useful for scripting / SOAR integration):

```bash
dkcissp-email-analyzer suspicious.eml --json
```

The CLI exits `0` for a benign verdict and `1` for anything else, so it's usable in scripts
and pre-commit-style hooks.

## Use it — local web UI

If you used the one-click launcher above, this is already running. To start it manually instead:

```bash
pip install -e ".[web]"
dkcissp-email-analyzer-web
```

Then open **http://127.0.0.1:1008**, paste the email, and click **Analyze Email**.

## Use it — as a library

```python
from dkcissp_email_analyzer import analyze_email

with open("suspicious.eml") as f:
    result = analyze_email(f.read(), org_domains=["example.com"])

print(result["verdict"], result["risk"], result["score"])
for signal in result["signals"]:
    print(signal["severity"], signal["title"])
```

## Best input to give it

1. **Best: the original raw message.** In Gmail: open the email → ⋮ (More) → **Show
   original** → **Download original**. That `.eml` carries real
   `Authentication-Results` headers, so SPF/DKIM/DMARC can be read directly.
2. **Also works: a forwarded snippet.** Paste the forwarded body (From/Subject/links
   included). Header authentication can't be read directly in that case, so the analyzer
   clearly flags this and leans more on live domain recon, content, and URL analysis.

## Configuration

All configuration is via environment variables (or a `cfg` dict if you use it as a library) —
nothing is hardcoded:

| Variable                        | Purpose                                                   |
|----------------------------------|------------------------------------------------------------|
| `EMAIL_ANALYZER_ORG_DOMAINS`     | Comma-separated list of your own domain(s), for look-alike detection |
| `EMAIL_ANALYZER_VT_API_KEY`      | VirusTotal API key — enables passive domain reputation lookups |
| `OPENAI_API_KEY`                 | Enables the optional LLM classification pass                |
| `EMAIL_ANALYZER_OPENAI_MODEL`    | Model to use for the LLM pass (default `gpt-4o-mini`)       |

## How a verdict is reached

Every deterministic check produces a weighted **Signal** (severity: critical/high/medium/low).
Signals are summed into a score, which maps to an initial heuristic verdict. If an LLM pass is
enabled, its classification is reconciled with the heuristic one — but a built-in
false-positive guard prevents the LLM from escalating a message that has essentially no
deterministic evidence (especially one that passes DMARC) into a scary verdict. This is what
keeps ordinary legitimate mail classified as legitimate.

## Contributing

Issues and PRs welcome — more brand-impersonation patterns, more lure-language locales, more
redirect-wrapper hosts, and false-positive reports are all useful contributions.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

---

Built by [DKCISSP](https://github.com/deepakkumarcissp) for the community: a free, local,
no-account-needed way to get a second opinion on a suspicious email before you click anything.
