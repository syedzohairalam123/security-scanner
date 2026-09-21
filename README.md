# Perimeter — Web Vulnerability Scanner

A full-stack vulnerability scanner: point it at a URL you own or are
authorized to test, and it checks HTTP headers, TLS/SSL configuration, open
ports, session token randomness, common misconfigurations, access-control
exposure, and known CVEs, then reports everything with a risk score and
concrete fixes.

Built with Flask + SQLite/Postgres + vanilla JS, deployable to Vercel with
zero build configuration.

## Important: authorized use only

This tool is for **educational and authorized security testing only**. Only
scan systems you own or have explicit written permission to test. The UI
requires an explicit confirmation checkbox before every scan, and that
confirmation is stored with the scan record. Scanning systems without
authorization may be illegal in your jurisdiction regardless of intent.

## Scanning methodology

Every check is **read-only detection**: it looks for the presence of a
weakness using the same publicly documented techniques taught in any intro
web security course (OWASP Testing Guide, Mozilla Observatory, etc.), and
reports it. Nothing here chains a finding into further access, brute-forces
credentials, evades a firewall by design, or disrupts the target — see
[`DESIGN_NOTES.md`](./DESIGN_NOTES.md) for the reasoning behind that
boundary, including why some "AI hacking" ideas from early brainstorming
were deliberately left out.

| Module | What it does |
|---|---|
| `scanner/scan_integrity.py` | Detects known interstitial phrases and compares repeat-scan fingerprints (page title, content-length bucket, normalized visible-text hash, and header names); the orchestrator makes one polite retry after a detection. |
| `scanner/http_headers.py` | Checks for HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy; flags version-disclosing `Server`/`X-Powered-By` headers. |
| `scanner/ssl_check.py` | Opens a real TLS handshake (stdlib `ssl`) and checks protocol version, cipher strength, certificate expiry, and certificate validity. |
| `scanner/port_scan.py` | Pure-socket sweep of ~20 common ports (databases, remote admin, mail, etc.) with short timeouts and bounded concurrency. |
| `scanner/misconfig.py` | Cookie flags (Secure/HttpOnly/SameSite), CORS misconfiguration, directory-listing detection, verbose error/stack-trace detection, exposed `.git`/`.env`/backup files. |
| `scanner/token_entropy.py` | Real Shannon-entropy measurement on session cookies to flag short, sequential, or low-randomness tokens. |
| `scanner/access_control.py` | Probes well-known admin/management paths (`/admin`, `phpMyAdmin`, Spring Actuator, etc.) for unauthenticated access; flags default install pages. |
| `scanner/dns_security.py` | CAA, DNSSEC posture, SPF/DMARC record validation, and dangling-CNAME subdomain-takeover detection - the DNS layer most HTTP-only scanners skip. |
| `scanner/ct_monitor.py` | Certificate Transparency log correlation (crt.sh) - surfaces forgotten/shadow subdomains and unusually broad CA issuance. |
| `scanner/frontend_deps.py` | Third-party `<script>` tags missing Subresource Integrity, and known-outdated/vulnerable JS library fingerprinting. |
| `scanner/active_probes.py` | Only runs with consent. Standard, publicly documented test strings for reflected XSS and error-based SQL injection, plus **one** bounded time-based SQLi check. Each finding carries a confidence tier based on how many independent signals agree. |
| `scanner/correlation.py` | Attack-chain engine: combines individual findings that compose into something categorically worse (e.g. reflected XSS + no CSP + non-HttpOnly cookie \u2192 a synthesized "full session compromise" chain), with the reasoning fully auditable in the finding's evidence. |
| `scanner/cve_lookup.py` | Matches detected software/version banners against the public NVD API. |
| `scanner/remediation.py` | Generates a framework-specific code snippet (Flask-Talisman / Helmet / Nginx / Apache / Django settings) for missing-header findings. |
| `scanner/risk_score.py` | Combines findings (including synthesized chains) into a single 0–100 score with a plain, documented formula - no black-box model. |
| `scan_service.compute_diff()` | Historical regression tracking: diffs each scan against the target's previous one, tagging findings NEW / RESOLVED / RECURRING and tracking the risk-score trend. |
| `reports/sarif_report.py` | Exports findings as SARIF 2.1.0 - plugs directly into GitHub Code Scanning / Azure DevOps so a CI pipeline can enforce the results, not just display them. |

## Feature checklist (maps to the assignment brief)

**Core**
- [x] Responsive homepage with live scan console (Server-Sent Events progress)
- [x] URL input with validation and required authorization checkbox
- [x] Vulnerability scanning across 8 concurrent check modules
- [x] Open port detection
- [x] HTTP security header analysis
- [x] SSL/TLS certificate inspection
- [x] Common misconfiguration detection
- [x] Results dashboard with severity levels and a risk score
- [x] Report generation (in-app + PDF + CSV)
- [x] Responsive design, dark/light theme

**Bonus**
- [x] Login/signup (Flask-Login, hashed passwords, CSRF-protected forms)
- [x] Scan history per account
- [x] Export as PDF and CSV
- [x] Scheduled automatic scans (Vercel Cron)
- [x] Email notifications for scheduled scans (SMTP)
- [x] Dashboard with vulnerability statistics (risk meter, severity distribution)
- [x] Dark mode
- [x] Database integration (SQLAlchemy, SQLite locally / Postgres in production)
- [x] AI assistant that explains findings and answers questions (optional, needs your own Anthropic API key)

**Beyond the brief**
- [x] **Attack Surface Monitoring** — DNS security posture (CAA, DNSSEC, SPF, DMARC) + Certificate Transparency log correlation (crt.sh) + dangling-CNAME subdomain-takeover detection
- [x] **Attack-chain correlation engine** — synthesizes individually low/medium findings into a higher-severity, auditable "chain" finding when they combine into something categorically worse (e.g. reflected XSS + no CSP + non-HttpOnly cookie)
- [x] **Historical regression tracking** — every scan is diffed against the target's previous scan: NEW / RESOLVED / RECURRING findings, plus a risk-score trend shown on the dashboard and history page
- [x] **Frontend supply-chain analysis** — missing Subresource Integrity on third-party scripts, outdated/vulnerable JS library fingerprinting
- [x] **Confidence-calibrated findings** — active-probe results carry a High/Medium/Low confidence tier based on multi-signal corroboration (e.g. a timing anomaly alone is medium; matched by a raw DB error on the same parameter, it becomes high)
- [x] **SARIF 2.1.0 export** — findings plug directly into GitHub Code Scanning / Azure DevOps, so a CI pipeline can gate on results instead of a human reading a report
- [x] **Live scan console** — Server-Sent Events stream real per-module progress instead of a fake progress bar

## Project structure

```
app.py                  Flask entry point (Vercel auto-detects `app` here)
config.py                All settings, read from environment variables
extensions.py             db / login_manager / csrf singletons
models.py                 User, Scan, Finding, ScheduledTarget
forms.py                  WTForms (CSRF-protected) for auth
scan_service.py           Persists a scan result dict to the database
notifications.py          SMTP email for scheduled scans
ai_assistant.py           Optional Anthropic API integration
time_utils.py              Shared UTC-now helper
scanner/                  The scan engine (see table above)
  orchestrator.py           Runs all checks concurrently, streams progress
reports/
  pdf_report.py             PDF export (reportlab)
  csv_report.py             CSV export
routes/
  main.py                    Page routes (/, /dashboard/<id>, /history)
  auth.py                    /login, /signup, /logout
  scan.py                    /api/scan/stream (SSE), report exports, AI ask, schedules
  cron.py                    /api/cron/scheduled-scans (Vercel Cron target)
templates/                Jinja templates
public/                   Static assets — Vercel serves this directory
                           directly via its CDN in production (Flask's own
                           static_folder is ignored on Vercel, so everything
                           the browser loads must live here, not in `static/`)
tests/                    Pytest suite (41 tests) - unit tests for the pure
                           logic plus end-to-end tests that spin up a local
                           "vulnerable" target and assert real findings
.github/workflows/ci.yml Runs the test suite on every push/PR
```

## Tests

```bash
pip install pytest
pytest -v
```

41 tests: pure-logic unit tests (risk scoring, entropy math, URL
normalization, framework detection), route/auth integration tests against
an in-memory-DB Flask test client, PDF/CSV export tests, and an end-to-end
test that runs a real scan against a local Flask server with deliberately
planted weaknesses and asserts the scanner actually finds them.

## Run it locally

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env             # fill in at least SECRET_KEY
python app.py                    # http://localhost:5000
```

The default local SQLite database is stored at `instance/dev.db` using an
absolute project-relative path, so the app can also be launched from another
working directory without losing the schema. Set `DATABASE_URL` to use a
different database.

Or with the Vercel CLI, which serves the app exactly as production does
(useful for testing cron routes and streaming):

```bash
npm i -g vercel
vercel dev
```

## Deploy to Vercel

1. Push this project to a GitHub/GitLab/Bitbucket repo.
2. Import it at [vercel.com/new](https://vercel.com/new). Vercel detects
   Flask automatically — **no build command or vercel.json edits needed**
   for the app itself.
3. In Project Settings → Environment Variables, set at minimum `SECRET_KEY`
   and `DATABASE_URL` (a hosted Postgres URL — see below). Add
   `ANTHROPIC_API_KEY`, `CRON_SECRET`, and the `SMTP_*` vars if you want
   those bonus features live.
4. Deploy.

**Database on Vercel:** the filesystem is ephemeral, so SQLite will not
persist scan history between requests in production. Create a free Postgres
database (Vercel Postgres, [Neon](https://neon.tech), or
[Supabase](https://supabase.com) all work), copy its connection string into
`DATABASE_URL`, and redeploy — the app creates its tables automatically on
first request, no migration step required for this project's scope.

**Cron jobs run only on production deployments** (not previews), and only
on paid Vercel plans support more than one cron job — this project defines
a single hourly job that internally checks which targets are actually due,
so it fits the Hobby plan's limits too.

## Environment variables

See [`.env.example`](./.env.example) for the full list with descriptions.
Everything except `SECRET_KEY` is optional and the corresponding feature
just turns itself off gracefully when unset.

## A note on the "extreme" feature ideas

Earlier brainstorming for this project (shared as reference docs) proposed
things like quantum-inspired token analysis, genetic-algorithm payload
evolution, and Nash-equilibrium business-logic testing. A few of those had
a real, honest version worth keeping — token entropy analysis and
time-based SQLi detection are both implemented above, under their real
names. The rest either don't correspond to anything a working program
actually does, or described real exploitation capability (WAF-evading
payload delivery, automated privilege escalation, race-condition fraud,
credential brute-forcing, denial-of-service). Those are left out on
purpose; see `DESIGN_NOTES.md`.
