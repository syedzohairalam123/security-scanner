# Perimeter - Web Vulnerability Scanner
## Complete Project Documentation (Easy English)

---

## 📋 Table of Contents
1. [What is This Project?](#what-is-this-project)
2. [How It Works](#how-it-works)
3. [Database Schema](#database-schema)
4. [Project Structure](#project-structure)
5. [How the Scanner Works](#how-the-scanner-works)
6. [Flask Framework](#flask-framework)
7. [Environment Variables (.env)](#environment-variables-env)
8. [Virtual Environment (venv)](#virtual-environment-venv)
9. [Deployment on Vercel](#deployment-on-vercel)
10. [File-by-File Explanation](#file-by-file-explanation)

---

## What is This Project?

**Perimeter** is a web-based security scanner tool that checks websites for security problems. Think of it like a doctor that checks your website for sickness.

### What It Can Do:
- ✅ Check if your website uses HTTPS properly
- ✅ Find missing security headers
- ✅ Check SSL/TLS certificates
- ✅ Detect open ports that should be closed
- ✅ Find SQL injection vulnerabilities
- ✅ Find XSS (Cross-Site Scripting) vulnerabilities
- ✅ Check cookies for security flags
- ✅ Scan DNS security settings
- ✅ Generate PDF/CSV reports
- ✅ Schedule automatic scans
- ✅ AI assistant to explain findings (optional)

### Who Can Use It:
- Website owners who want to check their site's security
- Developers who want to find bugs before hackers do
- Students learning about web security

**⚠️ Important:** You can ONLY scan websites you own or have permission to test. Scanning without permission is illegal.

---

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                     USER (Browser)                           │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    FLASK WEB APP                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Frontend (HTML/CSS/JS)                                │  │
│  │  - User enters URL                                     │  │
│  │  - User clicks "Scan" button                           │  │
│  │  - Real-time progress updates                          │  │
│  └──────────────────────────────────────────────────────┘  │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Backend (Python)                                      │  │
│  │  - Orchestrator runs all checks                       │  │
│  │  - Scanner modules check the target website         │  │
│  │  - Results saved to database                         │  │
│  └──────────────────────────────────────────────────────┘  │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                 TARGET WEBSITE                              │
│  (The website being scanned - must be authorized)          │
└─────────────────────────────────────────────────────────────┘
```

### The Scanning Process:

1. **User enters URL** → Browser sends request to Flask app
2. **Flask starts scan** → Orchestrator creates a scan context
3. **Scanner modules run** → Each module checks different things:
   - HTTP Headers Check
   - SSL/TLS Check
   - Port Scan
   - DNS Security Check
   - And more...
4. **Results collected** → All findings are gathered
5. **Risk score calculated** → How dangerous are the problems?
6. **Results saved** → Stored in database
7. **User sees report** → Dashboard shows all findings

---

## Database Schema

The database uses **SQLAlchemy ORM** (Object-Relational Mapping). This means we write Python code instead of SQL queries.

### Database Type:
- **Local Development:** SQLite (file-based database)
- **Production (Vercel):** PostgreSQL (hosted database)

### Why Different Databases?
- SQLite is easy for local development (just a file)
- Vercel's filesystem is temporary, so we need PostgreSQL for production
- SQLAlchemy handles both automatically!

### Database Tables:

```mermaid
erDiagram
    USER ||--o{ SCAN : "has many"
    USER ||--o{ SCHEDULED_TARGET : "has many"
    SCAN ||--o{ FINDING : "has many"

    USER {
        int id PK
        string email UK
        string password_hash
        datetime created_at
    }

    SCAN {
        int id PK
        int user_id FK
        string target_url
        string status
        boolean consent_confirmed
        float risk_score
        string risk_level
        datetime started_at
        datetime finished_at
        int duration_ms
        text meta_json
        text diff_summary_json
    }

    FINDING {
        int id PK
        int scan_id FK
        string category
        string title
        string severity
        int severity_rank
        text description
        text evidence
        text recommendation
        text cve_refs
        text code_snippet
        string code_snippet_label
        string confidence
    }

    SCHEDULED_TARGET {
        int id PK
        int user_id FK
        string target_url
        string frequency
        boolean notify_email
        boolean active
        datetime last_run_at
        datetime created_at
    }
```

### Table Explanations:

#### 1. USER Table
Stores user account information.

| Column | Type | Purpose |
|--------|------|---------|
| `id` | Integer | Unique ID for each user |
| `email` | String | User's email (must be unique) |
| `password_hash` | String | Encrypted password (never store plain text!) |
| `created_at` | DateTime | When the account was created |

**Code Example:**
```python
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)

    def set_password(self, password):
        # This uses Werkzeug to hash passwords securely
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        # This checks if the password matches the hash
        return check_password_hash(self.password_hash, password)
```

#### 2. SCAN Table
Stores information about each security scan.

| Column | Type | Purpose |
|--------|------|---------|
| `id` | Integer | Unique scan ID |
| `user_id` | Integer | Who ran this scan (NULL for anonymous scans) |
| `target_url` | String | The website that was scanned |
| `status` | String | "running", "completed", or "failed" |
| `consent_confirmed` | Boolean | Did user confirm they own the target? |
| `risk_score` | Float | Overall risk score (0-100) |
| `risk_level` | String | "critical", "high", "medium", "low", "info" |
| `started_at` | DateTime | When the scan started |
| `finished_at` | DateTime | When the scan finished |
| `duration_ms` | Integer | How long the scan took (milliseconds) |
| `meta_json` | Text | Extra metadata (JSON format) |
| `diff_summary_json` | Text | Comparison with previous scan (JSON) |

**Code Example:**
```python
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    target_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default="running")
    risk_score = db.Column(db.Float, default=0.0)
    risk_level = db.Column(db.String(20), default="info")

    # These properties convert JSON to Python objects automatically
    @property
    def meta(self):
        return json.loads(self.meta_json) if self.meta_json else {}

    @meta.setter
    def meta(self, value):
        self.meta_json = json.dumps(value)
```

#### 3. FINDING Table
Stores each security problem found during a scan.

| Column | Type | Purpose |
|--------|------|---------|
| `id` | Integer | Unique finding ID |
| `scan_id` | Integer | Which scan found this? |
| `category` | String | Type of finding (http_headers, tls, etc.) |
| `title` | String | Short description of the problem |
| `severity` | String | "critical", "high", "medium", "low", "info" |
| `severity_rank` | Integer | For sorting (0=critical, 4=info) |
| `description` | Text | Detailed explanation |
| `evidence` | Text | What was actually found |
| `recommendation` | Text | How to fix it |
| `cve_refs` | Text | Related CVE numbers (JSON) |
| `code_snippet` | Text | Example fix code |
| `confidence` | String | How sure are we? (high/medium/low) |

**Code Example:**
```python
class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=False, index=True)
    category = db.Column(db.String(50))
    title = db.Column(db.String(255))
    severity = db.Column(db.String(20))
    description = db.Column(db.Text)
    evidence = db.Column(db.Text)
    recommendation = db.Column(db.Text)
```

#### 4. SCHEDULED_TARGET Table
Stores automatic scan schedules.

| Column | Type | Purpose |
|--------|------|---------|
| `id` | Integer | Unique schedule ID |
| `user_id` | Integer | Who owns this schedule? |
| `target_url` | String | Website to scan automatically |
| `frequency` | String | "daily" or "weekly" |
| `notify_email` | Boolean | Send email when scan completes? |
| `active` | Boolean | Is this schedule currently active? |
| `last_run_at` | DateTime | When was the last scan? |
| `created_at` | DateTime | When was this schedule created? |

### How Data Flows:

```
User clicks "Scan"
    ↓
Orchestrator creates Scan record (status: "running")
    ↓
Scanner modules find vulnerabilities
    ↓
Findings are created and linked to Scan
    ↓
Risk score is calculated
    ↓
Scan record updated (status: "completed", risk_score: X)
    ↓
User sees results on dashboard
```

---

## Project Structure

```
security-scanner/
│
├── app.py                      # Main Flask application entry point
├── config.py                   # Configuration settings (from .env)
├── models.py                   # Database models (User, Scan, Finding, etc.)
├── extensions.py              # Database and login manager setup
├── forms.py                    # WTForms for login/signup
├── scan_service.py            # Saves scan results to database
├── notifications.py            # Email notifications for scheduled scans
├── ai_assistant.py            # Optional AI feature (Anthropic API)
├── time_utils.py               # Helper for UTC timestamps
│
├── scanner/                    # Security scanning modules
│   ├── __init__.py
│   ├── orchestrator.py        # Runs all scanner modules
│   ├── http_headers.py        # Checks HTTP security headers
│   ├── ssl_check.py           # Checks SSL/TLS certificates
│   ├── port_scan.py           # Scans for open ports
│   ├── misconfig.py           # Checks common misconfigurations
│   ├── token_entropy.py       # Checks session token randomness
│   ├── access_control.py      # Checks admin paths access
│   ├── active_probes.py       # SQL injection & XSS testing
│   ├── cve_lookup.py          # Looks up known vulnerabilities
│   ├── dns_security.py        # Checks DNS security (CAA, SPF, DMARC)
│   ├── ct_monitor.py          # Certificate Transparency logs
│   ├── frontend_deps.py       # Checks third-party JavaScript
│   ├── scan_integrity.py      # Detects bot challenges
│   ├── correlation.py         # Combines findings into chains
│   ├── remediation.py         # Generates fix code snippets
│   └── risk_score.py          # Calculates overall risk score
│
├── routes/                     # Flask routes (URL handlers)
│   ├── __init__.py
│   ├── main.py                # Homepage, dashboard, history
│   ├── auth.py                # Login, signup, logout
│   ├── scan.py                # Scan API, reports, schedules
│   └── cron.py                # Vercel cron job endpoint
│
├── reports/                    # Report generation
│   ├── __init__.py
│   ├── pdf_report.py          # Generates PDF reports
│   ├── csv_report.py          # Generates CSV reports
│   └── sarif_report.py        # Generates SARIF reports
│
├── templates/                  # HTML templates (Jinja2)
│   ├── base.html              # Base template with header/footer
│   ├── index.html             # Homepage
│   ├── dashboard.html         # Scan results dashboard
│   ├── history.html           # Scan history page
│   ├── login.html             # Login page
│   ├── signup.html            # Signup page
│   └── error.html             # Error pages (404, 500)
│
├── public/                     # Static files (CSS, JS, images)
│   ├── style.css              # Main stylesheet
│   ├── main.js                # Frontend JavaScript
│   └── favicon.svg            # Website icon
│
├── tests/                      # Test suite (pytest)
│   ├── conftest.py            # Test configuration
│   ├── test_app.py            # Flask app tests
│   ├── test_scanner_units.py  # Scanner module tests
│   ├── test_full_flow.py      # End-to-end scan test
│   └── ... (more test files)
│
├── instance/                   # Local SQLite database (dev only)
│   └── dev.db                 # Database file
│
├── .env                        # Environment variables (local)
├── .env.example               # Example environment variables
├── .gitignore                  # Files to ignore in git
├── .python-version             # Python version (3.12)
├── pyproject.toml             # Vercel Python build config
├── requirements.txt           # Python dependencies
├── pytest.ini                 # Pytest configuration
├── vercel.json                # Vercel deployment config
├── README.md                  # Project documentation
├── DESIGN_NOTES.md            # Design decisions
└── PROJECT_DOCUMENTATION.md   # This file
```

---

## How the Scanner Works

The scanner is the heart of this application. It runs multiple security checks on a target website.

### Scanner Architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                    ORCHESTRATOR                              │
│  (scanner/orchestrator.py)                                  │
│                                                              │
│  1. Creates ScanContext (URL, timeout, session)            │
│  2. Fetches homepage (checks for bot challenges)            │
│  3. Runs all scanner modules in parallel                    │
│  4. Collects all findings                                   │
│  5. Applies remediation suggestions                          │
│  6. Correlates findings into attack chains                   │
│  7. Calculates risk score                                   │
│  8. Returns complete result                                  │
└─────────────────────────────────────────────────────────────┘
                          │
         ┌────────────────┼────────────────┐
         │                │                │
         ▼                ▼                ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   Module 1   │  │   Module 2   │  │   Module 3   │
│ http_headers │  │  ssl_check   │  │  port_scan   │
└──────────────┘  └──────────────┘  └──────────────┘
         │                │                │
         └────────────────┼────────────────┘
                          │
                          ▼
              ┌──────────────────────┐
              │    All Findings      │
              └──────────────────────┘
```

### Scanner Modules Explained:

#### 1. http_headers.py
Checks HTTP security headers.

**What it checks:**
- **HSTS (Strict-Transport-Security):** Forces HTTPS
- **CSP (Content-Security-Policy):** Controls where scripts can load from
- **X-Content-Type-Options:** Prevents MIME sniffing
- **X-Frame-Options:** Prevents clickjacking
- **Referrer-Policy:** Controls what info is sent to other sites
- **Permissions-Policy:** Disables camera, microphone, etc.

**Code Example:**
```python
def check(ctx):
    findings = []
    resp = ctx.homepage_response
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    # Check if HSTS header is missing
    if "strict-transport-security" not in headers_lower:
        findings.append({
            "category": "http_headers",
            "title": "Missing Strict-Transport-Security (HSTS) header",
            "severity": "high",
            "description": "Without HSTS, browsers try HTTP first...",
            "recommendation": "Add: Strict-Transport-Security: max-age=63072000"
        })

    return findings
```

#### 2. ssl_check.py
Checks SSL/TLS certificate and protocol.

**What it checks:**
- Is the site using HTTPS?
- Is the certificate valid (not expired, trusted CA)?
- Is the TLS protocol modern (not SSLv3 or TLS 1.0)?
- Is the cipher suite strong enough?
- Will the certificate expire soon?

**Code Example:**
```python
def check(ctx):
    findings = []
    hostname = ctx.hostname
    port = 443

    # Create SSL context and connect
    ctx_ssl = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=ctx.timeout) as sock:
        with ctx_ssl.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            cert = tls_sock.getpeercert()
            protocol = tls_sock.version()

    # Check if protocol is weak
    if protocol in WEAK_PROTOCOLS:
        findings.append({
            "category": "tls",
            "title": f"Outdated TLS protocol negotiated ({protocol})",
            "severity": "high",
            "recommendation": "Disable SSLv3/TLSv1.0, require TLS 1.2+"
        })

    return findings
```

#### 3. port_scan.py
Scans for open ports on the server.

**What it does:**
- Tries to connect to common ports (21, 22, 80, 443, 3306, etc.)
- Reports which ports are open
- Checks if ports that should be closed are open

**Why it matters:**
- Open ports can be entry points for attackers
- Database ports (3306, 5432) should not be public
- SSH (22) should be restricted

#### 4. misconfig.py
Checks for common misconfigurations.

**What it checks:**
- Cookie flags (Secure, HttpOnly, SameSite)
- CORS misconfiguration
- Directory listing enabled
- Exposed .git, .env, backup files
- Verbose error messages showing stack traces

#### 5. token_entropy.py
Checks session token randomness.

**What it does:**
- Measures Shannon entropy of session cookies
- Low entropy = predictable tokens = easy to guess
- Uses formula: `-p * log2(p)` for each character

**Why it matters:**
- Predictable session tokens can be stolen
- High entropy = secure tokens

#### 6. access_control.py
Checks for exposed admin paths.

**What it checks:**
- `/admin` - Admin panel
- `/phpMyAdmin` - Database admin
- `/actuator` - Spring Boot admin
- `/wp-admin` - WordPress admin
- And more...

**Why it matters:**
- Admin panels should be protected by authentication
- Public admin panels are huge security risks

#### 7. active_probes.py
Tests for SQL injection and XSS.

**What it does:**
- Sends test payloads to input fields
- Checks if the response contains error messages
- Checks for timing anomalies (time-based SQLi)
- Reports confidence levels (high/medium/low)

**Important:** Only runs if user consents to active testing.

#### 8. dns_security.py
Checks DNS security settings.

**What it checks:**
- **CAA:** Certificate Authority Authorization
- **DNSSEC:** DNS Security Extensions
- **SPF:** Sender Policy Framework (email spoofing protection)
- **DMARC:** Domain-based Message Authentication
- **Dangling CNAME:** Subdomain takeover risk

#### 9. ct_monitor.py
Checks Certificate Transparency logs.

**What it does:**
- Queries crt.sh for certificates issued for the domain
- Finds forgotten/shadow subdomains
- Detects unusually broad CA issuance

#### 10. frontend_deps.py
Checks third-party JavaScript.

**What it checks:**
- Missing Subresource Integrity (SRI) on scripts
- Outdated JavaScript libraries
- Known vulnerable library versions

#### 11. correlation.py
Combines findings into attack chains.

**What it does:**
- Detects when multiple findings combine into something worse
- Example: XSS + no CSP + non-HttpOnly cookie = session hijack
- Creates "chain" findings with full reasoning

#### 12. risk_score.py
Calculates overall risk score.

**Formula:**
```
Risk Score = (Critical × 25) + (High × 15) + (Medium × 8) + (Low × 3)

Risk Levels:
- 0-20: info
- 21-40: low
- 41-60: medium
- 61-80: high
- 81-100: critical
```

### How Findings Are Created:

```python
# Example finding structure
finding = {
    "category": "http_headers",
    "title": "Missing Strict-Transport-Security (HSTS) header",
    "severity": "high",
    "description": "Without HSTS, browsers try HTTP first...",
    "evidence": "No 'strict-transport-security' header on response",
    "recommendation": "Add: Strict-Transport-Security: max-age=63072000",
    "code_snippet": "# Nginx config\nadd_header Strict-Transport-Security ...",
    "code_snippet_label": "Nginx",
    "confidence": "high"
}
```

---

## Flask Framework

Flask is a Python web framework used to build this application.

### What is Flask?

Flask is a "micro-framework" - it's lightweight but powerful. It handles:
- HTTP requests and responses
- URL routing (which function handles which URL)
- Template rendering (HTML pages)
- Database connections
- User sessions and authentication

### How Flask Works in This Project:

```
┌─────────────────────────────────────────────────────────────┐
│                     BROWSER                                  │
│  User visits: http://localhost:5000/                        │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    FLASK APP (app.py)                        │
│                                                              │
│  @app.route("/")                                            │
│  def index():                                               │
│      return render_template("index.html")                   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                 TEMPLATE (index.html)                       │
│  Rendered HTML is sent back to browser                       │
└─────────────────────────────────────────────────────────────┘
```

### Flask Components Used:

#### 1. Blueprints
Blueprints organize routes into logical groups.

```python
# routes/main.py
main_bp = Blueprint("main", __name__)

@main_bp.route("/")
def index():
    return render_template("index.html")

# In app.py
app.register_blueprint(main_bp)
```

#### 2. Flask-SQLAlchemy
Handles database operations.

```python
from extensions import db
from models import User

# Create a user
user = User(email="test@example.com")
user.set_password("password123")
db.session.add(user)
db.session.commit()

# Query users
users = User.query.all()
user = User.query.filter_by(email="test@example.com").first()
```

#### 3. Flask-Login
Handles user authentication.

```python
from flask_login import login_user, logout_user, login_required

# Login a user
login_user(user)

# Protect a route (requires login)
@app.route("/dashboard")
@login_required
def dashboard():
    return "Dashboard"

# Logout
logout_user()
```

#### 4. Flask-WTF
Handles form validation and CSRF protection.

```python
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField

class LoginForm(FlaskForm):
    email = StringField("Email")
    password = PasswordField("Password")
    submit = SubmitField("Login")

# In route
form = LoginForm()
if form.validate_on_submit():
    # Process the form
```

#### 5. Server-Sent Events (SSE)
For real-time scan progress updates.

```python
@scan_bp.route("/scan/stream")
def scan_stream():
    def generate():
        for event in run_scan_streaming(target_url, consent, Config):
            yield f"data: {json.dumps(event)}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")
```

### Flask Request Lifecycle:

```
1. Browser sends HTTP request
   ↓
2. Flask receives request
   ↓
3. Flask finds matching route
   ↓
4. Route function executes
   ↓
5. Function may query database
   ↓
6. Function renders template
   ↓
7. Flask sends HTTP response
   ↓
8. Browser displays response
```

---

## Environment Variables (.env)

Environment variables are configuration settings that change based on where the app runs (local vs production).

### What is .env?

The `.env` file is a text file that stores configuration in key-value pairs.

**⚠️ Important:** Never commit `.env` to git! It contains secrets.

### Example .env File:

```bash
# Required
SECRET_KEY=change-me-to-a-long-random-string

# Database
DATABASE_URL=sqlite:///dev.db

# Optional: AI assistant
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-sonnet-5

# Optional: Cron job protection
CRON_SECRET=

# Optional: Email notifications
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
MAIL_FROM=scanner@example.com

# Optional: NVD API for CVE lookup
NVD_API_KEY=
```

### How It Works:

1. **python-dotenv** library loads the `.env` file
2. Values are read into `os.environ`
3. `config.py` reads from `os.environ`
4. Flask uses these values at runtime

### Code Example:

```python
# config.py
import os

def _env(name: str, default=None):
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip()

class Config:
    SECRET_KEY = _env("SECRET_KEY")
    DATABASE_URL = _env("DATABASE_URL")
    ANTHROPIC_API_KEY = _env("ANTHROPIC_API_KEY")
```

### Environment Variables Explained:

| Variable | Required | Purpose |
|----------|----------|---------|
| `SECRET_KEY` | ✅ Yes | Encrypts session cookies (must be random!) |
| `DATABASE_URL` | Optional | Database connection string (defaults to SQLite) |
| `ANTHROPIC_API_KEY` | Optional | For AI assistant feature |
| `CRON_SECRET` | Optional | Protects cron job endpoint |
| `SMTP_HOST` | Optional | Email server for notifications |
| `SMTP_PORT` | Optional | Email server port (usually 587) |
| `SMTP_USER` | Optional | Email username |
| `SMTP_PASSWORD` | Optional | Email password |
| `MAIL_FROM` | Optional | Sender email address |
| `NVD_API_KEY` | Optional | For CVE lookup (higher rate limit) |

### Why Use Environment Variables?

✅ **Security:** Secrets are not in code
✅ **Flexibility:** Different settings for local vs production
✅ **Portability:** Same code works anywhere
✅ **Git Safety:** `.env` is in `.gitignore`

---

## Virtual Environment (venv)

A virtual environment is an isolated Python environment for a specific project.

### What is venv?

Python's `venv` is a tool that creates a self-contained Python environment. Each project can have its own dependencies without conflicts.

### Why Use venv?

**Without venv:**
```
System Python (global)
├── Flask 3.0
├── Requests 2.31
└── (all other projects share these)
```

**With venv:**
```
Project A/.venv/
├── Flask 3.0
└── Requests 2.31

Project B/.venv/
├── Flask 2.0
└── Requests 2.28
```

### How to Create venv:

```bash
# Create virtual environment
python -m venv .venv

# Activate on Linux/Mac
source .venv/bin/activate

# Activate on Windows
.venv\Scripts\activate

# Deactivate
deactivate
```

### How venv Works:

```
System Python
    │
    ├── .venv/bin/python (copy of Python)
    │
    ├── .venv/lib/python3.12/site-packages/
    │   ├── Flask/
    │   ├── Requests/
    │   └── (all installed packages)
    │
    └── When activated:
        - Commands use .venv/bin/python
        - Imports use .venv/lib/... packages
```

### Installing Dependencies:

```bash
# After activating venv
pip install -r requirements.txt

# This installs packages into .venv, not system Python
```

### venv Structure:

```
.venv/
├── bin/                    # Executables (python, pip, etc.)
│   ├── python              # Python interpreter
│   ├── pip                 # Package installer
│   └── activate            # Activation script
├── lib/                    # Installed packages
│   └── python3.12/
│       └── site-packages/
│           ├── Flask/
│           ├── Requests/
│           └── ...
├── include/                # C headers
└── pyvenv.cfg              # Configuration
```

### Why .venv is in .gitignore:

```gitignore
.venv/
```

**Reasons:**
- It's large (hundreds of MB)
- It's system-specific (won't work on other computers)
- It can be regenerated: `pip install -r requirements.txt`
- Different for Windows vs Linux vs Mac

---

## Deployment on Vercel

Vercel is a cloud platform that hosts web applications. This project is designed to deploy easily on Vercel.

### What is Vercel?

Vercel is a platform for deploying frontend and serverless applications. It:
- Automatically builds and deploys from GitHub
- Provides HTTPS and CDN
- Handles serverless functions
- Supports Python via their Python runtime

### Deployment Architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                      GITHUB                                  │
│  Code repository                                            │
└──────────────────────┬──────────────────────────────────────┘
                       │ Push
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                      VERCEL                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Build Phase                                           │  │
│  │  - Installs dependencies from pyproject.toml          │  │
│  │  - Creates a serverless function package             │  │
│  └──────────────────────────────────────────────────────┘  │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Deployment Phase                                     │  │
│  │  - Deploys to edge network                            │  │
│  │  - Assigns URL (e.g., scanner.vercel.app)             │  │
│  │  - Sets up SSL certificate                           │  │
│  └──────────────────────────────────────────────────────┘  │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    USER BROWSER                              │
│  Visits: https://scanner.vercel.app                         │
└─────────────────────────────────────────────────────────────┘
```

### Vercel Configuration Files:

#### 1. pyproject.toml
Tells Vercel how to build the Python app.

```toml
[project]
name = "security-scanner"
version = "1.0.0"
requires-python = ">=3.12"
dependencies = [
    "Flask>=3.0,<4.0",
    "Flask-SQLAlchemy>=3.1,<4.0",
    # ... more dependencies
]

[tool.vercel]
entrypoint = "app:app"  # This tells Vercel to import app from app.py
```

#### 2. vercel.json
Configures Vercel-specific settings.

```json
{
  "$schema": "https://openapi.vercel.sh/vercel.json",
  "crons": [
    { "path": "/api/cron/scheduled-scans", "schedule": "0 0 * * *" }
  ]
}
```

This sets up a cron job that runs daily at midnight.

### Database on Vercel:

**Problem:** Vercel's filesystem is temporary. SQLite won't persist between requests.

**Solution:** Use a hosted PostgreSQL database.

```bash
# In Vercel dashboard, set DATABASE_URL:
DATABASE_URL=postgresql://user:pass@host/dbname
```

The app automatically:
- Detects it's on Vercel (via `VERCEL=1` env var)
- Uses PostgreSQL instead of SQLite
- Creates tables on first request

### Deploying to Vercel:

#### Step 1: Push to GitHub
```bash
git add .
git commit -m "Ready for deployment"
git push origin main
```

#### Step 2: Import in Vercel
1. Go to vercel.com/new
2. Import your GitHub repository
3. Vercel detects Flask automatically
4. Click "Deploy"

#### Step 3: Set Environment Variables
In Vercel Project Settings → Environment Variables:
- `SECRET_KEY` (required)
- `DATABASE_URL` (required - use Postgres)
- `ANTHROPIC_API_KEY` (optional)
- `CRON_SECRET` (optional)
- SMTP settings (optional)

#### Step 4: Redeploy
After setting variables, click "Redeploy"

### Vercel vs Local:

| Feature | Local | Vercel |
|---------|-------|--------|
| Database | SQLite (file) | PostgreSQL (hosted) |
| Filesystem | Persistent | Temporary (/tmp only) |
| URL | http://localhost:5000 | https://your-app.vercel.app |
| SSL | Self-signed or HTTP | Automatic HTTPS |
| Cron Jobs | Manual or system cron | Vercel Cron |
| Scaling | Single machine | Auto-scaling serverless |

### Vercel Limitations:

- Free tier: 100GB bandwidth/month
- Serverless functions: 10-60 seconds timeout
- Hobby plan: 1 cron job (this project uses 1)
- Database: Must use hosted Postgres (not SQLite)

---

## File-by-File Explanation

### Root Directory Files

#### app.py
**Purpose:** Main Flask application entry point.

**What it does:**
- Creates the Flask app
- Configures database
- Registers blueprints (routes)
- Sets up security headers
- Handles errors (404, 500)

**Key Code:**
```python
def create_app():
    app = Flask(__name__, static_folder="public", static_url_path="")
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Register blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(cron_bp)

    # Create database tables
    with app.app_context():
        db.create_all()

    return app

app = create_app()
```

#### config.py
**Purpose:** Reads configuration from environment variables.

**What it does:**
- Reads `.env` file
- Provides defaults for missing values
- Handles database URL conversion
- Sets safety limits for scanner

**Key Code:**
```python
class Config:
    SECRET_KEY = _secret_key()
    SQLALCHEMY_DATABASE_URI = _database_url()
    ANTHROPIC_API_KEY = _env("ANTHROPIC_API_KEY")
    SMTP_HOST = _env("SMTP_HOST")

    # Safety limits
    HTTP_TIMEOUT_SECONDS = 8.0
    PORT_SCAN_TIMEOUT_SECONDS = 0.75
    PORT_SCAN_MAX_WORKERS = 12
```

#### models.py
**Purpose:** Defines database tables.

**What it does:**
- Defines User, Scan, Finding, ScheduledTarget models
- Handles password hashing
- Provides helper methods

**Key Code:**
```python
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
```

#### extensions.py
**Purpose:** Creates database and login manager instances.

**What it does:**
- Creates SQLAlchemy `db` object
- Creates Flask-Login `login_manager` object
- Creates CSRF protection object

**Key Code:**
```python
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
```

#### forms.py
**Purpose:** Defines login and signup forms.

**What it does:**
- Validates user input
- Provides CSRF protection
- Handles email format validation

**Key Code:**
```python
class SignupForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    confirm = PasswordField("Confirm", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Sign Up")
```

#### scan_service.py
**Purpose:** Saves scan results to database.

**What it does:**
- Creates Scan record
- Creates Finding records
- Links findings to scan
- Calculates diff with previous scan

**Key Code:**
```python
def persist_scan(result_dict, user_id=None, consent=False):
    scan = Scan(
        user_id=user_id,
        target_url=result_dict["target_url"],
        risk_score=result_dict["risk_score"],
        risk_level=result_dict["risk_level"],
        status="completed"
    )
    db.session.add(scan)
    db.session.commit()

    for finding_dict in result_dict["findings"]:
        finding = Finding(scan_id=scan.id, **finding_dict)
        db.session.add(finding)

    db.session.commit()
    return scan
```

#### notifications.py
**Purpose:** Sends email notifications for scheduled scans.

**What it does:**
- Connects to SMTP server
- Sends email with scan results
- Handles errors gracefully

**Key Code:**
```python
def send_scan_email(scan, to_email):
    msg = MIMEMultipart()
    msg["From"] = Config.MAIL_FROM
    msg["To"] = to_email
    msg["Subject"] = f"Scan completed for {scan.target_url}"

    body = f"Risk Score: {scan.risk_score}/100 ({scan.risk_level})"
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT) as server:
        server.starttls()
        server.login(Config.SMTP_USER, Config.SMTP_PASSWORD)
        server.send_message(msg)
```

#### ai_assistant.py
**Purpose:** Optional AI feature to explain findings.

**What it does:**
- Calls Anthropic API
- Sends scan findings as context
- Returns plain-English explanations

**Key Code:**
```python
def ask_about_scan(scan, question: str):
    user_message = f"{_findings_context(scan)}\n\nQuestion: {question}"

    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": Config.ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
        },
        json={
            "model": Config.ANTHROPIC_MODEL,
            "messages": [{"role": "user", "content": user_message}],
        }
    )
    return response.json()["content"][0]["text"]
```

#### time_utils.py
**Purpose:** Helper for UTC timestamps.

**What it does:**
- Returns current UTC time
- Avoids deprecated `datetime.utcnow()`

**Key Code:**
```python
def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
```

### scanner/ Directory

#### scanner/orchestrator.py
**Purpose:** Runs all scanner modules.

**What it does:**
- Creates scan context
- Fetches homepage
- Runs all modules in parallel
- Collects findings
- Applies remediation
- Correlates findings
- Calculates risk score

**Key Code:**
```python
def run_scan_streaming(target_url: str, allow_active_probes: bool, config):
    ctx = ScanContext(target_url, allow_active_probes, config)
    ctx.fetch_homepage()

    findings = []
    with ThreadPoolExecutor(max_workers=len(CHECK_MODULES)) as pool:
        future_to_module = {pool.submit(module.check, ctx): module for module in CHECK_MODULES}
        for future in as_completed(future_to_module):
            findings.extend(future.result())

    findings = remediation.apply(findings, ctx)
    chain_findings = correlation.correlate(findings)
    findings.extend(chain_findings)

    score, level = risk_score.compute(findings)
    return {"findings": findings, "risk_score": score, "risk_level": level}
```

#### scanner/http_headers.py
**Purpose:** Checks HTTP security headers.

**What it does:**
- Checks for HSTS, CSP, X-Frame-Options, etc.
- Checks for information disclosure headers
- Reports missing headers

#### scanner/ssl_check.py
**Purpose:** Checks SSL/TLS configuration.

**What it does:**
- Opens TLS handshake
- Checks certificate validity
- Checks protocol version
- Checks cipher strength

#### scanner/port_scan.py
**Purpose:** Scans for open ports.

**What it does:**
- Tries to connect to common ports
- Reports open ports
- Uses timeouts to avoid hanging

#### scanner/misconfig.py
**Purpose:** Checks common misconfigurations.

**What it does:**
- Checks cookie flags
- Checks CORS settings
- Checks for exposed files
- Checks for verbose errors

#### scanner/token_entropy.py
**Purpose:** Checks session token randomness.

**What it does:**
- Calculates Shannon entropy
- Flags low-entropy tokens
- Uses statistical analysis

#### scanner/access_control.py
**Purpose:** Checks admin path access.

**What it does:**
- Probes common admin paths
- Checks if they're accessible without auth
- Reports exposed admin panels

#### scanner/active_probes.py
**Purpose:** Tests for SQL injection and XSS.

**What it does:**
- Sends test payloads
- Checks for error messages
- Checks for timing anomalies
- Only runs with consent

#### scanner/cve_lookup.py
**Purpose:** Looks up known vulnerabilities.

**What it does:**
- Queries NVD API
- Matches detected software versions
- Returns CVE references

#### scanner/dns_security.py
**Purpose:** Checks DNS security.

**What it does:**
- Checks CAA records
- Checks DNSSEC
- Checks SPF and DMARC
- Checks for dangling CNAMEs

#### scanner/ct_monitor.py
**Purpose:** Checks Certificate Transparency logs.

**What it does:**
- Queries crt.sh
- Finds issued certificates
- Detects shadow subdomains

#### scanner/frontend_deps.py
**Purpose:** Checks third-party JavaScript.

**What it does:**
- Checks for SRI on scripts
- Checks library versions
- Detects outdated libraries

#### scanner/scan_integrity.py
**Purpose:** Detects bot challenges.

**What it does:**
- Detects interstitial pages
- Checks for consent walls
- Handles retries

#### scanner/correlation.py
**Purpose:** Combines findings into chains.

**What it does:**
- Detects attack chains
- Combines related findings
- Reports composite risks

#### scanner/remediation.py
**Purpose:** Generates fix code snippets.

**What it does:**
- Adds code snippets to findings
- Supports multiple frameworks
- Provides copy-paste fixes

#### scanner/risk_score.py
**Purpose:** Calculates overall risk score.

**What it does:**
- Weights findings by severity
- Returns 0-100 score
- Returns risk level string

### routes/ Directory

#### routes/main.py
**Purpose:** Main page routes.

**What it does:**
- Serves homepage
- Serves dashboard
- Serves history page

**Key Code:**
```python
@main_bp.route("/")
def index():
    return render_template("index.html")

@main_bp.route("/dashboard/<int:scan_id>")
def dashboard(scan_id):
    scan = db.get_or_404(Scan, scan_id)
    return render_template("dashboard.html", scan=scan)
```

#### routes/auth.py
**Purpose:** Authentication routes.

**What it does:**
- Handles signup
- Handles login
- Handles logout

**Key Code:**
```python
@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        user = User(email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for("main.index"))
    return render_template("signup.html", form=form)
```

#### routes/scan.py
**Purpose:** Scan API routes.

**What it does:**
- Scan streaming endpoint (SSE)
- Report download endpoints (PDF, CSV, SARIF)
- AI assistant endpoint
- Schedule management endpoints

**Key Code:**
```python
@scan_bp.route("/scan/stream")
def scan_stream():
    def generate():
        for event in run_scan_streaming(target_url, consent, Config):
            yield f"data: {json.dumps(event)}\n\n"
    return Response(stream_with_context(generate()), mimetype="text/event-stream")
```

#### routes/cron.py
**Purpose:** Vercel cron job endpoint.

**What it does:**
- Runs scheduled scans
- Protected by CRON_SECRET
- Sends email notifications

### reports/ Directory

#### reports/pdf_report.py
**Purpose:** Generates PDF reports.

**What it does:**
- Uses reportlab library
- Creates formatted PDF
- Includes all findings

#### reports/csv_report.py
**Purpose:** Generates CSV reports.

**What it does:**
- Creates CSV file
- Includes findings as rows
- Easy to import into Excel

#### reports/sarif_report.py
**Purpose:** Generates SARIF reports.

**What it does:**
- SARIF = Static Analysis Results Interchange Format
- Used by GitHub Code Scanning
- Integrates with CI/CD

### templates/ Directory

#### templates/base.html
**Purpose:** Base template with header/footer.

**What it does:**
- Includes CSS/JS
- Provides common layout
- Shows flash messages

#### templates/index.html
**Purpose:** Homepage.

**What it does:**
- URL input form
- Authorization checkbox
- Start scan button

#### templates/dashboard.html
**Purpose:** Scan results dashboard.

**What it does:**
- Shows risk score
- Lists all findings
- Provides download buttons
- AI assistant chat (if enabled)

#### templates/history.html
**Purpose:** Scan history page.

**What it does:**
- Lists past scans
- Shows scheduled scans
- Allows viewing past results

#### templates/login.html & signup.html
**Purpose:** Authentication pages.

**What it does:**
- Login/signup forms
- Error messages
- Links to other auth pages

### public/ Directory

#### public/style.css
**Purpose:** Main stylesheet.

**What it does:**
- Styles all pages
- Responsive design
- Dark/light theme

#### public/main.js
**Purpose:** Frontend JavaScript.

**What it does:**
- Handles scan form submission
- Connects to SSE endpoint
- Updates progress in real-time
- Handles AI assistant chat

#### public/favicon.svg
**Purpose:** Website icon.

### tests/ Directory

#### tests/conftest.py
**Purpose:** Test configuration.

**What it does:**
- Sets up test database
- Creates test client
- Provides fixtures

#### tests/test_app.py
**Purpose:** Flask app tests.

**What it does:**
- Tests routes
- Tests authentication
- Tests database operations

#### tests/test_scanner_units.py
**Purpose:** Scanner module tests.

**What it does:**
- Tests each scanner module
- Uses mock responses
- Validates findings

#### tests/test_full_flow.py
**Purpose:** End-to-end test.

**What it does:**
- Runs real scan against test server
- Validates all findings
- Tests complete pipeline

---

## Summary

This project is a complete web-based security scanner built with Flask. It:

✅ **Checks websites for security problems** using multiple scanner modules
✅ **Stores results in a database** (SQLite locally, PostgreSQL on Vercel)
✅ **Provides a nice web interface** with real-time progress
✅ **Generates reports** in PDF, CSV, and SARIF formats
✅ **Supports user accounts** with login/signup
✅ **Can run automatically** via scheduled scans
✅ **Can explain findings** using AI (optional)
✅ **Deploys easily** to Vercel with zero configuration

The code is well-organized, tested, and documented. It follows security best practices and is suitable for learning or production use.

---

## Quick Start Guide

### Local Development:

```bash
# 1. Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set up environment
cp .env.example .env
# Edit .env and set SECRET_KEY

# 4. Run the app
python app.py

# 5. Open browser
# Go to http://localhost:5000
```

### Vercel Deployment:

```bash
# 1. Push to GitHub
git add .
git commit -m "Deploy to Vercel"
git push origin main

# 2. Import in Vercel
# Go to vercel.com/new and import your repo

# 3. Set environment variables
# In Vercel dashboard: SECRET_KEY, DATABASE_URL

# 4. Deploy
# Vercel will build and deploy automatically
```

---

## Important Notes

⚠️ **Authorized Use Only:** Only scan websites you own or have permission to test.

⚠️ **Security:** Never commit `.env` to git. Keep your secrets safe.

⚠️ **Database:** On Vercel, use PostgreSQL. SQLite won't persist.

⚠️ **Time Limits:** Serverless functions have timeouts. Keep scans fast.

⚠️ **Rate Limits:** Don't abuse the scanner. It's for testing, not attacking.

---

## Need Help?

- Check the README.md for more details
- Check DESIGN_NOTES.md for design decisions
- Run tests: `pytest -v`
- Check logs in Vercel dashboard

---

**End of Documentation**
