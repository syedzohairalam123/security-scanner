# Perimeter - Complete Features List
## All Features Explained with Purpose

---

## 📋 Table of Contents
1. [Core Features](#core-features)
2. [Security Scanning Features](#security-scanning-features)
3. [User Management Features](#user-management-features)
4. [Report Generation Features](#report-generation-features)
5. [Advanced Features](#advanced-features)
6. [Technical Features](#technical-features)
7. [Deployment Features](#deployment-features)

---

## Core Features

### 1. Homepage with URL Input
**What it does:**
- Provides a clean interface to enter a website URL
- Shows authorization checkbox (user must confirm they own the target)
- Has a "Start Scan" button to begin scanning

**Why it's used:**
- Makes it easy for users to start a scan
- Ensures legal compliance by requiring authorization confirmation
- Provides a professional, user-friendly entry point

**Files involved:**
- `templates/index.html` - Homepage UI
- `public/main.js` - Form handling
- `routes/main.py` - Route handler

---

### 2. Real-Time Scan Progress (Server-Sent Events)
**What it does:**
- Shows live progress updates while scanning
- Displays which module is currently running
- Shows number of findings found so far
- Updates without page refresh

**Why it's used:**
- Security scans can take time (10-30 seconds)
- Users need to know the scan is working
- Better user experience than a loading spinner
- Allows users to see which checks are running

**Files involved:**
- `routes/scan.py` - SSE endpoint
- `scanner/orchestrator.py` - Progress streaming
- `public/main.js` - EventSource client
- `templates/dashboard.html` - Progress display

---

### 3. Risk Score & Risk Level
**What it does:**
- Calculates an overall risk score (0-100)
- Shows risk level: critical, high, medium, low, info
- Displays severity distribution (how many findings of each type)
- Shows risk meter on dashboard

**Why it's used:**
- Helps users quickly understand how serious the problems are
- Prioritizes which issues to fix first
- Makes it easy to compare scans over time
- Provides a simple metric for non-technical users

**Files involved:**
- `scanner/risk_score.py` - Score calculation
- `models.py` - Risk score storage
- `templates/dashboard.html` - Risk meter display

---

### 4. Findings Dashboard
**What it does:**
- Shows all security findings in a clean list
- Groups findings by severity (critical first)
- Shows title, description, evidence, and recommendation for each finding
- Allows expanding/collapsing details
- Shows code snippets for fixes

**Why it's used:**
- Presents results in an organized, readable way
- Helps users understand what problems were found
- Provides actionable recommendations
- Makes it easy to share results with developers

**Files involved:**
- `templates/dashboard.html` - Dashboard UI
- `models.py` - Finding model
- `scanner/remediation.py` - Code snippet generation

---

### 5. Authorization Confirmation
**What it does:**
- Requires user to check a box confirming they own the target
- Stores the confirmation with the scan record
- Prevents scanning without explicit permission

**Why it's used:**
- Legal requirement - scanning without permission is illegal
- Protects the project from misuse
- Creates an audit trail of authorized scans
- Educates users about legal responsibilities

**Files involved:**
- `templates/index.html` - Checkbox UI
- `routes/scan.py` - Consent validation
- `models.py` - Consent storage

---

## Security Scanning Features

### 6. HTTP Security Headers Check
**What it does:**
- Checks for presence of security headers:
  - HSTS (Strict-Transport-Security)
  - CSP (Content-Security-Policy)
  - X-Content-Type-Options
  - X-Frame-Options
  - Referrer-Policy
  - Permissions-Policy
- Reports missing headers with recommendations
- Checks for information disclosure headers (Server, X-Powered-By)

**Why it's used:**
- HTTP headers are the first line of defense
- Missing headers can lead to XSS, clickjacking, etc.
- Easy to fix but often forgotten
- Standard security practice recommended by OWASP

**Files involved:**
- `scanner/http_headers.py` - Header checking logic

---

### 7. SSL/TLS Certificate Inspection
**What it does:**
- Checks if site uses HTTPS
- Validates SSL/TLS certificate
- Checks certificate expiry (warns if expiring soon)
- Checks TLS protocol version (rejects SSLv3, TLS 1.0, 1.1)
- Checks cipher strength
- Reports hostname coverage

**Why it's used:**
- HTTP is insecure - all traffic can be intercepted
- Expired certificates cause browser warnings
- Weak protocols/ciphers can be broken
- Certificate errors indicate misconfiguration

**Files involved:**
- `scanner/ssl_check.py` - SSL/TLS checking

---

### 8. Open Port Detection
**What it does:**
- Scans common ports (21, 22, 80, 443, 3306, 5432, etc.)
- Reports which ports are open
- Identifies services running on open ports
- Uses timeouts to avoid hanging

**Why it's used:**
- Open ports are attack surfaces
- Database ports should not be public
- Unnecessary services should be disabled
- Helps reduce attack surface

**Files involved:**
- `scanner/port_scan.py` - Port scanning logic

---

### 9. Cookie Security Flags Check
**What it does:**
- Checks if cookies have:
  - Secure flag (only sent over HTTPS)
  - HttpOnly flag (not accessible via JavaScript)
  - SameSite attribute (CSRF protection)
- Reports missing flags

**Why it's used:**
- Cookies without Secure flag can be stolen over HTTP
- HttpOnly prevents XSS from stealing cookies
- SameSite prevents CSRF attacks
- Essential for session security

**Files involved:**
- `scanner/misconfig.py` - Cookie checking

---

### 10. CORS Misconfiguration Detection
**What it does:**
- Checks CORS headers
- Reports overly permissive CORS policies
- Detects wildcard origins (Access-Control-Allow-Origin: *)

**Why it's used:**
- Misconfigured CORS can allow unauthorized access
- Wildcard origins allow any site to make requests
- Can lead to data leakage
- Common security mistake

**Files involved:**
- `scanner/misconfig.py` - CORS checking

---

### 11. Directory Listing Detection
**What it does:**
- Checks if directory contents are visible
- Tries to access common directories
- Reports if directory listing is enabled

**Why it's used:**
- Directory listing exposes file structure
- Can reveal sensitive files
- Helps attackers map the application
- Should be disabled in production

**Files involved:**
- `scanner/misconfig.py` - Directory listing check

---

### 12. Exposed Sensitive Files Detection
**What it does:**
- Checks for exposed:
  - `.git` directory
  - `.env` files
  - Backup files (.bak, .backup, .old)
  - Configuration files
- Reports if these are accessible

**Why it's used:**
- `.git` contains source code and history
- `.env` contains secrets and API keys
- Backup files may contain old vulnerabilities
- Common mistake in deployments

**Files involved:**
- `scanner/misconfig.py` - Sensitive file detection

---

### 13. Session Token Entropy Analysis
**What it does:**
- Calculates Shannon entropy of session cookies
- Measures randomness of tokens
- Flags low-entropy (predictable) tokens
- Uses statistical analysis

**Why it's used:**
- Predictable tokens can be guessed
- Low entropy = weak security
- Helps ensure strong session management
- Standard security check

**Files involved:**
- `scanner/token_entropy.py` - Entropy calculation

---

### 14. Admin Path Access Control Check
**What it does:**
- Probes common admin paths:
  - `/admin`
  - `/phpMyAdmin`
  - `/wp-admin`
  - `/actuator` (Spring Boot)
  - `/console` (WebLogic)
- Reports if accessible without authentication

**Why it's used:**
- Admin panels should be protected
- Public admin panels are huge security risks
- Common mistake in development deployments
- Easy to check, important to fix

**Files involved:**
- `scanner/access_control.py` - Admin path probing

---

### 15. SQL Injection Detection (Active Probes)
**What it does:**
- Sends test SQL injection payloads
- Checks for database error messages
- Performs time-based blind SQLi (with consent)
- Reports confidence levels (high/medium/low)
- Only runs if user consents to active testing

**Why it's used:**
- SQL injection is #1 web vulnerability
- Can lead to data breach
- Active testing finds issues passive checks miss
- Bounded and safe (only 1 timing check per parameter)

**Files involved:**
- `scanner/active_probes.py` - SQL injection testing

---

### 16. XSS (Cross-Site Scripting) Detection (Active Probes)
**What it does:**
- Sends test XSS payloads
- Checks if payload is reflected in response
- Tests reflected XSS
- Reports confidence levels
- Only runs if user consents to active testing

**Why it's used:**
- XSS is #2 web vulnerability
- Can lead to session hijacking
- Active testing finds injection points
- Bounded and safe (standard test strings)

**Files involved:**
- `scanner/active_probes.py` - XSS testing

---

### 17. CVE (Known Vulnerability) Lookup
**What it does:**
- Detects software versions from headers
- Queries NVD (National Vulnerability Database) API
- Matches detected versions with known CVEs
- Returns CVE references with CVSS scores

**Why it's used:**
- Outdated software may have known vulnerabilities
- CVE lookup shows if software needs updating
- Helps prioritize updates
- Uses official NVD database

**Files involved:**
- `scanner/cve_lookup.py` - CVE matching

---

### 18. DNS Security Posture Check
**What it does:**
- Checks CAA (Certificate Authority Authorization)
- Checks DNSSEC (DNS Security Extensions)
- Checks SPF (Sender Policy Framework)
- Checks DMARC (Domain-based Message Authentication)
- Checks for dangling CNAME (subdomain takeover risk)

**Why it's used:**
- DNS is often overlooked in security
- CAA controls which CAs can issue certificates
- DNSSEC prevents DNS spoofing
- SPF/DMARC prevent email spoofing
- Dangling CNAMEs can lead to subdomain takeover

**Files involved:**
- `scanner/dns_security.py` - DNS security checks

---

### 19. Certificate Transparency Log Monitoring
**What it does:**
- Queries crt.sh (Certificate Transparency log)
- Finds all certificates issued for the domain
- Detects forgotten/shadow subdomains
- Identifies unusually broad CA issuance

**Why it's used:**
- CT logs show certificate history
- Can find forgotten subdomains
- Detects unauthorized certificate issuance
- Part of modern certificate ecosystem

**Files involved:**
- `scanner/ct_monitor.py` - CT log queries

---

### 20. Frontend Supply Chain Analysis
**What it does:**
- Checks third-party JavaScript libraries
- Validates Subresource Integrity (SRI) on scripts
- Detects outdated library versions
- Identifies known vulnerable libraries

**Why it's used:**
- Third-party scripts can be compromised
- Missing SRI allows script tampering
- Outdated libraries may have vulnerabilities
- Supply chain attacks are common

**Files involved:**
- `scanner/frontend_deps.py` - Frontend dependency checking

---

### 21. Scan Integrity & Bot Challenge Detection
**What it does:**
- Detects interstitial pages (consent walls, CAPTCHAs)
- Compares response fingerprints
- Performs single retry if challenge detected
- Reports if bot protection is interfering

**Why it's used:**
- Bot protection can block scans
- Need to distinguish real issues from challenges
- Single retry is polite
- Prevents false positives

**Files involved:**
- `scanner/scan_integrity.py` - Integrity checking

---

### 22. Attack Chain Correlation
**What it does:**
- Combines individual findings into attack chains
- Detects when multiple issues compose a worse problem
- Example: XSS + no CSP + non-HttpOnly cookie = session hijack
- Reports composite risk with full reasoning

**Why it's used:**
- Individual findings may seem minor
- Combined, they can be critical
- Helps understand real-world impact
- Unique feature not in basic scanners

**Files involved:**
- `scanner/correlation.py` - Chain detection

---

### 23. Remediation Code Snippets
**What it does:**
- Generates fix code for missing headers
- Supports multiple frameworks:
  - Flask-Talisman (Python)
  - Helmet (Node.js)
  - Nginx
  - Apache
  - Django
- Provides copy-paste solutions

**Why it's used:**
- Makes it easy to fix issues
- Users may not know how to implement fixes
- Supports different tech stacks
- Reduces time to remediation

**Files involved:**
- `scanner/remediation.py` - Code generation

---

## User Management Features

### 24. User Registration (Signup)
**What it does:**
- Allows users to create accounts
- Validates email format
- Requires password (minimum 8 characters)
- Hashes passwords before storing
- Checks for duplicate emails

**Why it's used:**
- Enables scan history tracking
- Allows scheduled scans
- Protects user data
- Password hashing prevents credential theft

**Files involved:**
- `routes/auth.py` - Signup logic
- `forms.py` - Form validation
- `models.py` - User model

---

### 25. User Login
**What it does:**
- Authenticates users with email and password
- Verifies password hash
- Creates user session
- Redirects to appropriate page

**Why it's used:**
- Secure access to user data
- Session management
- Protects scan history
- Required for scheduled scans

**Files involved:**
- `routes/auth.py` - Login logic
- `forms.py` - Form validation
- `extensions.py` - Login manager

---

### 26. User Logout
**What it does:**
- Ends user session
- Clears session cookies
- Redirects to homepage
- Shows success message

**Why it's used:**
- Allows users to sign out securely
- Prevents session hijacking on shared devices
- Good security practice

**Files involved:**
- `routes/auth.py` - Logout logic

---

### 27. Password Hashing
**What it does:**
- Uses Werkzeug's password hashing
- Never stores plain text passwords
- Uses PBKDF2 with SHA-256
- Automatically salts passwords

**Why it's used:**
- Plain text passwords are a security disaster
- Hashing protects against database breaches
- Salting prevents rainbow table attacks
- Industry standard practice

**Files involved:**
- `models.py` - Password hashing methods

---

### 28. Scan History Tracking
**What it does:**
- Stores all scans per user
- Shows list of past scans
- Allows viewing old results
- Limits to last 50 scans

**Why it's used:**
- Track security over time
- Compare scans to see improvements
- Audit trail of security checks
- Essential for ongoing security

**Files involved:**
- `routes/main.py` - History page
- `models.py` - Scan model
- `templates/history.html` - History UI

---

### 29. Anonymous Scans
**What it does:**
- Allows scanning without login
- Scans are viewable by anyone with the link
- Optional user account for history

**Why it's used:**
- Lowers barrier to entry
- Allows quick one-off scans
- Useful for testing before signup
- Flexible access model

**Files involved:**
- `routes/main.py` - Dashboard access logic
- `models.py` - User ID can be NULL

---

## Report Generation Features

### 30. PDF Report Generation
**What it does:**
- Generates professional PDF reports
- Includes all findings
- Shows risk score and severity distribution
- formatted with tables and sections
- Downloadable as .pdf file

**Why it's used:**
- Professional documentation
- Easy to share with stakeholders
- Printable for audits
- Standard report format

**Files involved:**
- `reports/pdf_report.py` - PDF generation
- `routes/scan.py` - Download endpoint

---

### 31. CSV Report Generation
**What it does:**
- Generates CSV (Comma-Separated Values) reports
- One row per finding
- Includes all finding details
- Downloadable as .csv file

**Why it's used:**
- Easy to import into Excel
- Good for data analysis
- Spreadsheet-friendly
- Compatible with many tools

**Files involved:**
- `reports/csv_report.py` - CSV generation
- `routes/scan.py` - Download endpoint

---

### 32. SARIF Report Generation
**What it does:**
- Generates SARIF (Static Analysis Results Interchange Format) reports
- Standard format for security tools
- Compatible with GitHub Code Scanning
- Integrates with CI/CD pipelines

**Why it's used:**
- Industry standard format
- Works with GitHub security features
- Integrates with DevOps tools
- Enables automated security gates

**Files involved:**
- `reports/sarif_report.py` - SARIF generation
- `routes/scan.py` - Download endpoint

---

## Advanced Features

### 33. Scheduled Automatic Scans
**What it does:**
- Allows users to schedule recurring scans
- Supports daily or weekly frequency
- Runs automatically via Vercel Cron
- Stores schedule in database

**Why it's used:**
- Continuous security monitoring
- No manual intervention needed
- Catches new vulnerabilities early
- Essential for production systems

**Files involved:**
- `routes/scan.py` - Schedule creation
- `routes/cron.py` - Cron job handler
- `models.py` - ScheduledTarget model
- `vercel.json` - Cron configuration

---

### 34. Email Notifications
**What it does:**
- Sends email when scheduled scan completes
- Includes risk score and summary
- Configured via SMTP settings
- Optional per schedule

**Why it's used:**
- Alerts users to scan results
- No need to check dashboard constantly
- Keeps stakeholders informed
- Professional communication

**Files involved:**
- `notifications.py` - Email sending
- `routes/cron.py` - Notification trigger
- `config.py` - SMTP configuration

---

### 35. AI Assistant (Optional)
**What it does:**
- Uses Anthropic Claude API
- Allows users to ask questions about findings
- Explains security issues in plain English
- Provides context-specific answers
- Disabled gracefully if API key not set

**Why it's used:**
- Helps non-technical users understand findings
- Provides personalized explanations
- Adds intelligence to the tool
- Optional feature (not required)

**Files involved:**
- `ai_assistant.py` - API integration
- `routes/scan.py` - Ask endpoint
- `config.py` - API key configuration

---

### 36. Historical Diff Tracking
**What it does:**
- Compares current scan with previous scan
- Tags findings as NEW, RESOLVED, or RECURRING
- Shows risk score trend
- Tracks improvements over time

**Why it's used:**
- Shows progress on security fixes
- Identifies new vulnerabilities
- Tracks regression (fixed issues reappearing)
- Motivates continued improvement

**Files involved:**
- `scan_service.py` - Diff computation
- `models.py` - Diff storage
- `templates/history.html` - Diff display

---

### 37. Confidence Levels on Findings
**What it does:**
- Assigns confidence (high/medium/low) to findings
- Based on multiple signal corroboration
- Timing anomaly alone = medium
- Timing + error message = high
- Helps users prioritize verification

**Why it's used:**
- Reduces false positives
- Indicates certainty of findings
- Helps prioritize investigation
- More transparent reporting

**Files involved:**
- `scanner/active_probes.py` - Confidence calculation

---

## Technical Features

### 38. Flask Web Framework
**What it does:**
- Provides web server functionality
- Handles HTTP requests and responses
- Manages URL routing
- Integrates with extensions

**Why it's used:**
- Lightweight and flexible
- Easy to learn and use
- Large ecosystem of extensions
- Well-documented and popular

**Files involved:**
- `app.py` - Flask app creation
- All route files - Blueprint usage

---

### 39. SQLAlchemy ORM
**What it does:**
- Object-Relational Mapping for database
- Allows using Python objects instead of SQL
- Handles database connections
- Supports multiple databases (SQLite, PostgreSQL)

**Why it's used:**
- No need to write raw SQL
- Database-agnostic code
- Type-safe queries
- Easy migrations

**Files involved:**
- `models.py` - Database models
- `extensions.py` - DB initialization
- All route files - Query usage

---

### 40. Flask-Login Authentication
**What it does:**
- Manages user sessions
- Handles login/logout
- Protects routes with @login_required
- Remembers logged-in users

**Why it's used:**
- Secure session management
- Easy to implement
- CSRF protection built-in
- Industry standard

**Files involved:**
- `extensions.py` - Login manager setup
- `routes/auth.py` - Auth routes
- All protected routes - @login_required decorator

---

### 41. Flask-WTF Form Validation
**What it does:**
- Validates form input
- Provides CSRF protection
- Handles form rendering
- Shows error messages

**Why it's used:**
- Prevents invalid data
- CSRF protection is critical
- Consistent validation
- User-friendly errors

**Files involved:**
- `forms.py` - Form definitions
- `routes/auth.py` - Form usage
- `templates/*.html` - Form rendering

---

### 42. Server-Sent Events (SSE)
**What it does:**
- Real-time communication from server to client
- Streams progress updates
- Keeps connection open
- No page refresh needed

**Why it's used:**
- Real-time progress updates
- Better than polling
- Low overhead
- Native browser support

**Files involved:**
- `routes/scan.py` - SSE endpoint
- `scanner/orchestrator.py` - Event generation
- `public/main.js` - EventSource client

---

### 43. ThreadPoolExecutor Concurrency
**What it does:**
- Runs scanner modules in parallel
- Uses thread pool for efficiency
- Manages concurrent connections
- Bounded to avoid overwhelming target

**Why it's used:**
- Faster scans (parallel execution)
- Better resource utilization
- Controlled concurrency
- Won't DoS the target

**Files involved:**
- `scanner/orchestrator.py` - Thread pool usage

---

### 44. python-dotenv Environment Management
**What it does:**
- Loads environment variables from .env file
- Separates config from code
- Works in development and production
- Easy to manage secrets

**Why it's used:**
- Security (secrets not in code)
- Flexibility (different envs)
- Portability (same code everywhere)
- Best practice

**Files involved:**
- `config.py` - Environment loading
- `.env` - Local configuration
- `.env.example` - Template

---

### 45. Requests HTTP Library
**What it does:**
- Makes HTTP requests to target websites
- Handles redirects
- Manages timeouts
- Parses responses

**Why it's used:**
- Simple and powerful
- Good error handling
- Session support
- Industry standard

**Files involved:**
- `scanner/orchestrator.py` - HTTP requests
- `ai_assistant.py` - API calls
- All scanner modules - HTTP usage

---

### 46. BeautifulSoup HTML Parsing
**What it does:**
- Parses HTML responses
- Extracts information from pages
- Finds specific elements
- Handles malformed HTML

**Why it's used:**
- Easy HTML parsing
- Robust against bad HTML
- Simple API
- Well-maintained

**Files involved:**
- `scanner/misconfig.py` - HTML parsing
- `scanner/frontend_deps.py` - Script extraction

---

### 47. ReportLab PDF Generation
**What it does:**
- Generates PDF documents
- Handles formatting and layout
- Creates tables and text
- Professional output

**Why it's used:**
- PDF is standard format
- Professional appearance
- Cross-platform
- Feature-rich

**Files involved:**
- `reports/pdf_report.py` - PDF creation

---

### 48. dnspython DNS Library
**What it does:**
- Performs DNS queries
- Checks DNS records
- Handles DNSSEC validation
- Parses DNS responses

**Why it's used:**
- Comprehensive DNS support
- DNSSEC capability
- Well-documented
- Pure Python

**Files involved:**
- `scanner/dns_security.py` - DNS queries

---

## Deployment Features

### 49. Vercel Serverless Deployment
**What it does:**
- Deploys as serverless functions
- Auto-scales based on traffic
- Provides global CDN
- Handles SSL certificates

**Why it's used:**
- No server management
- Automatic scaling
- Global distribution
- Free tier available

**Files involved:**
- `pyproject.toml` - Build config
- `vercel.json` - Deployment config
- `app.py` - Serverless entrypoint

---

### 50. PostgreSQL Database Support
**What it does:**
- Uses PostgreSQL in production
- Persistent data storage
- Handles concurrent connections
- Better performance than SQLite

**Why it's used:**
- Vercel filesystem is temporary
- PostgreSQL is production-ready
- Better performance
- Reliable persistence

**Files involved:**
- `config.py` - Database URL handling
- `models.py` - ORM models
- Vercel dashboard - Database setup

---

### 51. SQLite Database (Local Development)
**What it does:**
- Uses SQLite for local development
- File-based database
- No setup required
- Easy to use

**Why it's used:**
- Zero configuration
- Good for development
- Fast enough for local use
- Easy to reset

**Files involved:**
- `config.py` - Database URL handling
- `instance/dev.db` - Database file

---

### 52. Vercel Cron Jobs
**What it does:**
- Runs scheduled tasks automatically
- Triggers at specific times
- Calls cron endpoint
- Supports multiple schedules

**Why it's used:**
- Automated scans
- No manual intervention
- Reliable execution
- Built-in to Vercel

**Files involved:**
- `vercel.json` - Cron config
- `routes/cron.py` - Cron handler

---

### 53. GitHub CI/CD Integration
**What it does:**
- Runs tests on every push
- Automatically checks code quality
- Prevents broken code from merging
- Runs on GitHub Actions

**Why it's used:**
- Continuous integration
- Automated testing
- Code quality assurance
- Prevents regressions

**Files involved:**
- `.github/workflows/ci.yml` - CI config
- `tests/` - Test suite

---

### 54. Pytest Testing Framework
**What it does:**
- Runs automated tests
- 41 tests covering all functionality
- Unit tests and integration tests
- End-to-end scan test

**Why it's used:**
- Ensures code quality
- Catches bugs early
- Documents expected behavior
- Safe refactoring

**Files involved:**
- `tests/` - All test files
- `pytest.ini` - Test configuration
- `conftest.py` - Test fixtures

---

### 55. Response Security Headers
**What it does:**
- Sets security headers on all responses
- Practices what it preaches
- Includes:
  - X-Content-Type-Options
  - X-Frame-Options
  - Referrer-Policy
  - Permissions-Policy

**Why it's used:**
- Leads by example
- Protects the scanner itself
- Best practice demonstration
- Security by design

**Files involved:**
- `app.py` - Header middleware

---

### 56. Error Handling (404, 500)
**What it does:**
- Custom error pages
- Friendly error messages
- Prevents information leakage
- Good user experience

**Why it's used:**
- Better UX than default errors
- Prevents stack trace exposure
- Professional appearance
- Consistent branding

**Files involved:**
- `app.py` - Error handlers
- `templates/error.html` - Error page

---

### 57. CSRF Protection
**What it does:**
- Adds CSRF tokens to forms
- Validates tokens on submit
- Prevents cross-site request forgery
- Automatic with Flask-WTF

**Why it's used:**
- Critical security feature
- Prevents unauthorized actions
- Built-in to Flask-WTF
- Industry standard

**Files involved:**
- `extensions.py` - CSRF init
- All forms - Token inclusion

---

### 58. Static File Serving
**What it does:**
- Serves CSS, JS, images
- Uses `public/` directory
- Matches Vercel's CDN behavior
- Configured in app.py

**Why it's used:**
- Separate static assets
- CDN-friendly structure
- Faster loading
- Better caching

**Files involved:**
- `app.py` - Static folder config
- `public/` - Static files

---

### 59. Dark/Light Theme
**What it does:**
- Supports dark and light modes
- User can toggle theme
- Persists preference
- Modern UI design

**Why it's used:**
- User preference
- Better accessibility
- Modern design trend
- Reduces eye strain

**Files involved:**
- `public/style.css` - Theme styles
- `public/main.js` - Theme toggle
- `templates/base.html` - Theme class

---

### 60. Responsive Design
**What it does:**
- Works on mobile, tablet, desktop
- Uses CSS media queries
- Flexible layouts
- Touch-friendly

**Why it's used:**
- Mobile-first approach
- All users supported
- Better UX on all devices
- Modern web standard

**Files involved:**
- `public/style.css` - Responsive styles
- All templates - Fluid layouts

---

## Summary

This project includes **60 features** organized into categories:

### Core Features (5)
Homepage, Real-time Progress, Risk Score, Dashboard, Authorization

### Security Scanning Features (18)
HTTP Headers, SSL/TLS, Port Scan, Cookies, CORS, Directory Listing, Exposed Files, Token Entropy, Admin Paths, SQL Injection, XSS, CVE Lookup, DNS Security, CT Monitoring, Frontend Deps, Scan Integrity, Attack Chains, Remediation

### User Management Features (6)
Signup, Login, Logout, Password Hashing, Scan History, Anonymous Scans

### Report Generation Features (3)
PDF, CSV, SARIF

### Advanced Features (5)
Scheduled Scans, Email Notifications, AI Assistant, Historical Diff, Confidence Levels

### Technical Features (9)
Flask, SQLAlchemy, Flask-Login, Flask-WTF, SSE, ThreadPool, python-dotenv, Requests, BeautifulSoup, ReportLab, dnspython

### Deployment Features (12)
Vercel, PostgreSQL, SQLite, Cron Jobs, CI/CD, Pytest, Security Headers, Error Handling, CSRF, Static Files, Dark Theme, Responsive Design

---

## Feature Importance Ranking

### Critical (Must Have)
1. Security scanning modules
2. Authorization confirmation
3. Password hashing
4. HTTPS enforcement
5. CSRF protection

### High Priority
1. User authentication
2. Scan history
3. Report generation
4. Real-time progress
5. Error handling

### Medium Priority
1. Scheduled scans
2. Email notifications
3. AI assistant
4. Dark theme
5. Responsive design

### Nice to Have
1. Historical diff tracking
2. Confidence levels
3. Attack chain correlation
4. SARIF export
5. CT monitoring

---

**End of Features Documentation**
