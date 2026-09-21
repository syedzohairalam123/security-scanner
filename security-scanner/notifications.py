import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config import Config


def is_configured() -> bool:
    return bool(Config.SMTP_HOST and Config.SMTP_USER and Config.SMTP_PASSWORD)


def send_scan_summary_email(to_email: str, scan) -> bool:
    """Sends a plain-text summary of a completed scan. Returns False silently
    if SMTP isn't configured, so scheduled scans still work without email."""
    if not is_configured():
        return False

    counts = scan.severity_counts()
    subject = f"[Scan] {scan.target_url} \u2014 {scan.risk_level.upper()} ({scan.risk_score:.0f}/100)"

    lines = [
        f"Scheduled scan finished for {scan.target_url}",
        f"Risk score: {scan.risk_score:.1f}/100 ({scan.risk_level.upper()})",
        "",
        f"Critical: {counts['critical']}   High: {counts['high']}   "
        f"Medium: {counts['medium']}   Low: {counts['low']}   Info: {counts['info']}",
        "",
        "Top findings:",
    ]
    for f in scan.findings[:5]:
        lines.append(f"- [{f.severity.upper()}] {f.title}")
    lines += ["", "Log in to your dashboard for the full report."]

    msg = MIMEMultipart()
    msg["From"] = Config.MAIL_FROM
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText("\n".join(lines), "plain"))

    with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT, timeout=10) as server:
        server.starttls()
        server.login(Config.SMTP_USER, Config.SMTP_PASSWORD)
        server.send_message(msg)
    return True
