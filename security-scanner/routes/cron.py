from datetime import timedelta

from flask import Blueprint, request, jsonify

from config import Config
from extensions import db
from models import ScheduledTarget
from scanner.orchestrator import run_scan
from scan_service import persist_scan
from notifications import send_scan_summary_email
from time_utils import utcnow

cron_bp = Blueprint("cron", __name__, url_prefix="/api/cron")

FREQUENCY_DELTAS = {"daily": timedelta(days=1), "weekly": timedelta(weeks=1)}


@cron_bp.route("/scheduled-scans")
def run_scheduled_scans():
    """Triggered by Vercel Cron Jobs (see the 'crons' entry in vercel.json).
    Protected by CRON_SECRET so only Vercel's scheduler (or someone who has
    the secret) can trigger a batch of scans.
    """
    if Config.CRON_SECRET:
        provided = request.headers.get("Authorization", "")
        if provided != f"Bearer {Config.CRON_SECRET}":
            return jsonify(error="Unauthorized"), 401

    now = utcnow()
    due_targets = [
        t for t in ScheduledTarget.query.filter_by(active=True).all()
        if t.last_run_at is None or now - t.last_run_at >= FREQUENCY_DELTAS.get(t.frequency, timedelta(days=1))
    ]

    results = []
    for target in due_targets:
        try:
            # Scheduled scans never run active probing - the target owner set
            # this up in advance, but an unattended job is not the place to
            # send XSS/SQLi test payloads without a human watching.
            scan_result = run_scan(target.target_url, allow_active_probes=False, config=Config)
            scan = persist_scan(scan_result, user_id=target.user_id, consent=True)

            target.last_run_at = now
            db.session.commit()

            if target.notify_email and target.user and target.user.email:
                try:
                    send_scan_summary_email(target.user.email, scan)
                except Exception as mail_error:
                    results.append({"target_url": target.target_url, "scan_id": scan.id, "email_error": str(mail_error)})
                    continue

            results.append({"target_url": target.target_url, "scan_id": scan.id, "risk_level": scan.risk_level})
        except Exception as e:
            db.session.rollback()
            results.append({"target_url": target.target_url, "error": str(e)})

    return jsonify(checked=len(due_targets), results=results)
