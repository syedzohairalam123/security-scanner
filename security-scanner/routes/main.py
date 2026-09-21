from flask import Blueprint, render_template, abort
from flask_login import current_user, login_required

from extensions import db
from models import Scan, ScheduledTarget
from ai_assistant import is_configured as ai_is_configured

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/dashboard/<int:scan_id>")
def dashboard(scan_id):
    scan = db.get_or_404(Scan, scan_id)
    # Anonymous scans (user_id is None) stay viewable by anyone with the
    # link; scans tied to an account are only viewable by their owner.
    if scan.user_id is not None:
        if not current_user.is_authenticated or current_user.id != scan.user_id:
            abort(404)
    return render_template("dashboard.html", scan=scan, ai_enabled=ai_is_configured())


@main_bp.route("/history")
@login_required
def history():
    scans = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.started_at.desc())
        .limit(50)
        .all()
    )
    schedules = (
        ScheduledTarget.query.filter_by(user_id=current_user.id)
        .order_by(ScheduledTarget.created_at.desc())
        .all()
    )
    return render_template("history.html", scans=scans, schedules=schedules)
