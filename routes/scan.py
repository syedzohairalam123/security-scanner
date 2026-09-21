import io
import json

from flask import Blueprint, request, jsonify, Response, stream_with_context, abort, send_file
from flask_login import current_user, login_required

from config import Config
from extensions import db
from models import Scan, ScheduledTarget
from scanner.orchestrator import run_scan_streaming
from scan_service import persist_scan
from reports.pdf_report import build_pdf
from reports.csv_report import build_csv
from reports.sarif_report import build_sarif
import ai_assistant

scan_bp = Blueprint("scan", __name__, url_prefix="/api")


def _get_owned_scan_or_404(scan_id):
    scan = db.get_or_404(Scan, scan_id)
    if scan.user_id is not None:
        if not current_user.is_authenticated or current_user.id != scan.user_id:
            abort(404)
    return scan


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"


@scan_bp.route("/scan/stream")
def scan_stream():
    """Server-Sent Events endpoint: runs a scan and streams progress, then a
    final 'complete' event with the saved scan id. A plain GET (rather than
    POST) is used deliberately - the browser's EventSource API only speaks
    GET, which also keeps this compatible with a stateless serverless
    function (no job store needed between requests).
    """
    target_url = (request.args.get("target_url") or "").strip()
    consent = request.args.get("consent") == "1"

    def generate():
        if not consent:
            yield _sse({"type": "error", "message": "Confirm you own or are authorized to test this target first."})
            return
        if not target_url:
            yield _sse({"type": "error", "message": "Enter a target URL."})
            return

        try:
            final_result = None
            for event in run_scan_streaming(target_url, consent, Config):
                if event["type"] == "progress":
                    yield _sse(event)
                else:
                    final_result = event["result"]

            user_id = current_user.id if current_user.is_authenticated else None
            scan = persist_scan(final_result, user_id=user_id, consent=consent)
            yield _sse({
                "type": "complete", "scan_id": scan.id,
                "risk_level": scan.risk_level, "risk_score": scan.risk_score,
            })
        except ValueError as e:
            yield _sse({"type": "error", "message": str(e)})
        except Exception as e:
            yield _sse({"type": "error", "message": f"Scan failed unexpectedly: {e}"})

    return Response(stream_with_context(generate()), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    })


@scan_bp.route("/scan/<int:scan_id>/report.pdf")
def scan_report_pdf(scan_id):
    scan = _get_owned_scan_or_404(scan_id)
    pdf_bytes = build_pdf(scan)
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"scan-{scan.id}-report.pdf",
    )


@scan_bp.route("/scan/<int:scan_id>/report.csv")
def scan_report_csv(scan_id):
    scan = _get_owned_scan_or_404(scan_id)
    csv_text = build_csv(scan)
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=scan-{scan.id}-findings.csv"},
    )


@scan_bp.route("/scan/<int:scan_id>/report.sarif")
def scan_report_sarif(scan_id):
    scan = _get_owned_scan_or_404(scan_id)
    sarif_text = build_sarif(scan)
    return Response(
        sarif_text,
        mimetype="application/sarif+json",
        headers={"Content-Disposition": f"attachment; filename=scan-{scan.id}.sarif.json"},
    )


@scan_bp.route("/scan/<int:scan_id>/ask", methods=["POST"])
def scan_ask(scan_id):
    scan = _get_owned_scan_or_404(scan_id)
    if not ai_assistant.is_configured():
        return jsonify(error="The AI assistant isn't configured on this deployment. Set ANTHROPIC_API_KEY to enable it."), 503

    payload = request.get_json(silent=True) or {}
    question = (payload.get("question") or "").strip()
    if not question:
        return jsonify(error="Ask a question about this scan's findings."), 400

    try:
        answer = ai_assistant.ask_about_scan(scan, question)
    except Exception as e:
        return jsonify(error=f"AI assistant request failed: {e}"), 502

    return jsonify(answer=answer)


@scan_bp.route("/schedule", methods=["POST"])
@login_required
def create_schedule():
    payload = request.get_json(silent=True) or {}
    target_url = (payload.get("target_url") or "").strip()
    frequency = payload.get("frequency") if payload.get("frequency") in ("daily", "weekly") else "daily"
    notify_email = bool(payload.get("notify_email", True))

    if not target_url:
        return jsonify(error="Target URL is required."), 400

    target = ScheduledTarget(
        user_id=current_user.id,
        target_url=target_url,
        frequency=frequency,
        notify_email=notify_email,
    )
    db.session.add(target)
    db.session.commit()
    return jsonify(schedule=target.to_dict())


@scan_bp.route("/schedule/<int:schedule_id>", methods=["DELETE"])
@login_required
def delete_schedule(schedule_id):
    target = db.get_or_404(ScheduledTarget, schedule_id)
    if target.user_id != current_user.id:
        abort(404)
    db.session.delete(target)
    db.session.commit()
    return jsonify(ok=True)
