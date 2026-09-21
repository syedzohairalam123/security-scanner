import json

from extensions import db
from models import Scan, Finding
from time_utils import utcnow
from scanner import scan_integrity, risk_score


def _finding_key(category, title):
    """Identity used to match "the same issue" across two scans of the same
    target. (category, title) is stable for the vast majority of findings -
    it deliberately ignores evidence text, which is expected to change scan
    to scan even when the underlying issue hasn't."""
    return (category, title)


def compute_diff(current_findings, previous_scan):
    """Compares this scan's findings against the target's previous scan (if
    any) and returns a summary of what's new, resolved, or recurring - real
    regression tracking over data already stored, not a point-in-time
    snapshot pretending to be a trend."""
    if previous_scan is None:
        return None

    current_keys = {_finding_key(f.get("category"), f.get("title")) for f in current_findings}
    previous_keys = {_finding_key(f.category, f.title) for f in previous_scan.findings}

    new_keys = current_keys - previous_keys
    resolved_keys = previous_keys - current_keys
    recurring_keys = current_keys & previous_keys

    return {
        "previous_scan_id": previous_scan.id,
        "previous_scanned_at": previous_scan.started_at.isoformat() if previous_scan.started_at else None,
        "previous_risk_score": previous_scan.risk_score,
        "new_count": len(new_keys),
        "resolved_count": len(resolved_keys),
        "recurring_count": len(recurring_keys),
        "resolved_titles": sorted(title for (_, title) in resolved_keys)[:20],
        "new_titles": sorted(title for (_, title) in new_keys)[:20],
    }


def persist_scan(result, user_id=None, consent=True):
    """Writes a scanner.orchestrator result dict to the database and returns
    the saved Scan row (with .findings populated)."""
    previous_scan = (
        Scan.query.filter_by(target_url=result["target_url"], user_id=user_id, status="completed")
        .order_by(Scan.started_at.desc())
        .first()
    )
    diff = compute_diff(result["findings"], previous_scan)
    current_fingerprint = result.get("meta", {}).get("fingerprint")
    previous_fingerprint = previous_scan.meta.get("fingerprint") if previous_scan else None
    fingerprint_delta = scan_integrity.compare_fingerprints(previous_fingerprint, current_fingerprint)
    if fingerprint_delta:
        result["findings"].append(scan_integrity.baseline_fingerprint_finding(fingerprint_delta))
        result["meta"]["fingerprint_delta"] = fingerprint_delta
        result["risk_score"], result["risk_level"] = risk_score.compute(result["findings"])
        if diff is not None:
            diff["fingerprint_delta"] = fingerprint_delta

    scan = Scan(
        user_id=user_id,
        target_url=result["target_url"],
        status="completed",
        consent_confirmed=consent,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        finished_at=utcnow(),
        duration_ms=result.get("duration_ms"),
        error_message="; ".join(result["errors"]) if result.get("errors") else None,
    )
    scan.meta = result.get("meta", {})
    scan.diff_summary = diff
    db.session.add(scan)
    db.session.flush()  # assigns scan.id so findings can reference it

    for f in result["findings"]:
        finding = Finding(
            scan_id=scan.id,
            category=f.get("category"),
            title=f.get("title"),
            severity=f.get("severity", "info"),
            description=f.get("description"),
            evidence=f.get("evidence"),
            recommendation=f.get("recommendation"),
            code_snippet=f.get("code_snippet"),
            code_snippet_label=f.get("code_snippet_label"),
            confidence=f.get("confidence"),
        )
        if f.get("cve_refs"):
            finding.cve_refs = json.dumps(f["cve_refs"])
        db.session.add(finding)

    db.session.commit()
    return scan
