"""Exports a scan's findings as SARIF 2.1.0 (Static Analysis Results
Interchange Format) - an OASIS standard, not something invented for this
project. GitHub Code Scanning, Azure DevOps, and most CI security
dashboards natively ingest SARIF, so this turns the scan from "a report a
person reads" into "a check a pipeline can enforce" (e.g. fail a build on
any new 'error'-level result).
"""

import json
import re

SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

TOOL_NAME = "Perimeter"
TOOL_VERSION = "1.0.0"


def _rule_id(finding):
    category = finding.category or "finding"
    slug = re.sub(r"[^a-z0-9]+", "-", (finding.title or "finding").lower()).strip("-")[:60]
    return f"{category}/{slug}"


def build_sarif(scan) -> str:
    rules = {}
    results = []

    for f in scan.findings:
        rule_id = _rule_id(f)
        level = SEVERITY_TO_LEVEL.get(f.severity, "warning")

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": re.sub(r"[^A-Za-z0-9]", "", f.title or "Finding"),
                "shortDescription": {"text": f.title or "Finding"},
                "fullDescription": {"text": f.description or f.title or ""},
                "properties": {"category": f.category, "security-severity": _cvss_like_score(f.severity)},
                "defaultConfiguration": {"level": level},
            }

        message_text = f.title or ""
        if f.description:
            message_text += f"\n\n{f.description}"
        if f.recommendation:
            message_text += f"\n\nRecommendation: {f.recommendation}"

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": scan.target_url}
                }
            }],
            "properties": {
                "severity": f.severity,
                "confidence": f.confidence,
                "evidence": f.evidence or "",
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": scan.status == "completed",
                "startTimeUtc": _iso_z(scan.started_at),
                "endTimeUtc": _iso_z(scan.finished_at),
            }],
            "properties": {
                "targetUrl": scan.target_url,
                "riskScore": scan.risk_score,
                "riskLevel": scan.risk_level,
            },
        }],
    }
    return json.dumps(sarif, indent=2)


def _iso_z(dt):
    return dt.isoformat() + "Z" if dt else None


def _cvss_like_score(severity):
    # GitHub's Code Scanning UI reads "security-severity" as a 0-10 float
    # to color-code results, independent of the SARIF "level" field.
    return {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "2.5", "info": "0.0"}.get(severity, "5.0")
