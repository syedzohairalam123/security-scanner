"""
Vulnerability scanning engine.

Every check module exposes a `check(ctx)` function that returns a list of
finding dicts with the shape:

    {
        "category": "http_headers" | "tls" | "ports" | "misconfig" | ...,
        "title": str,
        "severity": "critical" | "high" | "medium" | "low" | "info",
        "description": str,   # what the issue is, in plain language
        "evidence": str,      # the concrete thing we observed
        "recommendation": str,  # how to fix it
        "cve_refs": list[dict] (optional),
    }

`ctx` is a `scanner.orchestrator.ScanContext` carrying the shared HTTP
session, the already-fetched homepage response, and helpers so individual
checks don't each re-implement URL parsing.

Every module here is read-only reconnaissance and detection: it looks for
the presence of a weakness and reports it. None of them attempt to exploit
a finding, gain unauthorized access, brute-force credentials, or disrupt
the target - see README.md for the reasoning behind that boundary.
"""
