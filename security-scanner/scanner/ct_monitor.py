"""Certificate Transparency (CT) log correlation.

Every publicly-trusted certificate issued since ~2018 is logged to public,
append-only CT logs (RFC 9162) - a standard, mandatory part of the CA
ecosystem, not a novel technique invented here. Querying them for a domain
surfaces certificates - and therefore subdomains - the site owner may not
remember exist: forgotten staging environments, certs issued by a
compromised internal process, or shadow-IT subdomains that share the
domain's trust without sharing its hardening.

This is entirely passive: a read against a public log (crt.sh, run by
Sectigo), nothing is ever sent to the target itself. Best-effort by design -
if the search is unreachable or rate-limited, the scan simply continues
without this module's findings rather than failing.
"""

from collections import Counter

import requests

CT_SEARCH_URL = "https://crt.sh/"
REQUEST_TIMEOUT = 10
LARGE_FOOTPRINT_THRESHOLD = 15
MANY_ISSUERS_THRESHOLD = 4
SAMPLE_SIZE = 8


def _extract_subdomains(entries, apex):
    names = set()
    for entry in entries:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and name.endswith(apex):
                names.add(name)
    return names


def check(ctx):
    findings = []
    hostname = ctx.hostname
    if not hostname:
        return findings

    labels = hostname.split(".")
    apex = ".".join(labels[-2:]) if len(labels) >= 2 else hostname

    try:
        resp = requests.get(CT_SEARCH_URL, params={"q": apex, "output": "json"}, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        entries = resp.json()
    except Exception:
        # CT search is best-effort and depends on a third-party service
        # (and, in network-restricted environments, on that host being
        # reachable at all) - never fail the scan over it.
        return findings

    if not isinstance(entries, list) or not entries:
        return findings

    subdomains = _extract_subdomains(entries, apex)
    ctx.meta["ct_subdomain_count"] = len(subdomains)

    if len(subdomains) > LARGE_FOOTPRINT_THRESHOLD:
        sample = sorted(subdomains)[:SAMPLE_SIZE]
        remainder = len(subdomains) - len(sample)
        findings.append({
            "category": "certificate_transparency",
            "title": f"Certificate Transparency logs show {len(subdomains)} distinct subdomains with certificates",
            "severity": "info",
            "description": (
                "This is a sizeable certificate footprint - worth a skim for "
                "anything unexpected. Old staging/demo/test environments are "
                "a common CT-log surprise, and they're often less hardened "
                "than the production site while inheriting the same domain "
                "trust in a browser's eyes."
            ),
            "evidence": ", ".join(sample) + (f" (+{remainder} more)" if remainder > 0 else ""),
            "recommendation": f"Review the full list at https://crt.sh/?q={apex} and decommission or lock down anything unrecognized or unused.",
        })

    issuers = Counter(e.get("issuer_name", "unknown") for e in entries)
    if len(issuers) > MANY_ISSUERS_THRESHOLD:
        findings.append({
            "category": "certificate_transparency",
            "title": f"Certificates for this domain have been issued by {len(issuers)} different CAs over time",
            "severity": "low",
            "description": (
                "A wide spread of issuing CAs isn't inherently wrong, but it "
                "does widen the set of organizations that have been trusted "
                "to issue certificates for this name. Pair this with the CAA "
                "finding, which restricts issuance going forward."
            ),
            "evidence": ", ".join(sorted(issuers)[:6]),
            "recommendation": "Cross-check against the CAA DNS finding; restrict future issuance to the CA(s) you actually use.",
        })

    return findings
