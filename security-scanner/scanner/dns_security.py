"""DNS-layer security posture: CAA, DNSSEC, SPF/DMARC, and subdomain
takeover risk via dangling CNAME detection.

Real, standards-based checks (RFC 8659 for CAA, RFC 7208 for SPF, RFC 7489
for DMARC) that most lightweight web scanners skip because they only look
at HTTP. A scanner that also reasons about DNS catches a distinct, commonly
missed class of misconfiguration - and subdomain takeover in particular is
a well-documented, real vulnerability class (a dangling CNAME pointing at a
deleted cloud resource that anyone else can re-claim).

Every lookup here is a plain DNS query (a read against public
infrastructure, same as any browser resolving the name) or a GET to the
target's own homepage to confirm a takeover fingerprint - nothing is
registered, claimed, or modified.
"""

import dns.resolver
import dns.exception
import requests

RESOLVE_TIMEOUT = 4.0
HTTP_TIMEOUT = 6.0

# A representative, not exhaustive, set of public fingerprints for services
# that return a distinctive "nothing here" response when a CNAME points at
# them but the underlying app/bucket/site was never claimed or was deleted.
# (The community-maintained "Can I take over XYZ?" reference lists 60+
# services; this covers the most common ones a student/small project is
# likely to actually be using.)
TAKEOVER_FINGERPRINTS = [
    ("github.io", "there isn't a github pages site here", "GitHub Pages"),
    ("herokuapp.com", "no such app", "Heroku"),
    ("herokudns.com", "no such app", "Heroku"),
    ("s3.amazonaws.com", "nosuchbucket", "AWS S3"),
    ("s3-website", "nosuchbucket", "AWS S3 (website endpoint)"),
    ("azurewebsites.net", "404 web site not found", "Azure App Service"),
    ("cloudapp.net", "404 web site not found", "Azure Cloud Service"),
    ("readme.io", "project doesnt exist", "ReadMe"),
    ("myshopify.com", "sorry, this shop is currently unavailable", "Shopify"),
    ("wpengine.com", "the site you were looking for couldn't be found", "WP Engine"),
    ("fastly.net", "fastly error: unknown domain", "Fastly"),
    ("zendesk.com", "help center closed", "Zendesk"),
    ("surge.sh", "project not found", "Surge.sh"),
    ("bitbucket.io", "repository not found", "Bitbucket Pages"),
    ("netlify.app", "not found - request id", "Netlify"),
]


def _resolve(name, rdtype):
    try:
        return list(dns.resolver.resolve(name, rdtype, lifetime=RESOLVE_TIMEOUT))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.exception.Timeout, dns.resolver.NoNameservers):
        return []
    except Exception:
        return []


def _txt_text(record):
    # dnspython renders TXT rdata with the character-string(s) individually
    # quoted, e.g. '"v=spf1 include:_spf.example.com ~all"' - strip the
    # quotes so substring/prefix checks work against the real content.
    return str(record).replace('"', "").strip()


def _check_caa(hostname):
    # CAA is inherited from the nearest ancestor domain that defines it, so
    # walk up the label tree the same way a validating CA would.
    labels = hostname.split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        records = _resolve(candidate, "CAA")
        if records:
            return records
    return []


def _check_dnssec(hostname):
    # Light, black-box signal: does the zone (or its parent) publish a DS
    # record? A full chain-of-trust validation needs a validating resolver;
    # this is the same first check a manual reviewer runs.
    labels = hostname.split(".")
    if len(labels) < 2:
        return False
    parent = ".".join(labels[1:])
    return bool(_resolve(hostname, "DS")) or bool(_resolve(parent, "DS"))


def _check_spf(hostname):
    for record in _resolve(hostname, "TXT"):
        text = _txt_text(record)
        if text.lower().startswith("v=spf1"):
            return text
    return None


def _check_dmarc(hostname):
    for record in _resolve(f"_dmarc.{hostname}", "TXT"):
        text = _txt_text(record)
        if text.lower().startswith("v=dmarc1"):
            return text
    return None


def _check_takeover(hostname):
    findings = []
    cnames = _resolve(hostname, "CNAME")
    if not cnames:
        return findings

    target = str(cnames[0].target).rstrip(".").lower()
    matching_service = next(
        ((suffix, marker, service) for suffix, marker, service in TAKEOVER_FINGERPRINTS if target.endswith(suffix)),
        None,
    )
    if not matching_service:
        return findings

    suffix, marker, service = matching_service
    try:
        resp = requests.get(f"http://{hostname}/", timeout=HTTP_TIMEOUT, allow_redirects=True)
        if marker in resp.text.lower():
            findings.append({
                "category": "dns",
                "title": f"Possible subdomain takeover via dangling {service} CNAME",
                "severity": "critical",
                "description": (
                    f"'{hostname}' has a CNAME pointing at {target} ({service}), "
                    f"and the response text matches {service}'s \"nothing claimed "
                    "here\" page. If that resource was deleted or never set up, "
                    "anyone else can register it and start serving their own "
                    "content on this hostname - including on a domain your "
                    "visitors already trust."
                ),
                "evidence": f"CNAME {hostname} -> {target}; response body matched \"{marker}\"",
                "recommendation": f"Remove the dangling CNAME record if {service} is unused, or re-claim/re-create the {service} resource it points to.",
            })
    except requests.RequestException:
        # Couldn't confirm over HTTP - still worth a lower-confidence flag,
        # since the CNAME target pattern alone is already a meaningful signal.
        findings.append({
            "category": "dns",
            "title": f"CNAME points at {service} - confirm it's still claimed",
            "severity": "medium",
            "description": (
                f"'{hostname}' has a CNAME pointing at {target} ({service}), "
                "which couldn't be verified over HTTP from here. Dangling "
                "CNAMEs to unclaimed cloud resources are a well-known "
                "subdomain-takeover vector - worth a manual check."
            ),
            "evidence": f"CNAME {hostname} -> {target}",
            "recommendation": f"Confirm the {service} resource is still owned by you; remove the CNAME if it's no longer in use.",
        })

    return findings


def check(ctx):
    findings = []
    hostname = ctx.hostname
    if not hostname:
        return findings

    if not _check_caa(hostname):
        findings.append({
            "category": "dns",
            "title": "No CAA record set",
            "severity": "low",
            "description": (
                "Without a CAA (Certification Authority Authorization) "
                "record, any publicly trusted certificate authority can "
                "issue a certificate for this domain. CAA lets you restrict "
                "issuance to the CA(s) you actually use, so a compromised or "
                "careless CA elsewhere can't mis-issue a certificate for "
                "your name."
            ),
            "evidence": f"No CAA record found on {hostname} or its parent domains",
            "recommendation": 'Add a CAA record, e.g. `example.com. CAA 0 issue "letsencrypt.org"` for the CA(s) you use.',
        })

    if not _check_dnssec(hostname):
        findings.append({
            "category": "dns",
            "title": "DNSSEC does not appear to be enabled",
            "severity": "info",
            "description": (
                "No DS record was found, so DNS responses for this domain "
                "aren't cryptographically signed - a network-level attacker "
                "capable of DNS spoofing could redirect traffic without "
                "detection. Flagged as informational rather than a hard "
                "fail since DNSSEC adoption is still partial industry-wide."
            ),
            "evidence": f"No DS record for {hostname} or its parent",
            "recommendation": "Enable DNSSEC signing at your DNS provider/registrar if your threat model includes DNS-level attackers.",
        })

    spf = _check_spf(hostname)
    if not spf:
        findings.append({
            "category": "dns",
            "title": "No SPF record",
            "severity": "medium",
            "description": "Without SPF, nothing tells receiving mail servers which hosts are allowed to send email as this domain, making spoofed \"from\" addresses easier to pull off.",
            "evidence": f"No 'v=spf1' TXT record on {hostname}",
            "recommendation": 'Publish an SPF record, e.g. `v=spf1 include:_spf.yourprovider.com -all`.',
        })
    elif "+all" in spf.replace(" ", ""):
        findings.append({
            "category": "dns",
            "title": "SPF record allows any server to send mail (+all)",
            "severity": "high",
            "description": "The SPF record ends in '+all', which explicitly authorizes every server on the internet to send mail as this domain - functionally equivalent to not having SPF at all.",
            "evidence": spf,
            "recommendation": "Change the record to end in '-all' (hard fail) after listing your real sending sources.",
        })

    dmarc = _check_dmarc(hostname)
    if not dmarc:
        findings.append({
            "category": "dns",
            "title": "No DMARC record",
            "severity": "medium",
            "description": "Without DMARC, receiving mail servers have no policy to enforce against spoofed email claiming to be from this domain, and you get no visibility when someone tries.",
            "evidence": f"No 'v=DMARC1' TXT record at _dmarc.{hostname}",
            "recommendation": 'Publish a DMARC record, e.g. `v=DMARC1; p=quarantine; rua=mailto:you@yourdomain.com`.',
        })
    elif "p=none" in dmarc.replace(" ", "").lower():
        findings.append({
            "category": "dns",
            "title": "DMARC policy is 'none' (monitoring only)",
            "severity": "low",
            "description": "A 'p=none' policy only requests reports - it doesn't tell mail servers to quarantine or reject spoofed mail.",
            "evidence": dmarc,
            "recommendation": "Move to 'p=quarantine' and eventually 'p=reject' once you've confirmed legitimate senders are covered.",
        })

    findings.extend(_check_takeover(hostname))

    return findings
