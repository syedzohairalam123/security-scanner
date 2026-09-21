"""SSL/TLS certificate and protocol inspection.

Uses only the Python standard library (ssl + socket) so there is no extra
dependency to bundle: opens a real TLS handshake to the host, reads back the
negotiated protocol/cipher and the peer certificate, and flags common
misconfigurations (expired/expiring certs, weak protocol versions, missing
hostname coverage, self-signed certs presented on a public site).
"""

import socket
import ssl
from datetime import datetime, timezone

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
EXPIRY_WARNING_DAYS = 21


def _parse_asn1_date(value):
    # Certificates encode dates like 'Jun  9 00:00:00 2026 GMT'
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def check(ctx):
    findings = []
    hostname = ctx.hostname
    port = ctx.port if ctx.scheme == "https" else 443

    if ctx.scheme != "https":
        findings.append({
            "category": "tls",
            "title": "Site is served over plain HTTP",
            "severity": "critical",
            "description": (
                "The target was reached over HTTP rather than HTTPS, so all "
                "traffic - including any login forms - is sent unencrypted and "
                "can be read or modified in transit."
            ),
            "evidence": f"Target URL scheme: http:// ({ctx.url})",
            "recommendation": "Obtain a TLS certificate (e.g. via Let's Encrypt) and redirect all HTTP traffic to HTTPS.",
        })
        # Still worth checking whether HTTPS is available at all on 443.

    ctx_ssl = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=ctx.timeout) as sock:
            with ctx_ssl.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                protocol = tls_sock.version()
                cipher_name, _, cipher_bits = tls_sock.cipher()
    except ssl.SSLCertVerificationError as e:
        findings.append({
            "category": "tls",
            "title": "TLS certificate failed validation",
            "severity": "critical",
            "description": (
                "The certificate presented by the server is not trusted by a "
                "standard certificate store (self-signed, wrong hostname, "
                "expired, or issued by an unknown CA). Browsers will show a "
                "hard warning to every visitor."
            ),
            "evidence": str(e),
            "recommendation": "Install a valid certificate from a publicly trusted CA covering the exact hostname(s) in use.",
        })
        return findings
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        findings.append({
            "category": "tls",
            "title": "Could not establish a TLS connection on port 443",
            "severity": "info",
            "description": "The scanner could not complete a TLS handshake with the target.",
            "evidence": str(e),
            "recommendation": "Confirm HTTPS is enabled and port 443 is reachable from the public internet.",
        })
        return findings

    if protocol in WEAK_PROTOCOLS:
        findings.append({
            "category": "tls",
            "title": f"Outdated TLS protocol negotiated ({protocol})",
            "severity": "high",
            "description": (
                f"The server accepted a handshake using {protocol}, which has "
                "known cryptographic weaknesses and is deprecated by every "
                "major browser."
            ),
            "evidence": f"Negotiated protocol: {protocol}",
            "recommendation": "Disable SSLv3/TLSv1.0/TLSv1.1 in your web server config and require TLS 1.2 or newer.",
        })

    if cipher_bits and cipher_bits < 128:
        findings.append({
            "category": "tls",
            "title": "Weak cipher suite negotiated",
            "severity": "high",
            "description": f"The negotiated cipher '{cipher_name}' uses a key strength below modern standards.",
            "evidence": f"Cipher: {cipher_name} ({cipher_bits}-bit)",
            "recommendation": "Restrict the server's cipher list to modern AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
        })

    # Expiry check
    not_after = cert.get("notAfter")
    if not_after:
        expires_at = _parse_asn1_date(not_after)
        days_left = (expires_at - datetime.now(timezone.utc)).days
        if days_left < 0:
            findings.append({
                "category": "tls",
                "title": "TLS certificate has expired",
                "severity": "critical",
                "description": "The certificate's validity period has already ended.",
                "evidence": f"notAfter: {not_after}",
                "recommendation": "Renew the certificate immediately (or automate renewal, e.g. certbot with a cron/systemd timer).",
            })
        elif days_left <= EXPIRY_WARNING_DAYS:
            findings.append({
                "category": "tls",
                "title": f"TLS certificate expires soon ({days_left} days)",
                "severity": "medium",
                "description": "The certificate is close to its expiry date; an outage will occur if it is not renewed in time.",
                "evidence": f"notAfter: {not_after}",
                "recommendation": "Renew the certificate and, if not already in place, automate future renewals.",
            })

    # Hostname coverage (defence in depth - wrap_socket already validated this
    # when a default context is used, but we surface it explicitly for the report)
    san_list = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    if san_list:
        findings.append({
            "category": "tls",
            "title": "Certificate hostname coverage",
            "severity": "info",
            "description": "Hostnames covered by the presented certificate, for reference.",
            "evidence": f"SAN: {', '.join(san_list)}",
            "recommendation": "Confirm this list matches every hostname you actually serve.",
        })

    ctx.meta["tls_protocol"] = protocol
    ctx.meta["tls_cipher"] = cipher_name
    return findings
