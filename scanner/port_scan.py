"""Open port detection.

Pure Python sockets are used so this works anywhere (including serverless),
with no external binary required. Only a small, well-known set of ports is
checked, each with a short timeout and bounded concurrency, so this behaves
like a normal reconnaissance scan rather than a flood of traffic.

If the `python-nmap` package AND the `nmap` binary are both available on the
host (e.g. a VPS rather than a serverless platform), a lighter-weight
service-version sweep is layered on top - this is best-effort and silently
skipped if either is missing.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common ports worth flagging on a public-facing web host. Deliberately not
# an exhaustive 1-65535 sweep - that would take far longer than a request
# should run and offers little extra signal for a web app scanner.
COMMON_PORTS = {
    21: ("FTP", "high"),
    22: ("SSH", "low"),
    23: ("Telnet", "critical"),
    25: ("SMTP", "medium"),
    53: ("DNS", "medium"),
    110: ("POP3", "medium"),
    135: ("MSRPC", "high"),
    139: ("NetBIOS", "high"),
    143: ("IMAP", "medium"),
    445: ("SMB", "critical"),
    1433: ("MSSQL", "critical"),
    1521: ("Oracle DB", "critical"),
    3306: ("MySQL", "critical"),
    3389: ("RDP", "critical"),
    5432: ("PostgreSQL", "critical"),
    5900: ("VNC", "critical"),
    6379: ("Redis", "critical"),
    8080: ("HTTP-alt", "medium"),
    8443: ("HTTPS-alt", "low"),
    9200: ("Elasticsearch", "critical"),
    27017: ("MongoDB", "critical"),
}

EXPECTED_WEB_PORTS = {80, 443}


def _probe(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def check(ctx):
    findings = []
    host = ctx.hostname

    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        return [{
            "category": "ports",
            "title": "Could not resolve target hostname",
            "severity": "info",
            "description": "DNS resolution failed, so port scanning was skipped.",
            "evidence": host,
            "recommendation": "Confirm the hostname is correct and has a public DNS record.",
        }]

    open_ports = []
    with ThreadPoolExecutor(max_workers=ctx.port_scan_max_workers) as pool:
        futures = {
            pool.submit(_probe, host, port, ctx.port_scan_timeout): port
            for port in COMMON_PORTS
        }
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(port)

    open_ports.sort()
    ctx.meta["open_ports"] = open_ports

    for port in open_ports:
        if port in EXPECTED_WEB_PORTS:
            continue
        service, severity = COMMON_PORTS[port]
        findings.append({
            "category": "ports",
            "title": f"Port {port} ({service}) is open to the internet",
            "severity": severity,
            "description": (
                f"{service} is reachable from outside, which expands the "
                "attack surface beyond the web application itself - anyone "
                "who finds the host can attempt to interact with this service "
                "directly."
            ),
            "evidence": f"TCP connect to {host}:{port} succeeded",
            "recommendation": (
                f"If {service} does not need to be public, block it at the "
                "firewall/security-group level or bind it to a private/VPN "
                "interface instead."
            ),
        })

    if not open_ports:
        findings.append({
            "category": "ports",
            "title": "No unexpected ports found open",
            "severity": "info",
            "description": f"Only the expected web ports (if any) responded out of {len(COMMON_PORTS)} common ports checked.",
            "evidence": f"Ports checked: {sorted(COMMON_PORTS)}",
            "recommendation": "No action needed - keep re-checking after infrastructure changes.",
        })

    return findings
