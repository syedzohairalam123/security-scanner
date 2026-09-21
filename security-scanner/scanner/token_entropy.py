"""Session token randomness analysis.

Real Shannon entropy (bits of randomness per character) on cookie/session
token values - the same basic statistical test used by tools like Burp
Suite's Sequencer. A short, low-entropy, or obviously-structured token
(sequential IDs, base64 of a predictable string, timestamps) is a strong
signal that session identifiers could be guessed or brute-forced.

This only reads values the server already sent back to us in Set-Cookie
headers; it does not attempt to guess or forge any token.
"""

import math
import re
from collections import Counter

MIN_LENGTH_TO_ANALYZE = 4  # below this there's nothing meaningful to measure
LOW_ENTROPY_BITS_PER_CHAR = 3.0  # below this, the token is suspiciously repetitive
SHORT_TOKEN_LENGTH = 16


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _looks_like_session_cookie(name: str) -> bool:
    name = name.lower()
    return any(k in name for k in ("session", "sid", "token", "auth", "id"))


def check(ctx):
    findings = []
    resp = ctx.homepage_response
    if resp is None:
        return findings

    try:
        raw_cookies = resp.raw.headers.get_all("Set-Cookie") or []
    except AttributeError:
        single = resp.headers.get("Set-Cookie")
        raw_cookies = [single] if single else []

    for raw in raw_cookies:
        name_value = raw.split(";")[0]
        if "=" not in name_value:
            continue
        name, value = name_value.split("=", 1)
        name, value = name.strip(), value.strip()

        # Only analyze cookies that look like a session/auth identifier -
        # a short, low-entropy value in an unrelated cookie (e.g. a UI
        # preference flag) isn't a security finding.
        if not _looks_like_session_cookie(name) or len(value) < MIN_LENGTH_TO_ANALYZE:
            continue

        bits_per_char = shannon_entropy(value)
        total_bits = bits_per_char * len(value)
        is_purely_numeric = bool(re.fullmatch(r"\d+", value))
        is_sequential_looking = bool(re.fullmatch(r"[A-Za-z]*\d{1,6}", value)) and len(value) < 12

        if is_purely_numeric or is_sequential_looking:
            # Checked first and independent of length/entropy: a short
            # numeric-looking identifier is exactly the failure mode this
            # check exists to catch, regardless of how many bits/char it
            # technically measures at.
            findings.append({
                "category": "token_entropy",
                "title": f"Cookie '{name}' looks sequential/predictable",
                "severity": "high",
                "description": (
                    "The token is short and numeric-looking rather than a "
                    "long, random string, which suggests session IDs may be "
                    "assigned in a guessable or incrementing pattern."
                ),
                "evidence": f"{name}={value} (length: {len(value)} chars)",
                "recommendation": "Generate session identifiers with a cryptographically secure random generator (e.g. secrets.token_urlsafe(32)), never sequential or timestamp-derived values.",
            })
        elif len(value) < SHORT_TOKEN_LENGTH or bits_per_char < LOW_ENTROPY_BITS_PER_CHAR:
            findings.append({
                "category": "token_entropy",
                "title": f"Cookie '{name}' has low randomness",
                "severity": "medium",
                "description": (
                    f"Measured at roughly {bits_per_char:.1f} bits of entropy per "
                    f"character over {len(value)} characters (~{total_bits:.0f} bits "
                    "total). For comparison, a properly random 32-byte session "
                    "token provides 256 bits. Lower entropy narrows the space an "
                    "attacker needs to search to guess a valid session."
                ),
                "evidence": f"{name}: length={len(value)}, ~{bits_per_char:.2f} bits/char, ~{total_bits:.0f} bits total",
                "recommendation": "Use a longer, cryptographically random token (32+ random bytes, e.g. secrets.token_urlsafe(32)).",
            })
        else:
            findings.append({
                "category": "token_entropy",
                "title": f"Cookie '{name}' randomness looks adequate",
                "severity": "info",
                "description": "No obvious weakness in this token's randomness from a black-box check.",
                "evidence": f"{name}: length={len(value)}, ~{bits_per_char:.2f} bits/char, ~{total_bits:.0f} bits total",
                "recommendation": "No action needed.",
            })

    return findings
