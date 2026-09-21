"""Optional "ask about this scan" assistant.

Real integration with the Anthropic Messages API - not a mock. Disabled
gracefully wherever ANTHROPIC_API_KEY is not set, so the rest of the app
works fully without it. Get a key at https://console.anthropic.com and set
it as an environment variable; this feature makes real, billed API calls
once configured. See docs.claude.com for current models/pricing.
"""

import requests

from config import Config

API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"

SYSTEM_PROMPT = (
    "You are a security engineer explaining the results of an automated "
    "vulnerability scan to the person who ran it, on a site they own or are "
    "authorized to test. You are given the scan's findings as structured "
    "text below - answer only using that data, and say so plainly if the "
    "findings don't cover what was asked. Explain risk in plain language "
    "and give concrete, specific remediation steps. Be concise. If asked how "
    "to exploit, attack, or gain unauthorized access rather than fix an "
    "issue, decline and redirect the answer toward remediation."
)

MAX_FINDINGS_IN_CONTEXT = 40


def is_configured() -> bool:
    return bool(Config.ANTHROPIC_API_KEY)


def _findings_context(scan) -> str:
    lines = [
        f"Target: {scan.target_url}",
        f"Risk score: {scan.risk_score}/100 ({scan.risk_level})",
        f"Findings ({len(scan.findings)} total):",
    ]
    for f in scan.findings[:MAX_FINDINGS_IN_CONTEXT]:
        lines.append(
            f"- [{f.severity.upper()}] {f.title} | {f.description} | Evidence: {f.evidence}"
        )
    return "\n".join(lines)


def ask_about_scan(scan, question: str, timeout: float = 25) -> str:
    if not is_configured():
        raise RuntimeError("ANTHROPIC_API_KEY is not set.")

    user_message = f"{_findings_context(scan)}\n\nQuestion: {question.strip()}"

    response = requests.post(
        API_URL,
        headers={
            "x-api-key": Config.ANTHROPIC_API_KEY,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        },
        json={
            "model": Config.ANTHROPIC_MODEL,
            "max_tokens": 700,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_message}],
        },
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()
    text_blocks = [block["text"] for block in data.get("content", []) if block.get("type") == "text"]
    return "\n".join(text_blocks).strip() or "The assistant didn't return an answer - try rephrasing."
