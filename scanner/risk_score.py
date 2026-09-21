"""Turns a list of findings into a single 0-100 risk score and a risk level.

The formula is deliberately simple and easy to defend/explain: each finding
contributes a fixed weight for its severity, weights are summed, and the sum
is passed through a saturating curve (1 - e^-x) so that, say, going from 1 to
2 critical findings still matters but the score doesn't blow past 100 the
moment a handful of issues are present. There is no hidden "AI model" here -
just arithmetic, so a reviewer can recompute it by hand from the findings
list.
"""

import math

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 6,
    "medium": 3,
    "low": 1,
    "info": 0.25,
}

# How quickly the curve saturates towards 100. Roughly: one critical alone
# lands in the mid-30s, two criticals plus a couple of highs lands you in
# "high" territory, and a wide spread of issues pushes you towards 100.
SATURATION_CONSTANT = 22.0

LEVEL_THRESHOLDS = [
    (75, "critical"),
    (50, "high"),
    (25, "medium"),
    (5, "low"),
]


def compute(findings):
    if not findings:
        return 0.0, "info"

    raw = sum(SEVERITY_WEIGHTS.get(f.get("severity", "info"), 0) for f in findings)
    score = 100 * (1 - math.exp(-raw / SATURATION_CONSTANT))
    score = round(score, 1)

    has_critical_finding = any(f.get("severity") == "critical" for f in findings)

    level = "info"
    for threshold, label in LEVEL_THRESHOLDS:
        if score >= threshold:
            level = label
            break
    if has_critical_finding and level not in ("critical", "high"):
        level = "high"  # a single critical finding should never be under-stated as "medium" or lower

    return score, level
