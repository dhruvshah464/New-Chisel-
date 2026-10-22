"""Framework coverage of a pack — what was judged, not a certification.

OpenAI can map GPT evals to a safety card it wrote. It cannot map *your* tool-boundary
tests to OWASP ASI, the EU AI Act, NIST AI RMF, ISO/IEC 42001 or AIUC-1 as third-party
evidence, and it will not print the gaps. This overlay always says it is not a certificate
of conformity.
"""

from __future__ import annotations

from typing import Any

from .scenario import OWASP_ASI
from .verdicts import FAILED, RESISTED

CLAUSES: tuple[dict[str, Any], ...] = (
    *tuple(
        {
            "framework": "OWASP ASI",
            "clause": code,
            "title": title,
            "asi": (code,),
            "note": "Judged in this pack if a scenario mapped to this code was FAILED or RESISTED.",
        }
        for code, title in OWASP_ASI.items()
    ),
    {
        "framework": "EU AI Act",
        "clause": "Art. 9",
        "title": "Risk management system",
        "asi": tuple(OWASP_ASI),
        "note": "This pack is a risk-test record of the scenarios that ran. It is not an Art. 9 conformity assessment.",
    },
    {
        "framework": "EU AI Act",
        "clause": "Art. 15",
        "title": "Accuracy, robustness, cybersecurity",
        "asi": ("ASI02", "ASI03", "ASI04", "ASI05"),
        "note": "Tool-use robustness and cybersecurity only. Model accuracy is out of scope.",
    },
    {
        "framework": "NIST AI RMF",
        "clause": "MEASURE",
        "title": "Measure",
        "asi": tuple(OWASP_ASI),
        "note": "Measurement of agent tool-use under attack, not of foundation-model capabilities.",
    },
    {
        "framework": "ISO/IEC 42001",
        "clause": "8.2",
        "title": "AI operation / risk treatment",
        "asi": ("ASI02", "ASI03", "ASI04"),
        "note": "Evidence that tool-boundary controls were exercised. Not an ISO certification.",
    },
    {
        "framework": "AIUC-1",
        "clause": "Agent tool use",
        "title": "Unauthorized tool use and data movement",
        "asi": ("ASI01", "ASI02", "ASI03"),
        "note": "Control evidence at the tool boundary. Not an AIUC-1 certification.",
    },
)


def judged_asi(verdict: dict[str, Any]) -> set[str]:
    codes: set[str] = set()
    for item in verdict.get("results") or []:
        if item.get("kind") != "attack":
            continue
        if item.get("verdict") not in (FAILED, RESISTED):
            continue
        codes.update(item.get("owasp") or [])
    return codes


def coverage(verdict: dict[str, Any]) -> list[dict[str, Any]]:
    present = judged_asi(verdict)
    rows = []
    for clause in CLAUSES:
        needed = list(clause["asi"])
        hit = [code for code in needed if code in present]
        miss = [code for code in needed if code not in present]
        if not needed:
            status = "absent"
        elif not miss:
            status = "covered"
        elif hit:
            status = "partial"
        else:
            status = "absent"
        rows.append(
            {
                "framework": clause["framework"],
                "clause": clause["clause"],
                "title": clause["title"],
                "status": status,
                "judged": hit,
                "missing": miss,
                "note": clause["note"],
            }
        )
    return rows
