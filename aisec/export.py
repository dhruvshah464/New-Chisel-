"""SARIF and JUnit views of a sealed run, for GitHub code scanning and CI.

These files are written into the pack before sealing so they are hashed with
everything else. They are derived from verdict.json; they are not a second
source of truth.
"""

from __future__ import annotations

from typing import Any
from xml.sax.saxutils import escape

from .verdicts import BLOCKED, FAILED, INCONCLUSIVE

SARIF_LEVEL = {"low": "note", "medium": "warning", "high": "error", "critical": "error"}
TICKET_VERDICTS = {FAILED, INCONCLUSIVE, BLOCKED}


def finding_results(verdict: dict[str, Any]) -> list[dict[str, Any]]:
    """Scenarios that should open a finding ticket."""
    return [r for r in verdict.get("results") or [] if r.get("verdict") in TICKET_VERDICTS]


def render_sarif(target: dict[str, Any], verdict: dict[str, Any]) -> str:
    import json

    results = []
    for item in finding_results(verdict):
        level = SARIF_LEVEL.get(item.get("severity") or "medium", "warning")
        message = item.get("reason") or item["verdict"]
        results.append(
            {
                "ruleId": item["id"],
                "level": level,
                "message": {"text": f"{item['verdict']}: {message}"},
                "properties": {
                    "verdict": item["verdict"],
                    "severity": item.get("severity"),
                    "owasp": item.get("owasp") or [],
                    "kind": item.get("kind"),
                },
            }
        )
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aisec",
                        "version": target.get("aisec_version") or "",
                        "informationUri": "https://github.com/dhruvshah464/ai-sec-check",
                    }
                },
                "results": results,
                "properties": {
                    "run_id": verdict.get("run_id"),
                    "summary": (verdict.get("summary") or {}).get("exit_reason"),
                },
            }
        ],
    }
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_junit(target: dict[str, Any], verdict: dict[str, Any]) -> str:
    results = list(verdict.get("results") or [])
    failures = [r for r in results if r.get("verdict") in {FAILED, BLOCKED}]
    errors = [r for r in results if r.get("verdict") == INCONCLUSIVE]
    cases = []
    for item in results:
        name = escape(str(item.get("id") or "scenario"))
        verdict_name = escape(str(item.get("verdict") or ""))
        reason = escape(str(item.get("reason") or ""))
        body = f'    <testcase name="{name}" classname="aisec">\n'
        if item.get("verdict") in {FAILED, BLOCKED}:
            body += f'      <failure message="{verdict_name}">{reason}</failure>\n'
        elif item.get("verdict") == INCONCLUSIVE:
            body += f'      <error message="{verdict_name}">{reason}</error>\n'
        body += "    </testcase>"
        cases.append(body)
    suite_name = escape(str((target.get("target") or {}).get("name") or "aisec"))
    header = (
        f'<testsuite name="{suite_name}" tests="{len(results)}" '
        f'failures="{len(failures)}" errors="{len(errors)}">'
    )
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + header + "\n" + "\n".join(cases) + "\n</testsuite>\n"
