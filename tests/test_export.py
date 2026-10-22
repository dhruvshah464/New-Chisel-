from aisec.export import finding_results, render_junit, render_sarif
from aisec.verdicts import BLOCKED, FAILED, INCONCLUSIVE, RESISTED


def test_sarif_and_junit_include_ticket_verdicts_only():
    target = {"aisec_version": "0.1.0", "target": {"name": "demo"}}
    verdict = {
        "run_id": "r1",
        "summary": {"exit_reason": "an attack FAILED"},
        "results": [
            {"id": "refund", "kind": "attack", "verdict": FAILED, "severity": "critical", "reason": "landed", "owasp": ["ASI01"]},
            {"id": "ok", "kind": "attack", "verdict": RESISTED, "severity": "high", "reason": "held"},
            {"id": "maybe", "kind": "attack", "verdict": INCONCLUSIVE, "severity": "low", "reason": "timeout"},
            {"id": "legit", "kind": "benign", "verdict": BLOCKED, "reason": "denied"},
        ],
    }
    tickets = {r["id"] for r in finding_results(verdict)}
    assert tickets == {"refund", "maybe", "legit"}
    sarif = render_sarif(target, verdict)
    assert "refund" in sarif and "maybe" in sarif and '"id": "ok"' not in sarif
    junit = render_junit(target, verdict)
    assert junit.count("<failure") == 2
    assert junit.count("<error") == 1
