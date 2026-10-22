from aisec import cli
from aisec.bundle import write_bundle
from aisec.compliance import coverage, judged_asi
from aisec.drift import drift_packs, fingerprint
from aisec.evidence import RunStore
from aisec.pin import read_pin, write_pin
from aisec.policy import evaluate_policy, load_policy
from aisec.verdicts import EXIT_FAILED, EXIT_OK
from test_report import ATTACK, TARGET
from test_unique_product import _attack


def _pack(tmp_path, run_id, tools, results=None):
    scenario_file = tmp_path / f"{run_id}.yaml"
    scenario_file.write_text("id: s\n", encoding="utf-8")
    store = RunStore(tmp_path / "runs", run_id=run_id)
    store.create()
    store.write_json(
        "target.json",
        {
            **TARGET,
            "run_id": run_id,
            "tool_inventory": tools,
            "tool_list_sha256": "c" * 64,
        },
    )
    store.add_scenario(scenario_file, "s")
    store.write_json(
        "verdict.json",
        {
            "run_id": run_id,
            "results": results or [_attack("refund", "RESISTED", "tools")],
            "summary": {"exit_code": 0},
        },
    )
    store.write_text("report.md", "# report\n")
    store.seal()
    return store.root


REFUND = {"server": "support_desk", "name": "issue_refund", "description": "refund", "input_schema": {}}
EMAIL = {"server": "support_desk", "name": "send_email", "description": "email", "input_schema": {}}


def test_drift_detects_added_removed_and_changed_tools(tmp_path):
    left = _pack(tmp_path, "old", [REFUND, EMAIL])
    right = _pack(
        tmp_path,
        "new",
        [{**REFUND, "description": "refund — now also wires money"}, EMAIL],
    )
    drifted = drift_packs(left, right)
    assert drifted["ok"] is False
    assert drifted["changed"] == ["support_desk/issue_refund"]
    assert fingerprint(REFUND) != fingerprint({**REFUND, "description": "other"})
    assert cli.main(["drift", str(left), str(right)]) == EXIT_FAILED

    dropped = _pack(tmp_path, "dropped", [REFUND])
    gone = drift_packs(left, dropped)
    assert gone["removed"] == ["support_desk/send_email"] and not gone["added"]


def test_policy_fails_tool_drift_against_a_baseline(tmp_path):
    left = _pack(tmp_path, "base", [REFUND])
    right = _pack(tmp_path, "moved", [{**REFUND, "description": "changed"}])
    result = evaluate_policy(right, load_policy(None), baseline=left)
    assert result["ok"] is False
    assert any(v["code"] == "tool_drift" for v in result["violations"])


def test_pin_remembers_the_digest(tmp_path):
    run_dir = _pack(tmp_path, "pin-me", [REFUND])
    pin = tmp_path / "baseline.json"
    payload = write_pin(run_dir, pin)
    assert payload["manifest_sha256"]
    assert read_pin(pin) == run_dir.resolve()
    assert cli.main(["pin", str(run_dir), "--out", str(tmp_path / "cli-pin.json")]) == EXIT_OK


def test_compliance_marks_judged_asi_and_disclaims_certification():
    verdict = {"results": [{**ATTACK, "verdict": "RESISTED", "owasp": ["ASI01", "ASI02"]}]}
    assert judged_asi(verdict) == {"ASI01", "ASI02"}
    rows = {f"{r['framework']} {r['clause']}": r for r in coverage(verdict)}
    assert rows["OWASP ASI ASI01"]["status"] == "covered"
    assert rows["OWASP ASI ASI05"]["status"] == "absent"
    assert "not an Art. 9 conformity" in rows["EU AI Act Art. 9"]["note"]
    assert rows["EU AI Act Art. 9"]["status"] == "partial"


def test_bundle_is_an_auditor_cover_sheet_not_a_certification(tmp_path):
    run_dir = _pack(tmp_path, "bundle-me", [REFUND], [_attack("refund", "RESISTED", "tools")])
    dest = tmp_path / "bundle"
    write_bundle(run_dir, dest)
    page = (dest / "index.html").read_text()
    assert "not a certification" in page
    assert "Independent evidence" in page or "independent evidence" in page
    assert "manifest SHA-256" in page
    assert (dest / "certificate.html").is_file() and (dest / "badge.svg").is_file()
    assert (dest / "graph.md").is_file()
    assert (dest / "flow.md").is_file()
    assert (dest / "attestation.json").is_file()
    assert (dest / "warrant.md").is_file()
    assert (dest / "scope.md").is_file()
    assert (dest / "reproduce.md").is_file()
    assert "Permission graph" in page
    assert "Canary data-flow" in page
    assert "Warrant" in page
    assert "Tool scope" in page
    assert cli.main(["bundle", str(run_dir), "--out", str(tmp_path / "cli-bundle")]) == EXIT_OK
