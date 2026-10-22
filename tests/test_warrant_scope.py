"""Customer warrant, tool scope, and a sealed reproduce recipe — not a model card."""

import hashlib

import yaml

from aisec import cli
from aisec.evidence import RunStore
from aisec.policy import evaluate_policy, load_policy
from aisec.reproduce import reproduce_pack
from aisec.scope import scope_pack
from aisec.verdicts import EXIT_FAILED, EXIT_INCONCLUSIVE, EXIT_OK
from aisec.warrant import warrant_pack
from test_report import COMMAND_TARGET, TARGET
from test_unique_product import _attack, _pack


def _auth(**overrides):
    record = {
        "client": "Northwind Example Ltd.",
        "authorized_by": {"name": "Sam Example", "title": "CTO"},
        "signed_on": "2026-10-09",
        "scope": {
            "agent": "northwind-support",
            "environment": "staging (synthetic data)",
            "servers": ["support_desk"],
            "held_tools": [],
        },
        "window": {
            "start": "2026-10-08T00:00:00+00:00",
            "end": "2026-10-10T00:00:00+00:00",
        },
        "data": "synthetic",
        "contacts": {"emergency_stop": "you@example.com"},
    }
    record.update(overrides)
    return record


def _command_pack(tmp_path, run_id, *, auth=None, started_at=None, events=None, tools=None):
    auth = auth or _auth()
    auth_path = tmp_path / f"{run_id}-authorization.yaml"
    auth_path.write_text(yaml.safe_dump(auth), encoding="utf-8")
    digest = hashlib.sha256(auth_path.read_bytes()).hexdigest()
    scenario_file = tmp_path / f"{run_id}.yaml"
    scenario_file.write_text("id: s\n", encoding="utf-8")
    store = RunStore(tmp_path / "runs", run_id=run_id)
    store.create()
    inner = {
        **COMMAND_TARGET,
        "authorization": {
            **COMMAND_TARGET["authorization"],
            "sha256": digest,
            "client": auth["client"],
            "environment": auth["scope"]["environment"],
            "data": auth["data"],
            "window": auth["window"],
        },
    }
    store.write_json(
        "target.json",
        {
            **TARGET,
            "run_id": run_id,
            "started_at": started_at or TARGET["started_at"],
            "target": inner,
            "tool_inventory": tools
            or [
                {"server": "support_desk", "name": "get_ticket", "description": "", "input_schema": {}},
                {"server": "support_desk", "name": "issue_refund", "description": "", "input_schema": {}},
            ],
        },
    )
    store.add_scenario(scenario_file, "s")
    store.add_file("authorization.yaml", auth_path)
    store.write_json(
        "verdict.json",
        {"run_id": run_id, "results": [_attack("refund", "RESISTED", "tools")], "summary": {"exit_code": 0}},
    )
    store.write_text("report.md", "# report\n")
    for event in events or []:
        store.append("events.jsonl", event)
    store.seal()
    return store.root


def test_demo_warrant_is_synthetic_and_ok(tmp_path):
    run_dir = _pack(tmp_path, "demo-w", "claude-sonnet-5", [_attack("refund", "RESISTED", "tools")])
    warrant = warrant_pack(run_dir)
    assert warrant["ok"] is True
    assert warrant["kind"] == "demo"
    assert warrant["data"] == "synthetic"
    assert cli.main(["warrant", str(run_dir)]) == EXIT_OK


def test_warrant_uses_started_at_not_the_clock(tmp_path):
    run_dir = _command_pack(tmp_path, "in-window")
    warrant = warrant_pack(run_dir)
    assert warrant["ok"] is True
    assert warrant["kind"] == "customer"
    assert warrant["inside_window"] is True
    assert warrant["client"] == "Northwind Example Ltd."
    assert cli.main(["warrant", str(run_dir)]) == EXIT_OK


def test_warrant_fails_a_run_started_outside_the_window(tmp_path):
    run_dir = _command_pack(
        tmp_path,
        "late",
        started_at="2026-10-11T00:00:00+00:00",
    )
    warrant = warrant_pack(run_dir)
    assert warrant["ok"] is False
    assert warrant["inside_window"] is False
    assert any("window" in p for p in warrant["problems"])
    assert cli.main(["warrant", str(run_dir)]) == EXIT_FAILED
    result = evaluate_policy(run_dir, load_policy(None))
    assert result["ok"] is False
    assert any(v["code"] == "authorization" for v in result["violations"])


def test_scope_flags_unused_and_shadow_tools(tmp_path):
    unused_dir = _pack(tmp_path, "unused", "claude-sonnet-5", [_attack("refund", "RESISTED", "tools")])
    unused = scope_pack(unused_dir)
    assert "support_desk/issue_refund" in unused["unused"]
    assert unused["ok"] is True
    assert cli.main(["scope", str(unused_dir)]) == EXIT_OK

    shadow_dir = _command_pack(
        tmp_path,
        "shadow",
        events=[
            {
                "kind": "call",
                "server": "support_desk",
                "tool": "send_email",
                "outcome": "ok",
                "scenario": "s",
                "arm": "trial",
            }
        ],
    )
    shadow = scope_pack(shadow_dir)
    assert "support_desk/send_email" in shadow["shadow"]
    assert "support_desk/get_ticket" in shadow["unused"]
    assert shadow["ok"] is False
    assert cli.main(["scope", str(shadow_dir)]) == EXIT_FAILED
    result = evaluate_policy(shadow_dir, load_policy(None))
    assert any(v["code"] == "shadow_tool" for v in result["violations"])


def test_reproduce_is_a_sealed_recipe_without_keys(tmp_path):
    demo = _pack(tmp_path, "repro-demo", "claude-sonnet-5", [_attack("refund", "RESISTED", "tools")])
    recipe = reproduce_pack(demo)
    assert recipe["complete"] is True
    assert "--target demo" in recipe["command"]
    assert "--variant fixed" in recipe["command"]
    assert str(demo / "scenarios") in recipe["command"]
    assert "ANTHROPIC" not in recipe["command"]
    assert "OPENAI" not in recipe["command"]
    assert cli.main(["reproduce", str(demo)]) == EXIT_OK

    command = _command_pack(tmp_path, "repro-cmd")
    incomplete = reproduce_pack(command)
    assert incomplete["complete"] is False
    assert "--target command" in incomplete["command"]
    assert cli.main(["reproduce", str(command)]) == EXIT_INCONCLUSIVE
