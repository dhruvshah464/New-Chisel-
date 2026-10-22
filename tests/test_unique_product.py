"""The pieces a model vendor structurally cannot ship: certificate, compare, init, OpenAI-compat."""

import json

from aisec import cli
from aisec.certificate import attribution, write_certificate
from aisec.compare import compare_packs, render_compare_markdown
from aisec.evidence import RunStore, verify_manifest
from aisec.init_cmd import write_init
from aisec.providers import from_openai_response, to_openai_messages, to_openai_tools
from aisec.targets.demo import DemoTarget
from test_report import ATTACK, TARGET, render


def _attack(scenario_id, verdict, resisted_by=None):
    item = {**ATTACK, "id": scenario_id, "verdict": verdict, "resisted_by": resisted_by}
    return item


def _pack(tmp_path, run_id, model, results):
    scenario_file = tmp_path / f"{run_id}.yaml"
    scenario_file.write_text("id: s\n", encoding="utf-8")
    store = RunStore(tmp_path / "runs", run_id=run_id)
    store.create()
    store.write_json("target.json", {**TARGET, "run_id": run_id, "target": {**TARGET["target"], "model": model}})
    store.add_scenario(scenario_file, "s")
    store.write_json("verdict.json", {"run_id": run_id, "results": results, "summary": {"exit_code": 0}})
    store.write_text("report.md", "# report\n")
    store.seal()
    return store.root


def test_certificate_names_the_issuer_and_attribution(tmp_path):
    run_dir = _pack(
        tmp_path,
        "run-cert",
        "claude-sonnet-5",
        [_attack("refund", "RESISTED", "tools"), _attack("email", "FAILED")],
    )
    html = write_certificate(run_dir)
    assert "Independent Evidence Certificate" in html
    assert "not by the model vendor" in html
    assert "Attacks stopped by tools: 1" in html
    assert verify_manifest(run_dir)
    counts = attribution({"results": [_attack("refund", "RESISTED", "tools")]})
    assert counts["tools"] == 1 and counts["failed"] == 0


def test_compare_separates_tool_fixes_from_model_splits_and_regressions(tmp_path):
    left = _pack(
        tmp_path,
        "left",
        "claude-sonnet-5",
        [
            _attack("refund", "RESISTED", "tools"),
            _attack("poison", "RESISTED", "model"),
            _attack("lookup", "RESISTED", "tools"),
        ],
    )
    right = _pack(
        tmp_path,
        "right",
        "gpt-4o-mini",
        [
            _attack("refund", "RESISTED", "tools"),
            _attack("poison", "RESISTED", "tools"),
            _attack("lookup", "FAILED"),
        ],
    )
    compared = compare_packs(left, right)
    assert compared["tool_fixes_that_held_on_both"] == ["refund"]
    assert compared["model_only_splits"] == ["poison"]
    assert compared["regressions"] == ["lookup"]
    md = render_compare_markdown(compared)
    assert "vendor-neutral comparison" in md and "lookup" in md
    assert cli.main(["compare", str(left), str(right)]) == 0


def test_init_writes_target_and_authorization_from_mcp(tmp_path):
    mcp = tmp_path / "mcp.json"
    mcp.write_text(json.dumps({"mcpServers": {"support_desk": {"command": "python"}, "kb": {"command": "python"}}}))
    out = tmp_path / "out"
    assert cli.main(["init", "--mcp", str(mcp), "--out", str(out), "--name", "acme"]) == 0
    target = (out / "aisec-target.yaml").read_text()
    auth = (out / "authorization.yaml").read_text()
    assert "name: acme" in target and "{task}" in target
    assert "support_desk" in auth and "kb" in auth and "you@example.com" in auth
    written = write_init(mcp, out / "again", name="acme")
    assert written["servers"] == ["kb", "support_desk"]


def test_openai_compat_shapes_anthropic_tools_and_messages():
    tools = to_openai_tools([{"name": "issue_refund", "description": "refund", "input_schema": {"type": "object"}}])
    assert tools[0]["function"]["name"] == "issue_refund"
    messages = to_openai_messages(
        "sys",
        [
            {"role": "user", "content": "handle the ticket"},
            {
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "1", "name": "get_ticket", "input": {"id": "T-1"}}],
            },
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "1", "content": "ok"}]},
        ],
    )
    assert messages[0]["role"] == "system"
    assert messages[-1] == {"role": "tool", "tool_call_id": "1", "content": "ok"}
    shaped = from_openai_response(
        {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "tool_calls": [
                            {"id": "c1", "function": {"name": "issue_refund", "arguments": '{"amount": 1}'}}
                        ]
                    },
                }
            ],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2},
        }
    )
    assert shaped.stop_reason == "tool_use" and shaped.content[0].name == "issue_refund"


def test_openai_provider_preflight_asks_for_openai_key(monkeypatch):
    monkeypatch.setenv("AISEC_PROVIDER", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert "OPENAI_API_KEY" in DemoTarget().preflight()


def test_report_declares_independence_from_model_vendors():
    md, page = render([ATTACK])
    assert "Independent of the model vendor" in md
    assert "New Chisel Independent Evidence" in md
    assert "not OpenAI" in md
    assert "Independent of the model vendor" in page
