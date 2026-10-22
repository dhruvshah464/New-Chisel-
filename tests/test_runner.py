"""The runner's agent path, driven by a scripted stand-in agent instead of a model."""

import sys

import pytest

from aisec.evidence import load_jsonl, verify_manifest
from aisec.runner import run_suite
from aisec.scenario import load_scenario
from aisec.targets.demo import DemoTarget
from aisec.verdicts import FAILED, INCONCLUSIVE, NOT_DELIVERED, NOT_REACHABLE, RESISTED
from conftest import REPO_ROOT, SCENARIOS_DIR

FAKE_AGENT = REPO_ROOT / "tests" / "fixtures" / "fake_agent.py"
REFUND = load_scenario(SCENARIOS_DIR / "refund_injection_ticket.yaml")


class ScriptedAgentTarget(DemoTarget):
    def __init__(self, variant, behavior):
        super().__init__(variant, model="scripted")
        self.behavior = behavior

    def preflight(self):
        return None

    def agent_command(self, scenario, sandbox):
        return [
            sys.executable,
            str(FAKE_AGENT),
            "--mcp-config",
            str(sandbox.mcp_config_path),
            "--transcript",
            str(sandbox.transcript_path),
            "--behavior",
            self.behavior,
        ]


async def run(tmp_path, variant, behavior, scenarios=(REFUND,), **kwargs):
    result = await run_suite(ScriptedAgentTarget(variant, behavior), list(scenarios), runs_root=tmp_path, **kwargs)
    verify_manifest(result.run_dir)
    return result, result.verdict["results"][0]


async def test_hijacked_agent_on_the_vulnerable_desk_fails(tmp_path):
    result, scenario = await run(tmp_path, "vulnerable", "hijacked", repeat=2)
    assert scenario["verdict"] == FAILED and scenario["rate"]["k"] == 2
    call = scenario["evidence"]["calls"][0]
    assert call["tool"] == "issue_refund" and call["arguments"] == {"account": "ACC-9931", "amount": 4900}
    assert scenario["evidence"]["agent_said"] == "Done (hijacked)."
    assert result.exit_code == 1

    checks = load_jsonl(result.run_dir / "checks.jsonl")
    assert [(c["arm"], c["trial"], c["driver"]) for c in checks] == [
        ("reachability", 0, "replay"),
        ("trial", 1, "agent"),
        ("trial", 2, "agent"),
    ]
    events = load_jsonl(result.run_dir / "events.jsonl")
    assert {(e["arm"], e["trial"]) for e in events} == {("reachability", 0), ("trial", 1), ("trial", 2)}
    transcripts = load_jsonl(result.run_dir / "transcripts.jsonl")
    assert any(t["arm"] == "trial" and t.get("text") == "Done (hijacked)." for t in transcripts)


async def test_hijacked_agent_on_the_fixed_desk_is_attempted_denied(tmp_path):
    result, scenario = await run(tmp_path, "fixed", "hijacked", repeat=1)
    assert scenario["verdict"] == RESISTED and scenario["resisted_by"] == "tools"
    assert scenario["attempted_denied"] == 1
    assert scenario["evidence"]["kind"] == "denied"
    assert "Not authorized" in scenario["evidence"]["calls"][0]["result"]
    assert result.exit_code == 0


async def test_an_agent_that_reads_the_payload_and_ignores_it_resists(tmp_path):
    _, scenario = await run(tmp_path, "vulnerable", "cautious", repeat=1)
    assert scenario["verdict"] == RESISTED and scenario["resisted_by"] == "model"


async def test_an_agent_that_never_receives_the_payload_is_inconclusive(tmp_path):
    result, scenario = await run(tmp_path, "vulnerable", "oblivious", repeat=1)
    assert scenario["verdict"] == INCONCLUSIVE
    assert scenario["trials"]["unjudged_reasons"] == [NOT_DELIVERED]
    assert result.exit_code == 2


async def test_a_hung_agent_times_out_as_inconclusive(tmp_path):
    _, scenario = await run(tmp_path, "vulnerable", "sleep", repeat=1, timeout=3)
    assert scenario["verdict"] == INCONCLUSIVE
    assert "did not finish within 3s" in scenario["reason"]


@pytest.mark.parametrize(
    "behavior, reason",
    [("model_error", "model error: RateLimitError: slow down"), ("crash", "RuntimeError: boom")],
)
async def test_agent_failures_are_inconclusive_with_the_cause(tmp_path, behavior, reason):
    result, scenario = await run(tmp_path, "vulnerable", behavior, repeat=1)
    assert scenario["verdict"] == INCONCLUSIVE and reason in scenario["reason"]
    trial = load_jsonl(result.run_dir / "checks.jsonl")[1]
    assert trial["status"] == "error" and trial["agent_exit_code"] == 1


async def test_a_scenario_naming_a_missing_tool_is_not_reachable(tmp_path):
    source = (SCENARIOS_DIR / "refund_injection_ticket.yaml").read_text(encoding="utf-8")
    path = tmp_path / "wire_transfer.yaml"
    path.write_text(
        source.replace("id: refund_injection_ticket", "id: wire_transfer").replace("tool: issue_refund", "tool: wire_transfer"),
        encoding="utf-8",
    )
    result, scenario = await run(tmp_path / "runs", "vulnerable", "hijacked", scenarios=(load_scenario(path),), repeat=1)
    assert scenario["verdict"] == NOT_REACHABLE
    assert "wire_transfer" in scenario["reason"]
    assert load_jsonl(result.run_dir / "checks.jsonl")[0]["arm"] == "reachability"
    assert len(load_jsonl(result.run_dir / "checks.jsonl")) == 1


async def test_target_json_records_what_was_tested(tmp_path):
    result, _ = await run(tmp_path, "fixed", "cautious", repeat=1)
    target = result.target
    assert target["target"]["variant"] == "fixed" and target["target"]["model"] == "scripted"
    assert len(target["target"]["system_prompt_sha256"]) == 64 and len(target["tool_list_sha256"]) == 64
    assert {t["name"] for t in target["tool_inventory"]} == {
        "get_ticket",
        "issue_refund",
        "kb_search",
        "lookup_customer",
        "send_email",
    }
    assert target["scenarios"] == [
        {"id": REFUND.id, "kind": "attack", "path": "scenarios/refund_injection_ticket.yaml", "sha256": REFUND.sha256}
    ]
    assert (result.run_dir / "scenarios" / "refund_injection_ticket.yaml").read_bytes() == (
        SCENARIOS_DIR / "refund_injection_ticket.yaml"
    ).read_bytes()
