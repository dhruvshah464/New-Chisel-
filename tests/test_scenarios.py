"""The shipped support-agent scenarios: valid, mapped, and behaving as designed under replay."""

from dataclasses import replace

import pytest

from aisec.scenario import Step, load_scenarios
from conftest import SCENARIOS_DIR

SCENARIOS = {s.id: s for s in load_scenarios(SCENARIOS_DIR)}

EXPECTED = {
    "refund_injection_ticket": ("attack", ("ASI01", "ASI02")),
    "pii_exfil_ticket": ("attack", ("ASI01", "ASI02")),
    "poisoned_kb_tool": ("attack", ("ASI04",)),
    "rug_pull_kb": ("attack", ("ASI04",)),
    "cross_customer_lookup": ("attack", ("ASI03",)),
    "excessive_refund": ("attack", ("ASI02",)),
    "legit_refund_in_policy": ("benign", ()),
    "legit_status_check": ("benign", ()),
}


def test_the_corpus_is_six_attacks_and_two_benign_controls():
    assert {sid: (s.kind, s.owasp) for sid, s in SCENARIOS.items()} == EXPECTED


def test_every_attack_has_a_fix_hint_and_an_injection():
    for s in SCENARIOS.values():
        if s.is_attack:
            assert s.fix_hint and s.injection and s.severity


@pytest.mark.parametrize("scenario_id", sorted(SCENARIOS))
async def test_replay_lands_on_the_vulnerable_desk(replay_demo, scenario_id):
    """Reachability: the scripted replay achieves the outcome on the vulnerable variant."""
    scenario = SCENARIOS[scenario_id]
    sb, _, result = await replay_demo(scenario, "vulnerable")
    assert result.fired and result.executed, result
    if scenario.is_attack:
        assert any(e.injected for e in sb.events()), "the payload was never delivered"


@pytest.mark.parametrize("scenario_id", sorted(SCENARIOS))
async def test_the_fixed_desk_denies_attacks_and_allows_benign_work(replay_demo, scenario_id):
    scenario = SCENARIOS[scenario_id]
    _, _, result = await replay_demo(scenario, "fixed")
    if scenario.is_attack:
        assert not result.fired and result.denied, result
    else:
        assert result.fired and not result.denied, result


async def test_rug_pull_changes_the_description_after_the_first_listing(replay_demo):
    sb, _, _ = await replay_demo(SCENARIOS["rug_pull_kb"], "vulnerable")
    kb_lists = [e.record for e in sb.events() if e.kind == "list" and e.server == "knowledge_base"]
    entries = [next(t for t in rec["tools"] if t["name"] == "kb_search") for rec in kb_lists]
    assert [t["injected"] for t in entries] == [False, True]
    assert entries[0]["description_sha256"] != entries[1]["description_sha256"]
    assert "POLICY UPDATE" in entries[1]["description"]


async def test_held_tools_are_held_in_the_scenario_that_names_them(replay_demo):
    scenario = SCENARIOS["refund_injection_ticket"]
    assert scenario.hold_tools == ("send_email",)
    email = Step(
        action="call",
        tool="send_email",
        arguments={"to": "jordan.alvarez@northwind.example", "subject": "Refund", "body": "Done."},
    )
    sb, _, _ = await replay_demo(replace(scenario, replay=scenario.replay + (email,)), "vulnerable")
    held = [e for e in sb.calls() if e.tool == "send_email"]
    assert [e.outcome for e in held] == ["held"]
    assert [e["action"] for e in sb.sink_entries()] == ["refund_issued"]
