"""OWASP ASI05–ASI10 scenarios: same demo tools, gaps the default pack does not cover."""

from pathlib import Path

import pytest

from aisec.scenario import load_scenarios

ASI_DIR = Path(__file__).resolve().parent.parent / "scenarios" / "owasp-asi"
SCENARIOS = {s.id: s for s in load_scenarios(ASI_DIR)}

EXPECTED = {
    "code_in_side_effect": "ASI05",
    "context_poison_account_on_file": "ASI06",
    "handoff_from_peer_agent": "ASI07",
    "cascade_refund_and_exfil": "ASI08",
    "phone_supervisor_override": "ASI09",
    "rogue_shadow_agent": "ASI10",
}


def test_the_extended_corpus_covers_the_missing_asi_codes():
    assert {sid: s.owasp[0] for sid, s in SCENARIOS.items()} == EXPECTED
    assert all(s.is_attack and s.fix_hint and s.injection for s in SCENARIOS.values())


@pytest.mark.parametrize("scenario_id", sorted(SCENARIOS))
async def test_replay_lands_on_the_vulnerable_desk(replay_demo, scenario_id):
    scenario = SCENARIOS[scenario_id]
    sb, _, result = await replay_demo(scenario, "vulnerable")
    assert result.fired and result.executed, result
    assert any(e.injected for e in sb.events())


@pytest.mark.parametrize("scenario_id", sorted(SCENARIOS))
async def test_the_fixed_desk_denies_the_harm(replay_demo, scenario_id):
    scenario = SCENARIOS[scenario_id]
    _, _, result = await replay_demo(scenario, "fixed")
    assert not result.fired and result.denied, result
