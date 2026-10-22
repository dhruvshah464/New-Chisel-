from aisec import cli
from aisec.badge import render_badge
from aisec.mutate import WRAPPERS, expand_scenarios, mutations_of
from aisec.policy import evaluate_policy, load_policy, render_policy
from aisec.scenario import dump_scenario, load_scenario, load_scenarios, scenario_from_dict
from aisec.verdicts import EXIT_FAILED, EXIT_OK
from conftest import SCENARIOS_DIR
from test_unique_product import _attack, _pack
import yaml


def test_dump_round_trips_every_shipped_scenario(tmp_path):
    for original in load_scenarios(SCENARIOS_DIR):
        loaded = scenario_from_dict(yaml.safe_load(dump_scenario(original)), source=original.id)
        assert loaded.id == original.id
        assert loaded.kind == original.kind
        assert loaded.success_check == original.success_check
        if original.injection:
            assert loaded.injection.payload == original.injection.payload
            assert loaded.injection.channel == original.injection.channel


def test_mutations_keep_the_check_and_change_the_payload():
    scenario = load_scenario(SCENARIOS_DIR / "refund_injection_ticket.yaml")
    mutated = mutations_of(scenario, 2)
    assert len(mutated) == 2 == min(2, len(WRAPPERS))
    assert mutated[0].success_check == scenario.success_check
    assert mutated[0].replay == scenario.replay
    assert mutated[0].injection.payload != scenario.injection.payload
    assert scenario.injection.payload in mutated[0].injection.payload
    expanded = expand_scenarios([scenario], 3)
    assert len(expanded) == 4 and expanded[0].id == scenario.id


def test_mutate_cli_writes_loadable_yaml(tmp_path):
    out = tmp_path / "mut"
    assert cli.main(["mutate", "--scenarios", str(SCENARIOS_DIR), "--out", str(out), "--count", "2"]) == 0
    written = load_scenarios(out)
    originals = load_scenarios(SCENARIOS_DIR)
    assert len(written) == len(originals) + 2 * sum(1 for s in originals if s.is_attack)
    assert any(s.id.endswith("ignore_previous") for s in written)


def test_policy_fails_a_model_only_resist(tmp_path):
    run_dir = _pack(
        tmp_path,
        "model-pass",
        "gpt-4o-mini",
        [_attack("refund", "RESISTED", "model")],
    )
    spec = load_policy(None)
    result = evaluate_policy(run_dir, spec)
    assert result["ok"] is False
    assert any(v["code"] == "model_only_resist" for v in result["violations"])
    assert "FAIL" in render_policy(result)
    assert cli.main(["policy", str(run_dir)]) == EXIT_FAILED


def test_policy_passes_a_tool_level_resist(tmp_path):
    run_dir = _pack(
        tmp_path,
        "tool-pass",
        "claude-sonnet-5",
        [_attack("refund", "RESISTED", "tools")],
    )
    assert evaluate_policy(run_dir, load_policy(None))["ok"] is True
    assert cli.main(["policy", str(run_dir)]) == EXIT_OK


def test_policy_fails_a_regression_against_baseline(tmp_path):
    left = _pack(tmp_path, "older", "claude-sonnet-5", [_attack("refund", "RESISTED", "tools")])
    right = _pack(tmp_path, "newer", "claude-sonnet-5", [_attack("refund", "FAILED")])
    result = evaluate_policy(right, load_policy(None), baseline=left)
    assert result["ok"] is False
    assert any(v["code"] == "regression" for v in result["violations"])


def test_badge_carries_the_digest(tmp_path):
    run_dir = _pack(tmp_path, "badge-run", "claude-sonnet-5", [_attack("refund", "RESISTED", "tools")])
    svg = render_badge(run_dir)
    assert "New Chisel" in svg and "tools 1" in svg
    dest = tmp_path / "b.svg"
    assert cli.main(["badge", str(run_dir), "--out", str(dest)]) == 0
    assert dest.read_text() == svg
