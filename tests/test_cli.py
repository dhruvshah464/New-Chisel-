"""End to end through the CLI: deterministic replay-only runs, verify, tamper detection, report."""

import json
import shutil
import stat

import pytest

from aisec import cli
from aisec.evidence import load_json, verify_manifest
from aisec.targets.demo import DemoTarget
from aisec.verdicts import COMPLETED, FAILED, INCONCLUSIVE, RESISTED
from conftest import SCENARIOS_DIR


def only_run(runs_root):
    (run_dir,) = [p for p in runs_root.iterdir() if p.is_dir()]
    return run_dir


@pytest.fixture(scope="module")
def packs(tmp_path_factory):
    """One replay-only run of each demo variant over the full scenario set."""
    out = {}
    for variant in ("vulnerable", "fixed"):
        root = tmp_path_factory.mktemp(variant)
        code = cli.main(
            ["run", "--variant", variant, "--replay-only", "--scenarios", str(SCENARIOS_DIR), "--runs-root", str(root)]
        )
        out[variant] = (code, only_run(root))
    return out


def verdicts(run_dir):
    return {r["id"]: r for r in load_json(run_dir / "verdict.json")["results"]}


def editable_copy(run_dir, tmp_path):
    copy = tmp_path / run_dir.name
    shutil.copytree(run_dir, copy)
    for path in copy.rglob("*"):
        path.chmod(path.stat().st_mode | stat.S_IWUSR)
    return copy


def test_replay_run_of_the_vulnerable_desk_fails_every_attack(packs):
    code, run_dir = packs["vulnerable"]
    assert code == 1
    results = verdicts(run_dir)
    assert {r["verdict"] for r in results.values() if r["kind"] == "attack"} == {FAILED}
    assert {r["verdict"] for r in results.values() if r["kind"] == "benign"} == {COMPLETED}
    assert len(results) == 8
    verify_manifest(run_dir)


def test_replay_run_of_the_fixed_desk_resists_every_attack(packs):
    code, run_dir = packs["fixed"]
    assert code == 0
    results = verdicts(run_dir)
    attacks = [r for r in results.values() if r["kind"] == "attack"]
    assert {r["verdict"] for r in attacks} == {RESISTED}
    assert {r["resisted_by"] for r in attacks} == {"tools"}
    assert all(r["attempted_denied"] == 1 for r in attacks)
    assert {r["verdict"] for r in results.values() if r["kind"] == "benign"} == {COMPLETED}


def test_the_pack_holds_every_file_in_the_layout(packs):
    _, run_dir = packs["fixed"]
    names = {p.relative_to(run_dir).as_posix() for p in run_dir.rglob("*") if p.is_file()}
    expected = {
        "target.json",
        "events.jsonl",
        "transcripts.jsonl",
        "sink.jsonl",
        "checks.jsonl",
        "verdict.json",
        "report.md",
        "report.html",
        "manifest.json",
    }
    assert expected <= names
    assert (run_dir / "certificate.html").is_file()
    assert "Independent Evidence Certificate" in (run_dir / "certificate.html").read_text()
    attest = load_json(run_dir / "attestation.json")
    assert attest["type"] == "new-chisel.attestation.v1"
    assert attest["not_a_certification"] is True
    assert attest["not_issued_by_a_model_vendor"] is True
    assert "1420 Larkspur" not in (run_dir / "attestation.json").read_text()
    assert {n for n in names if n.startswith("scenarios/")} == {f"scenarios/{p.name}" for p in SCENARIOS_DIR.glob("*.yaml")}
    target = load_json(run_dir / "target.json")
    assert target["driver"] == "replay" and target["target"]["variant"] == "fixed"


def test_events_mark_held_calls_and_injections(packs):
    _, run_dir = packs["vulnerable"]
    events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text().splitlines()]
    injected = {e["scenario"] for e in events if e.get("injected")}
    assert injected == {r for r, v in verdicts(run_dir).items() if v["kind"] == "attack"}


def test_the_report_states_its_limits(packs):
    _, run_dir = packs["vulnerable"]
    report = (run_dir / "report.md").read_text()
    assert "Scripted replay, no model." in report
    assert "Independent of the model vendor" in report
    assert "## What was not tested" in report and "It is not a guarantee" in report
    assert "ASI05 Unexpected Code Execution" in report
    assert "95% CI" not in report
    assert "ACC-9931" in report


def test_verify_passes_on_an_untouched_pack(packs, capsys):
    _, run_dir = packs["fixed"]
    assert cli.main(["verify", str(run_dir)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("OK ") and "manifest sha256 " in out


def test_verify_accepts_a_run_id_and_latest(packs):
    _, run_dir = packs["fixed"]
    assert cli.main(["verify", run_dir.name, "--runs-root", str(run_dir.parent)]) == 0
    assert cli.main(["verify", "latest", "--runs-root", str(run_dir.parent)]) == 0


@pytest.mark.parametrize("tamper, expected", [("edit", "changed: verdict.json"), ("delete", "missing: sink.jsonl"), ("add", "extra: notes.txt")])
def test_tampering_fails_verify_and_report_with_exit_3(packs, tmp_path, capsys, tamper, expected):
    _, run_dir = packs["vulnerable"]
    copy = editable_copy(run_dir, tmp_path)
    if tamper == "edit":
        verdict = copy / "verdict.json"
        verdict.write_text(verdict.read_text().replace('"FAILED"', '"RESISTED"'))
    elif tamper == "delete":
        (copy / "sink.jsonl").unlink()
    else:
        (copy / "notes.txt").write_text("added later")
    assert cli.main(["verify", str(copy)]) == 3
    assert expected in capsys.readouterr().out
    assert cli.main(["report", str(copy), "--out", str(tmp_path / "out")]) == 3
    assert not (tmp_path / "out").exists()


def test_report_rerenders_the_sealed_report_byte_for_byte(packs, tmp_path, capsys):
    _, run_dir = packs["fixed"]
    out = tmp_path / "rendered"
    assert cli.main(["report", str(run_dir), "--out", str(out)]) == 0
    assert "match the sealed report" in capsys.readouterr().out
    assert (out / "report.md").read_bytes() == (run_dir / "report.md").read_bytes()
    assert (out / "report.html").read_bytes() == (run_dir / "report.html").read_bytes()


def test_report_refuses_to_write_into_the_pack(packs):
    _, run_dir = packs["fixed"]
    assert cli.main(["report", str(run_dir), "--out", str(run_dir)]) == 2


def test_a_run_without_an_api_key_is_inconclusive(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    code = cli.main(
        ["run", "--scenarios", str(SCENARIOS_DIR / "refund_injection_ticket.yaml"), "--runs-root", str(tmp_path)]
    )
    assert code == 2
    run_dir = only_run(tmp_path)
    (result,) = verdicts(run_dir).values()
    assert result["verdict"] == INCONCLUSIVE and result["reachable"]
    assert DemoTarget().preflight() in result["reason"]
    assert "The agent did not run" in (run_dir / "report.md").read_text()
    verify_manifest(run_dir)


def test_usage_errors_exit_2(tmp_path, capsys):
    assert cli.main(["run", "--scenarios", str(tmp_path / "nowhere"), "--runs-root", str(tmp_path)]) == 2
    assert "no such file" in capsys.readouterr().err
    assert cli.main(["verify", str(tmp_path / "nowhere")]) == 2
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["run", "--repeat", "0"])
    assert excinfo.value.code == 2


def test_proxy_subcommand_accepts_both_forms(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "proxy_main", lambda argv: calls.append(argv) or 0)
    assert cli.main(["proxy", "--", "python", "server.py"]) == 0
    assert cli.main(["proxy", "--server-name", "kb", "--", "python", "kb.py"]) == 0
    assert cli.main(["proxy", "wrap", "--", "node", "x.js"]) == 0
    assert calls == [
        ["wrap", "--", "python", "server.py"],
        ["wrap", "--server-name", "kb", "--", "python", "kb.py"],
        ["wrap", "--", "node", "x.js"],
    ]
    assert cli.main(["proxy"]) == 2
    assert cli.main(["proxy", "--help"]) == 0
