import os
import stat

import pytest

from aisec.evidence import (
    EvidenceError,
    IntegrityError,
    RunStore,
    latest_run,
    manifest_digest,
    resolve_run,
    verify_manifest,
)


def build_store(tmp_path, run_id="run-a"):
    scenario_file = tmp_path / "s.yaml"
    scenario_file.write_text("id: s\n", encoding="utf-8")
    store = RunStore(tmp_path / "runs", run_id=run_id)
    store.create()
    store.write_json("target.json", {"target": "demo", "variant": "vulnerable"})
    store.add_scenario(scenario_file, "s")
    store.append("events.jsonl", {"seq": 1, "kind": "call", "tool": "issue_refund"})
    store.append("checks.jsonl", {"scenario": "s", "fired": True})
    store.write_json("verdict.json", {"scenarios": [{"id": "s", "verdict": "FAILED"}]})
    store.write_text("report.md", "# report\n")
    return store


def make_writable(path):
    path.chmod(path.stat().st_mode | stat.S_IWUSR)


def test_seal_hashes_every_file_and_freezes_them(tmp_path):
    store = build_store(tmp_path)
    manifest = store.seal()
    assert set(manifest["files"]) == {
        "target.json",
        "verdict.json",
        "report.md",
        "scenarios/s.yaml",
        "events.jsonl",
        "transcripts.jsonl",
        "sink.jsonl",
        "checks.jsonl",
    }
    assert not os.access(store.root / "verdict.json", os.W_OK)
    assert verify_manifest(store.root)["run_id"] == "run-a"
    assert len(manifest_digest(store.root)) == 64


def test_a_changed_file_is_detected(tmp_path):
    store = build_store(tmp_path)
    store.seal()
    verdict = store.root / "verdict.json"
    make_writable(verdict)
    verdict.write_text(verdict.read_text().replace("FAILED", "RESISTED"))
    with pytest.raises(IntegrityError, match="changed: verdict.json"):
        verify_manifest(store.root)


def test_a_missing_or_extra_file_is_detected(tmp_path):
    store = build_store(tmp_path)
    store.seal()
    (store.root / "report.md").unlink()
    (store.root / "notes.txt").write_text("added later")
    with pytest.raises(IntegrityError) as err:
        verify_manifest(store.root)
    assert "missing: report.md" in str(err.value) and "extra: notes.txt" in str(err.value)


def test_unsealed_or_corrupt_manifest_fails(tmp_path):
    store = build_store(tmp_path)
    with pytest.raises(IntegrityError, match="never sealed"):
        verify_manifest(store.root)
    store.seal()
    manifest = store.root / "manifest.json"
    make_writable(manifest)
    manifest.write_text("{not json")
    with pytest.raises(IntegrityError, match="not valid JSON"):
        verify_manifest(store.root)


def test_records_are_write_once(tmp_path):
    store = build_store(tmp_path)
    with pytest.raises(EvidenceError, match="already written"):
        store.write_json("verdict.json", {})
    with pytest.raises(EvidenceError, match="not in the pack schema"):
        store.write_json("other.json", {})
    store.seal()
    with pytest.raises(EvidenceError, match="sealed"):
        store.append("events.jsonl", {"seq": 2})


def test_seal_requires_the_verdict(tmp_path):
    store = RunStore(tmp_path / "runs", run_id="r")
    store.create()
    store.write_json("target.json", {})
    with pytest.raises(EvidenceError, match="verdict.json"):
        store.seal()


def test_resolve_run(tmp_path):
    runs = tmp_path / "runs"
    build_store(tmp_path, "20261009T100000Z-aaaaaa").seal()
    build_store(tmp_path, "20261009T110000Z-bbbbbb").seal()
    assert latest_run(runs).name == "20261009T110000Z-bbbbbb"
    assert resolve_run("latest", runs).name == "20261009T110000Z-bbbbbb"
    assert resolve_run("20261009T100000Z-aaaaaa", runs).name == "20261009T100000Z-aaaaaa"
    with pytest.raises(EvidenceError):
        resolve_run("nope", runs)
