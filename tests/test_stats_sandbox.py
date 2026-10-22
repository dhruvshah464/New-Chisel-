import json
import multiprocessing

import pytest

from aisec.sandbox import Sandbox, append_jsonl, contains_marker, read_jsonl
from aisec.stats import fmt_rate, rate, wilson_interval
from aisec.targets.replay import resolve_template


def test_wilson_interval_at_the_extremes():
    low, high = wilson_interval(0, 3)
    assert low == 0.0 and high == pytest.approx(0.5615, abs=1e-4)
    low, high = wilson_interval(3, 3)
    assert low == pytest.approx(0.4385, abs=1e-4) and high == 1.0


def test_rate_and_format():
    assert rate(0, 0) is None
    assert fmt_rate(None) == "n/a"
    assert fmt_rate(rate(2, 3)) == "2/3 (67%; 95% CI 21-94%)"


def _append_many(path, n):
    for _ in range(n):
        append_jsonl(path, {"kind": "call"}, sequence=True)


def test_concurrent_appends_get_unique_sequence_numbers(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("")
    procs = [multiprocessing.Process(target=_append_many, args=(path, 25)) for _ in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    seqs = [r["seq"] for r in read_jsonl(path)]
    assert sorted(seqs) == list(range(1, 101))


def test_read_jsonl_rejects_a_corrupt_line(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps({"seq": 1}) + "\n{truncated\n")
    with pytest.raises(ValueError, match="line 2"):
        read_jsonl(path)


def test_contains_marker_walks_nested_values():
    assert contains_marker({"body": ["x", {"y": "Call +55 11 5555 0133"}]}, ["+55 11 5555 0133"])
    assert not contains_marker({"amount": 4900, "ok": True}, ["4901"])


def test_sandbox_lifecycle():
    sb = Sandbox.create(canaries={"c": ["m"]})
    try:
        sb.write_proxy_config({"channel": "tool_result", "tool": "t", "payload": "p"}, ["b", "a"])
        assert json.loads(sb.proxy_config_path.read_text())["hold_tools"] == ["a", "b"]
        assert set(sb.proxy_env()) == {"AISEC_EVENTS", "AISEC_PROXY_CONFIG"}
        assert sb.events() == [] and sb.sink_entries() == [] and sb.transcript() == []
    finally:
        sb.destroy()
    assert not sb.root.exists()


def test_resolve_template_is_recursive():
    out = resolve_template({"body": "Record: {{last_result}}", "cc": ["{{last_result}}"], "n": 3}, "R")
    assert out == {"body": "Record: R", "cc": ["R"], "n": 3}
