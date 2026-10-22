from datetime import datetime, timedelta, timezone

from aisec import cli
from aisec.due import stale_packs
from aisec.evidence import RunStore, manifest_digest
from aisec.graph import graph_pack, render_graph_mermaid
from aisec.lineage import walk_lineage
from aisec.policy import evaluate_policy, load_policy
from aisec.verdicts import EXIT_FAILED, EXIT_OK
from test_report import TARGET
from test_unique_product import _attack


def _pack(tmp_path, run_id, *, events=None, started_at=None, parent=None, results=None):
    scenario_file = tmp_path / f"{run_id}.yaml"
    scenario_file.write_text("id: s\n", encoding="utf-8")
    store = RunStore(tmp_path / "runs", run_id=run_id)
    store.create()
    target = {
        **TARGET,
        "run_id": run_id,
        "started_at": started_at or TARGET["started_at"],
        "tool_inventory": [
            {"server": "support_desk", "name": "get_ticket", "description": "", "input_schema": {}},
            {"server": "support_desk", "name": "issue_refund", "description": "", "input_schema": {}},
        ],
    }
    if parent:
        target["parent_run_id"] = parent["run_id"]
        target["parent_manifest_sha256"] = parent["manifest_sha256"]
    store.write_json("target.json", target)
    store.add_scenario(scenario_file, "s")
    store.write_json(
        "verdict.json",
        {"run_id": run_id, "results": results or [_attack("refund", "RESISTED", "tools")], "summary": {"exit_code": 0}},
    )
    store.write_text("report.md", "# report\n")
    for event in events or []:
        store.append("events.jsonl", event)
    store.seal()
    return store.root


def test_graph_counts_listed_called_denied_and_injected(tmp_path):
    run_dir = _pack(
        tmp_path,
        "g1",
        events=[
            {
                "kind": "list",
                "server": "support_desk",
                "tools": [{"name": "get_ticket", "injected": False}, {"name": "issue_refund", "injected": True}],
                "scenario": "s",
                "arm": "trial",
                "trial": 1,
            },
            {
                "kind": "call",
                "server": "support_desk",
                "tool": "get_ticket",
                "outcome": "ok",
                "scenario": "s",
                "arm": "trial",
                "trial": 1,
            },
            {
                "kind": "call",
                "server": "support_desk",
                "tool": "issue_refund",
                "outcome": "error",
                "injected": True,
                "scenario": "s",
                "arm": "trial",
                "trial": 1,
            },
        ],
    )
    graph = graph_pack(run_dir)
    by_id = {n["id"]: n for n in graph["nodes"]}
    assert by_id["support_desk/get_ticket"]["ok"] == 1
    assert by_id["support_desk/issue_refund"]["error"] == 1
    assert by_id["support_desk/issue_refund"]["injected"] >= 1
    assert graph["paths"][0]["tools"] == ["support_desk/get_ticket", "support_desk/issue_refund"]
    mermaid = render_graph_mermaid(graph)
    assert "get_ticket" in mermaid and "-->" in mermaid
    assert cli.main(["graph", str(run_dir)]) == EXIT_OK


def test_lineage_walks_parent_digest(tmp_path):
    first = _pack(tmp_path, "old")
    second = _pack(
        tmp_path,
        "new",
        parent={"run_id": first.name, "manifest_sha256": manifest_digest(first)},
    )
    lineage = walk_lineage(second, runs_root=first.parent)
    assert [c["run_id"] for c in lineage["chain"]] == [second.name, first.name]
    assert lineage["complete"] is True
    assert cli.main(["lineage", str(second), "--runs-root", str(first.parent)]) == EXIT_OK


def test_policy_fails_a_stale_pack(tmp_path):
    old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat(timespec="seconds")
    run_dir = _pack(tmp_path, "stale", started_at=old)
    spec = load_policy(None)
    spec["max_age_days"] = 90
    result = evaluate_policy(run_dir, spec)
    assert result["ok"] is False
    assert any(v["code"] == "stale" for v in result["violations"])


def test_due_lists_packs_older_than_the_clock(tmp_path):
    old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat(timespec="seconds")
    run_dir = _pack(tmp_path, "aged", started_at=old)
    rows = stale_packs(run_dir.parent, days=90)
    assert rows and rows[0]["run_id"] == "aged"
    assert cli.main(["due", "--runs-root", str(run_dir.parent), "--days", "90"]) == EXIT_FAILED
    assert cli.main(["due", "--runs-root", str(run_dir.parent), "--days", "400"]) == EXIT_OK
