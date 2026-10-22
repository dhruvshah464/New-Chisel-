"""Permission graph of a sealed pack: what was listed, called, denied, held, injected.

A model card never contains this. It is the blast radius of *this agent*'s tools, read
from the proxy record, not from the model's account of what it did.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from .evidence import load_json, load_jsonl, verify_manifest


def _key(server: str, name: str) -> str:
    return f"{server}/{name}"


def _node(server: str, name: str) -> dict[str, Any]:
    return {
        "id": _key(server, name),
        "server": server,
        "name": name,
        "listed": 0,
        "ok": 0,
        "error": 0,
        "held": 0,
        "injected": 0,
    }


def graph_pack(run_dir: str | Path) -> dict[str, Any]:
    run_dir = Path(run_dir)
    verify_manifest(run_dir)
    target = load_json(run_dir / "target.json")
    nodes: dict[str, dict[str, Any]] = {}
    for tool in target.get("tool_inventory") or []:
        nodes[_key(tool.get("server") or "", tool.get("name") or "")] = _node(
            tool.get("server") or "", tool.get("name") or ""
        )
    paths: dict[tuple[str, ...], int] = defaultdict(int)
    current: list[str] = []
    current_trial: tuple[Any, ...] | None = None
    for event in load_jsonl(run_dir / "events.jsonl"):
        trial = (event.get("scenario"), event.get("arm"), event.get("trial"))
        if trial != current_trial:
            if current:
                paths[tuple(current)] += 1
            current, current_trial = [], trial
        server = str(event.get("server") or "")
        if event.get("kind") == "list":
            for tool in event.get("tools") or []:
                key = _key(server, str(tool.get("name") or ""))
                nodes.setdefault(key, _node(server, str(tool.get("name") or "")))
                nodes[key]["listed"] += 1
                if tool.get("injected"):
                    nodes[key]["injected"] += 1
            continue
        if event.get("kind") != "call":
            continue
        key = _key(server, str(event.get("tool") or ""))
        nodes.setdefault(key, _node(server, str(event.get("tool") or "")))
        outcome = event.get("outcome") or "ok"
        if outcome not in ("ok", "error", "held"):
            outcome = "ok"
        nodes[key][outcome] += 1
        if event.get("injected"):
            nodes[key]["injected"] += 1
        current.append(key)
    if current:
        paths[tuple(current)] += 1
    return {
        "run_id": target.get("run_id") or run_dir.name,
        "nodes": sorted(nodes.values(), key=lambda n: n["id"]),
        "paths": [{"tools": list(path), "count": count} for path, count in sorted(paths.items(), key=lambda kv: (-kv[1], kv[0]))],
        "note": (
            "Listed is what the servers exposed. Called is what actually went through the proxy. "
            "Denied (error) and held are attempts that did not take effect. Injected means the "
            "attack payload rode on that tool. This is not a runtime allow-list."
        ),
    }


def render_graph_mermaid(graph: dict[str, Any]) -> str:
    lines = ["flowchart LR"]
    for node in graph["nodes"]:
        ident = node["id"].replace("/", "_").replace("-", "_")
        bits = []
        if node["listed"]:
            bits.append("listed")
        if node["ok"]:
            bits.append(f"ok {node['ok']}")
        if node["error"]:
            bits.append(f"denied {node['error']}")
        if node["held"]:
            bits.append(f"held {node['held']}")
        if node["injected"]:
            bits.append("injected")
        label = f"{node['name']}\\n" + (", ".join(bits) or "unused")
        lines.append(f'  {ident}["{label}"]')
    seen: set[tuple[str, str]] = set()
    for path in graph["paths"]:
        tools = path["tools"]
        for left, right in zip(tools, tools[1:]):
            edge = (left, right)
            if edge in seen:
                continue
            seen.add(edge)
            a = left.replace("/", "_").replace("-", "_")
            b = right.replace("/", "_").replace("-", "_")
            lines.append(f"  {a} --> {b}")
    return "\n".join(lines) + "\n"


def render_graph_markdown(graph: dict[str, Any]) -> str:
    lines = [
        "# New Chisel permission graph",
        "",
        graph["note"],
        "",
        "| Tool | Listed | OK | Denied | Held | Injected |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for node in graph["nodes"]:
        lines.append(
            f"| `{node['id']}` | {node['listed']} | {node['ok']} | {node['error']} | {node['held']} | {node['injected']} |"
        )
    if graph["paths"]:
        lines += ["", "Call paths (unique sequences in the record):"]
        for path in graph["paths"][:20]:
            lines.append(f"- {path['count']}× " + " → ".join(f"`{t}`" for t in path["tools"]))
    lines += ["", "```mermaid", render_graph_mermaid(graph).rstrip(), "```", ""]
    return "\n".join(lines)
