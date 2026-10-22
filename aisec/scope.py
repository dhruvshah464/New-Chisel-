"""Least privilege from the sealed proxy record.

A model card lists capabilities. It does not say which of *your* MCP tools were
exposed, which were never called, and which appeared in a call without being in
the sealed inventory. That last case is a shadow tool — a supply-chain surprise
a vendor scoreboard cannot see.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .evidence import load_json, verify_manifest
from .graph import graph_pack


def _key(server: str, name: str) -> str:
    return f"{server}/{name}"


def scope_pack(run_dir: str | Path) -> dict[str, Any]:
    run_dir = Path(run_dir)
    verify_manifest(run_dir)
    target = load_json(run_dir / "target.json")
    graph = graph_pack(run_dir)
    inventory = sorted(
        {
            _key(str(t.get("server") or ""), str(t.get("name") or ""))
            for t in (target.get("tool_inventory") or [])
            if t.get("name")
        }
    )
    listed: list[str] = []
    called: list[str] = []
    injected: list[str] = []
    held: list[str] = []
    for node in graph["nodes"]:
        ident = node["id"]
        if node.get("listed"):
            listed.append(ident)
        if (node.get("ok") or 0) + (node.get("error") or 0) + (node.get("held") or 0):
            called.append(ident)
        if node.get("injected"):
            injected.append(ident)
        if node.get("held"):
            held.append(ident)
    known = set(inventory) | set(listed)
    unused = sorted(known - set(called))
    shadow = sorted(set(called) - set(inventory)) if inventory else []
    extra_listed = sorted(set(listed) - set(inventory)) if inventory else []
    return {
        "run_id": target.get("run_id") or run_dir.name,
        "inventory": inventory,
        "listed": sorted(listed),
        "called": sorted(called),
        "unused": unused,
        "shadow": shadow,
        "extra_listed": extra_listed,
        "injected": sorted(injected),
        "held": sorted(held),
        "ok": not shadow,
        "note": (
            "Unused tools were listed or inventoried and never called. Shadow tools were "
            "called but are not in the sealed inventory. This is not a runtime allow-list."
        ),
    }


def render_scope_markdown(scope: dict[str, Any]) -> str:
    lines = [
        "# New Chisel tool scope",
        "",
        scope["note"],
        "",
        f"Inventory: {len(scope['inventory'])} · listed: {len(scope['listed'])} · called: {len(scope['called'])}",
        "",
    ]
    if scope["shadow"]:
        lines += ["Shadow (called, not in inventory):"]
        lines += [f"- `{name}`" for name in scope["shadow"]]
        lines.append("")
    if scope["unused"]:
        lines += ["Unused (inventoried or listed, never called):"]
        lines += [f"- `{name}`" for name in scope["unused"]]
        lines.append("")
    if not scope["shadow"] and not scope["unused"]:
        lines.append("Every inventoried tool was called; no shadow tools.")
        lines.append("")
    lines.append("OK" if scope["ok"] else "FAIL")
    return "\n".join(lines) + "\n"
