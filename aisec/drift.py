"""Tool-inventory drift between two sealed packs.

A model vendor can tell you GPT's weights did not change. It cannot tell you that the
third-party MCP server your agent listed last week still has the same description and
schema. That is a supply-chain fact about *your* tools, hashed in the pack.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .evidence import load_json, manifest_digest, verify_manifest


def fingerprint(tool: dict[str, Any]) -> str:
    payload = {
        "server": tool.get("server") or "",
        "name": tool.get("name") or "",
        "description": tool.get("description") or "",
        "input_schema": tool.get("input_schema") or {},
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _key(tool: dict[str, Any]) -> str:
    return f"{tool.get('server') or ''}/{tool.get('name') or ''}"


def inventory_of(run_dir: str | Path) -> dict[str, dict[str, Any]]:
    target = load_json(Path(run_dir) / "target.json")
    return {_key(tool): tool for tool in target.get("tool_inventory") or []}


def drift_packs(left_dir: str | Path, right_dir: str | Path) -> dict[str, Any]:
    left_dir, right_dir = Path(left_dir), Path(right_dir)
    verify_manifest(left_dir)
    verify_manifest(right_dir)
    left, right = inventory_of(left_dir), inventory_of(right_dir)
    added = sorted(set(right) - set(left))
    removed = sorted(set(left) - set(right))
    changed = sorted(
        key for key in set(left) & set(right) if fingerprint(left[key]) != fingerprint(right[key])
    )
    return {
        "left": {"run_id": left_dir.name, "manifest_sha256": manifest_digest(left_dir), "tools": len(left)},
        "right": {"run_id": right_dir.name, "manifest_sha256": manifest_digest(right_dir), "tools": len(right)},
        "added": added,
        "removed": removed,
        "changed": changed,
        "ok": not (added or removed or changed),
        "note": (
            "A changed description or schema is a supply-chain event. Pin tool descriptions at "
            "approval time; do not treat a model refusal as covering a new instruction the tool now ships."
        ),
    }


def render_drift_markdown(drift: dict[str, Any]) -> str:
    lines = [
        "# New Chisel tool-inventory drift",
        "",
        f"Left: `{drift['left']['run_id']}` ({drift['left']['tools']} tools)",
        f"Right: `{drift['right']['run_id']}` ({drift['right']['tools']} tools)",
        "",
        drift["note"],
        "",
    ]
    if drift["ok"]:
        lines.append("No added, removed, or changed tools.")
        return "\n".join(lines) + "\n"
    if drift["added"]:
        lines.append("Added: " + ", ".join(f"`{k}`" for k in drift["added"]))
    if drift["removed"]:
        lines.append("Removed: " + ", ".join(f"`{k}`" for k in drift["removed"]))
    if drift["changed"]:
        lines.append("Changed description or schema: " + ", ".join(f"`{k}`" for k in drift["changed"]))
    return "\n".join(lines) + "\n"
