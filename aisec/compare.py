"""Vendor-neutral comparison of two sealed packs.

OpenAI can say how GPT behaved. It cannot put Claude, GPT and a local model on
the same evidence format, with the same reachability replay, and show whether a
fix lived in the *tools* (same across models) or in the *model* (vendor-specific).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .evidence import load_json, manifest_digest, verify_manifest
from .verdicts import FAILED, RESISTED


def _described(target_json: dict[str, Any]) -> dict[str, Any]:
    inner = target_json.get("target")
    return inner if isinstance(inner, dict) else target_json


def _by_id(verdict: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["id"]: r for r in verdict.get("results") or []}


def compare_packs(left_dir: str | Path, right_dir: str | Path) -> dict[str, Any]:
    left_dir, right_dir = Path(left_dir), Path(right_dir)
    verify_manifest(left_dir)
    verify_manifest(right_dir)
    left_t, right_t = load_json(left_dir / "target.json"), load_json(right_dir / "target.json")
    left_v, right_v = load_json(left_dir / "verdict.json"), load_json(right_dir / "verdict.json")
    left_ids, right_ids = _by_id(left_v), _by_id(right_v)
    rows = []
    for sid in sorted(set(left_ids) | set(right_ids)):
        a, b = left_ids.get(sid), right_ids.get(sid)
        rows.append(
            {
                "id": sid,
                "left": None if a is None else {"verdict": a.get("verdict"), "resisted_by": a.get("resisted_by")},
                "right": None if b is None else {"verdict": b.get("verdict"), "resisted_by": b.get("resisted_by")},
            }
        )
    tools_same = [
        r
        for r in rows
        if (r["left"] or {}).get("resisted_by") == "tools" and (r["right"] or {}).get("resisted_by") == "tools"
    ]
    model_split = [
        r
        for r in rows
        if (r["left"] or {}).get("verdict") == RESISTED
        and (r["right"] or {}).get("verdict") == RESISTED
        and (r["left"] or {}).get("resisted_by") != (r["right"] or {}).get("resisted_by")
    ]
    return {
        "left": {
            "run_id": left_v.get("run_id") or left_t.get("run_id"),
            "model": _described(left_t).get("model"),
            "manifest_sha256": manifest_digest(left_dir),
        },
        "right": {
            "run_id": right_v.get("run_id") or right_t.get("run_id"),
            "model": _described(right_t).get("model"),
            "manifest_sha256": manifest_digest(right_dir),
        },
        "scenarios": rows,
        "tool_fixes_that_held_on_both": [r["id"] for r in tools_same],
        "model_only_splits": [r["id"] for r in model_split],
        "regressions": [
            r["id"]
            for r in rows
            if (r["left"] or {}).get("verdict") == RESISTED
            and (r["right"] or {}).get("verdict") == FAILED
        ],
        "note": (
            "A fix that is resisted_by=tools on both packs lives below the model: changing "
            "vendor will not undo it. A split means you are depending on a specific model."
        ),
    }


def render_compare_markdown(cmp: dict[str, Any]) -> str:
    lines = [
        "# New Chisel vendor-neutral comparison",
        "",
        f"Left: `{cmp['left']['run_id']}` model `{cmp['left'].get('model') or 'n/a'}`",
        f"Right: `{cmp['right']['run_id']}` model `{cmp['right'].get('model') or 'n/a'}`",
        "",
        cmp["note"],
        "",
        "| Scenario | Left | Right |",
        "|---|---|---|",
    ]
    for row in cmp["scenarios"]:
        lv = (row["left"] or {})
        rv = (row["right"] or {})
        left = f"{lv.get('verdict') or '—'} ({lv.get('resisted_by') or '—'})"
        right = f"{rv.get('verdict') or '—'} ({rv.get('resisted_by') or '—'})"
        lines.append(f"| `{row['id']}` | {left} | {right} |")
    if cmp["tool_fixes_that_held_on_both"]:
        lines += ["", "Tool-level fixes that held on both models: " + ", ".join(f"`{s}`" for s in cmp["tool_fixes_that_held_on_both"])]
    if cmp["model_only_splits"]:
        lines += ["", "Model-only splits (do not treat as a tool fix): " + ", ".join(f"`{s}`" for s in cmp["model_only_splits"])]
    if cmp.get("regressions"):
        lines += ["", "Regressions (RESISTED → FAILED): " + ", ".join(f"`{s}`" for s in cmp["regressions"])]
    return "\n".join(lines) + "\n"
