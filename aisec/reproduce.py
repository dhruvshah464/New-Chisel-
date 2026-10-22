"""Sealed rerun recipe. The pack is the source of truth, not the operator's memory.

A vendor dashboard will not emit a command that rebuilds *your* agent trial from the
hashed scenario files in the pack. This does. It does not re-run the agent. It does
not print API keys or server env values.
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

from .evidence import load_json, verify_manifest


def reproduce_pack(run_dir: str | Path) -> dict[str, Any]:
    run_dir = Path(run_dir)
    verify_manifest(run_dir)
    target = load_json(run_dir / "target.json")
    inner = target.get("target") or {}
    kind = inner.get("target") or "demo"
    argv = ["aisec", "run"]
    notes: list[str] = [
        "The pack is the recipe. Do not trust a chat log of what was run.",
        "Model API keys are still yours; they are not in the pack.",
    ]
    complete = True
    if kind == "command":
        config = inner.get("config") or "aisec-target.yaml"
        argv += ["--target", "command", "--target-config", str(config)]
        complete = False
        notes.append(
            "Command targets need the original agent, MCP config, and a still-valid "
            "authorization. Those files live beside the agent, not in this pack."
        )
    else:
        argv += ["--target", "demo"]
        if inner.get("variant"):
            argv += ["--variant", str(inner["variant"])]
        if inner.get("model"):
            argv += ["--model", str(inner["model"])]
    if target.get("driver") == "replay":
        argv.append("--replay-only")
        notes.append("This pack was replay-only: it shows what the tools allow, not what a model does.")
    scenarios = run_dir / "scenarios"
    if scenarios.is_dir() and any(scenarios.iterdir()):
        argv += ["--scenarios", str(scenarios)]
    else:
        complete = False
        notes.append("No scenario files in the pack; supply --scenarios yourself.")
    if target.get("driver") != "replay":
        repeat = target.get("repeat_requested") or target.get("trials_per_scenario")
        if repeat:
            argv += ["--repeat", str(repeat)]
    if target.get("fail_on"):
        argv += ["--fail-on", str(target["fail_on"])]
    return {
        "run_id": target.get("run_id") or run_dir.name,
        "argv": argv,
        "command": shlex.join(argv),
        "complete": complete,
        "driver": target.get("driver"),
        "notes": notes,
        "note": (
            "Reconstructed from the sealed pack. An auditor can hash-check the pack, then "
            "run this command against the hashed scenario files. This is not a remote retest."
        ),
    }


def render_reproduce_markdown(recipe: dict[str, Any]) -> str:
    lines = [
        "# New Chisel reproduce",
        "",
        recipe["note"],
        "",
        "```sh",
        recipe["command"],
        "```",
        "",
        "Complete recipe" if recipe["complete"] else "Incomplete recipe (files outside the pack are required)",
        "",
    ]
    for item in recipe["notes"]:
        lines.append(f"- {item}")
    return "\n".join(lines) + "\n"
