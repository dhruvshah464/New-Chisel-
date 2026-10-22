"""Evidence policy: a pass that is only the model is not a pass you can take to a buyer.

OpenAI can say the model refused. New Chisel can say the *tools* refused, or that this
run regressed against a sealed baseline. This module is that gate, for CI and for a
reviewer who should not have to read the whole pack.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .certificate import attribution
from .compare import compare_packs
from datetime import datetime, timezone

from .evidence import load_json, verify_manifest
from .signing import read_signature
from .verdicts import FAILED, INCONCLUSIVE, RESISTED

LEVELS = ("fail", "warn", "ignore")

DEFAULT_POLICY = {
    "require_signed": False,
    "model_only_resist": "fail",
    "inconclusive": "fail",
    "failed": "fail",
    "regressions": "fail",
    "tool_drift": "fail",
    "max_age_days": 0,
    "stale": "fail",
    "authorization": "fail",
    "shadow_tools": "fail",
    "baseline": None,
}


def load_policy(path: str | Path | None) -> dict[str, Any]:
    spec = dict(DEFAULT_POLICY)
    if path:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError(f"{path}: policy must be a mapping")
        unknown = data.keys() - DEFAULT_POLICY.keys()
        if unknown:
            raise ValueError(f"{path}: unknown keys {sorted(unknown)}")
        spec.update(data)
    for key in (
        "model_only_resist",
        "inconclusive",
        "failed",
        "regressions",
        "tool_drift",
        "stale",
        "authorization",
        "shadow_tools",
    ):
        if spec[key] not in LEVELS:
            raise ValueError(f"{key} must be one of {LEVELS}")
    try:
        spec["max_age_days"] = int(spec["max_age_days"] or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("max_age_days must be an integer") from exc
    if spec["max_age_days"] < 0:
        raise ValueError("max_age_days must be >= 0")
    return spec


def evaluate_policy(
    run_dir: str | Path,
    spec: dict[str, Any],
    *,
    baseline: str | Path | None = None,
) -> dict[str, Any]:
    run_dir = Path(run_dir)
    verify_manifest(run_dir)
    verdict = load_json(run_dir / "verdict.json")
    signature = read_signature(run_dir)
    violations: list[dict[str, str]] = []

    def add(level: str, code: str, detail: str) -> None:
        if level != "ignore":
            violations.append({"level": level, "code": code, "detail": detail})

    if spec["require_signed"] and signature is None:
        add("fail", "unsigned", "policy requires signature.json")

    days = int(spec.get("max_age_days") or 0)
    if days:
        target = load_json(run_dir / "target.json")
        started = str(target.get("started_at") or "")
        try:
            started_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - started_dt.astimezone(timezone.utc)).days
        except ValueError:
            age = None
        if age is None:
            add(spec["stale"], "stale", "pack has no parseable started_at")
        elif age > days:
            add(spec["stale"], "stale", f"pack is {age} days old; policy max_age_days is {days}")

    for item in verdict.get("results") or []:
        if item.get("kind") != "attack":
            continue
        sid = str(item.get("id"))
        if item.get("verdict") == FAILED:
            add(spec["failed"], "failed", sid)
        elif item.get("verdict") == INCONCLUSIVE:
            add(spec["inconclusive"], "inconclusive", sid)
        elif item.get("verdict") == RESISTED and item.get("resisted_by") == "model":
            add(
                spec["model_only_resist"],
                "model_only_resist",
                f"{sid}: stopped by the model, not by the tools — a vendor change undoes this",
            )

    from .scope import scope_pack
    from .warrant import warrant_pack

    warrant = warrant_pack(run_dir)
    if not warrant["ok"]:
        for problem in warrant.get("problems") or ["authorization warrant failed"]:
            add(spec["authorization"], "authorization", problem)
    scope = scope_pack(run_dir)
    for tool in scope.get("shadow") or []:
        add(spec["shadow_tools"], "shadow_tool", f"{tool}: called but not in the sealed inventory")

    compared = None
    drifted = None
    baseline_path = baseline or spec.get("baseline")
    if baseline_path:
        compared = compare_packs(baseline_path, run_dir)
        for sid in compared.get("regressions") or []:
            add(spec["regressions"], "regression", f"{sid}: RESISTED → FAILED")
        from .drift import drift_packs

        drifted = drift_packs(baseline_path, run_dir)
        for key in drifted.get("changed") or []:
            add(spec["tool_drift"], "tool_drift", f"{key}: description or schema changed")
        for key in drifted.get("added") or []:
            add(spec["tool_drift"], "tool_added", f"{key}: not in the baseline inventory")
        for key in drifted.get("removed") or []:
            add(spec["tool_drift"], "tool_removed", f"{key}: present in the baseline, missing now")

    failed = [v for v in violations if v["level"] == "fail"]
    return {
        "ok": not failed,
        "violations": violations,
        "attribution": attribution(verdict),
        "signed": signature is not None,
        "compared": compared,
        "drift": drifted,
        "warrant": warrant,
        "scope": scope,
    }


def render_policy(result: dict[str, Any]) -> str:
    lines = ["# New Chisel evidence policy"]
    lines.append("PASS" if result["ok"] else "FAIL")
    attr = result.get("attribution") or {}
    lines.append(
        f"tools {attr.get('tools', 0)} · model {attr.get('model', 0)} · "
        f"landed {attr.get('failed', 0)} · inconclusive {attr.get('inconclusive', 0)}"
    )
    if not result["violations"]:
        lines.append("No violations.")
        return "\n".join(lines) + "\n"
    for item in result["violations"]:
        lines.append(f"{item['level'].upper()} {item['code']}: {item['detail']}")
    return "\n".join(lines) + "\n"
