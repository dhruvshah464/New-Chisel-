"""Evidence goes stale. A one-shot model eval does not.

``aisec due`` lists sealed packs older than N days. Insurers and buyers need a retest
clock; a vendor leaderboard does not.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .evidence import DEFAULT_RUNS_ROOT, load_json, manifest_digest


def _age_days(started_at: str) -> int | None:
    try:
        started = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - started.astimezone(timezone.utc)).days


def stale_packs(runs_root: str | Path = DEFAULT_RUNS_ROOT, *, days: int = 90) -> list[dict[str, Any]]:
    root = Path(runs_root)
    if not root.is_dir():
        return []
    rows = []
    for path in sorted(root.iterdir()):
        if not path.is_dir() or not (path / "manifest.json").is_file():
            continue
        target = load_json(path / "target.json")
        age = _age_days(str(target.get("started_at") or ""))
        if age is None or age <= days:
            continue
        rows.append(
            {
                "run_id": path.name,
                "path": str(path),
                "age_days": age,
                "started_at": target.get("started_at"),
                "manifest_sha256": manifest_digest(path),
            }
        )
    return rows


def render_due_markdown(rows: list[dict[str, Any]], *, days: int) -> str:
    if not rows:
        return f"# New Chisel retest clock\n\nNo sealed pack is older than {days} days.\n"
    lines = [
        "# New Chisel retest clock",
        "",
        f"These packs are older than {days} days. A model-vendor score from last quarter is not this.",
        "",
        "| Run | Age (days) | Started |",
        "|---|---:|---|",
    ]
    for row in rows:
        lines.append(f"| `{row['run_id']}` | {row['age_days']} | {row['started_at']} |")
    return "\n".join(lines) + "\n"
