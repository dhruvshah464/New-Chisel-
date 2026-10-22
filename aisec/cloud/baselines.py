"""Regression view: last two sealed packs for a project, compared vendor-neutrally."""

from __future__ import annotations

from typing import Any

from ..compare import compare_packs
from .db import Store


def project_baseline(store: Store, org_id: str, project_id: str) -> dict[str, Any]:
    rows = store.query(
        "SELECT run_id, manifest_sha256, pack_path, created_at FROM runs "
        "WHERE org_id=? AND project_id=? ORDER BY created_at DESC LIMIT 2",
        (org_id, project_id),
    )
    if len(rows) < 2:
        return {"status": "need_two_runs", "count": len(rows), "runs": rows}
    newer, older = rows[0], rows[1]
    compared = compare_packs(older["pack_path"], newer["pack_path"])
    compared["status"] = "ok"
    compared["older_run_id"] = older["run_id"]
    compared["newer_run_id"] = newer["run_id"]
    return compared
