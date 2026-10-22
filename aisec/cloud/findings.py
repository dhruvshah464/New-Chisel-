"""Finding tickets: one open ticket per (project, scenario) that failed, stalled, or blocked."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from ..evidence import now
from ..export import TICKET_VERDICTS, finding_results
from ..verdicts import COMPLETED, FAILED, RESISTED
from .db import Store
from .security import dumps

OPEN_STATUSES = ("open", "in_progress", "retesting")
TERMINAL = ("resolved", "accepted_risk", "wontfix")
SLA_HOURS = {"critical": 48, "high": 72, "medium": 120, "low": 240}


def _id(prefix: str) -> str:
    return prefix + "_" + secrets.token_hex(8)


def _body(item: dict[str, Any], run_id: str) -> str:
    owasp = ", ".join(item.get("owasp") or []) or "unmapped"
    rate = item.get("rate") or {}
    rate_s = f"{rate.get('k')}/{rate.get('n')}" if rate else "n/a"
    return (
        f"Verdict: {item.get('verdict')}\n"
        f"Severity: {item.get('severity') or 'n/a'}\n"
        f"OWASP: {owasp}\n"
        f"Rate: {rate_s}\n"
        f"Resisted by: {item.get('resisted_by') or 'n/a'}\n"
        f"Reason: {item.get('reason') or ''}\n"
        f"Run: {run_id}\n"
        f"Retest: aisec run --scenarios <this scenario file> --repeat 20\n"
    )


def sync_from_verdict(
    store: Store,
    *,
    org_id: str,
    project_id: str,
    run_id: str,
    verdict: dict[str, Any],
    actor: str,
) -> dict[str, int]:
    opened = updated = resolved = 0
    stamp = now()
    by_id = {r["id"]: r for r in verdict.get("results") or []}
    for item in finding_results(verdict):
        existing = store.one(
            "SELECT * FROM findings WHERE org_id=? AND project_id=? AND scenario_id=? "
            "AND status IN ('open','in_progress','retesting')",
            (org_id, project_id, item["id"]),
        )
        body = _body(item, run_id)
        if existing:
            store.execute(
                "UPDATE findings SET latest_run_id=?, severity=?, body=?, updated_at=? WHERE id=?",
                (run_id, item.get("severity"), body, stamp, existing["id"]),
            )
            _event(store, existing["id"], "run_updated", actor, {"run_id": run_id, "verdict": item["verdict"]})
            updated += 1
            continue
        finding_id = _id("fnd")
        store.execute(
            "INSERT INTO findings (id, org_id, project_id, scenario_id, title, owasp, severity, status, "
            "assignee, due_at, accepted_risk_reason, created_from_run_id, latest_run_id, body, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                finding_id,
                org_id,
                project_id,
                item["id"],
                item.get("title") or item["id"],
                dumps(item.get("owasp") or []),
                item.get("severity"),
                "open",
                None,
                (
                    datetime.now(timezone.utc)
                    + timedelta(hours=SLA_HOURS.get(item.get("severity") or "low", 240))
                ).isoformat(timespec="seconds"),
                None,
                run_id,
                run_id,
                body,
                stamp,
                stamp,
            ),
        )
        _event(store, finding_id, "opened", actor, {"run_id": run_id, "verdict": item["verdict"]})
        opened += 1

    for item in by_id.values():
        if item.get("verdict") not in {RESISTED, COMPLETED}:
            continue
        existing = store.one(
            "SELECT * FROM findings WHERE org_id=? AND project_id=? AND scenario_id=? "
            "AND status IN ('open','in_progress','retesting')",
            (org_id, project_id, item["id"]),
        )
        if not existing:
            continue
        store.execute(
            "UPDATE findings SET status='resolved', latest_run_id=?, updated_at=? WHERE id=?",
            (run_id, stamp, existing["id"]),
        )
        _event(store, existing["id"], "retest_result", actor, {"run_id": run_id, "verdict": item["verdict"]})
        resolved += 1

    # A later FAILED run reopens a terminal ticket for the same scenario.
    for item in by_id.values():
        if item.get("verdict") != FAILED:
            continue
        closed = store.one(
            "SELECT * FROM findings WHERE org_id=? AND project_id=? AND scenario_id=? "
            "AND status IN ('resolved','accepted_risk','wontfix') ORDER BY updated_at DESC",
            (org_id, project_id, item["id"]),
        )
        open_one = store.one(
            "SELECT id FROM findings WHERE org_id=? AND project_id=? AND scenario_id=? "
            "AND status IN ('open','in_progress','retesting')",
            (org_id, project_id, item["id"]),
        )
        if closed and not open_one:
            store.execute(
                "UPDATE findings SET status='open', latest_run_id=?, updated_at=? WHERE id=?",
                (run_id, stamp, closed["id"]),
            )
            _event(store, closed["id"], "reopened", actor, {"run_id": run_id})
    return {"opened": opened, "updated": updated, "resolved": resolved}


def set_status(store: Store, finding_id: str, org_id: str, status: str, actor: str, reason: str = "") -> dict[str, Any]:
    allowed = OPEN_STATUSES + TERMINAL
    if status not in allowed:
        raise ValueError(f"status must be one of {allowed}")
    row = store.one("SELECT * FROM findings WHERE id=? AND org_id=?", (finding_id, org_id))
    if row is None:
        raise KeyError(finding_id)
    stamp = now()
    store.execute(
        "UPDATE findings SET status=?, accepted_risk_reason=?, updated_at=? WHERE id=?",
        (status, reason or row.get("accepted_risk_reason"), stamp, finding_id),
    )
    _event(store, finding_id, "status", actor, {"from": row["status"], "to": status, "reason": reason})
    return store.one("SELECT * FROM findings WHERE id=?", (finding_id,)) or {}


def assign(store: Store, finding_id: str, org_id: str, assignee: str, actor: str) -> dict[str, Any]:
    row = store.one("SELECT * FROM findings WHERE id=? AND org_id=?", (finding_id, org_id))
    if row is None:
        raise KeyError(finding_id)
    store.execute(
        "UPDATE findings SET assignee=?, updated_at=? WHERE id=?",
        (assignee, now(), finding_id),
    )
    _event(store, finding_id, "assigned", actor, {"assignee": assignee})
    return store.one("SELECT * FROM findings WHERE id=?", (finding_id,)) or {}


def comment(store: Store, finding_id: str, org_id: str, text: str, actor: str) -> dict[str, Any]:
    row = store.one("SELECT * FROM findings WHERE id=? AND org_id=?", (finding_id, org_id))
    if row is None:
        raise KeyError(finding_id)
    event_id = _event(store, finding_id, "comment", actor, {"text": text})
    return {"id": event_id}


def retest_snippet(finding: dict[str, Any]) -> str:
    return f"aisec run --scenarios {finding['scenario_id']}.yaml --repeat 20"


def _event(store: Store, finding_id: str, kind: str, actor: str, payload: dict[str, Any]) -> str:
    event_id = _id("evt")
    store.execute(
        "INSERT INTO finding_events (id, finding_id, kind, actor, payload, created_at) VALUES (?,?,?,?,?,?)",
        (event_id, finding_id, kind, actor, dumps(payload), now()),
    )
    return event_id
