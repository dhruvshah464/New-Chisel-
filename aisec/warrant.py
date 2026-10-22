"""Post-hoc warrant: was this sealed run authorized when it ran?

A model vendor does not hold a customer-signed window that says you may attack
*this* agent, in this environment, with synthetic data, until a deadline. The
hashed ``authorization.yaml`` in the pack is that warrant. This check uses the
pack's ``started_at``, not the clock now, so an auditor can still verify last
week's run.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .evidence import load_json, verify_manifest
from .targets.command import AUTHORIZATION_FILE, Authorization, AuthorizationError


def _started_at(target: dict[str, Any]) -> datetime | None:
    raw = target.get("started_at")
    if not raw:
        return None
    try:
        moment = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def warrant_pack(run_dir: str | Path) -> dict[str, Any]:
    run_dir = Path(run_dir)
    verify_manifest(run_dir)
    target = load_json(run_dir / "target.json")
    inner = target.get("target") or {}
    auth_path = run_dir / AUTHORIZATION_FILE
    started = _started_at(target)
    note = (
        "A model vendor does not hold a customer-signed attack window for someone else's "
        "agent. This warrant is that record, hashed into the pack, checked at started_at."
    )
    if not auth_path.is_file():
        if inner.get("target") == "command":
            return {
                "ok": False,
                "kind": "missing",
                "client": None,
                "environment": None,
                "data": None,
                "window": None,
                "started_at": target.get("started_at"),
                "inside_window": False,
                "problems": ["command target pack has no authorization.yaml"],
                "note": note,
            }
        return {
            "ok": True,
            "kind": "demo",
            "client": "New Chisel demo (synthetic)",
            "environment": "demo-synthetic",
            "data": "synthetic",
            "window": None,
            "started_at": target.get("started_at"),
            "inside_window": True,
            "problems": [],
            "note": note,
        }
    problems: list[str] = []
    try:
        auth = Authorization.load(auth_path)
    except AuthorizationError as exc:
        return {
            "ok": False,
            "kind": "customer",
            "client": None,
            "environment": None,
            "data": None,
            "window": None,
            "started_at": target.get("started_at"),
            "inside_window": False,
            "problems": [str(exc)],
            "note": note,
        }
    recorded = (inner.get("authorization") or {}).get("sha256")
    digest = hashlib.sha256(auth_path.read_bytes()).hexdigest()
    if recorded and recorded != digest:
        problems.append("authorization.yaml sha256 does not match target.json")
    servers = sorted(
        {str(t.get("server") or "") for t in (target.get("tool_inventory") or []) if t.get("server")}
    ) or list(auth.servers)
    inside = False
    if started is None:
        problems.append("pack has no parseable started_at")
    else:
        inside = auth.window_start <= started <= auth.window_end
        try:
            auth.check(servers, at=started)
        except AuthorizationError as exc:
            problems.append(str(exc))
    return {
        "ok": not problems,
        "kind": "customer",
        "client": auth.client,
        "environment": auth.environment,
        "data": auth.data,
        "window": {"start": auth.window_start.isoformat(), "end": auth.window_end.isoformat()},
        "started_at": target.get("started_at"),
        "inside_window": inside,
        "authorized_by": auth.authorized_by.get("name"),
        "problems": problems,
        "note": note,
    }


def render_warrant_markdown(warrant: dict[str, Any]) -> str:
    lines = [
        "# New Chisel warrant",
        "",
        warrant["note"],
        "",
        f"Kind: `{warrant['kind']}`",
        f"Client: {warrant.get('client') or '—'}",
        f"Environment: {warrant.get('environment') or '—'}",
        f"Data: {warrant.get('data') or '—'}",
        f"Started: {warrant.get('started_at') or '—'}",
    ]
    window = warrant.get("window") or {}
    if window:
        lines.append(f"Window: {window.get('start')} → {window.get('end')}")
        lines.append(f"Inside window at start: {'yes' if warrant.get('inside_window') else 'no'}")
    if warrant.get("authorized_by"):
        lines.append(f"Authorized by: {warrant['authorized_by']}")
    lines.append("")
    lines.append("OK" if warrant["ok"] else "FAIL")
    for problem in warrant.get("problems") or []:
        lines.append(f"- {problem}")
    return "\n".join(lines) + "\n"
