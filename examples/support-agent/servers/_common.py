"""Shared data and session helpers for the demo support-desk servers.

The dataset is entirely synthetic. The two variants differ only in whether the tools
enforce authorization:

* ``vulnerable`` — the tools do whatever they are asked. This is the common shape of a
  first-cut agent: the model is trusted to only ask for the right thing.
* ``fixed`` — the tools enforce authorization in code, independent of the model: refunds
  and emails go only to the customer on this ticket, refunds are capped, and lookups are
  scoped to that customer. The model can be fully hijacked and the damage still does not
  happen.

The variant and the authenticated session (which ticket this agent is handling) are the
server's own deployment settings, read from ``SUPPORT_DESK_VARIANT`` and
``SUPPORT_DESK_TICKET``. ``AISEC_SINK`` tells it where to record side effects.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from mcp.server.mcpserver.exceptions import ToolError

DATA_PATH = Path(__file__).resolve().parent.parent / "data.json"
DATA: dict[str, Any] = json.loads(DATA_PATH.read_text(encoding="utf-8"))

VULNERABLE = "vulnerable"
FIXED = "fixed"
DEFAULT_TICKET = "T-1042"


def variant() -> str:
    value = os.environ.get("SUPPORT_DESK_VARIANT", VULNERABLE)
    if value not in (VULNERABLE, FIXED):
        raise SystemExit(f"SUPPORT_DESK_VARIANT must be {VULNERABLE!r} or {FIXED!r}, got {value!r}")
    return value


def is_fixed() -> bool:
    return variant() == FIXED


def session_ticket_id() -> str:
    ticket_id = os.environ.get("SUPPORT_DESK_TICKET", DEFAULT_TICKET)
    if ticket_id not in DATA["tickets"]:
        raise SystemExit(f"SUPPORT_DESK_TICKET {ticket_id!r} is not a known ticket")
    return ticket_id


def customer(customer_id: str) -> dict[str, Any]:
    record = DATA["customers"].get(customer_id)
    if record is None:
        raise ToolError(f"No customer {customer_id}.")
    return {"customer_id": customer_id, **record}


def session_customer() -> dict[str, Any]:
    return customer(DATA["tickets"][session_ticket_id()]["customer_id"])


def refund_cap() -> float:
    return float(DATA["policy"]["refund_cap"])


def record_sink(entry: dict[str, Any]) -> None:
    """Record a would-be side effect (a refund, an email) instead of performing it."""
    sink = os.environ.get("AISEC_SINK")
    if not sink:
        return
    path = Path(sink)
    seq = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip()) + 1 if path.exists() else 1
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"seq": seq, **entry}, sort_keys=True, ensure_ascii=False) + "\n")
