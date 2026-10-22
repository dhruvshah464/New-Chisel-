"""The demo's support-desk MCP server: customers, tickets, refunds and email.

Run directly with ``python support_desk.py``. Its variant is set by
``SUPPORT_DESK_VARIANT`` (``vulnerable`` or ``fixed``); see ``_common.py``.
"""

from __future__ import annotations

import json

from _common import DATA, customer, is_fixed, record_sink, refund_cap, session_customer, session_ticket_id
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

server = MCPServer(
    "acme-support-desk",
    version="1.4.0",
    instructions="Acme's internal support desk: customer records, tickets, refunds and outbound email.",
)


@server.tool(description="Look up a customer's account record by customer ID.", structured_output=False)
def lookup_customer(customer_id: str) -> str:
    if is_fixed():
        allowed = session_customer()["customer_id"]
        if customer_id != allowed:
            raise ToolError(f"Not authorized: this session can only access customer {allowed}.")
    return json.dumps(customer(customer_id), indent=2)


@server.tool(description="Fetch a support ticket by ticket ID.", structured_output=False)
def get_ticket(ticket_id: str) -> str:
    if is_fixed() and ticket_id != session_ticket_id():
        raise ToolError(f"Not authorized: this session can only access ticket {session_ticket_id()}.")
    ticket = DATA["tickets"].get(ticket_id)
    if ticket is None:
        raise ToolError(f"No ticket {ticket_id}.")
    return json.dumps({"ticket_id": ticket_id, **ticket}, indent=2)


@server.tool(description="Issue a refund of `amount` US dollars to a billing account.", structured_output=False)
def issue_refund(account: str, amount: float, reason: str = "") -> str:
    if amount <= 0:
        raise ToolError("Refund amount must be positive.")
    if is_fixed():
        owner = session_customer()
        if account != owner["account"]:
            raise ToolError(
                f"Not authorized: refunds can only go to {owner['account']}, the account on file "
                "for this ticket's customer."
            )
        if amount > refund_cap():
            raise ToolError(f"Refunds above ${refund_cap():.0f} need a supervisor's approval.")
    record_sink({"action": "refund_issued", "account": account, "amount": amount, "reason": reason})
    return json.dumps({"status": "refunded", "account": account, "amount": amount})


@server.tool(description="Send an email.", structured_output=False)
def send_email(to: str, subject: str, body: str) -> str:
    if is_fixed():
        owner = session_customer()
        if to.strip().casefold() != owner["email"].casefold():
            raise ToolError("Not authorized: email can only go to the address on file for this ticket's customer.")
    record_sink({"action": "email_sent", "to": to, "subject": subject, "body": body})
    return json.dumps({"status": "sent", "to": to})


if __name__ == "__main__":
    server.run()
