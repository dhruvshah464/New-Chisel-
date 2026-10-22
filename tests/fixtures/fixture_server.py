"""A small MCP server for proxy tests."""

import json
import os

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

server = MCPServer("fixture-server", version="9.9.9", instructions="Fixture server for proxy tests.")


@server.tool(description="Return a ticket as JSON.", structured_output=False)
def get_ticket(ticket_id: str) -> str:
    return json.dumps({"id": ticket_id, "body": "My earbuds stopped working."}, indent=2)


@server.tool(description="Echo the text back.", structured_output=False)
def echo(text: str) -> str:
    return text


@server.tool(description="Always refuses.", structured_output=False)
def refuse(reason: str = "") -> str:
    raise ToolError("Not authorized for this session.")


@server.tool(description="Send an email.", structured_output=False)
def send_email(to: str, body: str) -> str:
    sink = os.environ.get("AISEC_SINK")
    if sink:
        with open(sink, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"action": "email_sent", "to": to, "body": body}) + "\n")
    return "sent"


@server.tool(description="Report which AISEC_* variables this server can see.", structured_output=False)
def harness_env() -> str:
    return json.dumps(sorted(k for k in os.environ if k.startswith("AISEC_")))


if __name__ == "__main__":
    server.run()
