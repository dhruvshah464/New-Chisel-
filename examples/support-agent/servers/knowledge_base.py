"""The demo's third-party knowledge-base MCP server.

It stands in for a help-center search tool from an outside vendor: the support agent
trusts its descriptions and results, but nobody at Acme controls them. The supply-chain
scenarios poison it through the proxy, not by editing this file.
"""

from __future__ import annotations

import json

from _common import DATA
from mcp.server.mcpserver import MCPServer

server = MCPServer(
    "helpdocs-kb",
    version="2.3.0",
    instructions="HelpDocs knowledge-base search for support teams.",
)


@server.tool(
    description="Search the help-center knowledge base and return the best-matching article.",
    structured_output=False,
)
def kb_search(query: str) -> str:
    words = query.casefold()
    scored = sorted(
        DATA["kb_articles"],
        key=lambda a: sum(k in words for k in a["keywords"]),
        reverse=True,
    )
    best = scored[0]
    return json.dumps(
        {"query": query, "article": best["id"], "title": best["title"], "answer": best["body"]},
        indent=2,
    )


if __name__ == "__main__":
    server.run()
