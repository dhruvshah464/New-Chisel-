"""What a target is, and how its MCP servers are launched behind the proxy.

A target is the system under test: a set of MCP servers and an agent that uses them.
For every trial, aisec rewrites each server's launch command so that it runs behind the
intercepting proxy (``python -m aisec.proxy wrap ... -- <original command>``). The agent
then talks to the proxies exactly as it would talk to the servers, and every
``tools/list`` and ``tools/call`` lands in the trial's event log.
"""

from __future__ import annotations

import abc
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, TextIO

import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from ..proxy import text_of
from ..sandbox import Sandbox
from ..scenario import Scenario

__all__ = [
    "ServerSpec",
    "Target",
    "ToolRouter",
    "UnknownToolError",
    "list_all_tools",
    "mcp_config",
    "open_router",
    "proxied",
    "text_of",
]


class UnknownToolError(LookupError):
    """A call named a tool that none of the target's servers expose."""


@dataclass(frozen=True)
class ServerSpec:
    """How to launch one MCP server over stdio (one ``mcpServers`` entry)."""

    name: str
    command: str
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None

    def to_dict(self) -> dict[str, Any]:
        entry: dict[str, Any] = {"command": self.command, "args": list(self.args), "env": dict(self.env)}
        if self.cwd:
            entry["cwd"] = self.cwd
        return entry


def proxied(spec: ServerSpec, sandbox: Sandbox) -> ServerSpec:
    """The same server, launched behind the aisec proxy (``aisec proxy -- <command>``) for this trial.

    The proxy sets the server's working directory itself, since not every MCP client honors
    ``cwd`` in a config.
    """
    own = ("--server-name", spec.name) + (("--cwd", spec.cwd) if spec.cwd else ())
    return ServerSpec(
        name=spec.name,
        command=sys.executable,
        args=("-m", "aisec.proxy", "wrap", *own, "--", spec.command, *spec.args),
        env={**spec.env, **sandbox.proxy_env()},
    )


def mcp_config(specs: list[ServerSpec]) -> dict[str, Any]:
    """An ``mcpServers`` config, the format Claude Desktop, Cursor and most agents read."""
    return {"mcpServers": {s.name: s.to_dict() for s in specs}}


class ToolRouter:
    """One MCP client session per server, with tool calls routed by tool name."""

    def __init__(self, sessions: dict[str, ClientSession]):
        self.sessions = sessions
        self.owner: dict[str, str] = {}

    async def list_tools(self) -> list[tuple[str, types.Tool]]:
        listed: list[tuple[str, types.Tool]] = []
        owner: dict[str, str] = {}
        for server, session in self.sessions.items():
            for tool in await list_all_tools(session):
                if tool.name in owner:
                    raise ValueError(f"tool {tool.name!r} is exposed by both {owner[tool.name]!r} and {server!r}")
                owner[tool.name] = server
                listed.append((server, tool))
        self.owner = owner
        return listed

    async def call(self, tool: str, arguments: dict[str, Any], server: str | None = None) -> types.CallToolResult:
        if server is None:
            if not self.owner:
                await self.list_tools()
            server = self.owner.get(tool)
        if server not in self.sessions:
            raise UnknownToolError(f"no server exposes tool {tool!r}")
        return await self.sessions[server].call_tool(tool, arguments)


async def list_all_tools(session: ClientSession) -> list[types.Tool]:
    tools: list[types.Tool] = []
    cursor: str | None = None
    while True:
        params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
        page = await session.list_tools(params=params)
        tools.extend(page.tools)
        cursor = page.next_cursor
        if not cursor:
            return tools


@asynccontextmanager
async def open_router(specs: list[ServerSpec], errlog: TextIO = sys.stderr) -> AsyncIterator[ToolRouter]:
    """Launch every server and yield a router over the initialized sessions."""
    async with AsyncExitStack() as stack:
        sessions: dict[str, ClientSession] = {}
        for spec in specs:
            params = StdioServerParameters(command=spec.command, args=list(spec.args), env=dict(spec.env), cwd=spec.cwd)
            read, write = await stack.enter_async_context(stdio_client(params, errlog=errlog))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            sessions[spec.name] = session
        yield ToolRouter(sessions)


class Target(abc.ABC):
    """The system under test: its MCP servers and the agent that drives them."""

    name: str = "abstract"

    @abc.abstractmethod
    def describe(self) -> dict[str, Any]:
        """What was tested, for target.json."""

    def canaries(self) -> dict[str, list[str]]:
        """Named marker sets planted in the target's data, for canary checks."""
        return {}

    @abc.abstractmethod
    def servers(self, scenario: Scenario, sandbox: Sandbox, *, reachability: bool = False) -> list[ServerSpec]:
        """The (unproxied) servers for one trial.

        ``reachability=True`` asks for the configuration the scripted replay uses to prove
        an attack is possible at all. A target with a known-vulnerable configuration returns
        that one, so a fix shows up as RESISTED rather than NOT_REACHABLE.
        """

    def preflight(self) -> str | None:
        """Why the target's own agent cannot run (e.g. no API key), or None if it can."""
        return None

    def always_hold(self) -> set[str]:
        """Tools held in every trial, whatever the scenario says (e.g. those an authorization lists)."""
        return set()

    def evidence_files(self) -> dict[str, str]:
        """Files to copy verbatim into the evidence pack, as {pack file name: source path}."""
        return {}

    @abc.abstractmethod
    def agent_command(self, scenario: Scenario, sandbox: Sandbox) -> list[str]:
        """argv for the target's own agent.

        By the time this runs, the proxied MCP config is at ``sandbox.mcp_config_path``. The
        agent should write its transcript to ``sandbox.transcript_path`` if it can.
        """

    def agent_env(self, scenario: Scenario, sandbox: Sandbox) -> dict[str, str]:
        """Variables added to the agent's environment, on top of aisec's own."""
        return {}

    def agent_cwd(self) -> str | None:
        return None
