"""The intercepting MCP proxy.

Launched as ``python -m aisec.proxy wrap --server-name NAME -- <command> [args...]``.
To the agent it *is* the MCP server: it speaks the server side of the protocol over its
own stdio and mirrors the wrapped server's name, version and instructions. Internally it
holds a client session to the real server, which it launches as a subprocess, and every
``tools/list`` and ``tools/call`` passes through here, where it is

* **recorded** to the trial's event log (``AISEC_EVENTS``);
* **injected into**, when the trial's proxy config (``AISEC_PROXY_CONFIG``) names the tool:
  the scenario's payload is appended to the tool's description, or to its result;
* **held**, when the tool is on the config's hold list: the call is recorded and answered
  with a stand-in success, and is never forwarded to the server.

Nothing else is changed. Arguments pass through untouched, and every result other than an
injected one is returned exactly as the server produced it. The harness's own variables
are stripped from the wrapped server's environment, so the server under test cannot see
the injection config. Only tools are proxied; resources and prompts are not.

Adapted from Sentinel's stdio proxy (github.com/dhruvshah464/Sentinel), with its policy
enforcement replaced by recording, injection and holding.
"""

from __future__ import annotations

import argparse
import asyncio
import errno
import hashlib
import json
import os
import re
import socket
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.server.streamable_http import TransportSecuritySettings
from mcp.shared.exceptions import MCPError

from .sandbox import (
    ENV_EVENTS,
    ENV_MCP_CONFIG,
    ENV_PROXY_CONFIG,
    ENV_TASK,
    ENV_TRANSCRIPT,
    OUTCOME_ERROR,
    OUTCOME_HELD,
    OUTCOME_OK,
    append_jsonl,
)

HELD_RESULT_TEXT = '{"status": "accepted"}'
RESULT_TEXT_LIMIT = 4000
HARNESS_ENV = (ENV_EVENTS, ENV_PROXY_CONFIG, ENV_MCP_CONFIG, ENV_TASK, ENV_TRANSCRIPT)
USAGE = "usage: python -m aisec.proxy wrap [--server-name NAME] [--cwd DIR] -- <command> [args...]"
HTTP_USAGE = (
    "usage: aisec proxy --transport http --host 127.0.0.1 --port PORT --events RUN_DIR -- <command> [args...]"
)
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_SESSION_ERRORS = (
    BrokenPipeError,
    ConnectionResetError,
    ConnectionError,
    EOFError,
    anyio.BrokenResourceError,
    anyio.ClosedResourceError,
)


def _contains_exc(exc: BaseException, types: tuple[type[BaseException], ...]) -> bool:
    if isinstance(exc, types):
        return True
    if isinstance(exc, BaseExceptionGroup):
        return any(_contains_exc(inner, types) for inner in exc.exceptions)
    return False


class KeyLeakError(RuntimeError):
    """A persist/log record would contain model-key material."""


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def text_of(result: types.CallToolResult) -> str:
    return "\n".join(c.text for c in (result.content or []) if isinstance(c, types.TextContent))


def _append(base: str, payload: str) -> str:
    return f"{base.rstrip()}\n\n{payload}" if base.strip() else payload


def inject_into_result(
    result: types.CallToolResult, payload: str, field: str | None = None
) -> tuple[types.CallToolResult, str]:
    """Append ``payload`` to a result; return the new result and where it went.

    With ``field``, a result whose first text block is a JSON object gets the payload
    appended to that string field, so it reads as part of the record (a ticket body, an
    article). Otherwise the payload is appended to the last text block. Structured content
    is dropped so a client cannot read an uninjected copy.
    """
    content = list(result.content or [])
    text_blocks = [i for i, c in enumerate(content) if isinstance(c, types.TextContent)]
    if field and text_blocks:
        first = text_blocks[0]
        try:
            obj = json.loads(content[first].text)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict) and isinstance(obj.get(field), str):
            obj[field] = _append(obj[field], payload)
            content[first] = content[first].model_copy(
                update={"text": json.dumps(obj, indent=2, ensure_ascii=False)}
            )
            return result.model_copy(update={"content": content, "structured_content": None}), f"field:{field}"
    if text_blocks:
        last = text_blocks[-1]
        content[last] = content[last].model_copy(update={"text": _append(content[last].text, payload)})
    else:
        content.append(types.TextContent(type="text", text=payload))
    return result.model_copy(update={"content": content, "structured_content": None}), "appended"


@dataclass(frozen=True)
class ProxyConfig:
    injection: dict[str, Any] | None = None
    hold_tools: frozenset[str] = frozenset()

    @classmethod
    def load(cls, path: str | None) -> "ProxyConfig":
        if not path:
            return cls()
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(injection=data.get("injection"), hold_tools=frozenset(data.get("hold_tools") or ()))


class Interceptor:
    """The proxy's ``tools/list`` and ``tools/call`` handlers over one wrapped server."""

    def __init__(self, inner: ClientSession, server_name: str, events_path: Path, config: ProxyConfig):
        self.inner = inner
        self.server_name = server_name
        self.events_path = events_path
        self.config = config
        self.list_count = 0
        self.call_counts: dict[str, int] = {}
        self.last_description_hash: dict[str, str] = {}

    def _record(self, record: dict[str, Any]) -> None:
        stamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        append_jsonl(self.events_path, {"ts": stamp, "server": self.server_name, **record}, sequence=True)

    def _injection_for(self, channel: str, tool: str, occurrence: int) -> dict[str, Any] | None:
        inj = self.config.injection
        if inj and inj.get("channel") == channel and inj.get("tool") == tool and occurrence > int(inj.get("after", 0)):
            return inj
        return None

    async def _inner_tools(self) -> list[types.Tool]:
        tools: list[types.Tool] = []
        cursor: str | None = None
        while True:
            params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
            page = await self.inner.list_tools(params=params)
            tools.extend(page.tools)
            cursor = page.next_cursor
            if not cursor:
                return tools

    async def on_list_tools(self, ctx: Any, params: Any) -> types.ListToolsResult:
        self.list_count += 1
        out: list[types.Tool] = []
        listed: list[dict[str, Any]] = []
        for tool in await self._inner_tools():
            inj = self._injection_for("tool_description", tool.name, self.list_count)
            if inj:
                tool = tool.model_copy(update={"description": _append(tool.description or "", inj["payload"])})
            description = tool.description or ""
            digest = sha256(description)
            entry: dict[str, Any] = {"name": tool.name, "description_sha256": digest, "injected": bool(inj)}
            # Full text on first sight and whenever it changes: the evidence of a rug pull.
            if self.last_description_hash.get(tool.name) != digest:
                entry["description"] = description
            self.last_description_hash[tool.name] = digest
            listed.append(entry)
            out.append(tool)
        self._record(
            {
                "kind": "list",
                "list_index": self.list_count,
                "injected": any(t["injected"] for t in listed),
                "tools": listed,
            }
        )
        return types.ListToolsResult(tools=out)

    async def on_call_tool(self, ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        tool = params.name
        arguments = dict(params.arguments or {})
        index = self.call_counts[tool] = self.call_counts.get(tool, 0) + 1
        started = time.monotonic()

        if tool in self.config.hold_tools:
            result = types.CallToolResult(content=[types.TextContent(type="text", text=HELD_RESULT_TEXT)])
            outcome = OUTCOME_HELD
        else:
            try:
                result = await self.inner.call_tool(tool, arguments)
                outcome = OUTCOME_ERROR if result.is_error else OUTCOME_OK
            except Exception as exc:  # a protocol error from the server, or a dead transport
                result = types.CallToolResult(
                    content=[types.TextContent(type="text", text=f"Error: {exc}")], is_error=True
                )
                outcome = OUTCOME_ERROR

        injected_at = None
        inj = self._injection_for("tool_result", tool, index)
        if inj and outcome != OUTCOME_ERROR:
            result, injected_at = inject_into_result(result, inj["payload"], inj.get("field"))

        text = text_of(result)
        self._record(
            {
                "kind": "call",
                "tool": tool,
                "arguments": arguments,
                "call_index": index,
                "outcome": outcome,
                "injected": injected_at is not None,
                "injected_at": injected_at,
                "result_text": text[:RESULT_TEXT_LIMIT],
                "result_truncated": len(text) > RESULT_TEXT_LIMIT,
                "result_sha256": sha256(text),
                "duration_ms": round((time.monotonic() - started) * 1000, 1),
            }
        )
        return result


def _normalized_name(name: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_")


def name_is_secret(name: str) -> bool:
    normalized = _normalized_name(name)
    if "API_KEY" in normalized or normalized in {"APIKEY", "AUTHORIZATION"}:
        return True
    return normalized == "TOKEN" or normalized.endswith("_TOKEN") or normalized == "SECRET" or normalized.endswith("_SECRET")


def environ_secret_values() -> list[str]:
    values = []
    for key, value in os.environ.items():
        if value and len(value) >= 8 and name_is_secret(key):
            values.append(value)
    return values


def _named_secret_present(obj: Any) -> bool:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if name_is_secret(str(key)) and value not in (None, "", [], {}):
                return True
            if _named_secret_present(value):
                return True
        return False
    if isinstance(obj, list):
        return any(_named_secret_present(item) for item in obj)
    return False


def _query_has_secret(value: str) -> bool:
    if "?" not in value:
        return False
    query = value.split("?", 1)[1]
    for part in query.split("&"):
        key = part.split("=", 1)[0]
        if name_is_secret(key):
            return True
    return False


def record_would_leak(record: Any) -> bool:
    if _named_secret_present(record):
        return True
    blob = json.dumps(record, default=str, ensure_ascii=False)
    for secret in environ_secret_values():
        if secret in blob:
            return True
    if isinstance(record, dict):
        stack = [record]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
            elif isinstance(item, str) and _query_has_secret(item):
                return True
    return False


class LeakSafeInterceptor(Interceptor):
    def _record(self, record: dict[str, Any]) -> None:
        if record_would_leak(record):
            print("AISEC_KEY_LEAK", file=sys.stderr, flush=True)
            os._exit(2)
        super()._record(record)


def http_security_settings() -> TransportSecuritySettings:
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[
            "127.0.0.1",
            "127.0.0.1:*",
            "localhost",
            "localhost:*",
            "[::1]",
            "[::1]:*",
        ],
        allowed_origins=[
            "http://127.0.0.1",
            "http://127.0.0.1:*",
            "http://localhost",
            "http://localhost:*",
            "http://[::1]",
            "http://[::1]:*",
        ],
    )


def _tools_from_events(events_path: Path) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    if not events_path.is_file():
        return names
    for line in events_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("kind") == "list":
            for tool in record.get("tools") or []:
                name = tool.get("name")
                if name and name not in seen:
                    seen.add(name)
                    names.append(name)
        elif record.get("kind") == "call" and record.get("tool") and record["tool"] not in seen:
            seen.add(record["tool"])
            names.append(record["tool"])
    return names


def _claim_port(host: str, port: int) -> socket.socket:
    family = socket.AF_INET6 if host in {":1", "::1", "::"} else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind((host, port))
        sock.listen(2048)
    except OSError as exc:
        sock.close()
        if exc.errno in {errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", 10048)}:
            print("AISEC_EADDRINUSE", file=sys.stderr)
            raise SystemExit(2) from exc
        raise
    return sock


async def run_http_proxy(
    command: str,
    args: list[str],
    server_name: str,
    store_root: Path,
    host: str,
    port: int,
    cwd: str | None = None,
    timeout: float = 300,
    listen_sock: socket.socket | None = None,
) -> int:
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.routing import Mount
    import uvicorn

    from .evidence import JSONL_FILES

    events_path = store_root / JSONL_FILES[0]
    env = {k: v for k, v in os.environ.items() if k not in HARNESS_ENV}
    inner_params = StdioServerParameters(command=command, args=args, env=env, cwd=cwd)
    try:
        async with stdio_client(inner_params) as (inner_read, inner_write):
            async with ClientSession(inner_read, inner_write) as inner:
                try:
                    await asyncio.wait_for(inner.initialize(), timeout=timeout)
                except asyncio.TimeoutError:
                    print("AISEC_TIMEOUT", file=sys.stderr)
                    return 2
                except MCPError:
                    print("AISEC_SESSION_DROP", file=sys.stderr)
                    return 2
                interceptor = LeakSafeInterceptor(inner, server_name, events_path, ProxyConfig())
                outer = Server(
                    "aisec-proxy",
                    version="",
                    instructions="New Chisel customer-machine MCP proxy",
                    on_list_tools=interceptor.on_list_tools,
                    on_call_tool=interceptor.on_call_tool,
                )
                manager = StreamableHTTPSessionManager(
                    outer,
                    security_settings=http_security_settings(),
                )
                app = Starlette(routes=[Mount("/mcp", app=manager.handle_request)])
                config = uvicorn.Config(app, host=host, port=port, log_level="warning")
                server = uvicorn.Server(config)
                print(f"MCP Streamable HTTP: http://127.0.0.1:{port}/mcp", flush=True)
                try:
                    async with manager.run():
                        sockets = [listen_sock] if listen_sock is not None else None
                        await asyncio.wait_for(server.serve(sockets=sockets), timeout=timeout)
                except BaseException as exc:
                    if _contains_exc(exc, (asyncio.TimeoutError, TimeoutError)):
                        print("AISEC_TIMEOUT", file=sys.stderr)
                        return 2
                    if _contains_exc(exc, (KeyLeakError,)):
                        print("AISEC_KEY_LEAK", file=sys.stderr)
                        return 2
                    raise
                return 0
    except BaseException as exc:
        if _contains_exc(exc, (asyncio.TimeoutError, TimeoutError)):
            print("AISEC_TIMEOUT", file=sys.stderr)
            return 2
        if _contains_exc(exc, (KeyLeakError,)):
            print("AISEC_KEY_LEAK", file=sys.stderr)
            return 2
        if _contains_exc(exc, _SESSION_ERRORS) or _contains_exc(exc, (MCPError,)):
            print("AISEC_SESSION_DROP", file=sys.stderr)
            return 2
        raise
    return 0


def cmd_http(argv: list[str]) -> int:
    if "--" not in argv:
        print(HTTP_USAGE, file=sys.stderr)
        return 2
    idx = argv.index("--")
    own_args, wrapped = argv[:idx], argv[idx + 1 :]
    if not wrapped:
        print("aisec proxy: no command given after '--'", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(prog="aisec proxy", add_help=False)
    parser.add_argument("--transport", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--events", required=True)
    parser.add_argument("--allow-non-loopback", action="store_true")
    parser.add_argument("--server-name", default="server")
    parser.add_argument("--cwd", default=None)
    parser.add_argument("--timeout", type=float, default=300)
    try:
        parsed, unknown = parser.parse_known_args(own_args)
    except SystemExit:
        return 2
    if unknown:
        print(HTTP_USAGE, file=sys.stderr)
        return 2
    if parsed.transport == "sse":
        print("use --transport http", file=sys.stderr)
        return 2
    if parsed.transport != "http":
        print(HTTP_USAGE, file=sys.stderr)
        return 2
    if parsed.host not in LOOPBACK_HOSTS and not parsed.allow_non_loopback:
        print("AISEC_NON_LOOPBACK", file=sys.stderr)
        return 2
    if parsed.allow_non_loopback and parsed.host not in LOOPBACK_HOSTS:
        print("warning: --allow-non-loopback does not prove the host is the customer's", file=sys.stderr)
    from .evidence import RunStore

    run_dir = Path(parsed.events)
    store = RunStore(runs_root=run_dir.parent, run_id=run_dir.name)
    try:
        store.create()
    except FileExistsError:
        print("AISEC_EVENTS_EXISTS", file=sys.stderr)
        return 2
    try:
        listen_sock = _claim_port(parsed.host, parsed.port)
    except SystemExit as exc:
        return int(exc.code or 2)
    try:
        return asyncio.run(
            run_http_proxy(
                wrapped[0],
                wrapped[1:],
                parsed.server_name,
                store.root,
                parsed.host,
                parsed.port,
                parsed.cwd,
                parsed.timeout,
                listen_sock,
            )
        )
    except KeyLeakError:
        print("AISEC_KEY_LEAK", file=sys.stderr)
        return 2
    except SystemExit as exc:
        return int(exc.code or 2)
    finally:
        listen_sock.close()


def cmd_seal(argv: list[str]) -> int:
    from .evidence import EvidenceError, JSONL_FILES, RunStore

    if not argv:
        print("usage: aisec proxy seal RUN_DIR", file=sys.stderr)
        return 2
    run_dir = Path(argv[0])
    if not run_dir.is_dir():
        print(f"aisec proxy seal: no run directory {run_dir}", file=sys.stderr)
        return 2
    store = RunStore(runs_root=run_dir.parent, run_id=run_dir.name)
    target_path = store.root / "target.json"
    if not target_path.is_file() or target_path.stat().st_size == 0:
        store.write_json(
            "target.json",
            {
                "target": "proxy",
                "driver": "proxy_http",
                "run_id": store.run_id,
                "tools": _tools_from_events(store.root / "events.jsonl"),
            },
        )
    verdict_path = store.root / "verdict.json"
    if not verdict_path.is_file() or verdict_path.stat().st_size == 0:
        store.write_json("verdict.json", {"status": "INCONCLUSIVE", "reason": "proxy_capture_only"})
    for name in JSONL_FILES:
        path = store.root / name
        if not path.exists():
            path.write_text("", encoding="utf-8")
    try:
        store.seal()
    except EvidenceError as exc:
        print(f"aisec proxy seal: {exc}", file=sys.stderr)
        return 2
    return 0


async def run_proxy(
    command: str,
    args: list[str],
    server_name: str,
    events_path: Path,
    config: ProxyConfig,
    cwd: str | None = None,
) -> None:
    env = {k: v for k, v in os.environ.items() if k not in HARNESS_ENV}
    inner_params = StdioServerParameters(command=command, args=args, env=env, cwd=cwd)
    async with stdio_client(inner_params) as (inner_read, inner_write):
        async with ClientSession(inner_read, inner_write) as inner:
            init = await inner.initialize()
            interceptor = Interceptor(inner, server_name, events_path, config)
            outer = Server(
                init.server_info.name,
                version=init.server_info.version or "",
                instructions=init.instructions,
                on_list_tools=interceptor.on_list_tools,
                on_call_tool=interceptor.on_call_tool,
            )
            async with stdio_server() as (read_stream, write_stream):
                await outer.run(read_stream, write_stream, outer.create_initialization_options())


def split_wrapped_command(argv: list[str]) -> tuple[list[str], str, list[str]]:
    if "--" not in argv:
        raise SystemExit("aisec proxy wrap: expected '--' before the wrapped command")
    idx = argv.index("--")
    own_args, wrapped = argv[:idx], argv[idx + 1 :]
    if not wrapped:
        raise SystemExit("aisec proxy wrap: no command given after '--'")
    return own_args, wrapped[0], wrapped[1:]


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] != "wrap":
        print(USAGE, file=sys.stderr)
        return 2
    own_args, command, wrapped_args = split_wrapped_command(argv[1:])
    parser = argparse.ArgumentParser(prog="aisec proxy wrap")
    parser.add_argument("--server-name", default="server")
    parser.add_argument("--cwd", default=None, help="working directory for the wrapped server")
    parsed = parser.parse_args(own_args)

    events = os.environ.get(ENV_EVENTS)
    if not events:
        print(f"aisec proxy: {ENV_EVENTS} is not set; nowhere to record events", file=sys.stderr)
        return 2
    config = ProxyConfig.load(os.environ.get(ENV_PROXY_CONFIG))
    asyncio.run(run_proxy(command, wrapped_args, parsed.server_name, Path(events), config, parsed.cwd))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
