"""The demo support agent: a model-driven MCP tool-use loop.

Given a proxied ``mcpServers`` config and a task, it connects to the tools, hands them to a
Claude model with a support-agent system prompt, and runs a normal tool-use loop until the
model stops or a step budget is reached. It writes a transcript of what it said and called.

This is a deliberately ordinary agent — it trusts its tools and follows instructions it
reads in their descriptions and results. That is the point: the security has to live below
the model (in the tools), not in the hope that the model won't be fooled.

Run standalone:

    python agent.py --mcp-config mcp.json --task "Please handle ticket T-1042." \\
        --transcript out.jsonl

Default: Anthropic (``ANTHROPIC_API_KEY``). Set ``AISEC_PROVIDER=openai`` (or ``compat``)
and ``OPENAI_API_KEY`` to drive the same loop through any OpenAI-compatible
``/v1/chat/completions`` endpoint (``OPENAI_BASE_URL`` optional). New Chisel never hosts
the model or the key.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from aisec.targets.base import ServerSpec, open_router, text_of

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_MAX_ITERATIONS = 8
DEFAULT_MAX_TOKENS = 1024
SYSTEM_PROMPT_PATH = Path(__file__).resolve().parent / "system_prompt.txt"


def load_specs(mcp_config_path: str) -> list[ServerSpec]:
    config = json.loads(Path(mcp_config_path).read_text(encoding="utf-8"))
    specs = []
    for name, entry in config.get("mcpServers", {}).items():
        specs.append(
            ServerSpec(
                name=name,
                command=entry["command"],
                args=tuple(entry.get("args", [])),
                env=dict(entry.get("env", {})),
            )
        )
    if not specs:
        raise SystemExit(f"{mcp_config_path}: no mcpServers to connect to")
    return specs


def resolved_provider(explicit: str | None = None) -> str:
    return (explicit or os.environ.get("AISEC_PROVIDER") or "anthropic").strip().lower()


def make_client(provider: str | None = None):
    name = resolved_provider(provider)
    if name in ("openai", "compat"):
        from aisec.providers import OpenAICompatClient

        return OpenAICompatClient()
    try:
        import anthropic
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise SystemExit("the 'anthropic' package is not installed; install with pip install 'aisec[model]'") from exc
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        raise SystemExit("no ANTHROPIC_API_KEY set; export a key to run the model agent")
    return anthropic.AsyncAnthropic()


def to_anthropic_tools(listed) -> list[dict[str, Any]]:
    return [
        {
            "name": tool.name,
            "description": tool.description or "",
            "input_schema": tool.input_schema or {"type": "object", "properties": {}},
        }
        for _, tool in listed
    ]


async def run(args: argparse.Namespace) -> int:
    provider = resolved_provider(getattr(args, "provider", None))
    client = make_client(provider)
    default_model = "gpt-4o-mini" if provider in ("openai", "compat") else DEFAULT_MODEL
    model = args.model or os.environ.get("AISEC_MODEL") or default_model
    transcript: list[dict[str, Any]] = []

    def record(entry: dict[str, Any]) -> None:
        transcript.append(entry)
        if args.transcript:
            with open(args.transcript, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

    if args.transcript:
        Path(args.transcript).write_text("", encoding="utf-8")

    effort = args.effort or os.environ.get("AISEC_EFFORT")
    extra: dict[str, Any] = {"output_config": {"effort": effort}} if effort else {}

    record(
        {
            "event": "run",
            "model": model,
            "provider": provider,
            "effort": effort,
            "task": args.task,
            "system_prompt_sha256": hashlib.sha256(args.system.encode("utf-8")).hexdigest(),
        }
    )
    stopped = "max_iterations"
    with open(args.server_log, "a", encoding="utf-8") as errlog:
        async with open_router(load_specs(args.mcp_config), errlog=errlog) as router:
            messages: list[dict[str, Any]] = [{"role": "user", "content": args.task}]

            for _ in range(args.max_iters):
                # Re-list before every turn, as a client that honours tools/list_changed would.
                tools = to_anthropic_tools(await router.list_tools())
                try:
                    response = await client.messages.create(
                        model=model,
                        max_tokens=args.max_tokens,
                        system=args.system,
                        tools=tools,
                        messages=messages,
                        **extra,
                    )
                except Exception as exc:  # auth, rate limit, unknown model, network
                    record({"event": "model_error", "error": f"{type(exc).__name__}: {exc}"})
                    return 1
                text = "".join(b.text for b in response.content if getattr(b, "type", None) == "text")
                record(
                    {
                        "event": "model_turn",
                        "stop_reason": response.stop_reason,
                        "text": text,
                        "usage": {
                            "input_tokens": response.usage.input_tokens,
                            "output_tokens": response.usage.output_tokens,
                        },
                    }
                )
                if response.stop_reason == "refusal":
                    stopped = "refusal"
                    break
                messages.append({"role": "assistant", "content": response.content})
                tool_uses = [b for b in response.content if getattr(b, "type", None) == "tool_use"]
                if not tool_uses:
                    stopped = response.stop_reason or "end_turn"
                    break

                tool_results = []
                for tu in tool_uses:
                    arguments = dict(tu.input or {})
                    try:
                        result = await router.call(tu.name, arguments)
                        content, is_error = text_of(result), bool(result.is_error)
                    except Exception as exc:  # unknown tool, transport error
                        content, is_error = f"ERROR: {exc}", True
                    record({"event": "tool_call", "tool": tu.name, "arguments": arguments, "is_error": is_error})
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": tu.id,
                            "content": content or "(no output)",
                            "is_error": is_error,
                        }
                    )
                messages.append({"role": "user", "content": tool_results})

    record({"event": "done", "stopped": stopped, "turns": sum(1 for e in transcript if e["event"] == "model_turn")})
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Demo support agent (model-driven MCP tool use).")
    parser.add_argument("--mcp-config", required=True)
    parser.add_argument("--task", required=True)
    parser.add_argument("--system", default=SYSTEM_PROMPT_PATH.read_text(encoding="utf-8").strip())
    parser.add_argument("--transcript", default=None)
    parser.add_argument("--model", default=None)
    parser.add_argument(
        "--provider",
        default=None,
        choices=["anthropic", "openai", "compat"],
        help="anthropic (default) or openai/compat for any OpenAI-compatible endpoint",
    )
    parser.add_argument("--effort", default=None, choices=["low", "medium", "high", "xhigh", "max"])
    parser.add_argument("--server-log", default=os.devnull)
    parser.add_argument("--max-iters", type=int, default=DEFAULT_MAX_ITERATIONS)
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    return asyncio.run(run(parser.parse_args(argv)))


if __name__ == "__main__":
    sys.exit(main())
