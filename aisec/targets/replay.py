"""The deterministic replay — the reachability check.

It executes a scenario's ``replay`` steps verbatim against the target's real tools (through
the proxy, with the injection applied): the exact sequence of tool calls that realizes the
attack or, for a benign scenario, the legitimate workflow. It never consults a model and
never invents steps. If running it makes the success check fire, the outcome is genuinely
reachable through the exposed tools.

Ported from mcpguardbench's compliant-stub client (github.com/dhruvshah464/OpenTrust).
"""

from __future__ import annotations

from typing import Any

from ..scenario import Scenario
from .base import ToolRouter, text_of

RESULT_PREVIEW_CHARS = 500


def resolve_template(value: Any, last_result: str) -> Any:
    """Resolve ``{{last_result}}`` in string values, recursively; other values pass through."""
    if isinstance(value, str):
        return value.replace("{{last_result}}", last_result)
    if isinstance(value, dict):
        return {k: resolve_template(v, last_result) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_template(v, last_result) for v in value]
    return value


async def run_replay(router: ToolRouter, scenario: Scenario) -> list[dict[str, Any]]:
    """Execute the replay steps; return a transcript of what was called and returned."""
    transcript: list[dict[str, Any]] = []
    last_result = ""
    # A real client always lists tools before calling them.
    await router.list_tools()
    for step in scenario.replay:
        if step.action == "list_tools":
            listed = await router.list_tools()
            transcript.append({"event": "list_tools", "tools": [t.name for _, t in listed]})
            continue
        arguments = resolve_template(step.arguments, last_result)
        result = await router.call(step.tool, arguments, server=step.server)
        last_result = text_of(result)
        transcript.append(
            {
                "event": "tool_call",
                "tool": step.tool,
                "arguments": arguments,
                "is_error": bool(result.is_error),
                "result_preview": last_result[:RESULT_PREVIEW_CHARS],
            }
        )
    return transcript
