"""OpenAI-compatible chat completions, shaped like Anthropic ``messages.create``.

The demo agent stays one loop. New Chisel does not host the model or the key: the
operator points ``OPENAI_BASE_URL`` at OpenAI, Azure, a local server, or anyone else
who speaks ``/v1/chat/completions``.
"""

from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request
from types import SimpleNamespace
from typing import Any


DEFAULT_OPENAI_BASE = "https://api.openai.com/v1"


def to_openai_tools(anthropic_tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool.get("description") or "",
                "parameters": tool.get("input_schema") or {"type": "object", "properties": {}},
            },
        }
        for tool in anthropic_tools
    ]


def _block_type(block: Any) -> str | None:
    if isinstance(block, dict):
        return block.get("type")
    return getattr(block, "type", None)


def _block_text(block: Any) -> str:
    if isinstance(block, dict):
        return str(block.get("text") or "")
    return str(getattr(block, "text", "") or "")


def _tool_use_fields(block: Any) -> tuple[str, str, dict[str, Any]]:
    if isinstance(block, dict):
        return str(block.get("id") or ""), str(block.get("name") or ""), dict(block.get("input") or {})
    return (
        str(getattr(block, "id", "") or ""),
        str(getattr(block, "name", "") or ""),
        dict(getattr(block, "input", None) or {}),
    )


def to_openai_messages(system: str, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = [{"role": "system", "content": system}]
    for message in messages:
        role = message.get("role")
        content = message.get("content")
        if role == "user" and isinstance(content, str):
            out.append({"role": "user", "content": content})
            continue
        if role == "user" and isinstance(content, list):
            for block in content:
                if _block_type(block) != "tool_result":
                    continue
                if isinstance(block, dict):
                    tool_id = str(block.get("tool_use_id") or "")
                    text = str(block.get("content") or "")
                else:
                    tool_id = str(getattr(block, "tool_use_id", "") or "")
                    text = str(getattr(block, "content", "") or "")
                out.append({"role": "tool", "tool_call_id": tool_id, "content": text})
            continue
        if role == "assistant":
            blocks = content if isinstance(content, list) else []
            text_parts = [_block_text(b) for b in blocks if _block_type(b) == "text"]
            tool_calls = []
            for block in blocks:
                if _block_type(block) != "tool_use":
                    continue
                uid, name, arguments = _tool_use_fields(block)
                tool_calls.append(
                    {
                        "id": uid,
                        "type": "function",
                        "function": {"name": name, "arguments": json.dumps(arguments)},
                    }
                )
            entry: dict[str, Any] = {"role": "assistant", "content": "".join(text_parts) or None}
            if tool_calls:
                entry["tool_calls"] = tool_calls
            out.append(entry)
    return out


def from_openai_response(payload: dict[str, Any]) -> SimpleNamespace:
    choice = (payload.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    finish = choice.get("finish_reason") or "stop"
    blocks: list[SimpleNamespace] = []
    if message.get("content"):
        blocks.append(SimpleNamespace(type="text", text=message["content"]))
    for call in message.get("tool_calls") or []:
        function = call.get("function") or {}
        try:
            arguments = json.loads(function.get("arguments") or "{}")
        except json.JSONDecodeError:
            arguments = {}
        if not isinstance(arguments, dict):
            arguments = {}
        blocks.append(
            SimpleNamespace(
                type="tool_use",
                id=call.get("id") or "",
                name=function.get("name") or "",
                input=arguments,
            )
        )
    if finish == "tool_calls":
        stop_reason = "tool_use"
    elif finish == "content_filter":
        stop_reason = "refusal"
    else:
        stop_reason = "end_turn"
    usage = payload.get("usage") or {}
    return SimpleNamespace(
        content=blocks,
        stop_reason=stop_reason,
        usage=SimpleNamespace(
            input_tokens=usage.get("prompt_tokens") or 0,
            output_tokens=usage.get("completion_tokens") or 0,
        ),
    )


class OpenAICompatClient:
    """Minimal ``/v1/chat/completions`` client with an Anthropic-shaped ``messages.create``."""

    def __init__(self, *, api_key: str | None = None, base_url: str | None = None):
        self.api_key = api_key if api_key is not None else os.environ.get("OPENAI_API_KEY", "")
        if not self.api_key:
            raise SystemExit("no OPENAI_API_KEY set; export a key to run the OpenAI-compatible agent")
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL") or DEFAULT_OPENAI_BASE).rstrip("/")
        self.messages = self

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": "Bearer " + self.api_key,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:400]
            raise RuntimeError(f"OpenAI-compatible HTTP {exc.code}: {detail}") from exc

    async def create(
        self,
        *,
        model: str,
        max_tokens: int,
        system: str,
        tools: list[dict[str, Any]],
        messages: list[dict[str, Any]],
        **_extra: Any,
    ) -> SimpleNamespace:
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": to_openai_messages(system, messages),
            "tools": to_openai_tools(tools),
        }
        body = await asyncio.to_thread(self._post, payload)
        return from_openai_response(body)
