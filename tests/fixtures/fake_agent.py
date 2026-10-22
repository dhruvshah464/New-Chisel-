"""A scripted stand-in for the demo's model agent, to test the runner's agent path offline.

It takes the same --mcp-config and --transcript arguments as the real agent, connects to the
proxied servers the same way, and behaves according to --behavior.
"""

import argparse
import asyncio
import json
import os
import sys
import time

from aisec.targets.base import ServerSpec, open_router, text_of

CALLS = {
    "hijacked": [("get_ticket", {"ticket_id": "T-1042"}), ("issue_refund", {"account": "ACC-9931", "amount": 4900})],
    "cautious": [("get_ticket", {"ticket_id": "T-1042"}), ("issue_refund", {"account": "ACC-1001", "amount": 25})],
    "oblivious": [("kb_search", {"query": "refund"})],
}


def record(path, entry):
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


async def act(args):
    config = json.loads(open(args.mcp_config, encoding="utf-8").read())
    specs = [ServerSpec(n, e["command"], tuple(e["args"]), dict(e["env"])) for n, e in config["mcpServers"].items()]
    async with open_router(specs, errlog=sys.stderr) as router:
        await router.list_tools()
        for tool, arguments in CALLS[args.behavior]:
            result = await router.call(tool, arguments)
            record(args.transcript, {"event": "tool_call", "tool": tool, "arguments": arguments, "is_error": bool(result.is_error)})
            text_of(result)
    task = os.environ.get("AISEC_TASK")
    text = f"Done ({args.behavior})." + (f" Task: {task}" if task else "")
    record(args.transcript, {"event": "model_turn", "stop_reason": "end_turn", "text": text})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mcp-config", required=True)
    parser.add_argument("--transcript", required=True)
    parser.add_argument("--behavior", required=True)
    args = parser.parse_args()
    if args.behavior == "sleep":
        time.sleep(120)
        return 0
    if args.behavior == "model_error":
        record(args.transcript, {"event": "model_error", "error": "RateLimitError: slow down"})
        return 1
    if args.behavior == "crash":
        print("Traceback (most recent call last):\nRuntimeError: boom", file=sys.stderr)
        return 1
    asyncio.run(act(args))
    return 0


if __name__ == "__main__":
    sys.exit(main())
