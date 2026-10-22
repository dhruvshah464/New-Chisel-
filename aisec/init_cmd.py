"""``aisec init``: turn an MCP config into a starter target + authorization stub.

Setup time is why teams bounce. OpenAI's tools assume you already live in their
stack. This writes a vendor-neutral target file from the servers you already have.
"""

from __future__ import annotations

import json
from pathlib import Path

from .targets.command import AUTHORIZATION_FILE


def servers_from_mcp(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(entries, dict) or not entries:
        raise ValueError(f"{path}: no mcpServers")
    return sorted(entries)


def write_init(mcp_config: str | Path, out_dir: str | Path, *, name: str = "my-agent") -> dict[str, object]:
    mcp_config = Path(mcp_config).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    names = servers_from_mcp(mcp_config)
    target_path = out_dir / "aisec-target.yaml"
    auth_path = out_dir / AUTHORIZATION_FILE
    rel_mcp = mcp_config if mcp_config.parent == out_dir else mcp_config
    target_path.write_text(
        (
            f"name: {name}\n"
            "variant: staging\n"
            f"mcp_config: {rel_mcp.name if mcp_config.parent == out_dir else str(mcp_config)}\n"
            "agent:\n"
            "  command: [your-agent, --mcp-config, \"{mcp_config}\", --task, \"{task}\"]\n"
            "authorization: authorization.yaml\n"
        ),
        encoding="utf-8",
    )
    listed = "\n".join(f"    - {n}" for n in names)
    auth_path.write_text(
        (
            "client: \"(your company)\"\n"
            "authorized_by:\n"
            "  name: \"(person who can stop the test)\"\n"
            "signed_on: \"2026-10-09\"\n"
            "scope:\n"
            "  agent: \"(agent name)\"\n"
            "  environment: local-sandbox-synthetic\n"
            "  servers:\n"
            f"{listed}\n"
            "  held_tools: []\n"
            "window:\n"
            "  start: \"2026-10-01T00:00:00+00:00\"\n"
            "  end: \"2027-03-31T23:59:59+00:00\"\n"
            "data: synthetic\n"
            "contacts:\n"
            "  emergency_stop: \"you@example.com\"\n"
        ),
        encoding="utf-8",
    )
    return {"target": target_path, "authorization": auth_path, "servers": names}
