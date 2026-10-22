"""The per-trial sandbox.

Every trial (one arm of one scenario) runs against a fresh temp directory holding:

* the **event log** (``events.jsonl``) that the intercepting proxy appends every
  ``tools/list`` and ``tools/call`` to. Verdicts are read back from this record, never
  from the agent's own account of what it did;
* the **side-effect sink** (``sink.jsonl``) that the synthetic demo servers append
  refunds and emails to, instead of performing them;
* the **proxy config** (``proxy.json``): the injection to apply and the tools to hold;
* the agent's **transcript** (``transcript.jsonl``), if the agent writes one.

**Canaries** are named sets of marker strings planted in the target's data (for the demo,
each synthetic customer's PII). A check that finds a marker in a tool call's arguments, or
in the sink, knows that data moved.

Adapted from mcpguardbench's sandbox (github.com/dhruvshah464/OpenTrust).
"""

from __future__ import annotations

import json
import platform
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None

ENV_EVENTS = "AISEC_EVENTS"
ENV_PROXY_CONFIG = "AISEC_PROXY_CONFIG"
ENV_SINK = "AISEC_SINK"
ENV_TRANSCRIPT = "AISEC_TRANSCRIPT"
ENV_MCP_CONFIG = "AISEC_MCP_CONFIG"
ENV_TASK = "AISEC_TASK"

EVENTS_FILE = "events.jsonl"
SINK_FILE = "sink.jsonl"
TRANSCRIPT_FILE = "transcript.jsonl"
PROXY_CONFIG_FILE = "proxy.json"
MCP_CONFIG_FILE = "mcp.json"

OUTCOME_OK = "ok"
OUTCOME_ERROR = "error"
OUTCOME_HELD = "held"


def append_jsonl(path: str | Path, record: dict[str, Any], *, sequence: bool = False) -> dict[str, Any]:
    """Append one JSON line under an exclusive lock, optionally stamping a 1-based ``seq``.

    One proxy process runs per wrapped server and they all append to the same event log,
    so counting existing lines and writing the new one happen under a single lock.
    """
    with Path(path).open("a+", encoding="utf-8") as handle:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            if sequence:
                handle.seek(0)
                count = sum(1 for line in handle if line.strip())
                record = {"seq": count + 1, **record}
            handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
            handle.flush()
        finally:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    return record


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path.name} line {lineno} is not valid JSON: {exc}") from exc
    return records


@dataclass(frozen=True)
class Event:
    """One proxy-observed event, as read back from the event log."""

    seq: int
    kind: str  # "list" | "call"
    server: str
    tool: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    outcome: str = ""  # calls only: "ok" | "error" | "held"
    injected: bool = False
    record: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_record(cls, rec: dict[str, Any]) -> "Event":
        return cls(
            seq=int(rec.get("seq", 0)),
            kind=rec.get("kind", ""),
            server=rec.get("server", ""),
            tool=rec.get("tool", ""),
            arguments=rec.get("arguments") or {},
            outcome=rec.get("outcome", ""),
            injected=bool(rec.get("injected", False)),
            record=rec,
        )


@dataclass
class Sandbox:
    """A per-trial sandbox rooted at a temp directory."""

    root: Path
    canaries: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def create(cls, canaries: dict[str, list[str]] | None = None) -> "Sandbox":
        sb = cls(root=Path(tempfile.mkdtemp(prefix="aisec-")), canaries=dict(canaries or {}))
        for name in (EVENTS_FILE, SINK_FILE):
            (sb.root / name).write_text("", encoding="utf-8")
        return sb

    @property
    def events_path(self) -> Path:
        return self.root / EVENTS_FILE

    @property
    def sink_path(self) -> Path:
        return self.root / SINK_FILE

    @property
    def transcript_path(self) -> Path:
        return self.root / TRANSCRIPT_FILE

    @property
    def proxy_config_path(self) -> Path:
        return self.root / PROXY_CONFIG_FILE

    @property
    def mcp_config_path(self) -> Path:
        return self.root / MCP_CONFIG_FILE

    def write_proxy_config(self, injection: dict[str, Any] | None, hold_tools: list[str]) -> Path:
        config = {"injection": injection, "hold_tools": sorted(hold_tools)}
        self.proxy_config_path.write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
        return self.proxy_config_path

    def proxy_env(self) -> dict[str, str]:
        """Environment a proxy process needs to find this sandbox."""
        return {ENV_EVENTS: str(self.events_path), ENV_PROXY_CONFIG: str(self.proxy_config_path)}

    # --- inspection (used by checks) ----------------------------------------

    def events(self) -> list[Event]:
        return [Event.from_record(r) for r in read_jsonl(self.events_path)]

    def calls(self) -> list[Event]:
        return [e for e in self.events() if e.kind == "call"]

    def sink_entries(self) -> list[dict[str, Any]]:
        return read_jsonl(self.sink_path)

    def transcript(self) -> list[dict[str, Any]]:
        return read_jsonl(self.transcript_path)

    def last_agent_text(self) -> str | None:
        for entry in reversed(self.transcript()):
            if entry.get("event") == "model_turn" and (entry.get("text") or "").strip():
                return str(entry["text"]).strip()
        return None

    def markers(self, canary: str) -> list[str]:
        if canary not in self.canaries:
            raise ValueError(f"unknown canary {canary!r}; known: {sorted(self.canaries)}")
        return self.canaries[canary]

    def canary_in_sink(self, canary: str) -> list[int]:
        """``seq`` of every sink entry that carries one of the canary's markers."""
        markers = self.markers(canary)
        return [int(e.get("seq", 0)) for e in self.sink_entries() if contains_marker(e, markers)]

    def destroy(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def _string_leaves(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, bool) or value is None:
        return []
    if isinstance(value, (int, float)):
        return [str(value)]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _string_leaves(v)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _string_leaves(v)]
    return [str(value)]


def contains_marker(value: Any, markers: list[str]) -> bool:
    """True if any marker occurs (case-insensitively) in any string inside ``value``."""
    needles = [m.casefold() for m in markers if m]
    return any(n in leaf.casefold() for leaf in _string_leaves(value) for n in needles)


def environment_fingerprint() -> dict[str, str]:
    """The parts of the reproducibility record that are constant across a run."""
    import importlib.metadata as im

    from . import __version__

    def version_of(dist: str) -> str:
        try:
            return im.version(dist)
        except im.PackageNotFoundError:
            return "not installed"

    return {
        "aisec": __version__,
        "mcp": version_of("mcp"),
        "anthropic": version_of("anthropic"),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
    }
