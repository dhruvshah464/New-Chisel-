"""The bring-your-own-agent target: an agent and its MCP servers, described in a config file.

    # aisec-target.yaml
    name: acme-support-agent
    variant: after-fix                      # optional label for the report
    mcp_config: mcp.json                    # a standard mcpServers file (Claude Desktop, Cursor, ...)
    agent:
      command: [python, agent.py, --mcp-config, "{mcp_config}", --task, "{task}"]
      cwd: .                                # optional
      env: {}                               # optional
    model: claude-sonnet-5                  # optional, for the report
    system_prompt_file: prompt.txt          # optional; its SHA-256 is recorded
    session_env: {ticket: SUPPORT_DESK_TICKET}   # optional: scenario session key -> server env var
    canaries: {"customer:C-1001": ["1420 Larkspur Ln"]}
    authorization: authorization.yaml       # required

Relative paths are resolved against the config file's directory. For every trial, aisec
rewrites the MCP config so each server runs behind the recording proxy (``aisec proxy --
<original command>``), writes it into the trial sandbox, and launches the agent with
``{mcp_config}``, ``{task}`` and ``{transcript}`` filled in. The same values are also set as
``AISEC_MCP_CONFIG``, ``AISEC_TASK`` and ``AISEC_TRANSCRIPT``. Each server also gets
``AISEC_SINK``, a JSONL file it may append its side effects to.

Nothing starts without a valid authorization record. The run is refused if the environment
looks like production, the data is not synthetic or sanitized, the current time is outside the
authorized window, or a server in the MCP config is not in the authorized scope. Tools the
authorization lists as held are held in every trial. The record is copied into the evidence
pack verbatim. Server and agent ``env`` values are never recorded, only their names, and
commands are recorded with URL credentials and the values of secret-looking flags redacted.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import Any

import yaml

from ..redact import redact_args
from ..sandbox import ENV_MCP_CONFIG, ENV_SINK, ENV_TASK, ENV_TRANSCRIPT, Sandbox
from ..scenario import Scenario
from .base import ServerSpec, Target

AUTHORIZATION_FILE = "authorization.yaml"
DATA_KINDS = ("synthetic", "sanitized", "sanitised")
PLACEHOLDERS = ("{mcp_config}", "{task}", "{transcript}")
CONFIG_KEYS = {
    "name",
    "variant",
    "mcp_config",
    "agent",
    "model",
    "system_prompt_file",
    "session_env",
    "canaries",
    "authorization",
}
AUTH_REQUIRED = (
    "client",
    "authorized_by.name",
    "signed_on",
    "scope.agent",
    "scope.environment",
    "scope.servers",
    "window.start",
    "window.end",
    "data",
    "contacts.emergency_stop",
)


class TargetConfigError(ValueError):
    pass


class AuthorizationError(TargetConfigError):
    pass


def _get(data: dict[str, Any], dotted: str) -> Any:
    value: Any = data
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _moment(value: Any, field: str) -> datetime:
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, date):
        moment = datetime.combine(value, time.min)
    elif isinstance(value, str):
        try:
            moment = datetime.fromisoformat(value.strip())
        except ValueError as exc:
            raise AuthorizationError(f"{field}: not an ISO 8601 date-time: {value!r}") from exc
    else:
        raise AuthorizationError(f"{field}: expected a date-time, got {value!r}")
    if moment.tzinfo is None:
        raise AuthorizationError(f"{field}: include a timezone offset, e.g. 2026-10-21T09:00:00-04:00")
    return moment


def _load_yaml(path: Path, what: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TargetConfigError(f"{what} not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise TargetConfigError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise TargetConfigError(f"{path}: expected a mapping")
    return data


@dataclass(frozen=True)
class Authorization:
    """The machine-readable copy of a signed authorization (see validation/05-pilot-offer.md)."""

    path: Path
    sha256: str
    client: str
    authorized_by: dict[str, Any]
    signed_on: str
    agent: str
    environment: str
    servers: tuple[str, ...]
    held_tools: tuple[str, ...]
    window_start: datetime
    window_end: datetime
    data: str
    signed_copy_sha256: str | None

    @classmethod
    def load(cls, path: str | Path) -> "Authorization":
        path = Path(path)
        raw = path.read_bytes() if path.is_file() else None
        if raw is None:
            raise AuthorizationError(f"authorization record not found: {path}")
        data = _load_yaml(path, "authorization record")
        missing = [f for f in AUTH_REQUIRED if _get(data, f) in (None, "", [])]
        if missing:
            raise AuthorizationError(f"{path}: missing {', '.join(missing)}")
        servers = _get(data, "scope.servers")
        held = _get(data, "scope.held_tools") or []
        if not isinstance(servers, list) or not all(isinstance(s, str) for s in servers):
            raise AuthorizationError(f"{path}: scope.servers must be a list of server names")
        if not isinstance(held, list) or not all(isinstance(t, str) for t in held):
            raise AuthorizationError(f"{path}: scope.held_tools must be a list of tool names")
        authorized_by = data["authorized_by"]
        if not isinstance(authorized_by, dict):
            raise AuthorizationError(f"{path}: authorized_by must have a name and a title")
        return cls(
            path=path,
            sha256=hashlib.sha256(raw).hexdigest(),
            client=str(data["client"]),
            authorized_by={k: str(v) for k, v in authorized_by.items()},
            signed_on=str(data["signed_on"]),
            agent=str(_get(data, "scope.agent")),
            environment=str(_get(data, "scope.environment")),
            servers=tuple(servers),
            held_tools=tuple(held),
            window_start=_moment(_get(data, "window.start"), "window.start"),
            window_end=_moment(_get(data, "window.end"), "window.end"),
            data=str(data["data"]).strip().lower(),
            signed_copy_sha256=str(data["signed_copy_sha256"]) if data.get("signed_copy_sha256") else None,
        )

    def check(self, servers: list[str], at: datetime | None = None) -> None:
        """Raise AuthorizationError unless testing these servers is authorized at this moment."""
        at = at or datetime.now(timezone.utc)
        if re.search(r"\bprod", self.environment, re.IGNORECASE):
            raise AuthorizationError(f"scope.environment is {self.environment!r}: production is never tested")
        if self.data not in DATA_KINDS:
            raise AuthorizationError(f"data is {self.data!r}: only synthetic or sanitized data may be used")
        if self.window_end <= self.window_start:
            raise AuthorizationError("window.end must be after window.start")
        if not self.window_start <= at <= self.window_end:
            raise AuthorizationError(
                f"outside the authorized window ({self.window_start.isoformat()} to {self.window_end.isoformat()})"
            )
        outside = sorted(set(servers) - set(self.servers))
        if outside:
            raise AuthorizationError(f"MCP servers not in the authorized scope: {', '.join(outside)}")

    def summary(self) -> dict[str, Any]:
        return {
            "file": AUTHORIZATION_FILE,
            "sha256": self.sha256,
            "client": self.client,
            "authorized_by": self.authorized_by,
            "signed_on": self.signed_on,
            "agent": self.agent,
            "environment": self.environment,
            "servers": list(self.servers),
            "held_tools": list(self.held_tools),
            "window": {"start": self.window_start.isoformat(), "end": self.window_end.isoformat()},
            "data": self.data,
            "signed_copy_sha256": self.signed_copy_sha256,
        }


def _servers_from_mcp_config(path: Path) -> list[ServerSpec]:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TargetConfigError(f"MCP config not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise TargetConfigError(f"{path}: invalid JSON: {exc}") from exc
    entries = config.get("mcpServers") if isinstance(config, dict) else None
    if not isinstance(entries, dict) or not entries:
        raise TargetConfigError(f"{path}: no mcpServers")
    specs = []
    for name, entry in entries.items():
        if not isinstance(entry, dict) or "command" not in entry:
            raise TargetConfigError(
                f"{path}: server {name!r} has no 'command'; aisec only wraps stdio servers, not HTTP ones"
            )
        cwd = entry.get("cwd")
        specs.append(
            ServerSpec(
                name=name,
                command=str(entry["command"]),
                args=tuple(str(a) for a in entry.get("args", [])),
                env={str(k): str(v) for k, v in (entry.get("env") or {}).items()},
                cwd=str((path.parent / cwd).resolve()) if cwd else None,
            )
        )
    return specs


class CommandTarget(Target):
    name = "command"

    def __init__(self, config_path: str | Path, *, at: datetime | None = None):
        self.config_path = Path(config_path).resolve()
        base = self.config_path.parent
        config = _load_yaml(self.config_path, "target config")
        unknown = sorted(set(config) - CONFIG_KEYS)
        if unknown:
            raise TargetConfigError(f"{self.config_path}: unknown keys {unknown}")
        for key in ("mcp_config", "agent", "authorization"):
            if not config.get(key):
                raise TargetConfigError(f"{self.config_path}: {key!r} is required")
        agent = config["agent"]
        command = agent.get("command") if isinstance(agent, dict) else None
        if not isinstance(command, list) or not command or not all(isinstance(a, str) for a in command):
            raise TargetConfigError(f"{self.config_path}: agent.command must be a list of strings")

        self.label = str(config.get("name") or self.config_path.stem)
        self.variant = str(config["variant"]) if config.get("variant") else None
        self.model = str(config["model"]) if config.get("model") else None
        self.mcp_config_path = (base / config["mcp_config"]).resolve()
        self.specs = _servers_from_mcp_config(self.mcp_config_path)
        self.command = list(command)
        self.cwd = str((base / agent["cwd"]).resolve()) if agent.get("cwd") else str(base)
        self.env = {str(k): str(v) for k, v in (agent.get("env") or {}).items()}
        self.session_env = {str(k): str(v) for k, v in (config.get("session_env") or {}).items()}
        self._canaries = {str(k): [str(m) for m in v] for k, v in (config.get("canaries") or {}).items()}
        prompt_file = config.get("system_prompt_file")
        self.system_prompt_sha256 = (
            hashlib.sha256((base / prompt_file).read_bytes()).hexdigest() if prompt_file else None
        )
        self.authorization = Authorization.load(base / config["authorization"])
        self.authorization.check([s.name for s in self.specs], at)

    def describe(self) -> dict[str, Any]:
        return {
            "target": self.name,
            "name": self.label,
            "variant": self.variant,
            "config": self.config_path.name,
            "agent": " ".join(redact_args(self.command)),
            "agent_env_names": sorted(self.env),
            "model": self.model,
            "system_prompt_sha256": self.system_prompt_sha256,
            "servers": {
                s.name: {"command": s.command, "args": redact_args(s.args), "env_names": sorted(s.env)}
                for s in self.specs
            },
            "reachability_variant": None,
            "authorization": self.authorization.summary(),
        }

    def canaries(self) -> dict[str, list[str]]:
        return {name: list(markers) for name, markers in self._canaries.items()}

    def servers(self, scenario: Scenario, sandbox: Sandbox, *, reachability: bool = False) -> list[ServerSpec]:
        self.authorization.check([s.name for s in self.specs])
        session = {var: str(scenario.session[key]) for key, var in self.session_env.items() if key in scenario.session}
        return [
            ServerSpec(s.name, s.command, s.args, {**s.env, **session, ENV_SINK: str(sandbox.sink_path)}, s.cwd)
            for s in self.specs
        ]

    def preflight(self) -> str | None:
        program = self.command[0]
        if os.sep in program or (os.altsep and os.altsep in program):
            found = (Path(self.cwd) / program).exists()
        else:
            found = shutil.which(program) is not None
        return None if found else f"the agent command {program!r} was not found"

    def always_hold(self) -> set[str]:
        return set(self.authorization.held_tools)

    def evidence_files(self) -> dict[str, str]:
        return {AUTHORIZATION_FILE: str(self.authorization.path)}

    def _values(self, scenario: Scenario, sandbox: Sandbox) -> dict[str, str]:
        return {
            "{mcp_config}": str(sandbox.mcp_config_path),
            "{task}": scenario.task,
            "{transcript}": str(sandbox.transcript_path),
        }

    def agent_command(self, scenario: Scenario, sandbox: Sandbox) -> list[str]:
        values = self._values(scenario, sandbox)
        argv = []
        for arg in self.command:
            for placeholder in PLACEHOLDERS:
                arg = arg.replace(placeholder, values[placeholder])
            argv.append(arg)
        return argv

    def agent_env(self, scenario: Scenario, sandbox: Sandbox) -> dict[str, str]:
        values = self._values(scenario, sandbox)
        return {
            **self.env,
            ENV_MCP_CONFIG: values["{mcp_config}"],
            ENV_TASK: values["{task}"],
            ENV_TRANSCRIPT: values["{transcript}"],
        }

    def agent_cwd(self) -> str | None:
        return self.cwd
