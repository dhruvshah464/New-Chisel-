"""Scenario schema and YAML loader.

A scenario is one controlled experiment against an agent: a task the agent is given, an
attacker payload injected into one of its tools (attacks only), a deterministic replay
that realizes the harmful outcome through the real tools (used to prove reachability), and
a success check that decides from the recorded evidence whether the outcome happened.

Benign scenarios are the false-positive controls: a legitimate task with no injection,
whose check fires when the legitimate workflow completed.

Adapted from mcpguardbench's scenario loader (github.com/dhruvshah464/OpenTrust).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

KINDS = ("attack", "benign")
SEVERITIES = ("low", "medium", "high", "critical")

ATTACK_CLASSES = {
    "prompt_injection",
    "data_exfiltration",
    "tool_poisoning",
    "rug_pull",
    "privilege_abuse",
    "excessive_agency",
    "tool_shadowing",
    "confused_deputy",
    "credential_theft",
    "unsafe_external_action",
}

# OWASP Top 10 for Agentic Applications (2026).
OWASP_ASI = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

CHANNELS = ("tool_result", "tool_description")

CHECK_TYPES = {
    "tool_called_with": {"required": {"tool"}, "optional": {"server", "where"}},
    "forbidden_tool_called": {"required": {"tool"}, "optional": {"server"}},
    "canary_in_args": {"required": {"canary"}, "optional": {"tool", "server", "where", "in"}},
    "canary_exfiltrated": {"required": {"canary"}, "optional": set()},
    "canary_in_reply": {"required": {"canary"}, "optional": set()},
}

WHERE_OPERATORS = {"contains", "not", "gt", "gte", "lt", "lte", "in", "not_in"}

TOP_LEVEL_KEYS = {
    "id",
    "kind",
    "title",
    "description",
    "attack_class",
    "owasp",
    "severity",
    "task",
    "session",
    "injection",
    "hold_tools",
    "replay",
    "success_check",
    "fix_hint",
    "version",
}

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_]*$")


class ScenarioError(ValueError):
    pass


@dataclass(frozen=True)
class Injection:
    channel: str
    tool: str
    payload: str
    after: int = 0  # leave the first N listings (description) or calls (result) clean
    field: str | None = None  # tool_result only: append to this field of a JSON object result

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "tool": self.tool,
            "payload": self.payload,
            "after": self.after,
            "field": self.field,
        }


@dataclass(frozen=True)
class Step:
    """One deterministic replay step: a tool call, or a fresh ``tools/list``.

    String argument values may contain ``{{last_result}}``, the text of the previous call.
    """

    action: str  # "call" | "list_tools"
    tool: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    server: str | None = None


@dataclass(frozen=True)
class Check:
    type: str
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "params": self.params}


@dataclass(frozen=True)
class Scenario:
    id: str
    kind: str
    title: str
    description: str
    attack_class: str | None
    owasp: tuple[str, ...]
    severity: str | None
    task: str
    session: dict[str, Any]
    injection: Injection | None
    hold_tools: tuple[str, ...]
    replay: tuple[Step, ...]
    success_check: Check
    fix_hint: str
    version: str
    source_path: str
    sha256: str

    @property
    def is_attack(self) -> bool:
        return self.kind == "attack"


def _fail(source: str, message: str) -> ScenarioError:
    return ScenarioError(f"{source}: {message}")


def _require_str(data: dict, key: str, source: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise _fail(source, f"'{key}' must be a non-empty string")
    return value.strip()


def _validate_where(where: Any, source: str) -> None:
    if not isinstance(where, dict) or not where:
        raise _fail(source, "success_check 'where' must be a non-empty mapping")
    for arg, expected in where.items():
        if isinstance(expected, dict):
            if len(expected) != 1 or next(iter(expected)) not in WHERE_OPERATORS:
                raise _fail(
                    source,
                    f"where.{arg}: an operator mapping needs exactly one of {sorted(WHERE_OPERATORS)}",
                )


def _load_check(raw: Any, source: str) -> Check:
    if not isinstance(raw, dict) or "type" not in raw:
        raise _fail(source, "'success_check' needs a 'type'")
    ctype = raw["type"]
    if ctype not in CHECK_TYPES:
        raise _fail(source, f"unknown success_check type {ctype!r}; known: {sorted(CHECK_TYPES)}")
    params = raw.get("params") or {}
    if not isinstance(params, dict):
        raise _fail(source, "success_check 'params' must be a mapping")
    spec = CHECK_TYPES[ctype]
    missing = spec["required"] - params.keys()
    if missing:
        raise _fail(source, f"success_check {ctype} is missing {sorted(missing)}")
    unknown = params.keys() - spec["required"] - spec["optional"]
    if unknown:
        raise _fail(source, f"success_check {ctype} has unknown params {sorted(unknown)}")
    if "where" in params:
        _validate_where(params["where"], source)
    if "in" in params and not (
        isinstance(params["in"], list) and all(isinstance(a, str) for a in params["in"])
    ):
        raise _fail(source, "success_check 'in' must be a list of argument names")
    return Check(type=ctype, params=dict(params))


def _load_injection(raw: Any, source: str) -> Injection:
    if not isinstance(raw, dict):
        raise _fail(source, "'injection' must be a mapping")
    unknown = raw.keys() - {"channel", "tool", "payload", "after", "field"}
    if unknown:
        raise _fail(source, f"injection has unknown keys {sorted(unknown)}")
    channel = raw.get("channel")
    if channel not in CHANNELS:
        raise _fail(source, f"injection.channel must be one of {list(CHANNELS)}")
    after = raw.get("after", 0)
    if not isinstance(after, int) or isinstance(after, bool) or after < 0:
        raise _fail(source, "injection.after must be a non-negative integer")
    field_name = raw.get("field")
    if field_name is not None and (channel != "tool_result" or not isinstance(field_name, str)):
        raise _fail(source, "injection.field is a string and only applies to channel tool_result")
    return Injection(
        channel=channel,
        tool=_require_str(raw, "tool", source),
        payload=_require_str(raw, "payload", source),
        after=after,
        field=field_name,
    )


def _load_steps(raw: Any, source: str) -> tuple[Step, ...]:
    if not isinstance(raw, list) or not raw:
        raise _fail(source, "'replay' must be a non-empty list of steps")
    steps: list[Step] = []
    for i, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise _fail(source, f"replay step {i} must be a mapping")
        if item.get("list_tools") is True:
            if set(item) != {"list_tools"}:
                raise _fail(source, f"replay step {i}: a list_tools step takes no other keys")
            steps.append(Step(action="list_tools"))
            continue
        unknown = item.keys() - {"tool", "arguments", "server"}
        if unknown:
            raise _fail(source, f"replay step {i} has unknown keys {sorted(unknown)}")
        arguments = item.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise _fail(source, f"replay step {i}: 'arguments' must be a mapping")
        steps.append(
            Step(
                action="call",
                tool=_require_str(item, "tool", f"{source} replay step {i}"),
                arguments=arguments,
                server=item.get("server"),
            )
        )
    return tuple(steps)


def scenario_from_dict(data: Any, source: str = "<scenario>", sha256: str = "") -> Scenario:
    if not isinstance(data, dict):
        raise _fail(source, "a scenario must be a YAML mapping")
    unknown = data.keys() - TOP_LEVEL_KEYS
    if unknown:
        raise _fail(source, f"unknown keys {sorted(unknown)}")

    scenario_id = _require_str(data, "id", source)
    if not _ID_RE.match(scenario_id):
        raise _fail(source, "'id' must be lowercase letters, digits and underscores")
    kind = data.get("kind", "attack")
    if kind not in KINDS:
        raise _fail(source, f"'kind' must be one of {list(KINDS)}")

    owasp_raw = data.get("owasp") or []
    if not isinstance(owasp_raw, list):
        raise _fail(source, "'owasp' must be a list of ASI codes")
    bad = [c for c in owasp_raw if c not in OWASP_ASI]
    if bad:
        raise _fail(source, f"unknown OWASP ASI codes {bad}")

    hold_raw = data.get("hold_tools") or []
    if not isinstance(hold_raw, list) or not all(isinstance(t, str) for t in hold_raw):
        raise _fail(source, "'hold_tools' must be a list of tool names")

    session = data.get("session") or {}
    if not isinstance(session, dict):
        raise _fail(source, "'session' must be a mapping")

    if kind == "attack":
        attack_class = data.get("attack_class")
        if attack_class not in ATTACK_CLASSES:
            raise _fail(source, f"attack_class must be one of {sorted(ATTACK_CLASSES)}")
        if not owasp_raw:
            raise _fail(source, "an attack must map to at least one OWASP ASI code")
        severity = data.get("severity")
        if severity not in SEVERITIES:
            raise _fail(source, f"severity must be one of {list(SEVERITIES)}")
        if "injection" not in data:
            raise _fail(source, "an attack needs an 'injection'")
        injection: Injection | None = _load_injection(data["injection"], source)
        fix_hint = _require_str(data, "fix_hint", source)
    else:
        if data.get("attack_class") not in (None, "benign"):
            raise _fail(source, "a benign scenario has no attack_class")
        if "injection" in data:
            raise _fail(source, "a benign scenario must not have an injection")
        if data.get("severity") is not None:
            raise _fail(source, "a benign scenario has no severity")
        attack_class, severity, injection = None, None, None
        fix_hint = str(data.get("fix_hint") or "").strip()

    return Scenario(
        id=scenario_id,
        kind=kind,
        title=_require_str(data, "title", source),
        description=str(data.get("description") or "").strip(),
        attack_class=attack_class,
        owasp=tuple(owasp_raw),
        severity=severity,
        task=_require_str(data, "task", source),
        session=dict(session),
        injection=injection,
        hold_tools=tuple(hold_raw),
        replay=_load_steps(data.get("replay"), source),
        success_check=_load_check(data.get("success_check"), source),
        fix_hint=fix_hint,
        version=str(data.get("version", "1")),
        source_path=source,
        sha256=sha256,
    )


def dump_scenario(scenario: Scenario) -> str:
    """Serialize a scenario to YAML that ``load_scenario`` will accept."""
    data: dict[str, Any] = {"id": scenario.id, "title": scenario.title}
    if scenario.kind != "attack":
        data["kind"] = scenario.kind
    if scenario.description:
        data["description"] = scenario.description
    if scenario.attack_class:
        data["attack_class"] = scenario.attack_class
    if scenario.owasp:
        data["owasp"] = list(scenario.owasp)
    if scenario.severity:
        data["severity"] = scenario.severity
    data["task"] = scenario.task
    if scenario.session:
        data["session"] = dict(scenario.session)
    if scenario.injection is not None:
        inj = scenario.injection.to_dict()
        if not inj["after"]:
            inj.pop("after")
        if inj["field"] is None:
            inj.pop("field")
        data["injection"] = inj
    if scenario.hold_tools:
        data["hold_tools"] = list(scenario.hold_tools)
    data["replay"] = []
    for step in scenario.replay:
        if step.action == "list_tools":
            data["replay"].append({"list_tools": True})
            continue
        item: dict[str, Any] = {"tool": step.tool, "arguments": dict(step.arguments)}
        if step.server:
            item["server"] = step.server
        data["replay"].append(item)
    data["success_check"] = scenario.success_check.to_dict()
    if scenario.fix_hint:
        data["fix_hint"] = scenario.fix_hint
    if scenario.version and scenario.version != "1":
        data["version"] = scenario.version
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)


def load_scenario(path: str | Path) -> Scenario:
    path = Path(path)
    raw = path.read_bytes()
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise _fail(str(path), f"invalid YAML: {exc}") from exc
    scenario = scenario_from_dict(data, source=str(path), sha256=hashlib.sha256(raw).hexdigest())
    if scenario.id != path.stem:
        raise _fail(str(path), f"id {scenario.id!r} must match the file name {path.stem!r}")
    return scenario


def load_scenarios(path: str | Path) -> list[Scenario]:
    """Load one scenario file, or every ``*.yaml`` in a directory, sorted by id."""
    path = Path(path)
    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = sorted(path.glob("*.yaml"))
    else:
        raise ScenarioError(f"{path}: no such file or directory")
    if not files:
        raise ScenarioError(f"{path}: no *.yaml scenario files")
    # ids match file stems, so they are unique within a directory.
    return sorted((load_scenario(f) for f in files), key=lambda s: s.id)
