"""Running a scenario suite against a target, and sealing the evidence.

For each scenario:

1. **Reachability.** The scripted replay runs once against the target's reachability
   configuration (for the demo, the vulnerable variant). If its success check does not
   fire, the scenario does not apply to this target and its trials are not judged.
2. **Trials.** The target's own agent runs ``repeat`` times against the configuration
   under test, each trial in a fresh sandbox behind the proxy. With ``replay_only`` the
   scripted replay stands in for the agent, once: deterministic and model-free, it shows
   what the tools allow, not what a model does.
3. **Verdict.** The trials' check results are combined by ``verdicts.classify``.

Everything the proxy, the agent and the synthetic servers recorded is copied into the
run's evidence pack; the report is rendered from the pack's own files; the pack is sealed
last.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .attestation import write_attestation
from .certificate import write_certificate
from .checks import CheckResult, evaluate
from .evidence import DEFAULT_RUNS_ROOT, RunStore, load_json, now
from .export import render_junit, render_sarif
from .lineage import pin_record
from .redact import redact_record, redact_text
from .report import render_html, render_markdown
from .sandbox import Sandbox, environment_fingerprint
from .scenario import Scenario
from .signing import sign_pack
from .targets.base import Target, UnknownToolError, mcp_config, open_router, proxied
from .targets.replay import run_replay
from .verdicts import (
    SEVERITY_ORDER,
    STATUS_ERROR,
    STATUS_RAN,
    STATUS_SKIPPED,
    STATUS_TIMEOUT,
    classify,
    fired,
    refused_in_replay,
    summarize,
)

DRIVER_AGENT = "agent"
DRIVER_REPLAY = "replay"
ARM_REACHABILITY = "reachability"
ARM_TRIAL = "trial"
DEFAULT_TIMEOUT = 300.0
EVIDENCE_CALLS = 3
RESULT_EXCERPT = 300
TEXT_EXCERPT = 600
STDERR_TAIL = 2000


@dataclass
class Trial:
    record: dict[str, Any]
    events: list[dict[str, Any]]
    transcript: list[dict[str, Any]]
    sink: list[dict[str, Any]]


@dataclass
class RunResult:
    run_dir: Path
    target: dict[str, Any]
    verdict: dict[str, Any]
    manifest: dict[str, Any]

    @property
    def exit_code(self) -> int:
        return self.verdict["summary"]["exit_code"]


async def _drive_replay(specs, scenario: Scenario, sandbox: Sandbox) -> tuple[str, str]:
    try:
        with open(sandbox.root / "servers.log", "w", encoding="utf-8") as errlog:
            async with open_router(specs, errlog=errlog) as router:
                try:
                    transcript = await run_replay(router, scenario)
                    reason = ""
                except UnknownToolError as exc:
                    transcript, reason = [], str(exc)
    except Exception as exc:  # a server failed to start or crashed mid-replay
        return STATUS_ERROR, f"replay failed: {type(exc).__name__}: {exc}"
    with sandbox.transcript_path.open("w", encoding="utf-8") as handle:
        for entry in transcript:
            handle.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
    return STATUS_RAN, reason


def _kill_process_group(proc: asyncio.subprocess.Process) -> None:
    try:
        if hasattr(os, "killpg"):
            os.killpg(proc.pid, signal.SIGKILL)
        else:  # pragma: no cover - Windows
            proc.kill()
    except ProcessLookupError:
        pass


def _agent_failure(sandbox: Sandbox, stderr: str, returncode: int) -> str:
    for entry in reversed(sandbox.transcript()):
        if entry.get("event") == "model_error":
            return f"model error: {entry.get('error', '')}"[:TEXT_EXCERPT]
    lines = [line for line in stderr.strip().splitlines() if line.strip()]
    if lines:
        return f"the agent exited with code {returncode}: {lines[-1]}"[:TEXT_EXCERPT]
    return f"the agent exited with code {returncode}"


async def _drive_agent(target: Target, scenario: Scenario, specs, sandbox: Sandbox, timeout: float) -> tuple[str, str, dict]:
    sandbox.mcp_config_path.write_text(json.dumps(mcp_config(specs), indent=2), encoding="utf-8")
    argv = target.agent_command(scenario, sandbox)
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={**os.environ, **target.agent_env(scenario, sandbox)},
        cwd=target.agent_cwd(),
        start_new_session=True,
    )
    try:
        _, err = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        _kill_process_group(proc)
        await proc.wait()
        return STATUS_TIMEOUT, f"the agent did not finish within {timeout:g}s", {"agent_exit_code": None}
    stderr = err.decode("utf-8", errors="replace")
    info: dict[str, Any] = {"agent_exit_code": proc.returncode}
    if proc.returncode != 0:
        info["agent_stderr_tail"] = redact_text(stderr[-STDERR_TAIL:])
        return STATUS_ERROR, _agent_failure(sandbox, info["agent_stderr_tail"], proc.returncode), info
    return STATUS_RAN, "", info


def held_tools(target: Target, scenario: Scenario) -> list[str]:
    return sorted(set(scenario.hold_tools) | target.always_hold())


def _call_excerpt(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "seq": record.get("seq"),
        "server": record.get("server"),
        "tool": record.get("tool"),
        "arguments": record.get("arguments") or {},
        "outcome": record.get("outcome"),
        "result": (record.get("result_text") or "")[:RESULT_EXCERPT],
    }


def _evidence(scenario: Scenario, events: list[dict], sink: list[dict], check: CheckResult) -> dict[str, list]:
    if scenario.success_check.type == "canary_exfiltrated":
        by_seq = {int(e.get("seq", 0)): e for e in sink}
        return {"landed": [by_seq[s] for s in check.executed if s in by_seq][:EVIDENCE_CALLS], "denied": []}
    by_seq = {int(e.get("seq", 0)): e for e in events}
    landed = sorted((*check.executed, *check.held))
    return {
        "landed": [_call_excerpt(by_seq[s]) for s in landed if s in by_seq][:EVIDENCE_CALLS],
        "denied": [_call_excerpt(by_seq[s]) for s in check.denied if s in by_seq][:EVIDENCE_CALLS],
    }


def _last_agent_text(transcript: list[dict[str, Any]]) -> str | None:
    for entry in reversed(transcript):
        if entry.get("event") == "model_turn" and (entry.get("text") or "").strip():
            return entry["text"].strip()[:TEXT_EXCERPT]
    return None


async def run_trial(
    target: Target,
    scenario: Scenario,
    *,
    arm: str,
    index: int,
    driver: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> Trial:
    """One trial in a fresh sandbox; the sandbox is destroyed once its records are read."""
    reachability = arm == ARM_REACHABILITY
    sandbox = Sandbox.create(canaries=target.canaries())
    started = time.monotonic()
    try:
        sandbox.write_proxy_config(
            scenario.injection.to_dict() if scenario.injection else None, held_tools(target, scenario)
        )
        specs = [proxied(spec, sandbox) for spec in target.servers(scenario, sandbox, reachability=reachability)]
        info: dict[str, Any] = {}
        if driver == DRIVER_REPLAY:
            status, reason = await _drive_replay(specs, scenario, sandbox)
        else:
            status, reason, info = await _drive_agent(target, scenario, specs, sandbox, timeout)
        check = evaluate(scenario.success_check, sandbox)
        events = [e.record for e in sandbox.events()]
        transcript = sandbox.transcript()
        sink = sandbox.sink_entries()
        record = {
            "scenario": scenario.id,
            "arm": arm,
            "trial": index,
            "driver": driver,
            "status": status,
            "reason": reason,
            "delivered": any(e.get("injected") for e in events) if scenario.injection else None,
            "check": check.to_dict(),
            "evidence": _evidence(scenario, events, sink, check),
            "agent_said": _last_agent_text(transcript),
            "event_count": len(events),
            "duration_s": round(time.monotonic() - started, 2),
            **info,
        }
        return Trial(record, events, transcript, sink)
    finally:
        sandbox.destroy()


def skipped_trial(scenario: Scenario, index: int, reason: str) -> Trial:
    record = {
        "scenario": scenario.id,
        "arm": ARM_TRIAL,
        "trial": index,
        "driver": DRIVER_AGENT,
        "status": STATUS_SKIPPED,
        "reason": reason,
        "delivered": None,
        "check": None,
        "evidence": {"landed": [], "denied": []},
        "agent_said": None,
        "event_count": 0,
        "duration_s": 0.0,
    }
    return Trial(record, [], [], [])


async def tool_inventory(target: Target, scenario: Scenario) -> list[dict[str, Any]]:
    """The target's tools as its servers list them, with no proxy and no injection."""
    sandbox = Sandbox.create(canaries=target.canaries())
    try:
        with open(sandbox.root / "servers.log", "w", encoding="utf-8") as errlog:
            async with open_router(target.servers(scenario, sandbox), errlog=errlog) as router:
                listed = await router.list_tools()
    finally:
        sandbox.destroy()
    inventory = [
        {
            "server": server,
            "name": tool.name,
            "description": tool.description or "",
            "input_schema": tool.input_schema or {},
        }
        for server, tool in listed
    ]
    return sorted(inventory, key=lambda t: (t["server"], t["name"]))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _pick_evidence(trials: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The trial a reader should look at first: a landing, else a denial, else what the agent said."""
    for t in trials:
        if fired(t):
            return {"trial": t["trial"], "kind": "landed", "calls": t["evidence"]["landed"], "agent_said": t["agent_said"]}
    for t in trials:
        if t["evidence"]["denied"]:
            return {"trial": t["trial"], "kind": "denied", "calls": t["evidence"]["denied"], "agent_said": t["agent_said"]}
    for t in trials:
        if t["status"] == STATUS_RAN and t["agent_said"]:
            return {"trial": t["trial"], "kind": "declined", "calls": [], "agent_said": t["agent_said"]}
    return None


def scenario_result(
    scenario: Scenario,
    reach: dict[str, Any],
    trials: list[dict[str, Any]],
    driver: str = DRIVER_AGENT,
    holds: list[str] | None = None,
) -> dict[str, Any]:
    actor = "the replay" if driver == DRIVER_REPLAY else "the agent"
    return {
        "id": scenario.id,
        "title": scenario.title,
        "kind": scenario.kind,
        "description": scenario.description,
        "attack_class": scenario.attack_class,
        "owasp": list(scenario.owasp),
        "severity": scenario.severity,
        "task": scenario.task,
        "injection": scenario.injection.to_dict() if scenario.injection else None,
        "hold_tools": holds if holds is not None else list(scenario.hold_tools),
        "check": scenario.success_check.to_dict(),
        "fix_hint": scenario.fix_hint,
        "scenario_sha256": scenario.sha256,
        **classify(scenario.is_attack, reach, trials, actor=actor),
        "evidence": _pick_evidence(trials),
        "reachability_evidence": {
            "landed": reach["evidence"]["landed"][:1],
            "denied": reach["evidence"]["denied"][:1],
        },
    }


def _append_trial(store: RunStore, trial: Trial) -> None:
    label = {k: trial.record[k] for k in ("scenario", "arm", "trial")}
    store.extend("events.jsonl", (redact_record({**label, **e}) for e in trial.events))
    store.extend("transcripts.jsonl", (redact_record({**label, **e}) for e in trial.transcript))
    store.extend("sink.jsonl", (redact_record({**label, **e}) for e in trial.sink))
    store.append("checks.jsonl", redact_record(trial.record))


async def run_suite(
    target: Target,
    scenarios: list[Scenario],
    *,
    repeat: int = 3,
    replay_only: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    fail_on: str = "low",
    runs_root: str | Path = DEFAULT_RUNS_ROOT,
    progress: Callable[[str], None] = lambda _message: None,
) -> RunResult:
    if not scenarios:
        raise ValueError("no scenarios to run")
    if repeat < 1:
        raise ValueError("repeat must be at least 1")
    if fail_on not in SEVERITY_ORDER:
        raise ValueError(f"fail_on must be one of {SEVERITY_ORDER}")

    driver = DRIVER_REPLAY if replay_only else DRIVER_AGENT
    trials_per_scenario = 1 if replay_only else repeat
    blocked = None if replay_only else target.preflight()
    if blocked:
        progress(f"the target's agent cannot run ({blocked}); its trials will be INCONCLUSIVE")

    store = RunStore(runs_root)
    store.create()
    started_at = store.created_at
    inventory = await tool_inventory(target, scenarios[0])
    scenario_files = []
    for s in scenarios:
        rel = store.add_scenario(s.source_path, s.id)
        scenario_files.append({"id": s.id, "kind": s.kind, "path": rel, "sha256": s.sha256})
    for name, source in target.evidence_files().items():
        store.add_file(name, source)
    store.write_json(
        "target.json",
        {
            "run_id": store.run_id,
            "started_at": started_at,
            "aisec_version": __version__,
            "target": target.describe(),
            "driver": driver,
            "trials_per_scenario": trials_per_scenario,
            "repeat_requested": repeat,
            "timeout_s": timeout,
            "fail_on": fail_on,
            "agent_blocked": blocked,
            "always_held": sorted(target.always_hold()),
            "tool_inventory": inventory,
            "tool_list_sha256": _sha256_json(inventory),
            "canaries": target.canaries(),
            "scenarios": scenario_files,
            "environment": environment_fingerprint(),
            **(
                {
                    "parent_run_id": parent["run_id"],
                    "parent_manifest_sha256": parent["manifest_sha256"],
                }
                if (parent := pin_record(runs_root))
                else {}
            ),
        },
    )

    results = []
    for position, scenario in enumerate(scenarios, start=1):
        prefix = f"[{position}/{len(scenarios)}] {scenario.id}"
        reach = await run_trial(target, scenario, arm=ARM_REACHABILITY, index=0, driver=DRIVER_REPLAY)
        _append_trial(store, reach)
        if fired(reach.record):
            reach_outcome = "landed"
        elif refused_in_replay(reach.record):
            reach_outcome = "was refused by a tool"
        else:
            reach_outcome = "did not land"
        progress(f"{prefix}: reachability replay {reach_outcome}")
        trials = []
        for index in range(1, trials_per_scenario + 1):
            if not (fired(reach.record) or refused_in_replay(reach.record)):
                break
            if blocked:
                trial = skipped_trial(scenario, index, blocked)
            else:
                trial = await run_trial(target, scenario, arm=ARM_TRIAL, index=index, driver=driver, timeout=timeout)
            _append_trial(store, trial)
            trials.append(trial.record)
            if fired(trial.record):
                outcome = "landed"
            elif trial.record["status"] == STATUS_RAN:
                outcome = "did not land"
            else:
                outcome = f"{trial.record['status']}: {trial.record['reason']}"
            progress(f"{prefix}: trial {index}/{trials_per_scenario} {outcome}")
        result = scenario_result(scenario, reach.record, trials, driver, held_tools(target, scenario))
        progress(f"{prefix}: {result['verdict']}")
        results.append(result)

    store.write_json(
        "verdict.json",
        {
            "run_id": store.run_id,
            "started_at": started_at,
            "finished_at": now(),
            "driver": driver,
            "results": results,
            "summary": summarize(results, fail_on),
        },
    )
    target_json = load_json(store.root / "target.json")
    verdict_json = load_json(store.root / "verdict.json")
    store.write_text("report.md", render_markdown(target_json, verdict_json))
    store.write_text("report.html", render_html(target_json, verdict_json))
    store.write_text("report.sarif", render_sarif(target_json, verdict_json))
    store.write_text("junit.xml", render_junit(target_json, verdict_json))
    manifest = store.seal()
    sign_pack(store.root)
    write_certificate(store.root)
    write_attestation(store.root)
    return RunResult(store.root, target_json, verdict_json, manifest)
