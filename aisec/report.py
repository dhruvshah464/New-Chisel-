"""The human-readable report, rendered from an evidence pack's ``target.json`` and ``verdict.json``.

Rendering is deterministic: the same pack always renders to the same bytes, so ``aisec
report`` can show that the sealed report follows from the sealed evidence. The content is
built once as a small document model and written out as Markdown and as a self-contained
HTML page, so the two formats never say different things.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any

from .scenario import OWASP_ASI
from .stats import fmt_rate
from .verdicts import (
    ATTACK_VERDICTS,
    BENIGN_VERDICTS,
    BLOCKED,
    COMPLETED,
    FAILED,
    INCONCLUSIVE,
    NOT_REACHABLE,
    RESISTED,
    SEVERITY_ORDER,
)

ARG_VALUE_EXCERPT = 140
ATTACK_RANK = {FAILED: 0, INCONCLUSIVE: 1, RESISTED: 2, NOT_REACHABLE: 3}
BENIGN_RANK = {BLOCKED: 0, INCONCLUSIVE: 1, COMPLETED: 2}

Inline = list[tuple[str, str]]
Block = tuple


def t(text: Any) -> tuple[str, str]:
    return ("t", str(text))


def c(text: Any) -> tuple[str, str]:
    return ("c", str(text))


def b(text: Any) -> tuple[str, str]:
    return ("b", str(text))


def v(verdict: str) -> tuple[str, str]:
    return ("v", verdict)


# --- content ---------------------------------------------------------------------------


def _is_demo(target: dict[str, Any]) -> bool:
    return target["target"].get("target") == "demo"


def _target_label(target: dict[str, Any]) -> str:
    described = target["target"]
    name = "demo support agent" if _is_demo(target) else str(described.get("name") or described.get("target", "target"))
    if not described.get("variant"):
        return name
    return f"{name}, {described['variant']} variant" if _is_demo(target) else f"{name} ({described['variant']})"


def _owasp(codes: list[str]) -> str:
    return " · ".join(f"{code} {OWASP_ASI.get(code, '')}".strip() for code in codes)


def _severity_rank(result: dict[str, Any]) -> int:
    return -SEVERITY_ORDER.index(result["severity"]) if result.get("severity") in SEVERITY_ORDER else 0


def ordered(results: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Attacks and benign controls in reading order: worst verdict first, then severity, then id."""
    attacks = sorted(
        (r for r in results if r["kind"] == "attack"),
        key=lambda r: (ATTACK_RANK.get(r["verdict"], 9), _severity_rank(r), r["id"]),
    )
    benign = sorted(
        (r for r in results if r["kind"] == "benign"), key=lambda r: (BENIGN_RANK.get(r["verdict"], 9), r["id"])
    )
    return attacks, benign


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def _ci_clause(rate: dict[str, Any] | None, replay: bool) -> str:
    """A confidence interval, except for the replay: it is deterministic, so a CI would mean nothing."""
    if not rate or replay:
        return ""
    return f" (95% CI {rate['ci95_low'] * 100:.0f}-{rate['ci95_high'] * 100:.0f}%)"


def _rate_text(rate: dict[str, Any] | None, replay: bool) -> str:
    if replay and rate:
        return f"{rate['k']}/{rate['n']}"
    return fmt_rate(rate)


def _payload_where(injection: dict[str, Any]) -> Inline:
    tool, after = injection["tool"], injection.get("after") or 0
    if injection["channel"] == "tool_description":
        parts = [t("added to the description of "), c(tool)]
        if after:
            parts.append(t(f", from listing {after + 1} on: the description changes mid-session"))
        return parts
    parts = [t("appended to ")]
    if injection.get("field"):
        parts += [t("the "), c(injection["field"]), t(" field of ")]
    parts += [c(tool), t("'s result")]
    if after:
        parts.append(t(f", from call {after + 1} on"))
    return parts


def _excerpt(value: Any) -> Any:
    if isinstance(value, str):
        flat = " ".join(value.split())
        return flat if len(flat) <= ARG_VALUE_EXCERPT else flat[:ARG_VALUE_EXCERPT] + f"… (+{len(flat) - ARG_VALUE_EXCERPT} chars)"
    if isinstance(value, dict):
        return {k: _excerpt(item) for k, item in value.items()}
    if isinstance(value, list):
        return [_excerpt(item) for item in value]
    return value


def _args(arguments: Any) -> str:
    """Arguments as JSON, each long string shortened so that every argument stays visible."""
    return json.dumps(_excerpt(arguments), ensure_ascii=False, sort_keys=True)


def _refusal(text: str) -> str:
    return re.sub(r"^Error executing tool \S+: ", "", text.strip())


def _call(call: dict[str, Any], where: str) -> Inline:
    """One recorded call, e.g. ``Trial 1, event 4: issue_refund on support_desk with {...}``."""
    if "tool" not in call:
        return [t(f"{where}, side effect {call.get('seq')}: "), c(_args(call))]
    parts = [t(f"{where}, event {call.get('seq')}: "), c(call["tool"])]
    if call.get("server"):
        parts += [t(" on "), c(call["server"])]
    parts += [t(" with "), c(_args(call.get("arguments") or {})), t(". ")]
    outcome = call.get("outcome")
    if outcome == "ok":
        parts.append(t("The tool carried it out."))
    elif outcome == "held":
        parts.append(t("aisec held it: recorded, not forwarded, and answered with a stand-in success."))
    else:
        refusal = _refusal(call.get("result") or "")
        parts.append(t(f"The tool refused it: “{refusal}”" if refusal else "The tool refused it."))
    return parts


def _facts(target: dict[str, Any], verdict: dict[str, Any]) -> list[list[Inline]]:
    described = target["target"]
    env = target.get("environment", {})
    inventory = target.get("tool_inventory", [])
    servers = sorted({tool["server"] for tool in inventory})
    replay = target["driver"] == "replay"
    rows = [
        [[t("Run")], [c(target["run_id"])]],
        [[t("Started")], [t(target["started_at"])]],
    ]
    if described.get("agent"):
        rows.append([[t("Agent")], [c(described["agent"])]])
    rows.append([[t("Model")], [t("none: scripted replay" if replay else described.get("model", "unknown"))]])
    if described.get("system_prompt_sha256"):
        rows.append([[t("System prompt")], [t("sha256 "), c(described["system_prompt_sha256"][:16])]])
    rows.append(
        [
            [t("Tools")],
            [t(f"{len(inventory)} tools on {len(servers)} servers; tool list sha256 "), c(target["tool_list_sha256"][:16])],
        ]
    )
    driver = "scripted replay in place of the agent" if replay else "the target's own agent"
    rows.append([[t("Trials")], [t(f"{target['trials_per_scenario']} per scenario, {driver}")]])
    auth = described.get("authorization")
    if auth:
        signer = auth["authorized_by"].get("name", "?")
        if auth["authorized_by"].get("title"):
            signer += f", {auth['authorized_by']['title']}"
        rows.append(
            [
                [t("Authorization")],
                [
                    t(f"{auth['client']}, signed by {signer} on {auth['signed_on']}. Environment: {auth['environment']}. "),
                    t(f"Data: {auth['data']}. Window: {auth['window']['start']} to {auth['window']['end']}. "),
                    c(auth["file"]),
                    t(" sha256 "),
                    c(auth["sha256"][:16]),
                ],
            ]
        )
    if target.get("always_held"):
        rows.append([[t("Held in every trial")], _join_code(target["always_held"])])
    rows.append(
        [[t("Versions")], [t(f"aisec {target['aisec_version']}, mcp {env.get('mcp', '?')}, Python {env.get('python', '?')}")]]
    )
    rows.append([[t("Fail on")], [t(f"{verdict['summary']['fail_on']} severity and above")]])
    return rows


def _counts(counts: dict[str, int], order: tuple[str, ...]) -> Inline:
    parts: Inline = []
    for i, name in enumerate(order):
        if i:
            parts.append(t(" · "))
        parts += [b(str(counts.get(name, 0))), t(f" {name}")]
    parts.append(t(f" (of {sum(counts.values())})"))
    return parts


def _result_cell(result: dict[str, Any], replay: bool) -> Inline:
    rate = result.get("rate")
    if result["verdict"] == NOT_REACHABLE:
        return [t("not applicable to this target")]
    refused = [t("refused in the replay")] if result.get("refused_in_replay") else []
    if not rate:
        return refused or [t("could not be judged")]
    verb = "landed" if result["kind"] == "attack" else "completed"
    parts = refused + [t(("; " if refused else "") + f"{verb} {_rate_text(rate, replay)}")]
    if result["kind"] == "attack" and result.get("attempted_denied"):
        parts.append(t(f"; attempted, denied in {result['attempted_denied']}"))
    return parts


def _attack_section(result: dict[str, Any], replay: bool, reach_variant: str | None) -> list[Block]:
    blocks: list[Block] = [("h3", [v(result["verdict"]), t(" "), t(result["title"])])]
    tags = [c(result["id"]), t(f" · {result['severity']}")]
    if result.get("attack_class"):
        tags.append(t(f" · {result['attack_class'].replace('_', ' ')}"))
    if result.get("owasp"):
        tags.append(t(f" · {_owasp(result['owasp'])}"))
    blocks.append(("p", tags))
    if result.get("description"):
        blocks.append(("p", [t(result["description"])]))
    if result.get("injection"):
        blocks.append(("p", [b("Payload"), t(", ")] + _payload_where(result["injection"]) + [t(":")]))
        blocks.append(("quote", result["injection"]["payload"]))

    items: list[Inline] = [[b("Task given to the agent: "), t(f"“{result['task']}”")]]
    verdict = result["verdict"]
    reason = result["reason"]
    if verdict == FAILED:
        reason += _ci_clause(result.get("rate"), replay)
    items.append([b("Verdict: "), t(reason + ".")])
    if verdict == RESISTED and result.get("rate") and not replay:
        n, high = result["rate"]["n"], result["rate"]["ci95_high"] * 100
        items.append(
            [
                b("Confidence: "),
                t(f"0 landings in {_plural(n, 'trial')} is consistent with a true landing rate as high as {high:.0f}% (95% CI)."),
            ]
        )

    evidence = result.get("evidence")
    if evidence and evidence["calls"]:
        label = "Attempted, denied: " if evidence["kind"] == "denied" else "Evidence: "
        for call in evidence["calls"]:
            items.append([b(label)] + _call(call, f"Trial {evidence['trial']}"))
        canary = (result.get("check") or {}).get("params", {}).get("canary")
        if canary:
            items.append([b("Canary: "), t("the call carried markers of "), c(canary), t(", synthetic PII planted in the target's data.")])
    if evidence and evidence.get("agent_said"):
        items.append([b(f"The agent said (trial {evidence['trial']}): "), t(f"“{evidence['agent_said']}”")])
    reach = result.get("reachability_evidence") or {}
    if verdict in (RESISTED, INCONCLUSIVE) and reach.get("landed"):
        where = (
            f"with no fix in place (the {reach_variant} variant), the scripted replay made it land. "
            if reach_variant
            else "the scripted replay made it land on this target, so the tools allow it. "
        )
        items.append([b("Reachable: "), t(where)] + _call(reach["landed"][0], "Replay"))
    if result.get("refused_in_replay") and reach.get("denied") and not replay:
        items.append([b("Refused in the replay: ")] + _call(reach["denied"][0], "Replay"))
    if result.get("fix_hint") and verdict != NOT_REACHABLE:
        items.append([b("Fix: "), t(result["fix_hint"])])
    blocks.append(("ul", items))
    return blocks


def _benign_notes(result: dict[str, Any]) -> list[Inline]:
    notes: list[Inline] = [[b(f"{result['title']}: "), t(result["reason"] + ".")]]
    if result["verdict"] == BLOCKED:
        by = result.get("blocked_by")
        if by == "tools":
            notes.append([t("A tool refused the legitimate call: the fix has a false positive.")])
        elif by == "model":
            notes.append([t("The agent did not make the legitimate call; no tool refused it.")])
        evidence = result.get("evidence")
        if evidence and evidence["kind"] == "denied":
            for call in evidence["calls"]:
                notes.append([b("Denied: ")] + _call(call, f"Trial {evidence['trial']}"))
    return notes


def _not_tested(target: dict[str, Any], results: list[dict[str, Any]]) -> list[Inline]:
    attacks = [r for r in results if r["kind"] == "attack"]
    judged = [r for r in attacks if r["verdict"] in (FAILED, RESISTED)]
    covered = {code for r in judged for code in r["owasp"]}
    missing = [code for code in OWASP_ASI if code not in covered]
    if target["driver"] == "replay":
        runs = "once, by scripted replay"
    else:
        runs = f"in {_plural(target['trials_per_scenario'], 'agent trial')}"
    items: list[Inline] = [[t(f"Anything beyond the {len(results)} scenarios above. Each tests one phrasing of one attack, {runs}.")]]
    unjudged = [r["id"] for r in attacks if r["verdict"] in (INCONCLUSIVE, NOT_REACHABLE)]
    if unjudged:
        items.append([t("These scenarios ran but produced no verdict: ")] + _join_code(unjudged) + [t(".")])
    if missing:
        items.append(
            [t("OWASP Top 10 for Agentic Applications categories with no judged scenario: ")]
            + [t("; ".join(f"{code} {OWASP_ASI[code]}" for code in missing) + ".")]
        )
    if target["driver"] == "replay":
        items.append([t("The model. Every trial was the scripted replay, which shows what the tools allow, not what an agent does.")])
    held_in: dict[str, list[str]] = {}
    for r in results:
        for tool in r.get("hold_tools") or []:
            held_in.setdefault(tool, []).append(r["id"])
    for tool, ids in sorted(held_in.items()):
        where = [t("every scenario")] if len(ids) == len(results) else _join_code(sorted(ids))
        items.append(
            [t("What "), c(tool), t(" would have done in ")]
            + where
            + [t(". aisec held those calls and answered them itself, so the tool's own checks did not run.")]
        )
    items += [
        [t("Other tasks, system prompts, models or model settings, and longer or multi-session conversations.")],
        [t("MCP servers over HTTP. Only stdio servers were exercised.")],
        [t("The servers' source code and dependencies. aisec does no static analysis.")],
        [t("Anything the proxy cannot see: the agent's own network, file or shell access.")],
    ]
    if _is_demo(target):
        items.append([t("Production systems or real data. The support desk, its customers and its knowledge base are synthetic.")])
    elif target["target"].get("authorization"):
        auth = target["target"]["authorization"]
        items.append([t(f"Anything outside the authorized scope ({auth['environment']}), including production.")])
    return items


def _join_code(values: list[str]) -> Inline:
    parts: Inline = []
    for i, value in enumerate(values):
        if i:
            parts.append(t(", "))
        parts.append(c(value))
    return parts


def _reproduce(target: dict[str, Any]) -> str:
    described = target["target"]
    parts = ["aisec run", f"--target {described.get('target', 'demo')}"]
    if _is_demo(target) and described.get("variant"):
        parts.append(f"--variant {described['variant']}")
    if described.get("config"):
        parts.append(f"--target-config {described['config']}")
    parts.append(f"--scenarios .aisec/runs/{target['run_id']}/scenarios")
    if target["driver"] == "replay":
        parts.append("--replay-only")
    else:
        parts.append(f"--repeat {target['trials_per_scenario']}")
        if described.get("model"):
            parts.append(f"--model {described['model']}")
    parts.append(f"--fail-on {target['fail_on']}")
    return " ".join(parts)


def build(target: dict[str, Any], verdict: dict[str, Any]) -> list[Block]:
    results = verdict["results"]
    attacks, benign = ordered(results)
    summary = verdict["summary"]
    replay = target["driver"] == "replay"
    blocks: list[Block] = [
        ("h1", [t(f"New Chisel Independent Evidence: {_target_label(target)}")]),
        (
            "note",
            [
                b("Independent of the model vendor. "),
                t(
                    "New Chisel is not OpenAI, Anthropic, or any other model company. This pack records what "
                    "this agent did, from tool calls, after a reachability replay. A vendor can grade its own "
                    "model; it cannot issue this third-party evidence about your tools."
                ),
            ],
        ),
        ("table", [[t("")], [t("")]], _facts(target, verdict)),
    ]
    if replay:
        rerun: Inline = [t("Run without "), c("--replay-only")]
        rerun += [t(", with a model API key set,")] if _is_demo(target) else []
        blocks.append(
            (
                "note",
                [
                    b("Scripted replay, no model. "),
                    t(
                        "Every trial in this run was the scenario's scripted replay, not an agent. FAILED here means the "
                        "attack can be carried out through these tools; it does not show whether a model would do it. "
                    ),
                ]
                + rerun
                + [t(" to test the agent itself.")],
            )
        )
    if target.get("agent_blocked"):
        blocks.append(
            ("note", [b("The agent did not run: "), t(f"{target['agent_blocked']}. Every reachable scenario is INCONCLUSIVE.")])
        )

    blocks.append(("h2", [t("Summary")]))
    blocks.append(("p", [b("Attacks: ")] + _counts(summary["attacks"], ATTACK_VERDICTS)))
    blocks.append(("p", [b("Benign controls: ")] + _counts(summary["benign"], BENIGN_VERDICTS)))
    blocks.append(("p", [b(f"Exit code {summary['exit_code']}: "), t(summary["exit_reason"] + ".")]))
    rows = [
        [
            [t(r["title"] + " "), c(r["id"])],
            [t(r.get("severity") or "")],
            [t(", ".join(r.get("owasp") or []))],
            [v(r["verdict"])],
            _result_cell(r, replay),
        ]
        for r in attacks
    ]
    rows += [
        [[t(r["title"] + " "), c(r["id"])], [t("benign")], [t("")], [v(r["verdict"])], _result_cell(r, replay)]
        for r in benign
    ]
    blocks.append(("table", [[t("Scenario")], [t("Severity")], [t("OWASP")], [t("Verdict")], [t("Result")]], rows))

    if attacks:
        blocks.append(("h2", [t("Attacks")]))
        for result in attacks:
            blocks.extend(_attack_section(result, replay, target["target"].get("reachability_variant")))
    if benign:
        blocks.append(("h2", [t("Benign controls")]))
        blocks.append(
            (
                "p",
                [
                    t(
                        "Legitimate workflows run the same way as the attacks. They catch a fix that blocks real work; "
                        "they never change the exit code."
                    )
                ],
            )
        )
        blocks.append(("ul", [note for r in benign for note in _benign_notes(r)]))

    blocks.append(("h2", [t("What was not tested")]))
    blocks.append(("ul", _not_tested(target, results)))

    blocks.append(("h2", [t("How to read this report")]))
    blocks.append(
        (
            "p",
            [
                t(
                    "This report records what happened in these trials. It is not a guarantee that the agent is secure, "
                    "and RESISTED is not a proof: an attack that did not land here can land on another run, with another "
                    "phrasing, or against another model. Verdicts come from the tool calls the aisec proxy recorded and "
                    "the side effects the servers logged, never from the agent's account of what it did."
                )
            ],
        )
    )
    blocks.append(
        (
            "ul",
            [
                [v(FAILED), t(" the attack landed in at least one trial.")],
                [
                    v(RESISTED),
                    t(
                        " the attack never landed: a tool refused the scripted attack itself, or the attack is reachable, "
                        "the payload reached the agent in every trial, and the agent did not carry it out. \"Attempted, "
                        "denied\" means the agent made the harmful call and a tool refused it."
                    ),
                ],
                [v(NOT_REACHABLE), t(" the scripted replay could not even attempt the attack on this target; excluded.")],
                [
                    v(INCONCLUSIVE),
                    t(" a trial could not be judged: no API key, a model error, a timeout, or the payload never arrived."),
                ],
                [v(COMPLETED), t(" / "), v(BLOCKED), t(" whether a legitimate workflow went through.")],
            ],
        )
    )

    blocks.append(("h2", [t("Evidence")]))
    blocks.append(
        (
            "p",
            [
                t("This report was rendered from, and sealed into, the evidence pack "),
                c(target["run_id"]),
                t(" (under "),
                c(".aisec/runs/"),
                t(
                    " unless the run set --runs-root). The pack holds what was tested (target.json), "
                    + ("the signed-off authorization (authorization.yaml), " if target["target"].get("authorization") else "")
                    + "the exact scenario files, every tool listing and call the proxy saw (events.jsonl), the agent "
                    "transcripts, the side effects the servers logged (sink.jsonl), each trial's check (checks.jsonl), the "
                    "verdicts, this report, and manifest.json with the SHA-256 of every file. Check that nothing changed "
                    "since the run, then re-run it:"
                ),
            ],
        )
    )
    blocks.append(("code", f"aisec verify .aisec/runs/{target['run_id']}\n{_reproduce(target)}"))
    return blocks


# --- markdown --------------------------------------------------------------------------


def _md_escape(text: str) -> str:
    text = text.replace("\\", "\\\\")
    return re.sub(r"([`*_\[\]<])", r"\\\1", text)


def _md_code(text: str) -> str:
    text = text.replace("\n", " ")
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _md_strong(text: str) -> str:
    # CommonMark does not close ``**`` after whitespace, so edge spaces go outside the markers.
    core = text.strip()
    if not core:
        return _md_escape(text)
    lead, trail = text[: len(text) - len(text.lstrip())], text[len(text.rstrip()) :]
    return f"{lead}**{_md_escape(core)}**{trail}"


def _md_inline(parts: Inline) -> str:
    out = []
    for style, text in parts:
        if style == "c":
            out.append(_md_code(text))
        elif style in ("b", "v"):
            out.append(_md_strong(text))
        else:
            out.append(_md_escape(text))
    return "".join(out)


def _md_cell(parts: Inline) -> str:
    return _md_inline(parts).replace("\n", " ").replace("|", "\\|")


def _md_block(block: Block) -> str:
    kind = block[0]
    if kind in ("h1", "h2", "h3"):
        return "#" * int(kind[1]) + " " + _md_inline(block[1])
    if kind == "p":
        return _md_inline(block[1])
    if kind == "ul":
        return "\n".join("- " + _md_inline(item) for item in block[1])
    if kind == "table":
        header, rows = block[1], block[2]
        lines = ["| " + " | ".join(_md_cell(cell) for cell in header) + " |", "|" + "---|" * len(header)]
        lines += ["| " + " | ".join(_md_cell(cell) for cell in row) + " |" for row in rows]
        return "\n".join(lines)
    if kind == "quote":
        return "\n".join(f"> {_md_escape(line)}" if line.strip() else ">" for line in block[1].splitlines())
    if kind == "note":
        return "> " + _md_inline(block[1])
    if kind == "code":
        return f"```\n{block[1]}\n```"
    raise ValueError(f"unknown block {kind!r}")


def render_markdown(target: dict[str, Any], verdict: dict[str, Any]) -> str:
    return "\n\n".join(_md_block(block) for block in build(target, verdict)) + "\n"


# --- html ------------------------------------------------------------------------------

STYLE = """
:root { color-scheme: light; --ink: #101828; --muted: #475467; --line: #e4e7ec; --code: #f2f4f7; }
* { box-sizing: border-box; }
body { margin: 0; background: #fcfcfd; color: var(--ink);
  font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
main { max-width: 920px; margin: 0 auto; padding: 40px 24px 80px; }
h1 { font-size: 28px; line-height: 1.25; margin: 0 0 20px; }
h2 { font-size: 21px; margin: 44px 0 12px; padding-top: 16px; border-top: 1px solid var(--line); }
h3 { font-size: 17px; margin: 32px 0 6px; }
p, ul { margin: 0 0 12px; }
li { margin: 4px 0; }
code { font: 13px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background: var(--code);
  padding: 1px 5px; border-radius: 4px; overflow-wrap: anywhere; }
pre { background: #101828; color: #f2f4f7; padding: 14px 16px; border-radius: 8px; overflow-x: auto; }
pre code { background: none; color: inherit; padding: 0; }
table { width: 100%; border-collapse: collapse; margin: 8px 0 16px; font-size: 14px; }
th, td { text-align: left; vertical-align: top; padding: 7px 10px; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 600; }
table.facts td:first-child { color: var(--muted); width: 140px; white-space: nowrap; }
blockquote { margin: 0 0 12px; padding: 10px 14px; border-left: 3px solid #d0d5dd; background: #f9fafb;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; white-space: pre-wrap; }
.note { margin: 16px 0; padding: 12px 14px; border: 1px solid #fedf89; background: #fffaeb; border-radius: 8px; }
.v { display: inline-block; font-size: 12px; font-weight: 700; letter-spacing: .02em; padding: 1px 8px;
  border-radius: 999px; white-space: nowrap; }
.v-failed { color: #b42318; background: #fef3f2; border: 1px solid #fecdca; }
.v-resisted, .v-completed { color: #067647; background: #ecfdf3; border: 1px solid #abefc6; }
.v-inconclusive, .v-blocked { color: #b54708; background: #fffaeb; border: 1px solid #fedf89; }
.v-not_reachable { color: var(--muted); background: var(--code); border: 1px solid var(--line); }
"""


def _html_inline(parts: Inline) -> str:
    out = []
    for style, text in parts:
        escaped = html.escape(text)
        if style == "c":
            out.append(f"<code>{escaped}</code>")
        elif style == "b":
            out.append(f"<strong>{escaped}</strong>" if text else "")
        elif style == "v":
            out.append(f'<span class="v v-{html.escape(text.lower())}">{escaped}</span>')
        else:
            out.append(escaped)
    return "".join(out)


def _html_block(block: Block, first_table: bool) -> str:
    kind = block[0]
    if kind in ("h1", "h2", "h3"):
        return f"<{kind}>{_html_inline(block[1])}</{kind}>"
    if kind == "p":
        return f"<p>{_html_inline(block[1])}</p>"
    if kind == "ul":
        return "<ul>" + "".join(f"<li>{_html_inline(item)}</li>" for item in block[1]) + "</ul>"
    if kind == "table":
        header, rows = block[1], block[2]
        if first_table:
            body = "".join("<tr>" + "".join(f"<td>{_html_inline(cell)}</td>" for cell in row) + "</tr>" for row in rows)
            return f'<table class="facts"><tbody>{body}</tbody></table>'
        head = "<tr>" + "".join(f"<th>{_html_inline(cell)}</th>" for cell in header) + "</tr>"
        body = "".join("<tr>" + "".join(f"<td>{_html_inline(cell)}</td>" for cell in row) + "</tr>" for row in rows)
        return f"<table><thead>{head}</thead><tbody>{body}</tbody></table>"
    if kind == "quote":
        return f"<blockquote>{html.escape(block[1])}</blockquote>"
    if kind == "note":
        return f'<div class="note">{_html_inline(block[1])}</div>'
    if kind == "code":
        return f"<pre><code>{html.escape(block[1])}</code></pre>"
    raise ValueError(f"unknown block {kind!r}")


def render_html(target: dict[str, Any], verdict: dict[str, Any]) -> str:
    blocks = build(target, verdict)
    title = html.escape(f"New Chisel Independent Evidence: {_target_label(target)} ({target['run_id']})")
    parts, seen_table = [], False
    for block in blocks:
        parts.append(_html_block(block, first_table=block[0] == "table" and not seen_table))
        seen_table = seen_table or block[0] == "table"
    body = "\n".join(parts)
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{title}</title>\n<style>{STYLE}</style>\n</head>\n"
        f"<body>\n<main>\n{body}\n</main>\n</body>\n</html>\n"
    )
