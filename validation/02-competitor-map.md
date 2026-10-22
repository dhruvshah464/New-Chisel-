# Competitor map

Checked 2026-10-09. Only facts from the linked sources are stated; anything not checked says so.
Re-verify before quoting any of this publicly. Pricing was not researched for most entries
("not checked") and is a Day 3 follow-up.

## 1. Open-source and developer tools

| Product | Owner | What it does | How it plugs in | Licence / price | Gap we test against it |
|---|---|---|---|---|---|
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) (formerly mcp-scan) | Snyk (acquired Invariant Labs, June 2025) | Finds agents, MCP servers and skills on a machine; flags prompt injection, tool poisoning, tool shadowing, "toxic flows" | Reads local agent configs (Claude Code/Desktop, Cursor, Gemini CLI, Windsurf) and launches stdio servers to read tool descriptions; `--ci` mode | Needs a Snyk API token; tool names and descriptions are sent to Snyk's API. Price not checked | Static: inspects what tools *say*, not what the agent *does* with a malicious ticket. Data leaves the machine |
| [Cisco mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) | Cisco AI Defense | Scans MCP tools, prompts, resources, server instructions and server source code | YARA rules (offline), optional LLM-as-judge, optional Cisco AI Defense API | Apache-2.0 | Static and semantic analysis of the server, not observed agent behaviour |
| [mcp-guard](https://github.com/M8T-Jacob/mcp-guard) | Independent | Static linter for MCP server source and tool manifests: poisoning, hidden Unicode, secrets, command injection | CLI and GitHub Action, SARIF output; never runs the server | Open source, free | Server code only; nothing about the agent |
| [Promptfoo](https://www.promptfoo.dev/) | OpenAI (acquisition announced March 9, 2026) | Evals plus red-teaming: plugins for excessive agency, broken authorization, MCP; PR code-scan Action | YAML config and target providers; GitHub Action posts PR comments, SARIF | MIT. Enterprise price not checked | General-purpose and LLM-graded; now owned by a model vendor, which matters to buyers who want an independent assessor |
| [COAX](https://github.com/dylanpatriarchi/coax) | Independent | Red-teams agents with deterministic success checks, baselines and regression gates; maps to OWASP ASI01–10 | TypeScript target-adapter module (HTTP, OpenAI, Anthropic, Ollama, Playwright, MCP) | MIT, free | Closest to our idea. Needs an adapter written per agent; no tamper-evident evidence pack. Small project (0 stars when checked) |
| [garak](https://github.com/NVIDIA/garak) | NVIDIA | Broad vulnerability scanner for model endpoints, including an agent-breaker probe | CLI against a model or endpoint | Apache-2.0, free | Model-level probing, not business-action outcomes |
| [PyRIT](https://github.com/microsoft/PyRIT) | Microsoft | Programmable red-teaming framework (multi-turn attacks, converters, scorers) | Python SDK you write campaigns in | MIT, free | A framework for experts, not a product a startup runs in CI |
| [jenkins-agent-security](https://github.com/anslei/jenkins-agent-security), [purplegate](https://github.com/sameermohan-git/purplegate) | Independent | CI wrappers that combine other scanners and gate builds | Jenkins library / GitHub Action | Open source | Evidence that "agent security CI gate" is easy to start, so it is not a moat on its own |

## 2. Commercial platforms (incumbents buying in)

| Company | Status | Relevant offering (from the announcement) |
|---|---|---|
| Protect AI | Acquired by Palo Alto Networks, completed July 22, 2025 ([press release](https://www.paloaltonetworks.com/company/press/2025/palo-alto-networks-completes-acquisition-of-protect-ai)) | Folded into Prisma AIRS: model scanning, posture, AI red teaming, runtime protection, AI agent security |
| Prompt Security | Acquired by SentinelOne, announced August 5, 2025 ([press release](https://www.businesswire.com/news/home/20250805913926/en/SentinelOne-to-Acquire-Prompt-Security-to-Advance-GenAI-Security-and-Agent-Security-Strategy)) | Runtime visibility and enforcement against prompt injection and data leakage |
| Lakera | Acquired by Check Point, announced September 2025 ([press release](https://www.checkpoint.com/press-releases/check-point-acquires-lakera-to-deliver-end-to-end-ai-security-for-enterprises/)) | "Check Point AI Red Teaming" and "Check Point AI Agent Security": pre-deployment assessment and runtime enforcement |
| Invariant Labs | Acquired by Snyk, June 24, 2025 ([press release](https://www.globenewswire.com/news-release/2025/06/24/3104309/0/en/snyk-acquires-invariant-labs-to-accelerate-agentic-ai-security-innovation.html)) | Guardrails, MCP scanning; became Snyk Agent Scan |

A third-party tracker ([Agent Security Map](https://guptadeepak.com/agent-security/deals/)) lists
deal values from SEC filings: Protect AI $634.5M, Lakera $201.8M, Prompt Security $160.2M. Not
independently checked.

What this means for us:

- **Good:** the category is real and incumbents pay for it; an exit path exists.
- **Bad:** these vendors sell to CISOs at large companies with existing distribution. We should
  not try to out-feature them. Our first buyer (a 10–200 person startup) is usually below their
  sales motion, which is the opening.

## 3. Where we could be different (hypotheses to test in interviews)

1. **Evidence a third party can check.** The output is a sealed evidence pack a customer's
   security reviewer can verify (`aisec verify`) and re-run, not a dashboard screenshot.
2. **No false alarms by construction.** Every finding is first proven reachable by a
   deterministic replay through the agent's real tools.
3. **No code changes.** The agent runs as-is; its MCP servers are wrapped by an intercepting
   proxy. Side-effecting tools can be held instead of executed.
4. **Local-only.** Nothing about the customer's tools or data leaves their machine.
5. **"Resisted by the model" vs "resisted by your tools".** Tells a team whether their safety
   depends on a model's behaviour (fragile) or on enforced controls (durable).
6. **Independent of model vendors.** Relevant now that Promptfoo belongs to OpenAI.

## 4. What we will not compete on

Static config and tool-description scanning (free from Snyk, Cisco and others), runtime
enforcement platforms, model-level jailbreak breadth (garak, PyRIT), and dashboards.

## 5. Day 3 follow-ups

- Public pricing for Snyk Agent Scan, Promptfoo Enterprise, Check Point AI Red Teaming, Prisma
  AIRS.
- Ask every interviewee which of these they have tried and why they stopped.
- Check whether COAX or Promptfoo produce anything a customer's reviewer can independently
  verify; if they do, gap 1 above is weaker than assumed.
