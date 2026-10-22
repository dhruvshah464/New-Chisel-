# Existing work audit: OpenTrust, Sentinel, OpenTruth

Date: 2026-10-09. Method: fresh `git clone` of each public repo into a temp directory, then the
repo's own install and test commands. Nothing in the original repos was changed.

## Summary

| Repo | Decision | Why |
|---|---|---|
| [OpenTrust](https://github.com/dhruvshah464/OpenTrust) (`mcpguardbench`) | **Keep** as the neutral guard benchmark. **Reuse** small modules in ai-sec-check | Works, tested, and has one real, reproducible result. But it grades *guards*, not a customer's agent |
| [Sentinel](https://github.com/dhruvshah464/Sentinel) | **Park.** Reuse the MCP proxy plumbing only | Runtime enforcement is explicitly "later". Its policies are tuned to the benchmark's own wording |
| [OpenTruth](https://github.com/dhruvshah464/OpenTruth) | **Park** the product. Reuse the sealed evidence store, verdict rules and GitHub Action pattern | Different market (verifying AI-built apps against requirements), but its evidence discipline is exactly what ai-sec-check needs |

None of the three has outside users yet: 0 stars and 0 forks each (GitHub, 2026-10-09). OpenTrust
and Sentinel have no LICENSE file (OpenTrust's `pyproject.toml` says Apache-2.0); OpenTruth has an
Apache-2.0 LICENSE.

## OpenTrust (`mcpguardbench`)

**What it is.** An accountability benchmark for MCP guards. It runs each attack three ways
(reachability replay with no guard, bare model, guarded model) to separate "the guard blocked it"
from "the model refused" from "it got through".

**Verified today** (commit `d965b14`):

- `uv run pytest`: **37 passed**.
- Null baseline, deterministic attacker: 35 scenarios (31 attacks in 12 classes, 4 benign). All 31
  attacks reachable, 100% bypass, 0 of 4 false positives. The harness gives no free credit.
- **mcp-firewall v0.1.0** (installed from PyPI), deterministic attacker: **61.3% guard-attributable,
  38.7% bypass, 0 of 4 false positives**. This matches the published number exactly.
  - Blocked: credential theft, secret exposure, confused deputy, and the credential variants of
    poisoning, shadowing, rug pull, injection and cross-server attacks.
  - Missed entirely: authorization bypass (3/3), excessive agency (3/3), privilege escalation
    (2/2), plus every "proprietary data" variant.

**Gaps found:**

1. **The model arm has never run against a live API.** All published numbers use the deterministic
   attacker, so the guard-versus-model split (the project's core claim) is still unmeasured.
2. **All 31 attacks share one replay path**: read the secret, then send a report (AUDIT.md §5a.4).
   Class-specific behaviour only shows up in the unrun model arm.
3. **Packaging bug:** `pyproject.toml` allows `mcp>=1.2.0`, but `victim/server.py` imports
   `mcp.server.mcpserver`, which does not exist in MCP SDK 1.x (checked: fails on mcp 1.30.0,
   works on 2.1.1). It should be `mcp>=2.1,<3`.
4. **Docs disagree with each other**, which costs credibility if the finding is published:
   FINDINGS-M1.md says "22 tests" and tells readers to `cd Sentinel`; PROJECT-REPORT.md calls the
   corpus "20 test scenarios" in one place and 35 elsewhere. The README links to
   `../ideas/Sentinel.md`, which is not in the repo.
5. Web `POST /api/run` runs the benchmark with no authentication. Fine on localhost only, as the
   audit already says.

**Reused in ai-sec-check:** `sandbox.py`, `scenario.py`, `oracle.py`, `clients/stub.py`, the
tool-use loop in `clients/model.py`, `stats.py`.

**Next, if and when there is time (not in the 90-day focus):** run the model arm once with an API
key, fix gaps 3 and 4, add a LICENSE, then publish the attribution finding.

## Sentinel

**What it is.** An MCP control plane: stdio and HTTP proxies, nine policy packages (Rego plus
pure-Python mirrors), a hash-chained Ed25519-signed action-record log, identity tokens, a secrets
vault, a server registry with trust scores, tenancy, a dashboard and a certification badge.

**Verified today:**

- Control-plane tests (`Sentinel/Sentinel`): **61 passed, 2 failed**. Both failures are in
  `test_badge.py`: `certification/badge.py` imports `mcpguardbench`, which the package does not
  declare as a dependency.
- The older `mcpguardbench` copy at the repo root: **15 passed**.

**Gaps found:**

1. **Policies are tuned to the benchmark's own payloads.** `policy/native.py` flags descriptions
   containing markers such as `[[mcpgb-plan]]`, `you must`, `before you` and `is required`. A real
   attacker avoids those words, and an ordinary description ("A city name is required") would be
   flagged. The published 12/12 prevention should not be presented as general protection.
2. The repo root README is the `mcpguardbench` README; `Sentinel/README.md` is a placeholder. The
   nested `Sentinel/Sentinel` layout plus a second, older `mcpguardbench` copy will confuse readers.
3. Its own findings note that preventing an attack at `tools/list` time is scored as
   `not_executed` rather than as a block. That is a scoring gap in the benchmark, correctly not
   patched from the Sentinel side.

**Reused in ai-sec-check:** the proxy shape from `proxy/core.py` and `proxy/mcp_stdio.py`
(an MCP server facing the agent, an MCP client facing the real server, launched as
`wrap -- <command>`). Enforcement is replaced by record, inject and hold.

**Parked:** policy engine, identity, vault, registry, tenancy, dashboard. The signed action-record
log (`aar/store.py`) is the best candidate to reuse later, when evidence packs need signatures.

## OpenTruth

**What it is.** An independent verification protocol: it starts a declared application, operates
it, records a hash-sealed evidence graph and returns `PROVEN`, `PARTIALLY_PROVEN`, `FAILED`,
`NOT_PROVEN` or `INCONCLUSIVE`. Ships a GitHub Action.

**Verified today:** **84 passed, 1 failed**. The failure (`test_wheel_includes_site_assets_once`)
is environmental: the test runs `python -m pip`, and `uv`-created environments have no pip.

**Reused in ai-sec-check:** `store.py` (write-once run directory, SHA-256 manifest written last,
files made read-only, `verify_manifest` detects any change), the verdict discipline in
`verdicts.py` ("could not look" is never a pass), the exit-code contract, and the composite
`action.yml` pattern.

**Parked:** the product itself. It answers "did AI-built software meet its requirements", which is
a different buyer from agent security.

## Cross-cutting conclusions

1. **Buyer mismatch.** All three projects were built to grade guards or apps for an evaluator.
   ai-sec-check tests the *customer's own agent* for the team that ships it.
2. **No live-model data anywhere.** The first real-model run of the ai-sec-check demo will also be
   the first model data across all four repos.
3. **Strongest asset for outreach:** the reproducible mcp-firewall result above, stated with its
   limits (deterministic attacker, default policy, one guard version).
4. **Do not start new repos after this one.** OpenTrust, Sentinel and OpenTruth stay as they are
   until the 90-day validation cycle ends.
