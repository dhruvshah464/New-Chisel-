# Stage gates

Build the next stage only when the previous gate is true. Dates are illustrative.

## Stage 0 — Pilot-ready (now)

Gate: counsel has reviewed outside-work terms; prior-inventions list is attached;
redaction + signed packs + PyPI-ready 0.1.0; 3 paid authorizations **or** the
founder explicitly chooses to dogfood the control plane locally (this repo).

Shipped in this repo: engine hardening, `aisec serve` / `aisec upload`, finding tickets.

## Stage 1 — Check (2027)

Gate: $250k ARR path visible, or 10 teams on the Team tier. Then: HTTP/SSE
proxy, `aisec init`, mutation engine, 50–100 scenarios (ASI01–ASI10), adapters,
baselines.

Shipped without HTTP: `aisec init`, evidence policy, phrasing mutations, SVG badge,
`aisec compare` baselines, ASI05–ASI10 scenarios on the demo tools.

Still not started: HTTP/SSE proxy — keep stdio-only until a pilot's MCP servers are remote.

## Stage 2 — Assure (~$3–5M ARR)

Compliance maps (EU AI Act 9/15, ISO/IEC 42001, NIST AI RMF, AIUC-1), quarterly
retest, trust-center badge, insurer export.

Shipped as a slice, without claiming certification: `aisec bundle` (auditor cover
sheet), framework coverage overlay, `aisec drift` (tool description/schema),
`aisec pin` (local baseline), `aisec graph` (permission graph from the record),
`aisec lineage` (parent digest chain), `aisec due` / `max_age_days` (evidence
expires), `aisec attest` (GRC JSON, not a certification), `aisec flow` (canary
data-flow from the sealed record), `aisec warrant` (hashed authorization vs
`started_at`), `aisec scope` (unused vs shadow tools), `aisec reproduce` (sealed
recipe, no keys). Full Assure still wants paid retest cadence and a hosted
trust center.

## Stage 3 — Enforce (~$15–25M ARR)

Runtime MCP gateway from Sentinel's parked policy proxy. Permission graph.
Tamper-evident production action log.

## Stage 4 — Network (2030+)

Open evidence-pack spec (`aisec spec`, `docs/pack-spec.md`), scenario
marketplace, anonymized landing data, OpenTrust remains the neutral benchmark.
The spec slice is shipped; marketplace and landing data are not.

## Kill / divert

See `validation/04-interview-script.md`. Interviews and paid pilots remain
founder-owned; this repository cannot complete them.
