# New Chisel evidence pack spec (v1)

This is an independent, vendor-neutral format for a sealed record of an AI agent
under attack. New Chisel issues packs in this layout. Anyone can hash-check a pack
without New Chisel's servers and without a model API key.

It is **not** a certification, not a model score, and not a runtime allow-list.

## Seal

`manifest.json` lists every hashed file with SHA-256 and byte length. After
`aisec verify` recomputes those hashes, record the SHA-256 of `manifest.json`
itself somewhere you trust.

## Required files (in the manifest)

| File | What it is |
|---|---|
| `target.json` | What was tested: target, model, tools, canaries, parent digest if pinned |
| `verdict.json` | Per-scenario verdicts and the run summary |
| `events.jsonl` | Every `tools/list` and `tools/call` the proxy recorded |
| `transcripts.jsonl` | What the agent or the replay said, per trial |
| `sink.jsonl` | Side effects synthetic servers recorded instead of performing |
| `checks.jsonl` | Each trial's success-check result |
| `manifest.json` | SHA-256 and length of every hashed file |

`aisec run` also writes (hashed): `report.md`, `report.html`, `report.sarif`, `junit.xml`, and `scenarios/`.

Optional, hashed when present: `authorization.yaml`.

## Untracked overlays (after seal)

These can name the manifest digest, so they are not in the manifest:

- `signature.json` — HMAC-SHA256 of the manifest digest
- `certificate.html` — Independent Evidence Certificate
- `attestation.json` — GRC/SIEM JSON (`type`: `new-chisel.attestation.v1`)

## Commands

```
aisec verify <run>
aisec spec
aisec spec --check <run>
```

The browser verifier at `site/verify.html` hashes the same files.
