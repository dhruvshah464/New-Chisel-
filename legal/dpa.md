# Data processing addendum (template)

Status: template. Do not present this as executed. Have counsel finish it before
the first paid pack upload. Placeholder contact: you@example.com.

## What aisec processes

aisec is an evidence control plane. Customers upload **sealed evidence packs**
produced by the aisec CLI or GitHub Action running in *their* environment.

Typical contents of a pack: scenario YAML, redacted tool-call logs, redacted
agent transcripts, verdicts, and a report. Packs must not contain production
data, production environment names, or secret values. The CLI redacts
secret-looking strings before sealing. The control plane refuses unsigned packs
and packs whose recorded environment looks like production or whose data kind
is not synthetic or sanitized.

aisec does **not** run the customer's agent, does not receive model API keys,
and does not receive MCP server env values.

## Roles

- Customer: controller of any personal data that still appears in a pack
  after redaction (for example a synthetic email that happens to look real).
- aisec operator: processor, only for pack storage, verification, finding
  tickets, and audit logs.

## Instructions aisec follows

- Store packs encrypted at rest, keyed by organization prefix
- Allow access only to members of that organization and to the CI token
  that uploaded the pack
- Delete a pack and its tickets when the customer requests deletion
- Subprocessors: `legal/subprocessors.md` only
- No training of foundation models on customer packs
- No transfer of packs to a model vendor

## Security measures (V1)

- TLS in transit; HSTS and baseline security headers
- Tokens hashed at rest (`sha256` of `aisec_…` secrets); prefix shown once
- Signed, short-lived download URLs; packs are not publicly listed
- Append-only audit log for login, token lifecycle, upload, ticket status, export
- Authorization gate on ingest (no `\bprod` environment; data kind synthetic/sanitized)

## Breach notice

Notify the customer's emergency contact on the authorization record, and the
org owners, without undue delay after confirming a pack was accessed by
someone outside the org.
