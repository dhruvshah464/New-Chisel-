# Threat model (V1 control plane)

Scope: pack ingest, finding tickets, API tokens. aisec does not run the customer's
agent and does not receive model API keys. STRIDE on those three surfaces.

## Assets

- Sealed evidence packs (may still contain synthetic PII or redaction misses)
- Org API tokens
- Finding tickets and comments
- Audit log

## Trust boundaries

- Customer CI / laptop (where `aisec run` executes) is untrusted from our side
- The control plane trusts a pack only after: manifest verify, HMAC signature
  with the server's `AISEC_SIGNING_KEY`, secret scan, and the production / data
  gates copied from `Authorization.check`
- Browser dashboard is same-origin; tokens live in localStorage plus an HttpOnly session cookie

## STRIDE

| Surface | Spoofing | Tampering | Repudiation | Information disclosure | Denial of service | Elevation |
|---|---|---|---|---|---|---|
| Ingest | Bearer token required; unsigned packs refused | Manifest hashes + HMAC; path traversal in tarballs refused | Audit row `pack.upload` | Packs mode 0400, no public URLs, secret scan | 50 MiB cap | Token scopes (`upload-run` cannot admin) |
| Tickets | Same org_id filter on every query | Status changes are append-only events | `finding_events` + `audit` | Body is generated from an already-redacted pack | — | `write-findings` vs `read-findings` |
| Tokens | SHA-256 of `aisec_…` secret; prefix shown | Revoke sets `revoked_at` | `token.create` / `token.revoke` audit | Secret shown once | — | Owner token minted only at bootstrap |

## Explicit non-goals for V1

- Running untrusted agent code on aisec metal
- Encrypting pack bytes with a customer-held key (use disk / bucket encryption)
- Multi-tenant shared signing keys in production — each deploy sets `AISEC_SIGNING_KEY`

## Residual risk

HMAC is not Sigstore. A stolen signing key lets an attacker mint a pack the
server will accept. Rotate the key; old packs still verify with the old key
offline via `aisec verify`.
