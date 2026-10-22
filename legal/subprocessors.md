# Subprocessors

Last updated: 2026-10-09. Replace this list before production deploy.

| Processor | Purpose | Data | Region (fill in) |
|---|---|---|---|
| None in the default local V1 | SQLite + local disk | Packs and tickets stay on the machine that runs `aisec serve` | local |

When you host this:

| Processor | Purpose | Data | Region |
|---|---|---|---|
| Your object store (S3-compatible) | Pack blobs | Sealed evidence packs | |
| Your Postgres host | Org, token hashes, findings, audit log | Metadata, no raw env values | |
| Your identity provider (WorkOS/Clerk, if enabled) | Login | Email, IdP subject | |
| Transactional email (if you add it) | Ticket and invite mail | Email addresses | |

Do not add a subprocessors row for a model vendor. aisec must not send packs to one.
