# 90-day validation sprint (founder-owned)

This board is the operational form of `03-outreach.md`, `04-interview-script.md`
and `06-week-review.md`. The agent cannot send the 100 messages or sit the 30
calls. Status below is what the repo can know as of 2026-10-09.

## Counts

| Item | Target | Current |
|---|---|---|
| Prospects in `prospects.csv` | 100 qualified | 1 example row (P-000) |
| Outreach sent | 100 | 0 (founder) |
| Conversations logged in `interview-log.csv` | 30–40 | 0 |
| Strong signals (score 9+, pain and pilot 2+) | 5 | 0 |
| Paid pilots with signed authorization | 3 | 0 |

## Decision rule (do not skip)

After ≥30 conversations, apply `04-interview-script.md`:

- 3 paid pilots or 5 strong signals → keep selling sealed packs (notary). Customer-machine HTTP MCP is allowed when the buyer needs it. Do not keep a hosted control plane. Do not sell a runtime gateway.
- Problem real, will not buy a separate tool → consultancies
- Loved, unpaid → wrong buyer
- Most do not have this problem → change the use case

The notary is the sealed pack a reviewer hash-checks. It is not a substitute
for the conversations.

## Days 1–30 (founder)

- [ ] Counsel + prior inventions (`legal/`)
- [ ] 100 sourced rows in `prospects.csv` (qualifiers in `01-buyer-profile.md`)
- [ ] 100 personalised messages (`03-outreach.md`); no mass send
- [ ] Real-model sample when an Anthropic key is available:
      `ANTHROPIC_API_KEY=… ./scripts/build-sample.sh`

## Days 31–60

- [ ] 30–40 interviews scored in `interview-log.csv`
- [ ] Day-14 decision using `06-week-review.md`
- [ ] 3 paid pilots, synthetic data, signed `authorization.yaml`

## Days 61–90

- [ ] Company / pause / stop before January 2027
- [ ] If company: incorporate, assign IP, co-founder, pre-seed on pilot evidence
