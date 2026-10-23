# TODOs

## Deferred from /gstack-plan-ceo-review (2026-10-22)

- Larger public ratings corpus beyond `site/sample/fixed` and `site/sample/vulnerable`. D-E1 cap: version the pack spec and index those two packs only. No new scenario YAML until a later spec.

## Design

### DESIGN.md from site/index.html tokens

**What:** Run `/gstack-design-consultation` and write DESIGN.md from the homepage `:root` tokens.

**Why:** T2 copies `site/index.html` for verify.html. The next public page has no shared file and can drift.

**Context:** D5 A (2026-10-23) made `site/index.html:10-16` the system for this PR only. No DESIGN.md exists. Start from `--ink`, `--accent`, `--green`, serif/sans/mono, `.primary` / `.secondary` / `.pill`.

**Effort:** M
**Priority:** P3
**Depends on:** T2 can ship without this.

## Completed
