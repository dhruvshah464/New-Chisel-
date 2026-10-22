# Outreach: finding and contacting the first 100 companies

Goal for days 1–14: 30–40 problem-focused conversations with people who own an agent that takes
actions. The purpose is learning, not selling. Track everything in `prospects.csv`.

## 1. Sourcing (build the list before writing a single message)

Aim for 100 companies that pass the four qualifiers in `01-buyer-profile.md`.

| Source | What to search for | Signal that qualifies |
|---|---|---|
| [YC company directory](https://www.ycombinator.com/companies) | Recent batches, keyword "agent", industries support, sales, fintech, devtools | Product page shows the agent *doing* things (refunds, emails, code changes) |
| [Product Hunt](https://www.producthunt.com/) | Launches tagged AI agents in the last 12 months | Demo video shows tool actions in a business system |
| GitHub | Organisations publishing MCP servers or agent tool integrations | They ship tools agents call, so they think about tool safety |
| Engineering blogs and LinkedIn | "we launched our agent", "agent in production", "our AI handles refunds" | A named engineer or founder who wrote about it |
| Job posts | "AI agent engineer", "agent infrastructure", "LLM platform" | They are investing in agents now |

For each company, spend at most five minutes and fill in: what the agent does, which systems it
can write to, where untrusted content enters, who owns it, and one specific detail to mention.
If you cannot find a specific detail, do not message them yet.

## 2. Rules

- Personalise every message. No mass sends, no automation that writes the message for you.
- Never say or imply you found a vulnerability in their product. You have not tested it, and you
  must not test anything without written authorization.
- Never test a prospect's production system, even "just to see".
- In communities (Hacker News, Discord, Slack, Reddit): share useful findings, answer questions,
  never drop product links into unrelated threads.
- Ask for 15 minutes, not a demo.

## 3. Message variants

### A. Founder or CTO, security-review angle

> Hi {first name},
>
> I saw that {company}'s agent can {specific action, e.g. "issue refunds from inside Zendesk"}.
>
> I'm building an open-source-first tool that tests what an agent actually does when a ticket,
> email or document contains hidden instructions, and produces evidence a customer's security
> reviewer can check.
>
> I'm talking to teams shipping agents with write access to learn how they test this today and
> how they answer security questionnaires about it. Would you be open to 15 minutes? Not a pitch.
>
> Dhruv

### B. Engineer who owns the agent, technical angle

> Hi {first name},
>
> Your post about {specific post or launch} was useful, especially {specific detail}.
>
> Quick question from someone working on agent security testing: when {company}'s agent reads
> {untrusted input, e.g. "customer emails"}, how do you check it won't act on instructions
> hidden in them before a release?
>
> I'm collecting how teams do this in practice. If you're up for a 15-minute call, I'd value it,
> and I'm happy to share what I'm seeing across other teams.
>
> Dhruv

### C. Warm or community follow-up (after they posted or replied publicly)

> Hi {first name}, thanks for {their comment or post}. I'm researching how teams test agents
> that can {action}. Could I ask you a few questions about how you do it at {company}? 15 minutes,
> whenever suits you.

## 4. Follow-up cadence (maximum three touches)

| Day | Touch |
|---|---|
| 0 | Personalised message (variant A, B or C) |
| 3 | One short follow-up that gives something useful: the finding in section 5, or a 60-second clip of the demo |
| 8 | Last note: "No worries if the timing is wrong. Who on your team owns agent testing?" |

After three touches with no reply, mark the row `no-reply` and move on.

## 5. Credibility asset: a real, reproducible result

Use this in follow-ups and posts. It was re-run from a clean checkout on 2026-10-09 (see
`00-existing-work-audit.md`).

> I tested an open-source MCP guard (mcp-firewall v0.1.0, default policy) against 31 simulated
> attacks in 12 classes. It stopped 61.3% (19 of 31) and blocked none of the 4 legitimate
> workflows. All 19 attacks it stopped were trying to leak a credential. It stopped none of the
> 12 that didn't involve one: 4 leaks of confidential business data, 3 unrequested sends, and 5
> destructive deletes. Pattern-matching on secrets is not the same as controlling what an agent
> is allowed to do.

Limits to state whenever you use it: deterministic scripted attacker (no live model), one guard
version, default configuration, a 35-scenario corpus written by us. Reproduce with:

```bash
git clone https://github.com/dhruvshah464/OpenTrust && cd OpenTrust
uv sync --extra dev && uv pip install mcp-firewall
uv run mcpguardbench run --adapter mcp_firewall --client stub --corpus corpus --out records
uv run mcpguardbench report --records records
```

## 6. Targets and what to track

- Day 4: first 10 messages. Days 5–14: 10–15 per working day until 100 companies are contacted.
- Reply rate is unknown; measure it rather than guessing. Track per variant and per source.
- What counts: replies, conversations held, average interview score, pilots offered, pilots
  accepted. Followers and views do not count.

## 7. `prospects.csv` columns

`id, company, website, segment, agent_description, write_actions, untrusted_inputs, contact_name,
contact_role, contact_channel, source, personal_hook, qualifies, message_variant, sent_date,
followup1_date, followup2_date, replied, interview_date, status, notes`

`status` is one of: `researching`, `contacted`, `replied`, `interviewed`, `pilot-offered`,
`pilot-signed`, `no-fit`, `no-reply`.
