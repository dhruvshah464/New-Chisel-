# Buyer profile (one buyer, one page)

Status: hypothesis, written 2026-10-09 before any interviews. Every line below is something to
confirm or kill in the first 30 conversations. Update this file after the Day 7 review.

## The company

An AI-first software startup, 10–200 people, roughly Seed to Series B, that ships (or will ship
within 90 days) an agent that **takes actions** in business systems, not just one that answers
questions.

Typical agent jobs:

- Customer support: refunds, credits, plan changes, account updates.
- Sales and CRM: record updates, outbound email, meeting booking.
- Finance operations: invoices, payouts, reconciliation.
- Engineering: code changes, pull requests, deployments, cloud changes.
- IT and helpdesk: access grants, password resets, device actions.

## Qualifiers (all four must be true)

1. At least one agent is in production, or has a launch date.
2. The agent can **write** to at least one system where a wrong action costs money, data or trust.
3. **Untrusted content reaches the agent**: support tickets, inbound email, uploaded documents,
   web pages, or third-party MCP servers and tools.
4. The company sells to mid-market or enterprise customers who send security questionnaires.

## Who is involved

- **Economic buyer:** CTO, VP Engineering or Head of AI. Can approve a $1,000–$3,000 pilot from the
  engineering budget without procurement.
- **Champion:** the engineer who owns the agent and gets asked "is this safe?"
- **Influencer:** the security lead if there is one; more often the *customer's* security reviewer.

## Trigger events (why they would buy now)

- An enterprise deal is blocked or delayed in security review ("How do you prevent prompt
  injection?", "Can your agent issue refunds without approval?").
- First production launch of an agent with write access.
- SOC 2 or ISO 27001 preparation that now has to cover the agent.
- A near-miss or incident: the agent did something nobody asked for.
- A new integration or third-party MCP server added to the agent.
- Investor or acquirer technical diligence.

## Pain, in words we expect to hear (to be confirmed)

- "We can't answer the security questionnaire with evidence, only with a paragraph."
- "We test injection by hand, a few prompts, before big releases."
- "We don't actually know what the agent would do with a malicious ticket."
- "Every prompt change might undo whatever safety we had."

## What they do today (the real competitor)

Manual testing; an internal red-team afternoon; a few promptfoo or garak scripts; a general
penetration test that does not cover agent behaviour; or nothing.

## Disqualifiers (politely move on)

- Chatbot only, no tool actions.
- No production timeline.
- The agent only reads public data.
- Large regulated enterprise with a six-month procurement cycle (a later segment, not now).
- Wants a guarantee that the agent "can't be hacked". We sell tests and evidence, not guarantees.

## Where to find them

YC company directory (filter: AI agents), Product Hunt agent launches, GitHub organisations that
publish MCP servers, engineering blogs about agents in production, "AI agent engineer" job posts,
LinkedIn posts by founders about agent launches. Details in `03-outreach.md`.

## Budget hypotheses (test, do not assume)

- Pilot: fixed-scope assessment at $1,000–$3,000 (see `05-pilot-offer.md`).
- Recurring: Team tier at $500–$1,500 per month for CI checks and repeat evidence packs.

## The three things we most need to learn

1. Is "evidence for a customer's security review" a real, recurring purchase trigger, or a
   one-off?
2. Who owns agent security at a 30-person startup, and do they control any budget?
3. Will teams connect a staging copy of their agent to an outside tool, and what do they need
   from us (authorization, data handling, local-only operation) before they will?
