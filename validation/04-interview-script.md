# Interview script (15–25 minutes)

Purpose: learn how they test agent behaviour today, what failure costs them, and who pays. Not to
pitch. Log every call in `interview-log.csv` the same day.

## Before the call (5 minutes)

- Re-read their row in `prospects.csv`: what the agent does, what it can write to, where
  untrusted content enters.
- Write down the one thing you most want to learn from this person.
- Ask at the start whether you may take notes (and record, if you want to).

## Opening (1–2 minutes)

> Thanks for the time. I'm researching how teams that ship agents with real permissions test
> what those agents do with hostile input. I'm not selling anything today. I'd like to hear how
> you do it now, including what doesn't work. Is it OK if I take notes?

## Core questions

Ask about **past behaviour**, not opinions about the future. "Tell me about the last time..."
beats "Would you...". Follow-ups are in italics; use the ones that fit.

1. **What AI agents are you shipping now, or preparing to ship?**
   *What does it do end to end? What is the most expensive thing it is allowed to do? When does
   it go live, or when did it?*
2. **What tools and data can they access?**
   *Which of those can write or send? Where does content you don't control reach the agent:
   tickets, emails, documents, web pages, third-party tools or MCP servers?*
3. **How do you test their security today?**
   *Walk me through the last time you tested before a release. Who did it, how long did it take,
   and what did you find? What tools did you use? Did you keep anything you could show someone?*
4. **When did that process last fail or delay a release?**
   *What happened? Has the agent ever done something nobody asked it to do?*
5. **What did that cost: engineering time, customer trust, a delayed deal?**
   *Has a customer's security review asked about prompt injection or agent permissions? What did
   you answer, and what did they accept?*
6. **Who owns this problem, and who controls the budget?**
   *If you wanted to spend $2,000 on an outside assessment next month, who would approve it? Would
   it need procurement?*
7. **What would you need to see before paying for help with this?**
   *What would make you say no immediately? For example: data leaving your machine, code changes,
   access to production, no written authorization.*

## Avoid

- "Would you use a tool that...?" and "Would you pay for...?" (people say yes to hypotheticals).
- Describing the product before question 5.
- Arguing with their answer. If they say it isn't a problem, ask what they do instead and learn.

## Optional demo (5 minutes, only if they described the pain)

Show the support-agent demo: the injected ticket, the unauthorized refund, the evidence pack, the
fix in code, the retest. Then ask:

> Is this the kind of failure you worry about? What would be different in your system? What
> would you need from a report like this to hand it to a customer's security reviewer?

## Close (2 minutes)

- If the score is high: offer the fixed-scope pilot in `05-pilot-offer.md`. Ask for a specific
  next step with a date (authorization form, staging access, a call with the budget owner).
- Always ask: "Who else should I talk to about this, inside or outside your company?"
- Thank them and say when you will follow up.

## Scoring rubric (fill in right after the call)

| Score | Pain | Timeline | Budget owner | Pilot willingness |
|---|---|---|---|---|
| 0 | None; never thought about it | No agent with write access planned | Unknown | No |
| 1 | Theoretical ("could happen") | More than 6 months away | Identified, not in the call | "Send me something" |
| 2 | Real but tolerable; a past example given | Within 6 months | In the call, needs approval | Agreed to a follow-up on scope or environment |
| 3 | Active and costly; a deal delayed or an incident | Live now or within 90 days | In the call and can approve up to $3,000 | Agreed to a paid pilot, or signed the authorization |

Total is 0–12. A **strong signal** is a total of 9 or more with pain and pilot willingness both at 2
or above.

## Two-week decision rule

Apply on day 14 using `interview-log.csv`, after at least 30 conversations.

| What you see | What to do |
|---|---|
| Three or more paid pilots from unrelated companies, or 5+ strong signals | Build the narrow product: the `command` target and GitHub Action from the plan |
| The problem is real, but buyers cannot justify a separate tool | Test selling through security consultancies or AI implementation firms, or as part of an existing workflow |
| Developers like the open-source tool, but nobody pays | Find the real buyer and purchase trigger before adding features |
| Most interviewees don't have this problem | Narrow or change the use case. Don't spend six months defending the original idea |
