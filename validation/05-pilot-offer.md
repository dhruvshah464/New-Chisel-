# Pilot offer: agent attack assessment (fixed scope)

Send this after a strong interview. Price and scope are hypotheses; record every reaction to them
in `interview-log.csv`.

## The offer, in one paragraph

> We test one of your agents against a set of agreed attacks (hidden instructions in tickets,
> emails or documents; poisoned third-party tools; requests for other customers' data; unrequested
> actions) in your staging environment, and give you a sealed evidence pack plus a written report
> you can hand to a customer's security reviewer. Every finding includes the exact tool calls the
> agent made, how to reproduce it, and a recommended control. After you fix, we retest once.

## Included

- **One agent**, one environment (staging or a sandbox copy), up to 10 attack scenarios across the
  classes agreed at kickoff, plus benign controls so fixes are checked for breaking real work.
- **Sealed evidence pack** (`aisec verify` confirms nothing was edited after the run): scenarios,
  every tool call the agent made, check results, verdicts.
- **Written report:** findings with severity, OWASP Agentic Top 10 (ASI01–ASI10) mapping,
  reproduction steps, recommended controls, and an explicit list of what was *not* tested.
- **45-minute readout call** with your team.
- **One retest** within 30 days of the report.

## Not included

Production testing; infrastructure or network penetration testing; guarantees of any kind;
implementing fixes; ongoing monitoring.

## Timeline

| Step | When |
|---|---|
| Kickoff call: agree agent, environment, scenarios, held tools | Day 0 |
| Authorization (below) signed by someone with authority over the systems | Before any testing |
| Environment access, test run | Within 5 business days of signature |
| Report and readout | 2 business days after the run |
| Retest | Any time within 30 days of the report |

## Price (hypothesis)

$1,000–$3,000 depending on scope. Start the conversation at **$2,500**. The first three design
partners may get a lower price in exchange for permission to publish an anonymised case study.
Record the reaction to the number, not just yes or no.

## How we handle your data

- Tests run on a machine you approve; tool descriptions, transcripts and results are not sent to
  any third-party service. Model API calls go to the provider and account agreed at kickoff.
- Synthetic or sanitised data only. No real customer records.
- Side-effecting tools you list (payments, email, deployments) are **held**: the call is recorded
  but never sent to your system.
- You receive the evidence pack. Our copy is deleted within 30 days of the retest unless you ask
  us in writing to keep it.

---

## Authorization and rules of engagement (template)

**Not legal advice.** Have a lawyer review this template before the first real use.

1. **Parties.** Client: {legal name}. Assessor: {your name / company}.
2. **Authorized representative.** {name, title}, who confirms they have authority to permit
   testing of the systems below.
3. **In scope.**
   - Agent: {name, version or commit}.
   - Environment: {staging URL / sandbox}, accounts: {test accounts}.
   - MCP servers and tools: {list}.
   - Held tools (recorded, never forwarded): {list}.
4. **Out of scope.** Production systems; real customer data; third-party systems the client does
   not own or control; denial-of-service or load testing; social engineering of staff.
5. **Test window.** From {date, time, timezone} to {date, time, timezone}.
6. **Contacts.** Client technical contact: {name, phone}. Emergency stop contact: {name, phone}.
   Testing stops immediately on request.
7. **Methods.** Attack content is injected into tool descriptions and tool results through an
   intercepting proxy in front of the agent's MCP servers, and through task inputs agreed above.
   Model provider and who pays for model usage: {details}.
8. **Data handling.** Synthetic or sanitised data only. Evidence is stored on {machine} and
   deleted on {date or condition}. Deletion confirmed in writing.
9. **Confidentiality and publication.** Findings are shared only with the client. Nothing is
   published without written permission, and any published case study is anonymised.
10. **No guarantee.** The assessment reports what was tested and observed. It does not certify
    that the agent is secure.

Signed for the client: ____________________ Name / title / date

Signed for the assessor: ____________________ Name / date

Once it is signed, copy the terms into an `authorization.yaml` (format:
`examples/command-target/authorization.yaml`), with the SHA-256 of the signed PDF in
`signed_copy_sha256`. `aisec run --target command` refuses to start without it, or outside
its window, scope or data terms, and seals a copy into every evidence pack.
