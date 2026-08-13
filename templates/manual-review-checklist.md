# Agentic AI Manual Review Checklist

Static analysis covers roughly half of the OWASP ASI Top 10. The rest is
architecture, runtime configuration, and process — none of which is visible
in source. This checklist covers what the scanner cannot.

Work through it with an engineer who can answer for the deployment, not just
the code. Record evidence (a link, a config excerpt, a ticket) next to every
answer. "Yes" without evidence is not an answer an auditor will accept.

**How to score:** each item is Pass / Fail / N-A. Any Fail on a CRITICAL item
should block a production launch until remediated or formally risk-accepted
by a named owner.

---

## ASI01 — Agent Goal Hijack

| # | Check | Sev | Result | Evidence |
|---|---|---|---|---|
| 1.1 | Retrieved/external content is structurally separated from instructions (distinct message, delimiter, or field) — not concatenated into the system prompt. | CRITICAL | | |
| 1.2 | The system objective is re-asserted after every tool result, so a poisoned result cannot silently redefine the task. | HIGH | | |
| 1.3 | The agent operates against an explicit allowlist of permitted goals; it cannot self-assign new objectives. | HIGH | | |
| 1.4 | A change of objective mid-run requires human confirmation. | HIGH | | |
| 1.5 | You have tested indirect injection: a document/webpage/email containing instructions, fed through the real retrieval path. | CRITICAL | | |

## ASI02 — Tool Misuse & Exploitation

| # | Check | Sev | Result | Evidence |
|---|---|---|---|---|
| 2.1 | Every tool parameter is validated server-side against a strict schema before execution. | CRITICAL | | |
| 2.2 | Tools are scoped to least privilege — the narrow tool (`refundOrderById`) rather than the general one (`runSQL`). | CRITICAL | | |
| 2.3 | The agent holds only the tools required for the current task, not the full catalogue. | HIGH | | |
| 2.4 | Tool descriptions sourced from third-party/MCP servers are treated as untrusted input and reviewed before trust. | HIGH | | |
| 2.5 | A runtime policy check runs between model intent and tool execution. | HIGH | | |

## ASI03 — Identity & Privilege Abuse

| # | Check | Sev | Result | Evidence |
|---|---|---|---|---|
| 3.1 | Each agent has its own identity, distinct from any human user. | CRITICAL | | |
| 3.2 | Agents never operate using a human's session credentials or OAuth token. | CRITICAL | | |
| 3.3 | Credentials are short-lived (minutes, not months) and scoped to the task. | CRITICAL | | |
| 3.4 | Audit logs attribute actions to the agent identity, not to a human. | HIGH | | |
| 3.5 | Revoking one agent's credentials does not require rotating shared secrets. | MEDIUM | | |

## ASI04 — Agentic Supply Chain

| # | Check | Sev | Result | Evidence |
|---|---|---|---|---|
| 4.1 | An AIBOM exists covering models, prompts, tools, MCP servers, and datasets. | HIGH | | |
| 4.2 | MCP servers are pinned to exact versions with verified provenance or signatures. | CRITICAL | | |
| 4.3 | A new MCP server requires review before it can be added to a production agent. | HIGH | | |
| 4.4 | Dependency scanning runs in CI and blocks on known-vulnerable versions. | HIGH | | |
| 4.5 | Model artifacts are pulled from a trusted registry, pinned by digest. | MEDIUM | | |

## ASI05 — Unexpected Code Execution

| # | Check | Sev | Result | Evidence |
|---|---|---|---|---|
| 5.1 | Model-authored code executes only inside a container/microVM sandbox. | CRITICAL | | |
| 5.2 | Sandbox network egress is deny-by-default with an explicit allowlist. | CRITICAL | | |
| 5.3 | Sandbox filesystem is ephemeral and read-only outside a scratch directory. | HIGH | | |
| 5.4 | Execution has a hard wall-clock timeout and memory/CPU limits. | HIGH | | |
| 5.5 | Sandbox escape has been tested, not assumed. | HIGH | | |

## ASI06 — Memory & Context Poisoning

| # | Check | Sev | Result | Evidence |
|---|---|---|---|---|
| 6.1 | Memory is scoped per user and per tenant; no shared global memory across tenants. | CRITICAL | | |
| 6.2 | Every memory write records provenance — who/what wrote it, from what source. | HIGH | | |
| 6.3 | Memory entries expire; there is a TTL or eviction policy. | MEDIUM | | |
| 6.4 | An operator can inspect, export, and revoke what the agent has stored. | HIGH | | |
| 6.5 | Content arriving from tools/retrieval cannot write to long-term memory without validation. | CRITICAL | | |

## ASI07 — Insecure Inter-Agent Communication

| # | Check | Sev | Result | Evidence |
|---|---|---|---|---|
| 7.1 | Agent-to-agent channels use mutual authentication (mTLS or signed tokens). | CRITICAL | | |
| 7.2 | Messages are integrity-protected and include a nonce/timestamp to defeat replay. | HIGH | | |
| 7.3 | An explicit delegation allowlist defines which agent may instruct which. | HIGH | | |
| 7.4 | A sub-agent cannot escalate beyond the privileges of its caller. | CRITICAL | | |

## ASI08 — Cascading Failures

| # | Check | Sev | Result | Evidence |
|---|---|---|---|---|
| 8.1 | Agents run with isolated credentials and environments; one compromise does not grant another. | CRITICAL | | |
| 8.2 | Circuit breakers trip on behavioural deviation, not only on HTTP errors. | HIGH | | |
| 8.3 | Total steps, retries, and spend per run are bounded. | HIGH | | |
| 8.4 | The system fails closed — an agent that cannot verify state halts rather than proceeding. | HIGH | | |
| 8.5 | Blast radius has been modelled: you can state what a fully-hijacked agent could reach. | CRITICAL | | |

## ASI09 — Human-Agent Trust Exploitation

| # | Check | Sev | Result | Evidence |
|---|---|---|---|---|
| 9.1 | Approval prompts show the raw resolved action — exact command, target, and scope. | CRITICAL | | |
| 9.2 | Approval copy is templated, never model-generated prose. | CRITICAL | | |
| 9.3 | Immutable logs record what was *displayed* alongside what was *executed*. | HIGH | | |
| 9.4 | Irreversible actions require re-authentication, not just a click. | HIGH | | |
| 9.5 | Approval fatigue is measured — you know your approval rate and whether it is rubber-stamping. | MEDIUM | | |

## ASI10 — Rogue Agents

| # | Check | Sev | Result | Evidence |
|---|---|---|---|---|
| 10.1 | A tested kill switch halts execution and revokes credentials. | CRITICAL | | |
| 10.2 | Agents are registered with an owner and an expiry date; orphaned agents are deprovisioned. | HIGH | | |
| 10.3 | Behavioural baselines exist and deviation raises an alert. | HIGH | | |
| 10.4 | Every agent action is written to an append-only audit store. | CRITICAL | | |
| 10.5 | You can enumerate every agent running in production right now. | HIGH | | |

---

## Sign-off

| Role | Name | Date | Outstanding risk accepted |
|---|---|---|---|
| Engineering owner | | | |
| Security reviewer | | | |
| Product owner | | | |

> This checklist is an engineering control, not a legal instrument. It does not
> constitute a conformity assessment under any regulation.
