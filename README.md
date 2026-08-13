<div align="center">

# AgentAudit

**Static analysis for AI agent codebases.**
Audits against the OWASP Top 10 for Agentic Applications (ASI01–ASI10),
the OWASP Top 10 for LLM Applications, and EU AI Act Article 50.

</div>

---

```bash
npx agentaudit .
```

```
  AgentAudit — OWASP ASI / LLM Top 10 static audit
  2 files · 2 KB · 18 rules · 9ms

   CRITICAL   ASI01  Agent Goal Hijack

    agent.ts:13:9
      Untrusted or dynamic content is interpolated directly into the system
      prompt. Anything reachable by an attacker in that string becomes an
      instruction.
      │ const systemPrompt = `You are an ops assistant. Context: ${retrievedDoc}

   CRITICAL   ASI05  Unexpected Code Execution (RCE)

    agent.ts:44:5
      Shell command built by string interpolation. Model-influenced values in
      a shell string are a command-injection primitive.
      │ exec(`bash -c "${args.cmd}"`, (e, stdout) => {

   11 critical  ·  12 high  ·  3 medium
```

---

## Why this exists

OWASP published the **Top 10 for Agentic Applications** in December 2025 and
refreshed the **GenAI LLM Top 10** on 3 August 2026. EU AI Act Article 50
transparency obligations became enforceable on **2 August 2026**.

Every engineering lead who shipped an agent this year is now expected to show
they have assessed against frameworks that are months old, using tooling built
for a threat model that predates agents entirely. Your SAST scanner does not
know what a tool call is. It will not tell you that your agent has a standing
admin token, that retrieved documents land in your system prompt, or that
nobody can stop a running agent.

That is the gap this fills.

## What it actually checks

18 rules across three frameworks. The interesting part is *how* they check.

Most agentic risk is a **missing control**, not a forbidden token. A codebase
isn't insecure because it calls `exec` — it's insecure because it calls `exec`
on a model-influenced string, in a process with no sandbox and no egress
policy. So AgentAudit runs two kinds of probe:

- **Presence probes** flag genuinely dangerous constructs — a shell string
  built by interpolation, a hardcoded long-lived token, model output reaching
  `innerHTML`.
- **Control probes** fire only when your code demonstrably does the risky
  thing *and* shows no evidence anywhere in the project of the mitigating
  control. Trigger without control is the finding.

Control evidence is deliberately generous, and comments never count as
evidence. A `// TODO: add sandboxing` comment must not make a scanner report
you as mitigated — for a security tool, a false "you're safe" is the worst
possible output.

### Coverage

| Framework | Rules |
|---|---|
| OWASP Top 10 for Agentic Applications (2026) | ASI01–ASI10 — goal hijack, tool misuse, identity abuse, supply chain, RCE, memory poisoning, inter-agent comms, cascading failures, human-trust exploitation, rogue agents |
| OWASP Top 10 for LLM Applications (2025) | LLM01, LLM02, LLM05, LLM06, LLM07, LLM10 |
| EU AI Act | Art. 50 transparency and synthetic-content marking |

LLM04 (Data and Model Poisoning) and LLM09 (Misinformation) cannot be
meaningfully assessed from source. They are covered in the manual review
checklist rather than faked here with regexes.

### Measured behaviour

Against the fixtures in `test/fixtures/`:

| Fixture | Findings | Controls satisfied |
|---|---|---|
| `vulnerable-agent` (deliberately unsafe) | **26** | 0 |
| `secure-agent` (reference implementation) | **0** | 5 |
| `polyglot-agent` (Python / C# / Go) | ASI01, ASI03, ASI05 in all three | — |

Sensitivity and specificity both matter. A scanner that finds everything is
noise; one that finds nothing is decoration.

### Measured against real repositories

Fixtures prove a scanner can fire. They don't prove it is usable. v1.0 was
tuned against five large open-source agent frameworks (~3,100 source files):

| | Findings | Critical |
|---|---|---|
| Before tuning | 792 | 171 |
| After tuning | **36** | **6** |

The 756 findings removed were noise, and the causes are worth stating plainly
because they are the failure modes every regex-based scanner has:

- Flagging `url.startswith(('http://', 'https://'))` — *scheme-validation code*,
  i.e. reporting the security control as the vulnerability. 475 findings.
- Matching placeholder credentials (`api_key='your_vercel_api_key'`) and
  deliberately-public keys. 115 findings.
- Matching sensitive words inside log *strings* rather than logged *values*
  (`logger.info('using access token')`). 70 findings.
- Matching "YOLO" the object-detection model inside recorded test fixtures.
- Matching JavaScript's `regex.exec(text)` as process execution.

**Honest precision estimate: roughly 55% on real code.** Of the 36 surviving
findings, manual review judged about 20 genuinely worth acting on. That is a
usable signal-to-noise ratio for a security review, and it is not 100%. Expect
to dismiss some findings, and please report them — rules are data, and most
fixes are a one-line change that ships in the next v1.x.

## Usage

```bash
agentaudit [path] [options]

  -f, --format <fmt>     terminal | markdown | json | sarif   (default: terminal)
  -o, --output <file>    write report to a file
      --fail-on <sev>    exit 1 at/above severity             (default: high)
      --only <ids>       e.g. ASI01,ASI05
      --skip <ids>       exclude rules
      --frameworks <f>   asi | llm | euaia | all
```

```bash
# Human-readable audit
agentaudit .

# Evidence document for a security review
agentaudit . --format markdown --output audit.md

# GitHub code scanning
agentaudit . --format sarif --output results.sarif --fail-on critical

# Focus a specific review
agentaudit . --only ASI05,ASI09
```

### CI

Copy `.github/workflows/agentaudit.yml` into your repo. It runs on every PR,
uploads SARIF to the GitHub Security tab, writes a markdown summary to the
job page, and gates on critical findings.

### Programmatic

```ts
import { audit, ASI_RULES } from "agentaudit";

const result = audit({ root: "./src", rules: ASI_RULES });
console.log(result.findings.filter((f) => f.rule.severity === "critical"));
```

## What's in the box

```
src/                          Scanner, rule engine, four reporters
templates/
  manual-review-checklist.md  47 checks covering what static analysis can't see
  eu-ai-act-readiness.md      Scope, classification, Art. 50, evidence map
redteam/
  probes.jsonl                30 adversarial probes mapped to risk IDs
  README.md                   How to run them through real channels
.github/workflows/            CI workflow with SARIF upload
test/fixtures/                Vulnerable and secure reference agents
```

The templates matter as much as the scanner. Static analysis covers roughly
half of the ASI Top 10 — the rest is architecture, runtime config, and
process. The checklist is what you hand an engineer to cover the other half,
with an evidence column, because "yes" without evidence is not an answer an
auditor accepts.

## Honest limitations

Read this part before you rely on the tool.

- **It reads source, not behaviour.** It cannot see runtime configuration,
  IAM policy, network topology, or what your model actually does.
- **Control probes are project-wide.** If a mitigation exists anywhere, the
  rule stays quiet — even if it isn't applied on the path that needs it. This
  favours quiet over noisy, and it means a clean result is weaker evidence
  than a dirty one.
- **Regex-based, not AST-based.** It will miss things a compiler wouldn't, and
  it can be fooled by unusual formatting.
- **Not a certification.** Not a conformity assessment. Not legal advice.
  Findings under the EU AI Act heading are engineering-visible proxies for
  obligations that require documented human assessment.

A clean report means "nothing detectable from source." It does not mean secure.
The manual checklist exists precisely because the scanner is not sufficient.

## Requirements

Node 18+. No network access, no telemetry, no data leaves your machine.

## License

Commercial. See `LICENSE`. Redistribution and resale are not permitted;
the Consultancy tier adds the right to use it in paid client engagements.

## References

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/)
- [EU AI Act Article 50](https://artificialintelligenceact.eu/article/50/)
