# EU AI Act — Engineering Readiness Worksheet

**This is not legal advice and not a conformity assessment.** It is a
worksheet for engineering teams to gather the technical facts a lawyer or
compliance officer will ask for. Classification under the AI Act is a legal
determination. Get it made by someone qualified to make it.

## Why this is on your desk now

| Date | Obligation | Status |
|---|---|---|
| 2 Feb 2025 | Article 5 prohibited practices | In force |
| 2 Aug 2025 | GPAI model obligations | In force |
| **2 Aug 2026** | **Article 50 transparency obligations** | **In force** |
| 2 Dec 2026 | Marking of synthetic content (extended) | Pending |
| 2 Dec 2026 | Prohibitions on AI-generated intimate imagery / CSAM | Pending |
| 2 Dec 2027 | Stand-alone high-risk systems (extended) | Pending |
| 2 Aug 2028 | High-risk as product safety components (extended) | Pending |

The 2027/2028 extensions were agreed as part of the digital omnibus package.
Verify current status before relying on any date here — this table reflects
the position as of August 2026 and the file is a worksheet, not a source of
truth.

---

## Section 1 — Scope

| # | Question | Answer |
|---|---|---|
| 1.1 | Is the system placed on the market, put into service, or used within the EU? | |
| 1.2 | Are outputs used in the EU, even if the system is operated elsewhere? | |
| 1.3 | What is your role: provider, deployer, importer, distributor, or product manufacturer? | |
| 1.4 | If you fine-tune or substantially modify a third-party model, do you become a provider? | |

> Non-EU companies are commonly in scope via 1.2. "We're a US company" is not
> a scope answer.

## Section 2 — Classification

| # | Question | Answer |
|---|---|---|
| 2.1 | Does the system implicate any Article 5 prohibited practice (social scoring, manipulative techniques, emotion inference in workplace/education, untargeted facial scraping)? | |
| 2.2 | Does it fall under an Annex III high-risk use case (employment, education, credit, essential services, law enforcement, migration, biometrics, critical infrastructure)? | |
| 2.3 | Is it a safety component of a product covered by Annex I legislation? | |
| 2.4 | Does it interact directly with natural persons? (→ Art. 50 transparency) | |
| 2.5 | Does it generate synthetic audio, image, video, or text? (→ Art. 50 marking) | |
| 2.6 | Do you develop or substantially modify a general-purpose AI model? | |

## Section 3 — Article 50 transparency (in force since 2 Aug 2026)

| # | Control | Evidence | Status |
|---|---|---|---|
| 3.1 | Users are informed they are interacting with an AI system, unless obvious from context. | | |
| 3.2 | The disclosure is visible before or at first interaction — not buried in a privacy policy. | | |
| 3.3 | The disclosure text and its effective date are recorded in technical documentation. | | |
| 3.4 | Synthetic content is marked in a machine-readable format (C2PA or equivalent). | | |
| 3.5 | Deepfake content is disclosed as artificially generated. | | |
| 3.6 | Emotion recognition or biometric categorisation, if used, is disclosed to affected persons. | | |
| 3.7 | Accessibility requirements are met for the disclosure itself. | | |

## Section 4 — Technical documentation you will be asked for

Regardless of classification, these artifacts are what auditors request first.
Most teams can produce none of them on demand.

| # | Artifact | Owner | Location | Exists |
|---|---|---|---|---|
| 4.1 | System description: purpose, intended use, foreseeable misuse | | | |
| 4.2 | Architecture diagram including models, tools, data flows, and third parties | | | |
| 4.3 | AIBOM — models, prompts, tools, MCP servers, datasets, versions | | | |
| 4.4 | Data governance: sources, licensing, PII handling, retention | | | |
| 4.5 | Risk management record — identified risks, mitigations, residual risk | | | |
| 4.6 | Accuracy, robustness, and cybersecurity measures with test evidence | | | |
| 4.7 | Human oversight design — who can intervene, how, and with what authority | | | |
| 4.8 | Logging and traceability: what is logged, retention period, who can access | | | |
| 4.9 | Incident response procedure for AI-specific failures | | | |
| 4.10 | Post-market monitoring plan | | | |

## Section 5 — Engineering evidence map

Link each claim to something inspectable. A claim without an artifact is a
finding waiting to happen.

| Obligation | Technical control | Where it lives | Verified by |
|---|---|---|---|
| Transparency (Art. 50) | AI disclosure component | | |
| Synthetic marking | C2PA manifest attachment | | |
| Human oversight | Approval gate / interrupt | | |
| Traceability | Append-only audit log | | |
| Cybersecurity | AgentAudit CI gate + pen test | | |
| Accuracy | Eval suite and thresholds | | |
| Data governance | Retention + redaction pipeline | | |

## Section 6 — Gaps and owners

| Gap | Severity | Owner | Target date | Status |
|---|---|---|---|---|
| | | | | |

---

## Sign-off

| Role | Name | Date |
|---|---|---|
| Engineering lead | | |
| Legal / compliance | | |
| Executive sponsor | | |

> Completing this worksheet does not establish compliance, does not
> constitute a conformity assessment, and is not a substitute for legal
> advice from a qualified professional.
