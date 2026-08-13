/**
 * Reporters: terminal, markdown (audit evidence), JSON, and SARIF 2.1.0
 * for GitHub code scanning.
 */

import pc from "picocolors";
import type { Finding, ScanResult, Severity } from "./types.js";
import { SEVERITY_ORDER } from "./types.js";

const SEV_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

function paint(sev: Severity, s: string): string {
  switch (sev) {
    case "critical":
      return pc.bgRed(pc.white(pc.bold(` ${s} `)));
    case "high":
      return pc.red(pc.bold(s));
    case "medium":
      return pc.yellow(pc.bold(s));
    case "low":
      return pc.blue(s);
    default:
      return pc.dim(s);
  }
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const s = SEVERITY_ORDER[a.rule.severity] - SEVERITY_ORDER[b.rule.severity];
    if (s !== 0) return s;
    if (a.rule.id !== b.rule.id) return a.rule.id.localeCompare(b.rule.id);
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const c: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) c[f.rule.severity]++;
  return c;
}

export function terminalReport(result: ScanResult): string {
  const out: string[] = [];
  const findings = sortFindings(result.findings);
  const counts = countBySeverity(findings);

  out.push("");
  out.push(pc.bold("  AgentAudit") + pc.dim(" — OWASP ASI / LLM Top 10 static audit"));
  out.push(
    pc.dim(
      `  ${result.filesScanned} files · ${(result.bytesScanned / 1024).toFixed(0)} KB · ${result.rulesEvaluated} rules · ${result.durationMs}ms`,
    ),
  );
  out.push("");

  if (findings.length === 0) {
    out.push(pc.green("  ✓ No findings. "));
    out.push(
      pc.dim(
        "    Static analysis clears only what it can see. Complete the manual\n" +
          "    review in templates/manual-review-checklist.md before claiming coverage.",
      ),
    );
    out.push("");
    return out.join("\n");
  }

  let currentRule = "";
  for (const f of findings) {
    if (f.rule.id !== currentRule) {
      currentRule = f.rule.id;
      out.push("");
      out.push(
        `  ${paint(f.rule.severity, SEV_LABEL[f.rule.severity])}  ${pc.bold(f.rule.id)}  ${f.rule.title}`,
      );
      out.push(pc.dim(`  ${wrap(f.rule.description, 74, "  ")}`));
      out.push("");
    }
    const loc =
      f.line > 0 ? `${f.file}:${f.line}:${f.column}` : `${f.file}`;
    out.push(`    ${pc.cyan(loc)}`);
    out.push(`      ${wrap(f.message, 70, "      ")}`);
    if (f.excerpt) out.push(pc.dim(`      │ ${f.excerpt}`));
    out.push("");
  }

  out.push(pc.bold("  Remediation"));
  const seen = new Set<string>();
  for (const f of findings) {
    if (seen.has(f.rule.id)) continue;
    seen.add(f.rule.id);
    out.push("");
    out.push(`  ${pc.bold(f.rule.id)} ${f.rule.title}`);
    out.push(`  ${wrap(f.rule.remediation, 74, "  ")}`);
  }

  out.push("");
  out.push(
    "  " +
      [
        counts.critical ? paint("critical", `${counts.critical} critical`) : "",
        counts.high ? paint("high", `${counts.high} high`) : "",
        counts.medium ? paint("medium", `${counts.medium} medium`) : "",
        counts.low ? paint("low", `${counts.low} low`) : "",
      ]
        .filter(Boolean)
        .join(pc.dim("  ·  ")),
  );
  if (result.controlsSatisfied.length) {
    out.push(
      pc.dim(`  controls satisfied: ${result.controlsSatisfied.sort().join(", ")}`),
    );
  }
  out.push("");
  return out.join("\n");
}

function wrap(s: string, width: number, indent: string): string {
  const words = s.split(/\s+/);
  const lines: string[] = [];
  let line = "";
  for (const w of words) {
    if ((line + " " + w).trim().length > width) {
      lines.push(line.trim());
      line = w;
    } else {
      line += " " + w;
    }
  }
  if (line.trim()) lines.push(line.trim());
  return lines.join("\n" + indent);
}

export function markdownReport(result: ScanResult, root: string): string {
  const findings = sortFindings(result.findings);
  const counts = countBySeverity(findings);
  const now = new Date().toISOString();
  const out: string[] = [];

  out.push("# Agentic AI Security Audit");
  out.push("");
  out.push(`**Target:** \`${root}\`  `);
  out.push(`**Generated:** ${now}  `);
  out.push(`**Tool:** AgentAudit v1.0.0  `);
  out.push(
    `**Frameworks:** OWASP Top 10 for Agentic Applications (2026) · OWASP Top 10 for LLM Applications (2025) · EU AI Act Art. 50`,
  );
  out.push("");
  out.push("## Summary");
  out.push("");
  out.push("| Severity | Count |");
  out.push("| --- | --- |");
  out.push(`| Critical | ${counts.critical} |`);
  out.push(`| High | ${counts.high} |`);
  out.push(`| Medium | ${counts.medium} |`);
  out.push(`| Low | ${counts.low} |`);
  out.push(`| **Total** | **${findings.length}** |`);
  out.push("");
  out.push(
    `Scanned ${result.filesScanned} files (${(result.bytesScanned / 1024).toFixed(0)} KB) against ${result.rulesEvaluated} rules in ${result.durationMs} ms.`,
  );
  out.push("");

  if (result.controlsSatisfied.length) {
    out.push(
      `**Controls found satisfied:** ${result.controlsSatisfied.sort().join(", ")}`,
    );
    out.push("");
  }

  if (findings.length === 0) {
    out.push("No static findings were produced.");
  } else {
    out.push("## Findings");
    out.push("");
    let currentRule = "";
    for (const f of findings) {
      if (f.rule.id !== currentRule) {
        currentRule = f.rule.id;
        out.push("");
        out.push(`### ${f.rule.id} — ${f.rule.title}`);
        out.push("");
        out.push(`**Severity:** ${SEV_LABEL[f.rule.severity]}  `);
        out.push(`**Framework:** ${f.rule.framework}`);
        out.push("");
        out.push(f.rule.description);
        out.push("");
        out.push("**Remediation**");
        out.push("");
        out.push(f.rule.remediation);
        out.push("");
        out.push("**Occurrences**");
        out.push("");
      }
      const loc = f.line > 0 ? `\`${f.file}:${f.line}\`` : `\`${f.file}\``;
      out.push(`- ${loc} — ${f.message}`);
      if (f.excerpt) {
        out.push("");
        out.push("  ```");
        out.push(`  ${f.excerpt}`);
        out.push("  ```");
      }
    }
  }

  out.push("");
  out.push("## Scope and limitations");
  out.push("");
  out.push(
    "This report reflects static analysis of source code only. It cannot observe runtime " +
      "configuration, infrastructure policy, model behaviour, or data governance. A clean " +
      "report is not a certification of compliance and is not legal advice. Findings under " +
      "the EU AI Act heading are engineering-visible proxies for obligations that require " +
      "a documented human assessment; see `templates/eu-ai-act-readiness.md`.",
  );
  out.push("");
  out.push("## References");
  out.push("");
  const refs = new Set<string>();
  for (const f of findings) f.rule.references.forEach((r) => refs.add(r));
  if (refs.size === 0) {
    refs.add("https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/");
    refs.add("https://genai.owasp.org/llm-top-10/");
  }
  for (const r of [...refs].sort()) out.push(`- ${r}`);
  out.push("");
  return out.join("\n");
}

export function jsonReport(result: ScanResult): string {
  return JSON.stringify(
    {
      tool: { name: "agentaudit", version: "1.0.0" },
      generatedAt: new Date().toISOString(),
      summary: {
        ...countBySeverity(result.findings),
        total: result.findings.length,
        filesScanned: result.filesScanned,
        durationMs: result.durationMs,
        controlsSatisfied: result.controlsSatisfied,
      },
      findings: sortFindings(result.findings).map((f) => ({
        ruleId: f.rule.id,
        framework: f.rule.framework,
        title: f.rule.title,
        severity: f.rule.severity,
        file: f.file,
        line: f.line,
        column: f.column,
        message: f.message,
        excerpt: f.excerpt,
        remediation: f.rule.remediation,
        references: f.rule.references,
      })),
    },
    null,
    2,
  );
}

const SARIF_LEVEL: Record<Severity, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

export function sarifReport(result: ScanResult): string {
  const rules = new Map<string, Finding["rule"]>();
  for (const f of result.findings) rules.set(f.rule.id, f.rule);

  return JSON.stringify(
    {
      $schema:
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "AgentAudit",
              version: "1.0.0",
              informationUri: "https://github.com/",
              rules: [...rules.values()].map((r) => ({
                id: r.id,
                name: r.title.replace(/[^A-Za-z0-9]/g, ""),
                shortDescription: { text: r.title },
                fullDescription: { text: r.description },
                help: {
                  text: r.remediation,
                  markdown: `**${r.title}**\n\n${r.description}\n\n**Remediation:** ${r.remediation}`,
                },
                properties: {
                  tags: [r.framework, "security", "ai-agent"],
                  "security-severity":
                    r.severity === "critical"
                      ? "9.0"
                      : r.severity === "high"
                        ? "7.5"
                        : r.severity === "medium"
                          ? "5.0"
                          : "3.0",
                },
              })),
            },
          },
          results: sortFindings(result.findings).map((f) => ({
            ruleId: f.rule.id,
            level: SARIF_LEVEL[f.rule.severity],
            message: { text: f.message },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.file === "(project)" ? "." : f.file },
                  region:
                    f.line > 0
                      ? { startLine: f.line, startColumn: Math.max(1, f.column) }
                      : { startLine: 1, startColumn: 1 },
                },
              },
            ],
          })),
        },
      ],
    },
    null,
    2,
  );
}
