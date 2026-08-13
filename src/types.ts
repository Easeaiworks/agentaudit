/**
 * Core types for the AgentAudit rule engine.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * A "presence" probe flags code that matches a dangerous pattern.
 *
 * A "control" probe is the inverse and is what separates this tool from grep:
 * it only fires when the codebase demonstrably performs an agentic behaviour
 * (the `trigger`) but shows no evidence anywhere of the corresponding
 * mitigating control (the `control`). That models the way the OWASP ASI list
 * is actually written -- most entries are missing-control findings, not
 * dangerous-token findings.
 */
export type Probe =
  | {
      kind: "presence";
      /** Pattern whose presence in a file constitutes a finding. */
      match: RegExp;
      /** Optional pattern that, if found on the same line, suppresses the finding. */
      unless?: RegExp;
      /** Only consider files whose path matches. */
      files?: RegExp;
      message: string;
    }
  | {
      kind: "control";
      /** Evidence the codebase does the risky thing at all. */
      trigger: RegExp;
      /** Evidence the mitigating control exists somewhere in the project. */
      control: RegExp;
      files?: RegExp;
      message: string;
    };

export interface Rule {
  /** OWASP identifier, e.g. ASI01 or LLM01. */
  id: string;
  framework: "OWASP-ASI-2026" | "OWASP-LLM-2025" | "EU-AI-ACT";
  title: string;
  severity: Severity;
  /** What the risk is, in one or two sentences. */
  description: string;
  /** Concrete steps to fix it. */
  remediation: string;
  references: string[];
  probes: Probe[];
}

export interface Finding {
  rule: Rule;
  file: string;
  line: number;
  column: number;
  /** The source line, trimmed. */
  excerpt: string;
  message: string;
  probeKind: Probe["kind"];
}

export interface ScanOptions {
  root: string;
  include: RegExp;
  exclude: RegExp;
  maxFileBytes: number;
  rules: Rule[];
}

export interface ScanResult {
  findings: Finding[];
  filesScanned: number;
  bytesScanned: number;
  durationMs: number;
  /** Rule ids that had a trigger but whose control was satisfied. Useful for the report's "passed" section. */
  controlsSatisfied: string[];
  rulesEvaluated: number;
}
