#!/usr/bin/env node
/**
 * AgentAudit CLI.
 *
 * Exit codes:
 *   0  no findings at or above the fail threshold
 *   1  findings at or above the fail threshold (CI gate)
 *   2  usage or runtime error
 */

import { writeFileSync, existsSync, statSync } from "node:fs";
import { resolve } from "node:path";
import pc from "picocolors";
import { scan, DEFAULT_INCLUDE, DEFAULT_EXCLUDE } from "./scanner.js";
import { ASI_RULES } from "./rules/asi.js";
import { LLM_RULES, EU_AI_ACT_RULES } from "./rules/llm.js";
import {
  terminalReport,
  markdownReport,
  jsonReport,
  sarifReport,
  countBySeverity,
} from "./report.js";
import { SEVERITY_ORDER, type Severity } from "./types.js";

const VERSION = "1.0.0";

const HELP = `
${pc.bold("agentaudit")} — OWASP ASI / LLM Top 10 static audit for AI agent codebases

${pc.bold("USAGE")}
  agentaudit [path] [options]

${pc.bold("OPTIONS")}
  -f, --format <fmt>     terminal | markdown | json | sarif      (default: terminal)
  -o, --output <file>    write report to a file instead of stdout
      --fail-on <sev>    exit 1 at or above this severity        (default: high)
                         critical | high | medium | low | none
      --only <ids>       comma-separated rule ids (e.g. ASI01,ASI05)
      --skip <ids>       comma-separated rule ids to exclude
      --frameworks <f>   asi | llm | euaia | all                 (default: all)
      --max-file-size    skip files larger than N bytes          (default: 512000)
  -h, --help             show this help
  -v, --version          show version

${pc.bold("EXAMPLES")}
  agentaudit .
  agentaudit ./src --format markdown --output audit.md
  agentaudit . --format sarif --output results.sarif --fail-on critical
  agentaudit . --only ASI05,ASI09
`;

function fail(msg: string): never {
  console.error(pc.red(`error: ${msg}`));
  process.exit(2);
}

function parseArgs(argv: string[]) {
  const opts = {
    path: ".",
    format: "terminal" as "terminal" | "markdown" | "json" | "sarif",
    output: "" as string,
    failOn: "high" as Severity | "none",
    only: [] as string[],
    skip: [] as string[],
    frameworks: "all",
    maxFileSize: 512_000,
  };
  const positional: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) fail(`${a} requires a value`);
      return v;
    };
    switch (a) {
      case "-h":
      case "--help":
        console.log(HELP);
        process.exit(0);
      // eslint-disable-next-line no-fallthrough
      case "-v":
      case "--version":
        console.log(VERSION);
        process.exit(0);
      // eslint-disable-next-line no-fallthrough
      case "-f":
      case "--format": {
        const v = next();
        if (!["terminal", "markdown", "json", "sarif"].includes(v))
          fail(`unknown format: ${v}`);
        opts.format = v as typeof opts.format;
        break;
      }
      case "-o":
      case "--output":
        opts.output = next();
        break;
      case "--fail-on": {
        const v = next();
        if (!["critical", "high", "medium", "low", "none"].includes(v))
          fail(`unknown severity: ${v}`);
        opts.failOn = v as Severity | "none";
        break;
      }
      case "--only":
        opts.only = next().split(",").map((s) => s.trim().toUpperCase()).filter(Boolean);
        break;
      case "--skip":
        opts.skip = next().split(",").map((s) => s.trim().toUpperCase()).filter(Boolean);
        break;
      case "--frameworks": {
        const v = next().toLowerCase();
        if (!["asi", "llm", "euaia", "all"].includes(v)) fail(`unknown framework: ${v}`);
        opts.frameworks = v;
        break;
      }
      case "--max-file-size": {
        const n = Number(next());
        if (!Number.isFinite(n) || n <= 0) fail("--max-file-size must be a positive number");
        opts.maxFileSize = n;
        break;
      }
      default:
        if (a.startsWith("-")) fail(`unknown option: ${a}`);
        positional.push(a);
    }
  }
  if (positional.length > 1) fail("expected at most one path");
  if (positional.length === 1) opts.path = positional[0];
  return opts;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const root = resolve(opts.path);

  if (!existsSync(root) || !statSync(root).isDirectory()) {
    fail(`not a directory: ${root}`);
  }

  let rules = [
    ...(opts.frameworks === "all" || opts.frameworks === "asi" ? ASI_RULES : []),
    ...(opts.frameworks === "all" || opts.frameworks === "llm" ? LLM_RULES : []),
    ...(opts.frameworks === "all" || opts.frameworks === "euaia" ? EU_AI_ACT_RULES : []),
  ];
  if (opts.only.length) rules = rules.filter((r) => opts.only.includes(r.id));
  if (opts.skip.length) rules = rules.filter((r) => !opts.skip.includes(r.id));
  if (rules.length === 0) fail("no rules selected");

  const result = scan({
    root,
    include: DEFAULT_INCLUDE,
    exclude: DEFAULT_EXCLUDE,
    maxFileBytes: opts.maxFileSize,
    rules,
  });

  let out: string;
  switch (opts.format) {
    case "markdown":
      out = markdownReport(result, root);
      break;
    case "json":
      out = jsonReport(result);
      break;
    case "sarif":
      out = sarifReport(result);
      break;
    default:
      out = terminalReport(result);
  }

  if (opts.output) {
    writeFileSync(opts.output, out, "utf8");
    console.log(pc.green(`✓ wrote ${opts.output}`) + pc.dim(` (${result.findings.length} findings)`));
  } else {
    console.log(out);
  }

  if (opts.failOn === "none") process.exit(0);
  const counts = countBySeverity(result.findings);
  const threshold = SEVERITY_ORDER[opts.failOn];
  const breaching = (Object.keys(counts) as Severity[])
    .filter((s) => SEVERITY_ORDER[s] <= threshold)
    .reduce((n, s) => n + counts[s], 0);
  process.exit(breaching > 0 ? 1 : 0);
}

try {
  main();
} catch (err) {
  fail(err instanceof Error ? err.message : String(err));
}
