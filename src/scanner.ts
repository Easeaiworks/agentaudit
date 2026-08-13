/**
 * The scan engine.
 *
 * Two passes:
 *   1. Walk the tree once, reading every candidate file into memory (bounded),
 *      and evaluate all `presence` probes line by line.
 *   2. Evaluate `control` probes against the corpus as a whole -- a control
 *      counts as satisfied if evidence appears anywhere in the project, since
 *      mitigations legitimately live in middleware, config, or a shared module
 *      rather than next to the risky call.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import type { Finding, Rule, ScanOptions, ScanResult } from "./types.js";

export const DEFAULT_INCLUDE =
  /\.(?:ts|tsx|js|jsx|mjs|cjs|py|rb|go|rs|java|cs|php|json|ya?ml|toml|env\.example|sh|Dockerfile)$/i;

/**
 * Directories excluded by default.
 *
 * Recorded HTTP fixtures (VCR cassettes), snapshots, and test data are the
 * single largest source of noise when scanning real repositories: they contain
 * arbitrary third-party prose and payloads that trip content-shaped rules
 * without representing anything the application actually does. They are not
 * production code paths, so they are out of scope.
 */
export const DEFAULT_EXCLUDE =
  /(?:^|[\\/])(?:node_modules|\.git|dist|build|out|\.next|\.nuxt|coverage|vendor|__pycache__|\.venv|venv|target|bin|obj|\.turbo|\.cache|cassettes|__snapshots__|snapshots|fixtures|testdata|test_data|__mocks__|\.pytest_cache|docs|examples?|tests?|spec|__tests__)(?:[\\/]|$)/;

interface LoadedFile {
  path: string;
  rel: string;
  lines: string[];
  text: string;
  /** `text` with comments blanked out. Control probes run against this. */
  code: string;
}

/**
 * Blank out comments while preserving offsets and string literals.
 *
 * This matters more than it looks. Control probes ask "does evidence of the
 * mitigation appear anywhere in the project?" -- and a comment reading
 * "TODO: add sandboxing" or "no approval gate here yet" would otherwise count
 * as evidence that the control exists. That turns the scanner into a machine
 * that reassures you precisely when someone has written down that they are
 * worried. For a security tool, a false "mitigated" is the worst possible
 * output, so comments are excluded from control evidence entirely.
 *
 * String literals are preserved: `"http://x"` must not lose its `//`.
 */
export function stripComments(src: string, rel: string): string {
  const hashStyle = /\.(?:py|rb|sh|ya?ml|toml)$|Dockerfile/i.test(rel);
  const out = src.split("");
  let i = 0;
  const n = src.length;

  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];

    // String literals -- skip over, honouring backslash escapes.
    if (c === '"' || c === "'" || c === "`") {
      const quote = c;
      i++;
      while (i < n) {
        if (src[i] === "\\") {
          i += 2;
          continue;
        }
        if (src[i] === quote) {
          i++;
          break;
        }
        if (quote !== "`" && src[i] === "\n") break; // unterminated
        i++;
      }
      continue;
    }

    // Line comment
    if ((!hashStyle && c === "/" && c2 === "/") || (hashStyle && c === "#")) {
      while (i < n && src[i] !== "\n") {
        out[i] = " ";
        i++;
      }
      continue;
    }

    // Block comment
    if (!hashStyle && c === "/" && c2 === "*") {
      while (i < n && !(src[i] === "*" && src[i + 1] === "/")) {
        if (src[i] !== "\n") out[i] = " ";
        i++;
      }
      if (i < n) {
        out[i] = " ";
        out[i + 1] = " ";
        i += 2;
      }
      continue;
    }

    i++;
  }

  return out.join("");
}

function walk(
  dir: string,
  opts: ScanOptions,
  acc: string[],
  depth = 0,
): string[] {
  if (depth > 24) return acc;
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return acc;
  }
  for (const entry of entries) {
    const full = join(dir, entry);
    // Exclusions are matched against the path RELATIVE to the scan root.
    // Matching the absolute path means a repo that happens to live under
    // ~/build/ or ~/docs/ scans zero files and reports a clean bill of health,
    // which is the most dangerous possible failure for a security tool.
    const relPath = relative(opts.root, full).split(sep).join("/");
    if (opts.exclude.test("/" + relPath)) continue;
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      walk(full, opts, acc, depth + 1);
    } else if (st.isFile()) {
      // Dockerfile and similar have no extension; match on basename too.
      if (opts.include.test(entry) || opts.include.test(full)) {
        if (st.size <= opts.maxFileBytes) acc.push(full);
      }
    }
  }
  return acc;
}

/** Reset lastIndex so a /g regex reused across files behaves deterministically. */
function test(re: RegExp, s: string): boolean {
  if (re.global || re.sticky) re.lastIndex = 0;
  return re.test(s);
}

function findColumn(re: RegExp, line: string): number {
  if (re.global || re.sticky) re.lastIndex = 0;
  const m = re.exec(line);
  return m ? m.index + 1 : 1;
}

export function scan(opts: ScanOptions): ScanResult {
  const started = Date.now();
  const paths = walk(opts.root, opts, []);
  const files: LoadedFile[] = [];
  let bytesScanned = 0;

  for (const p of paths) {
    let text: string;
    try {
      text = readFileSync(p, "utf8");
    } catch {
      continue;
    }
    // Skip minified or generated blobs: they produce noise, not signal.
    if (text.length > 2000 && text.split("\n").length < text.length / 500) continue;
    bytesScanned += text.length;
    const rel = relative(opts.root, p).split(sep).join("/");
    files.push({
      path: p,
      rel,
      lines: text.split(/\r?\n/),
      text,
      code: stripComments(text, rel),
    });
  }

  const findings: Finding[] = [];
  const controlsSatisfied: string[] = [];

  // Corpus used for control-probe evaluation. Comment-stripped: see stripComments.
  const corpus = files.map((f) => f.code).join("\n");

  for (const rule of opts.rules) {
    for (const probe of rule.probes) {
      if (probe.kind === "presence") {
        for (const f of files) {
          if (probe.files && !probe.files.test(f.rel)) continue;
          for (let i = 0; i < f.lines.length; i++) {
            const line = f.lines[i];
            if (!line || line.length > 1000) continue;
            if (!test(probe.match, line)) continue;
            if (probe.unless && test(probe.unless, line)) continue;
            // Skip obvious comment-only lines to cut noise.
            const trimmed = line.trim();
            if (/^(?:\/\/|#|\*|<!--)/.test(trimmed) && !/\.(?:json|ya?ml)$/i.test(f.rel)) {
              continue;
            }
            findings.push({
              rule,
              file: f.rel,
              line: i + 1,
              column: findColumn(probe.match, line),
              excerpt: trimmed.slice(0, 200),
              message: probe.message,
              probeKind: "presence",
            });
          }
        }
      } else {
        // control probe
        const scopedFiles = probe.files
          ? files.filter((f) => probe.files!.test(f.rel))
          : files;
        const scopedCorpus = probe.files
          ? scopedFiles.map((f) => f.code).join("\n")
          : corpus;

        if (!test(probe.trigger, scopedCorpus)) continue; // behaviour not present -> rule N/A

        if (test(probe.control, corpus)) {
          if (!controlsSatisfied.includes(rule.id)) controlsSatisfied.push(rule.id);
          continue; // mitigated somewhere -> stay quiet
        }

        // Report at the first place the trigger appears, so the finding is actionable.
        let located = false;
        for (const f of scopedFiles) {
          // Locate against comment-stripped lines so a comment mentioning the
          // trigger does not become the reported location.
          const codeLines = f.code.split(/\r?\n/);
          for (let i = 0; i < codeLines.length; i++) {
            const line = codeLines[i];
            if (!line || !test(probe.trigger, line)) continue;
            findings.push({
              rule,
              file: f.rel,
              line: i + 1,
              column: findColumn(probe.trigger, line),
              // Show the original source line, not the comment-stripped one.
              excerpt: (f.lines[i] ?? line).trim().slice(0, 200),
              message: probe.message,
              probeKind: "control",
            });
            located = true;
            break;
          }
          if (located) break;
        }
        if (!located) {
          findings.push({
            rule,
            file: "(project)",
            line: 0,
            column: 0,
            excerpt: "",
            message: probe.message,
            probeKind: "control",
          });
        }
      }
    }
  }

  return {
    findings,
    filesScanned: files.length,
    bytesScanned,
    durationMs: Date.now() - started,
    controlsSatisfied,
    rulesEvaluated: opts.rules.length,
  };
}
