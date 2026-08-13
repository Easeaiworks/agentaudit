import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  audit,
  ASI_RULES,
  LLM_RULES,
  EU_AI_ACT_RULES,
  markdownReport,
  jsonReport,
  sarifReport,
  countBySeverity,
} from "../dist/index.js";
import { stripComments } from "../dist/scanner.js";

const here = dirname(fileURLToPath(import.meta.url));
const VULN = join(here, "fixtures/vulnerable-agent");
const SECURE = join(here, "fixtures/secure-agent");

test("detects findings in the vulnerable fixture", () => {
  const r = audit({ root: VULN });
  assert.ok(r.findings.length >= 20, `expected >=20 findings, got ${r.findings.length}`);
  const counts = countBySeverity(r.findings);
  assert.ok(counts.critical >= 8, `expected >=8 critical, got ${counts.critical}`);
});

test("vulnerable fixture triggers the specific rules it was written for", () => {
  const r = audit({ root: VULN });
  const ids = new Set(r.findings.map((f) => f.rule.id));
  for (const id of ["ASI01", "ASI02", "ASI03", "ASI05", "ASI06", "ASI10", "LLM10"]) {
    assert.ok(ids.has(id), `expected ${id} to fire on the vulnerable fixture`);
  }
});

test("secure fixture is clean (false-positive control)", () => {
  const r = audit({ root: SECURE });
  assert.equal(
    r.findings.length,
    0,
    `expected 0 findings, got ${r.findings.length}: ` +
      r.findings.map((f) => `${f.rule.id}@${f.file}:${f.line}`).join(", "),
  );
});

test("secure fixture registers satisfied controls", () => {
  const r = audit({ root: SECURE });
  assert.ok(r.controlsSatisfied.length >= 3, "expected several controls recognised");
});

// This is the regression test for the bug that mattered most: a comment
// mentioning a mitigation must never count as evidence the mitigation exists.
test("comments do not satisfy control probes", () => {
  const src = `// TODO: add sandbox and docker isolation here
const x = 1; /* we should use a sandbox */`;
  const stripped = stripComments(src, "a.ts");
  assert.ok(!/sandbox/.test(stripped), "comment text must be stripped");
  assert.ok(!/docker/.test(stripped), "comment text must be stripped");
  assert.ok(/const x = 1;/.test(stripped), "code must survive");
});

test("string literals survive comment stripping", () => {
  const src = `const u = "http://example.com/a//b"; // trailing`;
  const stripped = stripComments(src, "a.ts");
  assert.ok(stripped.includes('"http://example.com/a//b"'), "URL must survive");
  assert.ok(!/trailing/.test(stripped), "trailing comment must go");
});

test("hash-style comments are stripped for python/yaml", () => {
  const src = `key: value  # use a sandbox\nother: 1`;
  const stripped = stripComments(src, "conf.yaml");
  assert.ok(!/sandbox/.test(stripped));
  assert.ok(/other: 1/.test(stripped));
});

test("comment stripping preserves file length and line count", () => {
  const src = `a\n// comment\nb\n/* block\nmore */\nc`;
  const stripped = stripComments(src, "a.ts");
  assert.equal(stripped.length, src.length, "offsets must be preserved");
  assert.equal(stripped.split("\n").length, src.split("\n").length);
});

test("all rules have required metadata", () => {
  for (const rule of [...ASI_RULES, ...LLM_RULES, ...EU_AI_ACT_RULES]) {
    assert.ok(rule.id, "rule needs id");
    assert.ok(rule.title, `${rule.id} needs title`);
    assert.ok(rule.description.length > 40, `${rule.id} needs a real description`);
    assert.ok(rule.remediation.length > 40, `${rule.id} needs real remediation`);
    assert.ok(rule.references.length > 0, `${rule.id} needs references`);
    assert.ok(rule.probes.length > 0, `${rule.id} needs probes`);
  }
});

test("rule ids are unique", () => {
  const all = [...ASI_RULES, ...LLM_RULES, ...EU_AI_ACT_RULES].map((r) => r.id);
  assert.equal(new Set(all).size, all.length, "duplicate rule id");
});

test("ASI01-ASI10 are all present", () => {
  const ids = ASI_RULES.map((r) => r.id).sort();
  assert.deepEqual(ids, [
    "ASI01","ASI02","ASI03","ASI04","ASI05",
    "ASI06","ASI07","ASI08","ASI09","ASI10",
  ]);
});

test("reporters produce valid output", () => {
  const r = audit({ root: VULN });

  const md = markdownReport(r, VULN);
  assert.ok(md.startsWith("# Agentic AI Security Audit"));
  assert.ok(md.includes("## Findings"));
  assert.ok(md.includes("Scope and limitations"), "must disclose limitations");

  const json = JSON.parse(jsonReport(r));
  assert.equal(json.findings.length, r.findings.length);
  assert.ok(json.summary.total > 0);

  const sarif = JSON.parse(sarifReport(r));
  assert.equal(sarif.version, "2.1.0");
  assert.ok(sarif.runs[0].tool.driver.rules.length > 0);
  assert.equal(sarif.runs[0].results.length, r.findings.length);
  for (const res of sarif.runs[0].results) {
    assert.ok(["error", "warning", "note"].includes(res.level));
    const region = res.locations[0].physicalLocation.region;
    assert.ok(region.startLine >= 1, "SARIF startLine must be >= 1");
    assert.ok(region.startColumn >= 1, "SARIF startColumn must be >= 1");
  }
});

test("rule filtering works", () => {
  const r = audit({ root: VULN, rules: ASI_RULES.filter((x) => x.id === "ASI05") });
  assert.ok(r.findings.every((f) => f.rule.id === "ASI05"));
});

test("scanning an empty directory is safe", () => {
  const r = audit({ root: join(here, "fixtures") , rules: [] });
  assert.equal(r.findings.length, 0);
});

// Regression: the FAQ claims multi-language support. These assert it is real
// rather than aspirational — C# and Go originally matched only ASI03.
test("detects risks in Python, C#, and Go agent code", () => {
  const r = audit({ root: join(here, "fixtures/polyglot-agent") });
  const byFile = (ext) => new Set(
    r.findings.filter((f) => f.file.endsWith(ext)).map((f) => f.rule.id),
  );

  for (const [ext, expected] of [
    [".py", ["ASI01", "ASI03", "ASI05"]],
    [".cs", ["ASI01", "ASI03", "ASI05"]],
    [".go", ["ASI01", "ASI03", "ASI05"]],
  ]) {
    const ids = byFile(ext);
    for (const id of expected) {
      assert.ok(ids.has(id), `expected ${id} to fire in ${ext} (got: ${[...ids].join(",")})`);
    }
  }
});

// Regression: exclusions must match paths RELATIVE to the scan root.
// Matching absolute paths meant a repo living under any directory named
// build/, docs/, or fixtures/ scanned zero files and reported clean — a
// silent false-negative, the worst failure mode for a security scanner.
test("exclusions do not match the scan root's own ancestor directories", () => {
  // VULN itself lives under .../test/fixtures/vulnerable-agent, and
  // "fixtures" is in DEFAULT_EXCLUDE. It must still scan.
  const r = audit({ root: VULN });
  assert.ok(
    r.filesScanned > 0,
    "scan root under an excluded-looking ancestor must still be scanned",
  );
  assert.ok(r.findings.length > 0, "findings must still be produced");
});
