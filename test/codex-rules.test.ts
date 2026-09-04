/**
 * Red-green loop for codex-rules.ts. Every test here fails right now because the
 * bodies throw "not implemented" — that is the point. Work down the file.
 *
 *   npx vitest run test/codex-rules.test.ts
 */
import { describe, it, expect } from "vitest";
import {
  shannonEntropy,
  redactMatch,
  classifySuppression,
  scanForSecrets,
  checkHasReadme,
  checkHasLicense,
  checkHasCodeowners,
  checkHasCiConfig,
  checkHasTestsDir,
  checkNoHardcodedSecrets,
  runAllRules,
  explainRule,
  ALL_RULE_IDS,
} from "../src/codex-rules";
import {
  COMPLIANT_REPO,
  BARE_REPO,
  EMPTY_REPO,
  NESTED_README_REPO,
  FALSE_TEST_DIR_REPO,
  LEAKY_REPO,
  NOISY_REPO,
  NO_CONTENT_REPO,
  LOWERCASE_REPO,
  DUMMY_SCOPE,
} from "./fixtures";

describe("shannonEntropy", () => {
  it("is zero for a single repeated character", () => {
    expect(shannonEntropy("aaaaaaaa")).toBe(0);
  });
  it("is 1 bit for an even two-symbol split", () => {
    expect(shannonEntropy("abab")).toBeCloseTo(1, 6);
  });
  it("is high for a random-looking key body", () => {
    expect(shannonEntropy("7QF3JZ2XN8VLKD4M")).toBeGreaterThan(3);
  });
  it("handles the empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });
});

describe("redactMatch", () => {
  it("keeps the prefix and masks the rest", () => {
    expect(redactMatch("AKIAIOSFODNN7EXAMPLE", 4)).toBe("AKIA****************");
  });
  it("never returns the raw value", () => {
    const raw = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    expect(redactMatch(raw, 4)).not.toBe(raw);
  });
});

describe("classifySuppression", () => {
  it("flags AWS's documentation key as a placeholder", () => {
    expect(classifySuppression("AKIAIOSFODNN7EXAMPLE", "README.md")).toBe("placeholder");
  });
  it("flags a real-shaped key under tests/ as a test path", () => {
    expect(classifySuppression("AKIA7QF3JZ2XN8VLKD4M", "tests/fixtures/aws.js")).toBe("test_path");
  });
  it("flags a low-entropy match", () => {
    expect(classifySuppression("AKIAAAAAAAAAAAAAAAAA", "src/x.ts")).toBe("low_entropy");
  });
  it("treats Go's testdata/ and Python's test_data/ as test paths", () => {
    // Regression: both conventions were reported as real violations when
    // scanning gitleaks and trufflehog, because "test/" does not prefix-match
    // "testdata/".
    expect(classifySuppression("AKIA7QF3JZ2XN8VLKD4M", "testdata/secrets.txt")).toBe("test_path");
    expect(classifySuppression("AKIA7QF3JZ2XN8VLKD4M", "pkg/engine/testdata/secrets.txt")).toBe("test_path");
    expect(classifySuppression("AKIA7QF3JZ2XN8VLKD4M", "test_data/config.yaml")).toBe("test_path");
  });

  it("suppresses nothing for a plausible key in production source", () => {
    expect(classifySuppression("AKIA7QF3JZ2XN8VLKD4M", "src/config.js")).toBeUndefined();
  });
});

describe("scanForSecrets", () => {
  it("finds the AWS key in production source and marks it a violation", () => {
    const findings = scanForSecrets(LEAKY_REPO);
    expect(findings).toHaveLength(1);
    expect(findings[0].patternName).toBe("aws_access_key_id");
    expect(findings[0].severity).toBe("violation");
    expect(findings[0].path).toBe("src/config.js");
    expect(findings[0].line).toBe(2);
  });
  it("never leaks the raw secret into a finding", () => {
    const findings = scanForSecrets(LEAKY_REPO);
    expect(JSON.stringify(findings)).not.toContain("AKIA7QF3JZ2XN8VLKD4M");
  });
  it("downgrades every noisy match to a warning", () => {
    const findings = scanForSecrets(NOISY_REPO);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.severity === "warning")).toBe(true);
  });
  it("ignores files with no content", () => {
    expect(scanForSecrets(NO_CONTENT_REPO)).toEqual([]);
  });
});

describe("structural rules", () => {
  it("passes everything on a compliant repo", () => {
    expect(checkHasReadme(COMPLIANT_REPO).passed).toBe(true);
    expect(checkHasLicense(COMPLIANT_REPO).passed).toBe(true);
    expect(checkHasCodeowners(COMPLIANT_REPO).passed).toBe(true);
    expect(checkHasCiConfig(COMPLIANT_REPO).passed).toBe(true);
    expect(checkHasTestsDir(COMPLIANT_REPO).passed).toBe(true);
  });

  it("fails the four missing rules on a bare repo", () => {
    expect(checkHasReadme(BARE_REPO).passed).toBe(true);
    expect(checkHasLicense(BARE_REPO).passed).toBe(false);
    expect(checkHasCodeowners(BARE_REPO).passed).toBe(false);
    expect(checkHasCiConfig(BARE_REPO).passed).toBe(false);
    expect(checkHasTestsDir(BARE_REPO).passed).toBe(false);
  });

  it("does not count a README outside the root", () => {
    expect(checkHasReadme(NESTED_README_REPO).passed).toBe(false);
  });

  it("does not mistake 'latest' or 'contest' for a test directory", () => {
    expect(checkHasTestsDir(FALSE_TEST_DIR_REPO).passed).toBe(false);
  });

  it("survives an empty repo without throwing", () => {
    for (const check of [checkHasReadme, checkHasLicense, checkHasCodeowners, checkHasCiConfig, checkHasTestsDir]) {
      expect(check(EMPTY_REPO).passed).toBe(false);
    }
  });

  it("matches lowercase readme/license, as most real repos use", () => {
    expect(checkHasReadme(LOWERCASE_REPO).passed).toBe(true);
    expect(checkHasLicense(LOWERCASE_REPO).passed).toBe(true);
    expect(checkHasTestsDir(LOWERCASE_REPO).passed).toBe(true);
  });

  it("cites evidence when a rule passes", () => {
    expect(checkHasCiConfig(COMPLIANT_REPO).evidence).toContain(".github/workflows/ci.yml");
  });
});

describe("checkNoHardcodedSecrets", () => {
  it("fails when there is a violation", () => {
    expect(checkNoHardcodedSecrets(LEAKY_REPO).passed).toBe(false);
  });
  it("passes on warnings alone, but still reports them", () => {
    const result = checkNoHardcodedSecrets(NOISY_REPO);
    expect(result.passed).toBe(true);
    expect(result.findings?.length).toBeGreaterThan(0);
  });
});

describe("runAllRules", () => {
  it("returns every rule in a stable order", () => {
    const report = runAllRules("acme/widget", COMPLIANT_REPO, DUMMY_SCOPE);
    expect(report.results.map((r) => r.ruleId)).toEqual(ALL_RULE_IDS);
  });
  it("counts passes and failures consistently", () => {
    const report = runAllRules("acme/widget", BARE_REPO, DUMMY_SCOPE);
    expect(report.passed + report.failed).toBe(ALL_RULE_IDS.length);
    expect(report.failed).toBe(4);
  });
  it("carries the scan scope through so the agent can report coverage", () => {
    const report = runAllRules("acme/widget", COMPLIANT_REPO, DUMMY_SCOPE);
    expect(report.scope.scannedFiles).toBe(6);
  });
});

describe("explainRule", () => {
  it("returns metadata for a known rule", () => {
    expect(explainRule("has_codeowners")?.title).toBeTruthy();
  });
  it("returns undefined for an unknown rule instead of throwing", () => {
    expect(explainRule("has_vibes")).toBeUndefined();
  });
});
