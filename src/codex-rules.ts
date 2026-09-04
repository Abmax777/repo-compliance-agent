/**
 * codex-rules.ts — pure rule logic.
 *
 * HARD CONSTRAINT: no imports from "cloudflare:*", no fetch, no DOM, no agents SDK.
 * Everything in here must be callable from a plain unit test with literal objects.
 * That constraint is the whole reason this file is separate — keep it.
 *
 * The types and the pattern table below are the CONTRACT. github.ts and agent.ts
 * are written against them, so change a type here and expect breakage there.
 * The function bodies are yours.
 */

// ---------------------------------------------------------------------------
// Contract types
// ---------------------------------------------------------------------------

export type RuleId =
  | "has_readme"
  | "has_license"
  | "has_codeowners"
  | "has_ci_config"
  | "no_hardcoded_secrets"
  | "has_tests_dir";

export const ALL_RULE_IDS: RuleId[] = [
  "has_readme",
  "has_license",
  "has_codeowners",
  "has_ci_config",
  "no_hardcoded_secrets",
  "has_tests_dir",
];

/** violation = we believe this is real. warning = matched, but a suppressor fired. */
export type Severity = "violation" | "warning";

export type SuppressReason = "placeholder" | "test_path" | "low_entropy";

/**
 * One blob in the repo tree.
 * `content` is populated ONLY for the files github.ts selected as scan candidates.
 * Structural rules (readme/license/...) see every path; the secret scan sees content.
 */
export interface RepoFile {
  /** POSIX, repo-root-relative, no leading slash. e.g. "src/index.ts", ".github/workflows/ci.yml" */
  path: string;
  /** bytes, from the git tree API */
  size: number;
  content?: string;
}

export interface SecretFinding {
  patternName: string;
  severity: Severity;
  path: string;
  /** 1-based */
  line: number;
  /** NEVER the raw match. Keep a short prefix, mask the rest. */
  redacted: string;
  suppressedBy?: SuppressReason;
}

export interface RuleResult {
  ruleId: RuleId;
  passed: boolean;
  title: string;
  /** One sentence a human reads. The LLM narrates from this — make it specific. */
  summary: string;
  /** Paths / "path:line" strings that justify the verdict. Keep it short. */
  evidence: string[];
  /** Only set by no_hardcoded_secrets. */
  findings?: SecretFinding[];
}

/** What we actually looked at. This goes in the report so the agent can be honest about coverage. */
export interface ScanScope {
  totalFiles: number;
  scannedFiles: number;
  skippedFiles: number;
  /** e.g. { vendored: 312, binary: 80, too_large: 20, not_source: 14 } */
  skipReasons: Record<string, number>;
  /** GitHub caps the recursive tree API; if true, we did not see every path. */
  treeTruncated: boolean;
  /**
   * Set when GITHUB_TOKEN was present but rejected, and the scan fell back to
   * unauthenticated requests (60 req/hr instead of 5,000). The scan still ran;
   * the report must say so rather than hide the degradation.
   */
  authFallback?: boolean;
}

export interface ComplianceReport {
  repo: string; // "owner/name"
  checkedAt: string; // ISO 8601
  passed: number;
  failed: number;
  results: RuleResult[];
  scope: ScanScope;
}

// ---------------------------------------------------------------------------
// Static rule metadata (config, not logic — wired up for you)
// ---------------------------------------------------------------------------

export const RULE_META: Record<RuleId, { title: string; rationale: string }> = {
  has_readme: {
    title: "Repository has a README",
    rationale:
      "Every repository must carry a root README.md so a newcomer can determine what the service does, who owns it, and how to run it without reading source.",
  },
  has_license: {
    title: "Repository declares a license",
    rationale:
      "A root LICENSE file is required for legal review. Absent an explicit license, the default is 'all rights reserved', which blocks internal reuse.",
  },
  has_codeowners: {
    title: "Repository defines CODEOWNERS",
    rationale:
      "CODEOWNERS routes review requests automatically and gives an auditable answer to 'who approves changes here'. Required for any repo in the production dependency graph.",
  },
  has_ci_config: {
    title: "Repository has continuous integration configured",
    rationale:
      "At least one GitHub Actions workflow must exist so that tests and policy checks run on every pull request rather than on a developer's laptop.",
  },
  no_hardcoded_secrets: {
    title: "No hardcoded credentials in source",
    rationale:
      "Credentials committed to source control must be treated as compromised. Secrets belong in a secret store and are injected at runtime.",
  },
  has_tests_dir: {
    title: "Repository has a test directory",
    rationale:
      "A conventional test directory (test/, tests/, or __tests__/) is the minimum signal that the code is exercised automatically.",
  },
};

// ---------------------------------------------------------------------------
// Secret patterns (config — tune freely, but keep them prefix-anchored)
// ---------------------------------------------------------------------------

/**
 * Deliberately high-precision. Every pattern here is anchored on a vendor prefix
 * with a known body length, so a match is strong evidence on its own.
 *
 * There is NO generic `(api_key|secret|token)\s*=\s*"..."` pattern, on purpose:
 * it fires on `API_KEY = "your-api-key-here"` in every README on GitHub, and a
 * false positive is worse than a miss when an LLM is going to narrate the result
 * to a human as fact.
 *
 * Note the `g` flag — if you reuse these across files, remember RegExp.lastIndex
 * is stateful on /g regexes. Either reset it or build fresh per call.
 */
export const SECRET_PATTERNS: { name: string; re: RegExp; keep: number }[] = [
  { name: "aws_access_key_id", re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b/g, keep: 4 },
  { name: "github_token", re: /\bgh[pousr]_[A-Za-z0-9]{36}\b/g, keep: 4 },
  { name: "github_fine_grained_pat", re: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g, keep: 11 },
  { name: "slack_token", re: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g, keep: 5 },
  { name: "stripe_key", re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b/g, keep: 8 },
  { name: "google_api_key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, keep: 4 },
  { name: "openai_key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/g, keep: 3 },
  { name: "private_key_header", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, keep: 40 },
  { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, keep: 6 },
];

/** Substrings that mean "this is documentation, not a credential". Case-insensitive. */
export const PLACEHOLDER_MARKERS = [
  "example", "xxxx", "placeholder", "your-", "your_", "dummy",
  "redacted", "changeme", "insert", "sample", "fake", "notreal", "todo",
];

/**
 * A hit under one of these path segments is a warning, not a violation.
 *
 * `testdata/` (Go convention) and `test_data/` (Python convention) need their own
 * entries: matching is `startsWith(marker) || includes("/" + marker)`, so the
 * "test/" entry does NOT cover them. Found by scanning gitleaks and trufflehog,
 * whose planted fixtures live in `testdata/` and were being reported as real
 * violations.
 */
export const TEST_PATH_MARKERS = [
  "test/", "tests/", "testdata/", "test_data/", "__tests__/",
  "fixtures/", "docs/", "examples/", "example/", "spec/",
];

/** Matches scoring below this are dropped as not-random-enough to be a real key. */
export const ENTROPY_FLOOR = 3.0;

// ---------------------------------------------------------------------------
// YOUR CODE STARTS HERE
// ---------------------------------------------------------------------------

/**
 * Shannon entropy in bits per character.
 *
 * STAGED HINT:
 *   1. Count occurrences of each character into a Map<string, number>.
 *   2. For each count c, let p = c / s.length.
 *   3. Sum -p * Math.log2(p).
 * Sanity checks for your test: entropy("aaaaaaaa") === 0,
 * entropy of a 40-char random base62 string lands around 5.
 * Guard s.length === 0 -> return 0.
 */
export function shannonEntropy(s: string): number {
  if(s.length == 0) return 0;
  const frequencies: { [key: string]: number} = {};

  for(let i = 0; i < s.length; i++){
    const char = s[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
    }

  let entropy = 0;
  const len = s.length;

  for(const char in frequencies){
    const probability = frequencies[char]/len;
    entropy -= probability * (Math.log(probability)/Math.log(2));
  }

  return entropy;
}

/**
 * Mask a matched secret for output. `keep` characters of prefix survive.
 * redactMatch("AKIAIOSFODNN7EXAMPLE", 4) -> "AKIA****************"
 *
 * This exists so no raw credential ever reaches the LLM context or the chat
 * transcript. Call it at the moment of matching, not later.
 */
export function redactMatch(match: string, keep: number): string {
  const visibleLength = Math.max(0, Math.min(keep, match.length));
  return `${match.slice(0, visibleLength)}${"*".repeat(
    match.length - visibleLength,
  )}`;
}

/**
 * Decide whether a match should be downgraded, and why.
 * Returns undefined when nothing suppresses it (-> severity "violation").
 *
 * STAGED HINT — check in this order, first hit wins:
 *   1. low_entropy  : shannonEntropy(match) < ENTROPY_FLOOR
 *   2. placeholder  : match.toLowerCase() contains any PLACEHOLDER_MARKERS entry
 *   3. test_path    : path.toLowerCase() starts with, or contains "/" + , any TEST_PATH_MARKERS entry
 *
 * EDGE CASE worth a test: "AKIAIOSFODNN7EXAMPLE" is AWS's own documentation key.
 * It should come back "placeholder". Make sure it does.
 */
export function classifySuppression(
  match: string, 
  path: string
  ): SuppressReason | undefined {
  if (shannonEntropy(match) < ENTROPY_FLOOR) {
    return "low_entropy";
  }

  const lowerMatch = match.toLowerCase();
  if (
    PLACEHOLDER_MARKERS.some((marker) =>
      lowerMatch.includes(marker),
    )
  ) {
    return "placeholder";
  }

  const lowerPath = path.toLowerCase();
  if (
    TEST_PATH_MARKERS.some(
      (marker) =>
        lowerPath.startsWith(marker) ||
        lowerPath.includes(`/${marker}`),
    )
  ) {
    return "test_path";
  }

  return undefined;
}

/**
 * Scan every file that has content for the patterns above.
 * Files without `content` are invisible to this function — that is correct,
 * github.ts already decided what was worth fetching.
 *
 * STAGED HINT:
 *   - Split content on /\r?\n/ once per file and scan line by line; you need the
 *     1-based line number for evidence, and per-line scanning sidesteps the
 *     /g lastIndex trap.
 *   - Build a fresh RegExp per pattern per call, or reset re.lastIndex = 0.
 *   - Dedupe: the same secret repeated on 40 lines should not produce 40 findings.
 *     Key on `${patternName}:${redacted}:${path}` and keep the first line.
 *   - Cap total findings (say 50) so a pathological file cannot blow up the report.
 */
export function scanForSecrets(files: RepoFile[]): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const seen = new Set<string>();
  const maxFindings = 50;

  for (const file of files) {
    if (file.content === undefined) continue;

    const lines = file.content.split(/\r?\n/);

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];

      for (const pattern of SECRET_PATTERNS) {
        // Create a fresh regex so its global /g lastIndex cannot leak
        // between lines or files.
        const regex = new RegExp(pattern.re.source, pattern.re.flags);
        let match: RegExpExecArray | null;

        while ((match = regex.exec(line)) !== null) {
          const rawMatch = match[0];
          const redacted = redactMatch(rawMatch, pattern.keep);
          const dedupeKey = `${pattern.name}:${redacted}:${file.path}`;

          if (seen.has(dedupeKey)) continue;
          seen.add(dedupeKey);

          const suppressedBy = classifySuppression(rawMatch, file.path);

          findings.push({
            patternName: pattern.name,
            severity: suppressedBy ? "warning" : "violation",
            path: file.path,
            line: lineIndex + 1,
            redacted,
            ...(suppressedBy ? { suppressedBy } : {}),
          });

          if (findings.length >= maxFindings) {
            return findings;
          }
        }
      }
    }
  }

  return findings;
}

// --- Structural rules -------------------------------------------------------
// Each takes the FULL file list (paths only is enough) and returns a RuleResult.
// Pull title from RULE_META[id].title. Write summaries a human would want to read:
// "No LICENSE file at the repository root" beats "has_license: false".

/** Root README.md. Case-insensitive on the name; must be at root (no "/" in path). */
export function checkHasReadme(files: RepoFile[]): RuleResult {
  // // TODO
  // throw new Error("not implemented");
  const readme = files.find(
    (file) => file.path.toLowerCase() === "readme.md",
  );

  return {
    ruleId: "has_readme",
    passed: readme !== undefined,
    title: RULE_META.has_readme.title,
    summary: readme
      ? `Root README found at ${readme.path}.`
      : "No README.md file at the repository root.",
    evidence: readme ? [readme.path] : [],
  };
}

/** LICENSE, LICENSE.md, or LICENSE.txt at root. Case-insensitive. */
export function checkHasLicense(files: RepoFile[]): RuleResult {
  // // TODO
  // throw new Error("not implemented");
  const allowedNames = new Set(["license", "license.md", "license.txt"]);

  const license = files.find((file) =>
    allowedNames.has(file.path.toLowerCase()),
  );

  return {
    ruleId: "has_license",
    passed: license !== undefined,
    title: RULE_META.has_license.title,
    summary: license
      ? `Root license found at ${license.path}.`
      : "No LICENSE, LICENSE.md, or LICENSE.txt file at the repository root.",
    evidence: license ? [license.path] : [],
  };
}

/** CODEOWNERS at root, in .github/, or in docs/. Exact name, uppercase by convention. */
export function checkHasCodeowners(files: RepoFile[]): RuleResult {
  // // TODO — .github/CODEOWNERS is by far the most common location
  // throw new Error("not implemented");
  const allowedPaths = new Set([
    "codeowners",
    ".github/codeowners",
    "docs/codeowners",
  ]);

  const codeowners = files.find((file) =>
    allowedPaths.has(file.path.toLowerCase()),
  );

  return {
    ruleId: "has_codeowners",
    passed: codeowners !== undefined,
    title: RULE_META.has_codeowners.title,
    summary: codeowners
      ? `CODEOWNERS found at ${codeowners.path}.`
      : "No CODEOWNERS file found at the root, .github/, or docs/.",
    evidence: codeowners ? [codeowners.path] : [],
  };
}

/** Any .github/workflows/*.yml or *.yaml. Evidence should list the workflow filenames. */
export function checkHasCiConfig(files: RepoFile[]): RuleResult {
  // // TODO
  // throw new Error("not implemented");
  const workflows = files
    .filter((file) =>
      /^\.github\/workflows\/[^/]+\.ya?ml$/i.test(file.path),
    )
    .map((file) => file.path);

  return {
    ruleId: "has_ci_config",
    passed: workflows.length > 0,
    title: RULE_META.has_ci_config.title,
    summary:
      workflows.length > 0
        ? `Found ${workflows.length} GitHub Actions workflow${
            workflows.length === 1 ? "" : "s"
          }.`
        : "No GitHub Actions workflow found in .github/workflows/.",
    evidence: workflows,
  };
}

/**
 * A test/, tests/, or __tests__/ directory anywhere in the tree.
 * The tree gives you blobs, not dirs — so infer from path segments.
 * CAREFUL: "src/latest/foo.ts" must not match "test". Split on "/" and compare
 * whole segments; do not use includes() on the raw path.
 */
export function checkHasTestsDir(files: RepoFile[]): RuleResult {
  // // TODO
  // throw new Error("not implemented");
  const testDirectoryNames = new Set(["test", "tests", "__tests__"]);

  const testFiles = files.filter((file) => {
    const directorySegments = file.path
      .toLowerCase()
      .split("/")
      .slice(0, -1);

    return directorySegments.some((segment) =>
      testDirectoryNames.has(segment),
    );
  });

  const evidence = testFiles.slice(0, 10).map((file) => file.path);

  return {
    ruleId: "has_tests_dir",
    passed: testFiles.length > 0,
    title: RULE_META.has_tests_dir.title,
    summary:
      testFiles.length > 0
        ? `Found test files under a conventional test directory.`
        : "No test/, tests/, or __tests__/ directory found.",
    evidence,
  };
}

/**
 * Wraps scanForSecrets into a RuleResult.
 *
 * PASS CONDITION: zero findings with severity "violation". Warnings do not fail
 * the rule, but they must still appear in `findings` so the agent can mention
 * them separately ("3 possible matches, all in test fixtures").
 */
export function checkNoHardcodedSecrets(files: RepoFile[]): RuleResult {
  // // TODO
  // throw new Error("not implemented");
  const findings = scanForSecrets(files);
  const violations = findings.filter(
    (finding) => finding.severity === "violation",
  );
  const warnings = findings.filter(
    (finding) => finding.severity === "warning",
  );

  const passed = violations.length === 0;

  return {
    ruleId: "no_hardcoded_secrets",
    passed,
    title: RULE_META.no_hardcoded_secrets.title,
    summary: !passed
      ? `Found ${violations.length} possible hardcoded credential${
          violations.length === 1 ? "" : "s"
        } in scanned files.`
      : warnings.length > 0
        ? `No hardcoded credentials found; ${warnings.length} possible match${
            warnings.length === 1 ? "" : "es"
          } was suppressed as a warning.`
        : "No hardcoded credentials found in scanned files.",
    evidence: findings
      .slice(0, 10)
      .map((finding) => `${finding.path}:${finding.line}`),
    findings,
  };
}

// --- Orchestration ----------------------------------------------------------

/**
 * Run every rule and assemble the report.
 * Keep results in ALL_RULE_IDS order so output is stable across runs —
 * the chat UI and your tests both benefit.
 */
export function runAllRules(
  repo: string,
  files: RepoFile[],
  scope: ScanScope,
): ComplianceReport {
  const results = [
    checkHasReadme(files),
    checkHasLicense(files),
    checkHasCodeowners(files),
    checkHasCiConfig(files),
    checkNoHardcodedSecrets(files),
    checkHasTestsDir(files),
  ];

  const passed = results.filter((result) => result.passed).length;

  return {
    repo,
    checkedAt: new Date().toISOString(),
    passed,
    failed: results.length - passed,
    results,
    scope,
  };
}

/**
 * Used by the explain_rule tool. Returns undefined for an unknown id so the
 * agent can say "no such rule" instead of throwing inside a tool call.
 */
export function explainRule(
  ruleId: string,
): { ruleId: RuleId; title: string; rationale: string } | undefined {
  if (!ALL_RULE_IDS.includes(ruleId as RuleId)) {
    return undefined;
  }

  const id = ruleId as RuleId;
  const meta = RULE_META[id];

  return {
    ruleId: id,
    title: meta.title,
    rationale: meta.rationale,
  };
}