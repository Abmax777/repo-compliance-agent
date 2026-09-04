import type { RepoFile, ScanScope } from "../src/codex-rules";

const f = (path: string, size = 100, content?: string): RepoFile => ({ path, size, content });

/** A repo that satisfies every rule. */
export const COMPLIANT_REPO: RepoFile[] = [
  f("README.md", 2000, "# Service\nDoes a thing.\n"),
  f("LICENSE", 1100, "MIT License\n"),
  f(".github/CODEOWNERS", 60, "* @platform-team\n"),
  f(".github/workflows/ci.yml", 800, "name: CI\non: [push]\n"),
  f("src/index.ts", 1500, "export const key = process.env.API_KEY;\n"),
  f("tests/index.test.ts", 900, "import { it } from 'vitest';\n"),
];

/** Missing license, codeowners, CI and tests. */
export const BARE_REPO: RepoFile[] = [
  f("README.md", 300, "# scratch\n"),
  f("main.py", 400, "print('hello')\n"),
];

/** Nothing at all — every structural rule should fail without throwing. */
export const EMPTY_REPO: RepoFile[] = [];

/** README.md exists but only in a subdirectory — must NOT satisfy has_readme. */
export const NESTED_README_REPO: RepoFile[] = [
  f("docs/README.md", 500, "# docs\n"),
  f("src/app.ts", 200, "export {};\n"),
];

/**
 * "latest" contains the substring "test" but is not a test directory.
 * If checkHasTestsDir uses includes() instead of segment comparison, this passes
 * when it should fail. That is the bug this fixture exists to catch.
 */
export const FALSE_TEST_DIR_REPO: RepoFile[] = [
  f("README.md", 100, "# x\n"),
  f("src/latest/handler.ts", 300, "export {};\n"),
  f("contest/solution.py", 300, "pass\n"),
];

/** One real-looking AWS key in production source. Should be a violation. */
export const LEAKY_REPO: RepoFile[] = [
  f("README.md", 100, "# leaky\n"),
  f(
    "src/config.js",
    400,
    [
      "const region = 'us-east-1';",
      "const accessKeyId = 'AKIA7QF3JZ2XN8VLKD4M';",
      "module.exports = { region, accessKeyId };",
    ].join("\n"),
  ),
];

/**
 * Every hit here should be suppressed to a warning, so the rule still PASSES:
 *   - AWS's own documentation key (placeholder marker "EXAMPLE")
 *   - a real-shaped key living under tests/ (test_path)
 *   - a low-entropy string that matches the shape but cannot be a key
 */
export const NOISY_REPO: RepoFile[] = [
  f("README.md", 200, "Set AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE before running.\n"),
  f("tests/fixtures/aws.js", 300, "const k = 'AKIA7QF3JZ2XN8VLKD4M';\n"),
  f("src/placeholder.ts", 200, "const token = 'AKIAAAAAAAAAAAAAAAAA';\n"),
];

/** Content-free file list: the secret scan must simply ignore these. */
export const NO_CONTENT_REPO: RepoFile[] = [
  { path: "README.md", size: 100 },
  { path: "src/index.ts", size: 4000 },
];

export const DUMMY_SCOPE: ScanScope = {
  totalFiles: 6,
  scannedFiles: 6,
  skippedFiles: 0,
  skipReasons: {},
  treeTruncated: false,
};

/**
 * Taken from the real root of sindresorhus/got, which is all lowercase and has
 * an extensionless license file. Every structural rule must be case-insensitive
 * or this repo reads as non-compliant when it is not.
 */
export const LOWERCASE_REPO: RepoFile[] = [
  f("readme.md", 9000, "# got\n"),
  f("license", 1100, "MIT\n"),
  f(".github/workflows/main.yml", 900, "name: CI\n"),
  f("test/create.ts", 800, "export {};\n"),
  f("package.json", 2000, '{"name":"got"}\n'),
];
