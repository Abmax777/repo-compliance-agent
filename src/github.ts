/**
 * github.ts — fetch a public repo's tree and selectively pull file contents.
 *
 * Two-phase by design:
 *   1. ONE call to the recursive git-tree API gives every path + size + blob sha.
 *      That is enough to answer all five structural rules for free.
 *   2. Only then do we spend requests fetching content, and only for files that
 *      could plausibly hold a credential.
 *
 * Content is pulled from raw.githubusercontent.com rather than the REST blobs
 * API: raw does not consume the 5000/hr REST quota. The candidate cap is
 * therefore about LATENCY and the Workers subrequest budget, not rate limits —
 * a Worker on the free plan is capped at 50 subrequests per request (1000 on
 * paid), so 40 candidates + 2 API calls deliberately sits just under it.
 * Verify the current limit for your plan before raising DEFAULT_MAX_CANDIDATES.
 */

import type { RepoFile, ScanScope } from "./codex-rules";

const GITHUB_API = "https://api.github.com";
const RAW_BASE = "https://raw.githubusercontent.com";

const DEFAULT_MAX_CANDIDATES = 40;
const DEFAULT_MAX_FILE_BYTES = 200_000;
const FETCH_CONCURRENCY = 8;

export interface FetchRepoOptions {
  /** GitHub PAT. Strongly recommended: unauthenticated is 60 req/hr. */
  token?: string;
  maxCandidates?: number;
  maxFileBytes?: number;
}

export interface FetchRepoResult {
  files: RepoFile[];
  scope: ScanScope;
  /** Commit sha the tree was read at — pin raw fetches to this, not to a branch name. */
  commitSha: string;
  defaultBranch: string;
}

export class GitHubError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly kind: "not_found" | "rate_limited" | "network" | "other" = "other",
  ) {
    super(message);
    this.name = "GitHubError";
  }
}

// --- selection policy -------------------------------------------------------

/** Directory segments that are never worth scanning. */
const SKIP_DIR_SEGMENTS = new Set([
  "node_modules", "vendor", "dist", "build", "out", "target",
  ".git", ".next", ".nuxt", ".venv", "venv", "__pycache__",
  "site-packages", "bower_components", "coverage", ".terraform",
]);

const SKIP_EXACT_NAMES = new Set([
  "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb",
  "Cargo.lock", "poetry.lock", "Gemfile.lock", "composer.lock", "go.sum",
]);

const BINARY_EXTS = new Set([
  "png","jpg","jpeg","gif","webp","ico","svg","bmp","tiff","pdf",
  "zip","gz","tar","tgz","bz2","xz","7z","rar",
  "woff","woff2","ttf","otf","eot",
  "mp3","mp4","mov","avi","webm","wav","ogg",
  "so","dylib","dll","exe","bin","o","a","class","jar","wasm",
  "db","sqlite","pyc","pack","idx",
]);

/** Extensions worth reading for credentials. */
const SOURCE_EXTS = new Set([
  "js","jsx","ts","tsx","mjs","cjs","py","rb","go","java","kt","kts",
  "php","cs","rs","swift","scala","sh","bash","zsh","ps1","pl","lua","r",
  "yml","yaml","json","toml","ini","cfg","conf","properties","env",
  "tf","tfvars","tpl","gradle","xml","md","txt","sql",
]);

/** Higher score = read first. Config and IaC leak far more often than source. */
function candidateScore(path: string): number {
  const lower = path.toLowerCase();
  const name = lower.split("/").pop() ?? "";
  let score = 0;

  if (name.startsWith(".env")) score += 100;
  if (/\.(tf|tfvars)$/.test(name)) score += 80;
  if (/^(docker-compose|compose)\..*(yml|yaml)$/.test(name)) score += 70;
  if (/(^|\.)(config|settings|secrets|credentials)(\.|$)/.test(name)) score += 60;
  if (/\.(properties|ini|cfg|conf|toml)$/.test(name)) score += 50;
  if (lower.startsWith(".github/workflows/")) score += 45;
  if (/\.(ya?ml|json)$/.test(name)) score += 30;
  if (/\.(sh|bash|zsh|ps1)$/.test(name)) score += 25;
  if (/\.(js|ts|py|go|rb|java|php|rs)$/.test(name)) score += 20;

  // Shallow files are likelier to be real config than deeply nested ones.
  score -= Math.min(path.split("/").length - 1, 6) * 2;

  // Tests and docs still get scanned, just last — findings there become warnings.
  if (/(^|\/)(test|tests|__tests__|spec|fixtures|docs|examples?)(\/)/.test(lower)) score -= 15;

  return score;
}

type SkipReason = "vendored" | "lockfile" | "binary" | "too_large" | "not_source";

function skipReasonFor(path: string, size: number, maxFileBytes: number): SkipReason | null {
  const segments = path.split("/");
  for (const seg of segments.slice(0, -1)) {
    if (SKIP_DIR_SEGMENTS.has(seg)) return "vendored";
  }
  const name = segments[segments.length - 1] ?? "";
  if (SKIP_EXACT_NAMES.has(name)) return "lockfile";
  if (/\.min\.(js|css)$/.test(name) || name.endsWith(".map")) return "vendored";

  const dot = name.lastIndexOf(".");
  const ext = dot > 0 ? name.slice(dot + 1).toLowerCase() : "";
  if (BINARY_EXTS.has(ext)) return "binary";
  if (size > maxFileBytes) return "too_large";

  // Extensionless files (Dockerfile, Makefile, CODEOWNERS) are worth a look.
  if (ext === "" && !/^(dockerfile|makefile|procfile|codeowners|jenkinsfile)$/i.test(name)) {
    return "not_source";
  }
  if (ext !== "" && !SOURCE_EXTS.has(ext)) return "not_source";

  return null;
}

// --- HTTP -------------------------------------------------------------------

/**
 * Secrets arrive via `wrangler secret put`, a CLI prompt, so they routinely pick
 * up a trailing newline or the surrounding quotes from a copied `KEY="value"`
 * line. GitHub answers `Bearer "ghp_..."` with a flat 401 and no explanation,
 * which is a miserable thing to debug. Normalize defensively.
 */
export function normalizeToken(token?: string): string | undefined {
  if (!token) return undefined;
  const cleaned = token.trim().replace(/^["']|["']$/g, "").trim();
  return cleaned.length > 0 ? cleaned : undefined;
}

function apiHeaders(token?: string): Record<string, string> {
  const h: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    // GitHub rejects requests without a User-Agent.
    "User-Agent": "codex-compliance-agent",
  };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

async function ghJson<T>(url: string, token?: string): Promise<T> {
  let res: Response;
  try {
    res = await fetch(url, { headers: apiHeaders(token) });
  } catch (e) {
    throw new GitHubError(`Network error calling GitHub: ${String(e)}`, 0, "network");
  }
  if (res.status === 404) {
    throw new GitHubError("Repository not found, or it is private.", 404, "not_found");
  }
  if (res.status === 403 || res.status === 429) {
    const remaining = res.headers.get("x-ratelimit-remaining");
    if (remaining === "0") {
      const reset = res.headers.get("x-ratelimit-reset");
      const when = reset ? new Date(Number(reset) * 1000).toISOString() : "shortly";
      throw new GitHubError(`GitHub rate limit exhausted; resets at ${when}.`, res.status, "rate_limited");
    }
    throw new GitHubError("GitHub refused the request (403).", res.status, "other");
  }
  if (res.status === 401) {
    throw new GitHubError(
      "GitHub rejected the credentials (401). GITHUB_TOKEN is set but invalid, " +
        "expired, or picked up stray quotes/whitespace. Verify with: " +
        "curl -H \"Authorization: Bearer <token>\" https://api.github.com/user",
      401,
      "other"
    );
  }
  if (!res.ok) {
    throw new GitHubError(`GitHub returned ${res.status}.`, res.status, "other");
  }
  return (await res.json()) as T;
}

/**
 * No Authorization header on purpose. This app only audits PUBLIC repositories,
 * raw.githubusercontent.com serves those anonymously, and it does not accept PAT
 * bearer auth the way the REST API does — sending one can turn every content
 * fetch into a 401 that this function swallows as `null`, silently reporting
 * "0 files scanned" instead of an error.
 */
async function fetchRawFile(
  owner: string,
  repo: string,
  sha: string,
  path: string,
): Promise<string | null> {
  const url = `${RAW_BASE}/${owner}/${repo}/${sha}/${path.split("/").map(encodeURIComponent).join("/")}`;
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": "codex-compliance-agent" },
    });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null; // one unreadable file must not fail the whole scan
  }
}

async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const i = cursor++;
      if (i >= items.length) return;
      out[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return out;
}

// --- public API -------------------------------------------------------------

/** Parse "owner/repo", a full github.com URL, or a git@ remote. */
export function parseRepoRef(input: string): { owner: string; repo: string } | null {
  const cleaned = input.trim().replace(/\.git$/, "").replace(/\/+$/, "");
  const m =
    cleaned.match(/^https?:\/\/(?:www\.)?github\.com\/([^/]+)\/([^/]+)/) ??
    cleaned.match(/^git@github\.com:([^/]+)\/([^/]+)$/) ??
    cleaned.match(/^([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)$/);
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

export async function fetchRepoTree(
  owner: string,
  repo: string,
  options: FetchRepoOptions = {},
): Promise<FetchRepoResult> {
  const maxCandidates = options.maxCandidates ?? DEFAULT_MAX_CANDIDATES;
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const token = normalizeToken(options.token);

  // 1. repo metadata -> default branch + head sha
  const meta = await ghJson<{ default_branch: string }>(
    `${GITHUB_API}/repos/${owner}/${repo}`,
    token,
  );
  const defaultBranch = meta.default_branch;

  // 2. full recursive tree in one request
  const tree = await ghJson<{
    sha: string;
    truncated: boolean;
    tree: { path: string; type: "blob" | "tree" | "commit"; size?: number; sha: string }[];
  }>(
    `${GITHUB_API}/repos/${owner}/${repo}/git/trees/${encodeURIComponent(defaultBranch)}?recursive=1`,
    token,
  );

  const blobs = tree.tree.filter((n) => n.type === "blob");
  const files: RepoFile[] = blobs.map((n) => ({ path: n.path, size: n.size ?? 0 }));

  // 3. decide what is worth reading
  const skipReasons: Record<string, number> = {};
  const candidates: RepoFile[] = [];
  for (const f of files) {
    const reason = skipReasonFor(f.path, f.size, maxFileBytes);
    if (reason) {
      skipReasons[reason] = (skipReasons[reason] ?? 0) + 1;
    } else {
      candidates.push(f);
    }
  }

  candidates.sort((a, b) => candidateScore(b.path) - candidateScore(a.path));
  const selected = candidates.slice(0, maxCandidates);
  const overflow = candidates.length - selected.length;
  if (overflow > 0) skipReasons.over_candidate_cap = overflow;

  // 4. pull content for the selection (raw.githubusercontent — no REST quota cost)
  const contents = await mapWithConcurrency(selected, FETCH_CONCURRENCY, (f) =>
    fetchRawFile(owner, repo, tree.sha, f.path),
  );

  let scanned = 0;
  selected.forEach((f, i) => {
    const body = contents[i];
    if (body !== null) {
      f.content = body;
      scanned++;
    } else {
      skipReasons.fetch_failed = (skipReasons.fetch_failed ?? 0) + 1;
    }
  });

  const scope: ScanScope = {
    totalFiles: files.length,
    scannedFiles: scanned,
    skippedFiles: files.length - scanned,
    skipReasons,
    treeTruncated: tree.truncated === true,
  };

  return { files, scope, commitSha: tree.sha, defaultBranch };
}
