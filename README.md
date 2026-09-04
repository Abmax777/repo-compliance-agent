# Repo Compliance Agent

A chat agent that audits public GitHub repositories against a set of engineering
standards — referred to throughout as **the Codex** — explains what it found in
plain language, and can file an approval-gated exception request when an engineer
argues a rule should not apply.

Built on Cloudflare Workers, Durable Objects and Workers AI.

**Live:** https://repo-compliance-agent.abhinavk891.workers.dev

Abridged from a real session:

```
> Check gitleaks/gitleaks against the Codex

4 of 6 Codex rules pass. Two failures:

  no_hardcoded_secrets — 1 violation: a Google API key in config/gitleaks.toml:619
  has_tests_dir        — no test/, tests/ or __tests__/ directory

The test directory failure is arguably a false positive on a Go project: Go keeps
tests beside the source they cover, so the convention this rule encodes does not
apply. That is a good candidate for an exception request.

There is also 1 warning I did not count as a failure: an AWS key in
testdata/config/valid/allowlist_rule_regex.toml, suppressed as a test fixture.

Coverage: 60 of 454 files were read for credentials. The rest were skipped as
vendored, binary or over the size limit, so "clean" applies to what was scanned.
```

## Why this project

The role sits with Platforms & Productivity — Codex enforcement, CI/CD policy
checks, remediation and exception workflows. Rather than build a generic chat
demo, I built a small version of that remit: a deterministic policy engine, a
conversational layer over it, and a human approval gate on the one action with
consequences.

## Assignment requirements

| Requirement | Where it lives |
|---|---|
| LLM | Workers AI (`@cf/meta/llama-3.3-70b-instruct-fp8-fast`) via `workers-ai-provider` and the Vercel AI SDK, in `src/server.ts` |
| Workflow / coordination | `ChatAgent`, a Durable Object extending `AIChatAgent`; multi-step tool loop with `stopWhen: stepCountIs(20)`; DO alarms drive scheduled re-audits |
| User input | React chat UI (`src/app.tsx`) over the Agents SDK WebSocket transport |
| Memory / state | Message history persisted in the DO's SQLite, plus explicit agent state (`scans`, `exceptions`) via `setState`, broadcast to connected clients |

Both model choice and the streaming configuration are the result of two failures worth reading about — see [What broke, and how it was found](#what-broke-and-how-it-was-found).

## The Codex

Six rules, all programmatically checkable:

| Rule | Passes when |
|---|---|
| `has_readme` | A README exists at the repository root |
| `has_license` | `LICENSE`, `LICENSE.md` or `LICENSE.txt` at the root |
| `has_codeowners` | `CODEOWNERS` at the root, in `.github/` or in `docs/` |
| `has_ci_config` | At least one `.github/workflows/*.yml` or `*.yaml` |
| `no_hardcoded_secrets` | No credential violations in the scanned files |
| `has_tests_dir` | A `test/`, `tests/` or `__tests__/` directory exists |

All matching is case-insensitive. That is not cosmetic: `sindresorhus/got` ships
`readme.md` and an extensionless `license`, and a naive implementation reports one
of the best-known packages on npm as non-compliant.

## Two decisions worth explaining

### Bounded scanning, with coverage reported

Reading every file to hunt for secrets is not viable — a Worker on the Free plan
is capped at 50 subrequests per request, and `facebook/react` alone has 7,211
files.

So the scan is bounded. One call to the recursive git-tree API returns every path
and size, which is enough to answer all five structural rules for free. Content is
then fetched only for ranked candidates: vendored directories, lockfiles, minified
output, binaries and files over 200 KB are dropped; the remainder is ranked with
env/IaC/config files first, then source; the top 40 are read. Content comes from
`raw.githubusercontent.com`, which does not consume the REST quota, so the cap is
a subrequest and latency budget rather than a rate-limit one.

The important part is that the limit is **reported, not hidden**. Every report
carries `scannedFiles`, `skippedFiles` and a breakdown of skip reasons, and the
system prompt requires the agent to state coverage whenever it discusses secrets.
Scanning 40 of 7,211 files and announcing "no secrets found" would be a false
assurance. Saying "no secrets in the 40 files scanned, here is what was skipped"
is a true statement a reviewer can act on.

### Precision over recall, with two severities

The obvious `(api_key|secret|token)\s*=\s*"..."` pattern is a false-positive
cannon — it fires on `API_KEY = "your-api-key-here"` in most READMEs on GitHub.
It is deliberately absent.

Every pattern here is anchored on a vendor prefix with a known body length:
`AKIA…`, `ghp_…`, `sk_live_…`, `xox[abposr]-…`, `AIza…`, PEM headers. When an LLM
narrates findings to a human as fact, a false positive is more damaging than a
miss: it teaches the reviewer to distrust the tool.

Findings are then split in two. A match with nothing suppressing it is a
`violation`. A match that trips a suppressor is a `warning`:

- **placeholder** — the match contains `example`, `your-`, `changeme`, …
  (this catches `AKIAIOSFODNN7EXAMPLE`, AWS's own documentation key)
- **test_path** — the file sits under `test/`, `testdata/`, `test_data/`,
  `fixtures/`, `docs/`, …
- **low_entropy** — Shannon entropy of the match is below 3.0 bits/char, so it
  matches the shape but cannot be a real key

Only violations fail the rule; warnings are reported as context. Matches are
redacted at the point of detection (`AKIA****************`), so no credential ever
reaches model context or the chat transcript.

Validated against repositories that deliberately contain planted keys —
`gitleaks/gitleaks`, `trufflesecurity/trufflehog`, `Yelp/detect-secrets`. That
exercise is what surfaced the `testdata/` gap: Go's convention does not
prefix-match `test/`, so fixtures were being reported as real violations.

## What broke, and how it was found

The model is Llama 3.3 rather than the agents-starter default. The default,
`@cf/moonshotai/kimi-k2.7-code`, is not available on the Workers Free plan and
fails every inference call with error 5035 — but `streamText` does not throw on a
failed call, so this surfaced only as blank assistant messages with no error
anywhere in the UI. Diagnosing it needed a temporary route that called the model
outside the chat plumbing; the fix was to probe every function-calling model with
a real tool call and pick from the ones that worked. Five did. Llama 3.3 was the
choice because the assignment names it.

The `onError` handler on `toUIMessageStreamResponse` is a direct result: a model
call that fails silently is worse than one that fails loudly.

With the model fixed, a second bug appeared. `workers-ai-provider` 3.3.1 emits
every streamed tool-call argument delta twice, consecutively, so

    {"ruleId": "has_codeowners"}

arrives as

    {"ruleId": "{"ruleId": "hashas_code_codeowners"}owners"}

and fails to parse. It reproduces identically on Llama 3.3, Llama 4 Scout and
Qwen3, which rules out the model. Upgrading the provider is not available: version
4 requires `ai@^7`, while `agents` and `@cloudflare/ai-chat` both peer on `ai@^6`.

The fix is `simulateStreamingMiddleware`, which routes through the provider's
`doGenerate` — whose tool arguments are well formed — and synthesises the stream
from the completed result. The chat, the tool loop and the approval gate are all
unchanged; the only cost is that responses arrive in one piece rather than token
by token. See `codexModel()` in `src/server.ts`.

Both bugs shared a shape: a failure in the model layer that produced no error
anywhere a user would look. Both were isolated the same way — with a temporary
HTTP route that called the model outside the agent, the tools and the WebSocket
transport, so the variable under test was the only one moving.

The first probe used `generateText` while the application uses `streamText`. Those
are different code paths in the provider and the second bug lives only in the
streamed one, so that probe reported a clean bill of health on a broken system.
Rewriting it to call `streamText` through the same `codexModel()` factory the
agent uses caught the bug on the first run. Test the path you ship.

Throughout both outages `/api/scan` continued returning correct reports, because
the rule engine has no model in its path. That is the separation this project is
built around, demonstrated under a real failure rather than asserted.

## Human in the loop

`file_exception_request` is gated with `needsApproval`. The model can propose an
exception and populate the justification, but the SDK suspends the call in
`approval-requested` state and the UI renders Approve / Reject. Nothing is
recorded until a person clicks.

Granting a compliance exemption is a governance action. It is exactly the class of
thing that should not happen on a language model's say-so, which is why it is the
one gated tool while the read-only tools execute freely.

## Architecture

```
src/
  codex-rules.ts   pure rule logic — no Cloudflare imports, no network, no I/O
  github.ts        GitHub REST + raw client, scoping and ranking policy
  server.ts        ChatAgent (Durable Object), tool definitions, /api/scan
  app.tsx          chat UI
test/
  codex-rules.test.ts   29 tests
  fixtures.ts           synthetic repos, including real-world edge cases
```

`codex-rules.ts` imports nothing. That is what lets the rule engine be tested in a
plain Node environment with no miniflare, no wrangler and no network — the suite
runs in about 130 ms. It also means the deterministic core can be reasoned about
independently of the agent wrapped around it.

The same `scanRepository()` backs both the chat tool and a plain HTTP endpoint, so
the two can never disagree:

```bash
curl "https://repo-compliance-agent.abhinavk891.workers.dev/api/scan?repo=gitleaks/gitleaks"
```

That endpoint is the rule engine with no LLM in the path — useful for debugging a
rule without spending a model call, and it makes the deterministic core demoable
on its own.

## Tools exposed to the model

| Tool | Behaviour |
|---|---|
| `check_repo_compliance` | Audits a repository. Auto-executes. |
| `explain_rule` | Returns a rule's requirement and rationale. Auto-executes. |
| `file_exception_request` | **Requires human approval.** Records an exception request. |
| `recent_activity` | Reads scan and exception history from DO state. |
| `schedule_rescan` / `list_scheduled_rescans` / `cancel_rescan` | Re-audits on a delay or cron, driven by DO alarms. |

## Running it

```bash
npm install
cp .dev.vars.example .dev.vars      # add a GitHub PAT (see below)
npm run dev
```

The PAT is only there to lift GitHub's rate limit from 60 to 5,000 requests/hour;
every endpoint used is public read. A classic token with **no scopes ticked** is
enough, as is a fine-grained token limited to public repositories — granting
`repo` would add write access to every private repository for no benefit. It is optional — if `GITHUB_TOKEN` is absent,
or present but rejected, the scan falls back to unauthenticated requests and sets
`authFallback` in the report so the agent can say so. A dead token degrades the
tool rather than taking it down, which matters for something reviewed weeks after
the credential was minted.

Workers AI has no local simulator, so `npm run dev` proxies to Cloudflare and
needs `wrangler login`.

```bash
npm test              # rule engine, no network
npm run deploy
npx wrangler secret put GITHUB_TOKEN
```

## Limitations

- **Public repositories only.** Private repos return "not found, or it is private".
- **Bounded secret scanning.** 40 files by default. Coverage is reported rather
  than papered over, but it is not a substitute for gitleaks in CI.
- **No secret verification.** A matched key is never tested against its provider,
  so a revoked credential still reports as a violation.
- **The unauthenticated fallback is a safety net, not a usable mode.** Requests
  from a Worker leave via Cloudflare's shared egress IPs, so GitHub's 60/hour
  anonymous allowance is shared with every other Worker and can be exhausted
  before you make a single call. A rejected token keeps the app alive; it does not
  keep it usable.
- **The model can supply a stale repository identifier.** `file_exception_request`
  takes `repo` from the model, which may reproduce a name from training data
  rather than the repository just scanned — an observed case filed against
  `zricethezav/gitleaks` after auditing `gitleaks/gitleaks`. The rule and
  justification were correct; the identifier was not. The fix is to default `repo`
  from the most recent entry in agent state and treat the model's value as a
  fallback, so the model never restates a fact the system already holds.
- **`has_tests_dir` encodes a JavaScript/Python convention.** Go places tests
  beside the source they cover, so idiomatic Go repositories fail this rule
  correctly by the letter and wrongly in spirit. This is the intended use of the
  exception workflow rather than a bug, but a real Codex would make the rule
  language-aware.
- **The rules are invented.** They are plausible platform standards, not a real
  compliance framework.
- **Exception requests are recorded, not routed.** They persist in Durable Object
  state; wiring them to a real ticketing system is a `TODO` in `server.ts`.
- **Responses are not token-streamed.** The provider's streaming path corrupts
  tool-call arguments, so the model runs through `doGenerate` behind
  `simulateStreamingMiddleware`. Replies appear all at once. Reverting is a
  one-line change once the provider is fixed.
- **Tree truncation.** GitHub truncates the recursive tree API on very large
  repositories. The report exposes `treeTruncated`, but the structural rules would
  be scanning an incomplete file list when it is set.

## AI prompt history

`PROMPTS.md` — required by the assignment. It records what was asked, what was
accepted, what was rejected and why.

## License

MIT
