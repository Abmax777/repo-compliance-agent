# AI prompt history

Required by the assignment. Kept as a running log — append as you go rather than
reconstructing at the end, since the submission asks for the actual history.

Tools used: Claude (Cowork), with a linked-device shell writing directly into
this repo.

---

## Session 1 — 2026-09-03 — design decisions and scaffolding

**Prompt: project brief.** Supplied the full build brief (assignment
requirements, chosen concept, stack, six-rule set, file layout, tool list, 2-day
build order) and asked for scaffolding rather than finished code, plus a view on
two open questions:

1. Should the secret scan read every file's content, or only likely candidates?
2. How paranoid should the secret regexes be versus false-positive tolerance?

**Outcome — decision 1: bounded candidate scan, with coverage reported.**
The recursive git-tree API returns every path plus size in a single request, so
filtering happens before any content is fetched. Skip vendored directories,
lockfiles, minified output, binaries and files over 200 KB; rank the remainder
(env/IaC/config first, then source); cap at 40. The cap is sized against the
Workers subrequest budget (50 per request on the free plan), not the GitHub rate
limit — content is pulled from raw.githubusercontent.com, which does not consume
the REST quota. Coverage is reported in the output (`scannedFiles`,
`skippedFiles`, `skipReasons`) so the agent states what it actually looked at
instead of implying a whole-repo guarantee.

**Outcome — decision 2: precision over recall, with two severities.**
Only prefix-anchored vendor patterns (AKIA…, ghp_…, sk_live_…, xox…, AIza…,
PEM headers). The generic `(api_key|secret|token) = "..."` pattern was dropped:
it fires on `API_KEY = "your-api-key-here"` in most READMEs, and a false positive
is worse than a miss when a model narrates the result to a human as fact.
Findings are split into `violation` and `warning`, with three suppressors —
placeholder markers in the match, test/fixture/docs paths, and a Shannon entropy
floor of 3.0. Only violations fail the rule. Matches are redacted at the point of
detection so no credential reaches model context.

**Generated:** `src/github.ts` (complete), `test/fixtures.ts` and
`test/codex-rules.test.ts` (28 assertions), and the contract half of
`src/codex-rules.ts` — types, rule metadata, pattern table, and one TODO per
function. Rule logic written by hand.

**Verification:** ran `fetchRepoTree` against `sindresorhus/got` before writing
any rules. 127 files, 40 scanned, 3.4s. Surfaced that got's root is `readme.md`
and `license` — lowercase, no extension — which is why every structural check is
case-insensitive and why `LOWERCASE_REPO` exists as a fixture.

**Prompt: scaffold deployed, wire up the Worker.** Deployed the unmodified
agents-starter to confirm the pipeline, then had the Worker glue written.

Notes on the starter as of this date, which differs from the assignment's
example stack:
- entry point is `src/server.ts`, not `agent.ts`
- `AIChatAgent` now comes from `@cloudflare/ai-chat`, not `agents/ai-chat-agent`
- default model is `@cf/moonshotai/kimi-k2.7-code`, kept over Llama 3.3 for
  stronger tool-calling
- the starter already ships a `needsApproval` tool pattern and a generic
  approval UI, so the human-in-the-loop requirement needed no frontend work
- MCP *client* support is built in; the stretch goal is the *server* side

**Generated:** tool definitions in `src/server.ts`, Durable Object state shape
(`scans`, `exceptions`), a shared `scanRepository()` used by both the chat tools
and a plain `GET/POST /api/scan` endpoint, vitest config, `.dev.vars.example`,
and the `GITHUB_TOKEN` secret binding.

---

## Session 2 — 2026-09-04 — validation, hardening, and a silent model failure

**Validated the rule engine against real repositories** before trusting it. Five
public repos for the structural rules, then three repos that deliberately contain
planted credentials (gitleaks, trufflehog, detect-secrets) for the secret scan.

That surfaced a real gap: `testdata/` (Go) and `test_data/` (Python) were not in
`TEST_PATH_MARKERS`, and matching is `startsWith(marker) || includes("/" + marker)`,
so `test/` does not cover them. Planted fixtures in both repos were being reported
as genuine violations. Fixed, with a regression test.

**Made a rejected GitHub token degrade instead of fail.** The PAT is a rate-limit
optimisation, not an access requirement — every endpoint used is public read. A
401 now retries once unauthenticated and sets `authFallback` in the report, which
the agent is instructed to mention. Same principle as the coverage reporting:
degrade, then say plainly that you degraded.

**The chat produced empty assistant messages, with no error anywhere.**

Diagnosis in order: `onError` on `toUIMessageStreamResponse` did not fire, so the
failure was upstream of the stream. A temporary `/api/diag` route that called the
model directly — outside the agent, the tools and the WebSocket transport —
returned the real cause immediately:

    5035: Model @cf/moonshotai/kimi-k2.7-code is not available on the Workers Free plan

The agents-starter default is paid-plan only. `streamText` resolves rather than
throws when the provider rejects a call, so the failure had been invisible.

Rather than guess a replacement, the diag route was rewritten to probe every
function-calling model in the catalogue with a real tool call. Five worked on the
free plan: llama-3.3-70b-instruct-fp8-fast, llama-4-scout-17b, mistral-small-3.1,
gpt-oss-120b and qwen3-30b. gpt-oss-20b ran but never invoked the tool.
Llama 3.3 was chosen because the assignment names it.

**Then the tool arguments came back corrupted.** With a working model, the agent
selected the right tool but its arguments arrived as
`{"ruleId": "{"ruleId": "hashas_code_codeowners"}owners"}`.

Decomposing three models' output showed the pattern exactly: every argument delta
emitted twice, consecutively (`has`+`has`, `_code`+`_code`, `owners`+`owners`).
Identical across Llama 3.3, Llama 4 Scout and Qwen3 — so, the provider, not the
model. `workers-ai-provider` 4.0.0 fixes nothing here because it requires `ai@^7`
while the Agents SDK peers on `ai@^6`.

Resolved with `simulateStreamingMiddleware` from the AI SDK: route through
`doGenerate`, whose arguments are well formed, and synthesise the stream. Costs
token-by-token streaming; keeps the tool loop and approval gate intact.

Method note, since it cost two wasted cycles: the first probe used `generateText`
and the application uses `streamText`. Those are different code paths in the
provider, and the bug lives only in the streamed one. Validating the path you do
not ship tells you nothing. The second probe called `streamText` through the same
`codexModel()` factory the agent uses, and caught it immediately.

Worth noting: `/api/scan` returned 200 throughout this outage. The rule engine has
no model in its path, so the deterministic half of the system was unaffected by a
total failure of the conversational half — which is the point of the split.

## Session 3 — TODO

<!--
Append as you go. For each meaningful prompt, record:
  - what you asked for
  - what you accepted, changed, or rejected, and why
The "rejected" entries are the interesting ones for a reviewer.
-->
