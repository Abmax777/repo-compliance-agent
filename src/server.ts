import { createWorkersAI } from "workers-ai-provider";
import { callable, routeAgentRequest, type Schedule } from "agents";
import { getSchedulePrompt, scheduleSchema } from "agents/schedule";
import { AIChatAgent, type OnChatMessageOptions } from "@cloudflare/ai-chat";
import {
  convertToModelMessages,
  pruneMessages,
  simulateStreamingMiddleware,
  stepCountIs,
  streamText,
  tool,
  wrapLanguageModel
} from "ai";
import { z } from "zod";

import {
  ALL_RULE_IDS,
  explainRule,
  runAllRules,
  type ComplianceReport,
  type RuleId
} from "./codex-rules";
import { GitHubError, fetchRepoTree, parseRepoRef } from "./github";

// ---------------------------------------------------------------------------
// Durable Object state — this is the "memory" leg of the assignment.
// Agent state is persisted in the DO and broadcast to connected clients on
// every setState, so the UI can render scan history without extra plumbing.
// ---------------------------------------------------------------------------

export interface ScanRecord {
  repo: string;
  checkedAt: string;
  passed: number;
  failed: number;
  failedRuleIds: RuleId[];
}

export interface ExceptionRecord {
  id: string;
  repo: string;
  ruleId: RuleId;
  justification: string;
  filedAt: string;
}

export interface CodexAgentState {
  scans: ScanRecord[];
  exceptions: ExceptionRecord[];
}

const MAX_REMEMBERED_SCANS = 20;

// ---------------------------------------------------------------------------
// Shared scan path — used by BOTH the plain HTTP endpoint and the LLM tool.
// Keeping one implementation means the day-1 checkpoint and the day-2 chat
// agent can never disagree about what a scan returns.
// ---------------------------------------------------------------------------

export async function scanRepository(
  ref: string,
  token?: string
): Promise<ComplianceReport> {
  const parsed = parseRepoRef(ref);
  if (!parsed) {
    throw new GitHubError(
      `"${ref}" is not a repository reference. Use owner/name or a github.com URL.`,
      400,
      "other"
    );
  }
  const { files, scope } = await fetchRepoTree(parsed.owner, parsed.repo, {
    token: token || undefined
  });
  return runAllRules(`${parsed.owner}/${parsed.repo}`, files, scope);
}

/**
 * Project a full report down to what the model actually needs.
 *
 * The full report can carry hundreds of evidence paths; feeding all of it back
 * into context wastes tokens and gives the model room to hallucinate detail.
 * Trim evidence to three entries per rule and keep findings redacted.
 */
function forModel(report: ComplianceReport) {
  return {
    repo: report.repo,
    checkedAt: report.checkedAt,
    passed: report.passed,
    failed: report.failed,
    coverage: {
      filesInRepo: report.scope.totalFiles,
      filesScannedForSecrets: report.scope.scannedFiles,
      filesSkipped: report.scope.skippedFiles,
      skipReasons: report.scope.skipReasons,
      treeTruncated: report.scope.treeTruncated,
      authFallback: report.scope.authFallback
    },
    results: report.results.map((r) => ({
      ruleId: r.ruleId,
      passed: r.passed,
      title: r.title,
      summary: r.summary,
      evidence: r.evidence.slice(0, 3),
      findings: r.findings?.map((f) => ({
        pattern: f.patternName,
        severity: f.severity,
        location: `${f.path}:${f.line}`,
        match: f.redacted,
        suppressedBy: f.suppressedBy
      }))
    }))
  };
}

/**
 * The model, with the provider's streaming path bypassed.
 *
 * Two problems with the stock configuration, both found by probing:
 *
 * 1. The agents-starter default (`@cf/moonshotai/kimi-k2.7-code`) is not
 *    available on the Workers Free plan and fails every call with error 5035.
 *    Llama 3.3 is free-plan available and is the model the assignment names.
 *
 * 2. workers-ai-provider 3.3.1 emits every streamed tool-call argument delta
 *    TWICE, consecutively, so `{"ruleId": "has_codeowners"}` arrives as
 *    `{"ruleId": "{"ruleId": "hashas_code_codeowners"}owners"}` and fails to
 *    parse. Reproduced identically on Llama 3.3, Llama 4 Scout and Qwen3, which
 *    is what rules out the model as the cause. Version 4 of the provider is not
 *    an option: it requires ai@^7, while `agents` and `@cloudflare/ai-chat` both
 *    peer on ai@^6.
 *
 * `simulateStreamingMiddleware` routes through the provider's `doGenerate`
 * instead — which produces well-formed tool arguments — and synthesises the
 * stream from the completed result. The trade-off is that responses arrive in
 * one piece rather than token by token. Correct output beats a nicer cursor.
 */
export function codexModel(env: Env, sessionAffinity?: unknown) {
  const workersai = createWorkersAI({ binding: env.AI });
  return wrapLanguageModel({
    model: workersai("@cf/meta/llama-3.3-70b-instruct-fp8-fast", {
      sessionAffinity: sessionAffinity as never
    }),
    middleware: simulateStreamingMiddleware()
  });
}

const SYSTEM_PROMPT = `You are the Codex Compliance Agent. You audit public GitHub repositories against the Codex engineering standards and explain the results to engineers in plain language.

The six Codex rules are: ${ALL_RULE_IDS.join(", ")}.

How to behave:
- When a user names a repository, call check_repo_compliance. Never guess a verdict; never claim a rule passed or failed without a tool result.
- Report the outcome conversationally. Lead with the headline (how many rules passed), then walk the failures. Do not dump raw JSON at the user.
- Always state scan coverage when discussing no_hardcoded_secrets. The scan reads a bounded subset of files, so "no secrets found" means "none in the files scanned". Say so, with the numbers.
- Distinguish severities. A "violation" is a credible finding. A "warning" was matched but suppressed as a placeholder, a test fixture, or low-entropy — mention warnings as context, not as failures.
- Secrets are already redacted when they reach you. Never attempt to reconstruct or print a full credential.
- If a user disagrees with a finding or says a rule does not apply, offer file_exception_request. That tool requires explicit human approval before it runs — tell the user you are requesting their approval, and do not pretend it succeeded until you see the result.
- Use explain_rule when someone asks why a standard exists.
- If the repository is private, missing, or GitHub rate-limits the request, say exactly that rather than inventing a report.
- If coverage reports authFallback, the configured GitHub token was rejected and the scan ran unauthenticated on a much tighter rate limit. Mention it once — the results are still valid, but the operator should know the token needs replacing.`;

export class ChatAgent extends AIChatAgent<Env, CodexAgentState> {
  initialState: CodexAgentState = { scans: [], exceptions: [] };

  maxPersistedMessages = 100;
  chatRecovery = true;
  waitForMcpConnections = true;

  onStart() {
    this.mcp.configureOAuthCallback({
      customHandler: (result) => {
        if (result.authSuccess) {
          return new Response("<script>window.close();</script>", {
            headers: { "content-type": "text/html" },
            status: 200
          });
        }
        return new Response(
          `Authentication Failed: ${result.authError || "Unknown error"}`,
          { headers: { "content-type": "text/plain" }, status: 400 }
        );
      }
    });
  }

  @callable()
  async addServer(name: string, url: string) {
    return await this.addMcpServer(name, url);
  }

  @callable()
  async removeServer(serverId: string) {
    await this.removeMcpServer(serverId);
  }

  private rememberScan(report: ComplianceReport) {
    const record: ScanRecord = {
      repo: report.repo,
      checkedAt: report.checkedAt,
      passed: report.passed,
      failed: report.failed,
      failedRuleIds: report.results.filter((r) => !r.passed).map((r) => r.ruleId)
    };
    this.setState({
      ...this.state,
      scans: [record, ...this.state.scans].slice(0, MAX_REMEMBERED_SCANS)
    });
  }

  private rememberException(record: ExceptionRecord) {
    this.setState({
      ...this.state,
      exceptions: [record, ...this.state.exceptions]
    });
  }

  async onChatMessage(_onFinish: unknown, options?: OnChatMessageOptions) {
    const mcpTools = this.mcp.getAITools();
    const workersai = createWorkersAI({ binding: this.env.AI });

    const result = streamText({
      model: codexModel(this.env, this.sessionAffinity),
      system: `${SYSTEM_PROMPT}

${getSchedulePrompt({ date: new Date() })}`,
      messages: pruneMessages({
        messages: await convertToModelMessages(this.messages),
        toolCalls: "before-last-2-messages",
        reasoning: "before-last-message"
      }),
      tools: {
        ...mcpTools,

        check_repo_compliance: tool({
          description:
            "Audit a public GitHub repository against all six Codex engineering standards. Returns a per-rule verdict plus the coverage of the secret scan. Use this whenever a user names a repository.",
          inputSchema: z.object({
            repo: z
              .string()
              .describe(
                'The repository, as "owner/name" or a full github.com URL.'
              )
          }),
          execute: async ({ repo }) => {
            try {
              const report = await scanRepository(repo, this.env.GITHUB_TOKEN);
              this.rememberScan(report);
              return forModel(report);
            } catch (error) {
              if (error instanceof GitHubError) {
                return { error: error.message, kind: error.kind };
              }
              return { error: `Scan failed: ${String(error)}` };
            }
          }
        }),

        explain_rule: tool({
          description:
            "Explain what a single Codex rule requires and why the standard exists. Use when a user asks why a rule matters or pushes back on a finding.",
          inputSchema: z.object({
            ruleId: z.enum(ALL_RULE_IDS as [RuleId, ...RuleId[]])
          }),
          execute: async ({ ruleId }) =>
            explainRule(ruleId) ?? {
              error: `No Codex rule with id "${ruleId}".`
            }
        }),

        // --- the human-in-the-loop piece --------------------------------
        // needsApproval short-circuits execution: the SDK persists the call in
        // "approval-requested" state, the UI renders Approve / Reject, and
        // execute() only runs on approval. Filing a compliance exception is
        // exactly the kind of action that should never happen on a model's say-so.
        file_exception_request: tool({
          description:
            "File a formal request to exempt a repository from one Codex rule. Requires human approval before it is recorded. Only offer this when the user has given a concrete justification.",
          inputSchema: z.object({
            repo: z.string().describe('The repository, as "owner/name".'),
            ruleId: z.enum(ALL_RULE_IDS as [RuleId, ...RuleId[]]),
            justification: z
              .string()
              .min(10)
              .describe(
                "The engineer's stated reason the rule should not apply. Use their words, do not invent a rationale."
              )
          }),
          needsApproval: async () => true,
          execute: async ({ repo, ruleId, justification }) => {
            const record: ExceptionRecord = {
              id: crypto.randomUUID(),
              repo,
              ruleId,
              justification,
              filedAt: new Date().toISOString()
            };
            this.rememberException(record);
            // TODO(day 2, optional): POST to a real ticketing system here.
            console.log("[codex] exception filed", record);
            return {
              status: "filed",
              id: record.id,
              message: `Exception request ${record.id} recorded for ${repo} / ${ruleId}. It is pending review by the Codex owners.`
            };
          }
        }),

        recent_activity: tool({
          description:
            "Recall repositories scanned earlier in this conversation and any exceptions filed. Use when the user refers back to a previous scan.",
          inputSchema: z.object({}),
          execute: async () => ({
            scans: this.state.scans,
            exceptions: this.state.exceptions
          })
        }),

        schedule_rescan: tool({
          description:
            "Schedule a repository to be re-audited later, once or on a cron schedule.",
          inputSchema: scheduleSchema.extend({
            repo: z.string().describe('The repository, as "owner/name".')
          }),
          execute: async ({ when, repo }) => {
            if (when.type === "no-schedule") return "Not a valid schedule input";
            const input =
              when.type === "scheduled"
                ? when.date
                : when.type === "delayed"
                  ? when.delayInSeconds
                  : when.type === "cron"
                    ? when.cron
                    : null;
            if (!input) return "Invalid schedule type";
            try {
              this.schedule(input, "runScheduledScan", { repo }, { idempotent: true });
              return `Re-audit of ${repo} scheduled (${when.type}: ${input}).`;
            } catch (error) {
              return `Error scheduling re-audit: ${error}`;
            }
          }
        }),

        list_scheduled_rescans: tool({
          description: "List every scheduled re-audit.",
          inputSchema: z.object({}),
          execute: async () => {
            const tasks = this.getSchedules();
            return tasks.length > 0 ? tasks : "No re-audits scheduled.";
          }
        }),

        cancel_rescan: tool({
          description: "Cancel a scheduled re-audit by its ID.",
          inputSchema: z.object({
            taskId: z.string().describe("The ID of the scheduled re-audit")
          }),
          execute: async ({ taskId }) => {
            try {
              this.cancelSchedule(taskId);
              return `Re-audit ${taskId} cancelled.`;
            } catch (error) {
              return `Error cancelling re-audit: ${error}`;
            }
          }
        })
      },
      stopWhen: stepCountIs(20),
      abortSignal: options?.abortSignal
    });

    return result.toUIMessageStreamResponse({
      /**
       * streamText does not throw — a failed inference call resolves with an
       * empty stream, so without this the UI renders a blank assistant message
       * and the cause is lost. Log it server-side and surface it to the client.
       */
      onError: (error) => {
        const err = error as { message?: string; cause?: unknown; name?: string };
        console.error("[codex] streamText failed:", {
          name: err?.name,
          message: err?.message,
          cause: err?.cause,
          raw: JSON.stringify(error, Object.getOwnPropertyNames(error ?? {})).slice(0, 2000)
        });
        return `Model call failed: ${err?.message ?? String(error)}`;
      }
    });
  }

  /**
   * Alarm callback for schedule_rescan. Runs with no user present, so it writes
   * to state and broadcasts rather than injecting into chat history — pushing a
   * message into `this.messages` here would give the model new context to react
   * to and can send it into a loop.
   */
  async runScheduledScan(
    payload: { repo: string },
    _task: Schedule<{ repo: string }>
  ) {
    try {
      const report = await scanRepository(payload.repo, this.env.GITHUB_TOKEN);
      this.rememberScan(report);
      this.broadcast(
        JSON.stringify({
          type: "scheduled-scan",
          repo: report.repo,
          passed: report.passed,
          failed: report.failed,
          timestamp: report.checkedAt
        })
      );
    } catch (error) {
      this.broadcast(
        JSON.stringify({
          type: "scheduled-scan-failed",
          repo: payload.repo,
          error: String(error),
          timestamp: new Date().toISOString()
        })
      );
    }
  }
}

export default {
  async fetch(request: Request, env: Env) {
    const url = new URL(request.url);

    /**
     * Day-1 checkpoint endpoint: the rule engine with no LLM in the path.
     *
     *   curl "https://<worker>/api/scan?repo=sindresorhus/got"
     *   curl -X POST https://<worker>/api/scan -d '{"repo":"owner/name"}'
     *
     * Keep this after day 2. It is the fastest way to debug a rule without
     * burning a model call, and it makes the deterministic core demoable on
     * its own — useful when explaining the design in an interview.
     */
    if (url.pathname === "/api/scan") {
      let repo = url.searchParams.get("repo") ?? "";
      if (request.method === "POST") {
        try {
          const body = (await request.json()) as { repo?: string };
          repo = body.repo ?? repo;
        } catch {
          return Response.json({ error: "Body must be JSON." }, { status: 400 });
        }
      }
      if (!repo) {
        return Response.json(
          { error: 'Provide a repository, e.g. ?repo=owner/name' },
          { status: 400 }
        );
      }
      try {
        const report = await scanRepository(repo, env.GITHUB_TOKEN);
        return Response.json(report);
      } catch (error) {
        if (error instanceof GitHubError) {
          return Response.json(
            { error: error.message, kind: error.kind },
            { status: error.status === 0 ? 502 : error.status }
          );
        }
        return Response.json({ error: String(error) }, { status: 500 });
      }
    }

    return (
      (await routeAgentRequest(request, env)) ||
      new Response("Not found", { status: 404 })
    );
  }
} satisfies ExportedHandler<Env>;
