import { defineConfig } from "vitest/config";

/**
 * Plain node environment on purpose.
 *
 * codex-rules.ts has no Cloudflare imports, so its tests need no Workers pool,
 * no miniflare, no wrangler. That is the payoff for keeping the rule logic pure:
 * the test loop is instant and runs anywhere.
 *
 * If you later want tests that exercise the Durable Object itself, add
 * @cloudflare/vitest-pool-workers as a SECOND project rather than converting
 * this one.
 */
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
  },
});
