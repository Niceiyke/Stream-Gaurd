import type { Plugin } from "@opencode-ai/plugin"

/**
 * StreamGuard project guards.
 *
 * Belt-and-suspenders on top of the static `permission` rules in
 * opencode.json: the repo is intentionally NOT rustfmt-formatted, and
 * Wintun binary artifacts must never be staged. Aborting via throw
 * surfaces the message and blocks the tool call.
 */
export default (async () => {
  const fmtRe = /^\s*cargo fmt(\s|$)/
  const checkRe = /--check/
  const binaryRe = /(\.dll|\.zip|wintun)/i

  return {
    "tool.execute.before": async (input, output) => {
      if (input.tool !== "bash") return

      const command: string = output.args?.command ?? ""
      if (!command) return

      if (fmtRe.test(command) && !checkRe.test(command)) {
        throw new Error(
          "Blocked: `cargo fmt` (without --check) is forbidden in stream-guard. " +
            "The repo is intentionally not rustfmt-formatted; running it rewrites the " +
            "whole tree into an unrelated giant diff. Use `cargo fmt --check` to inspect only."
        )
      }

      if (/git (add|commit)\b/.test(command) && binaryRe.test(command)) {
        throw new Error(
          "Blocked: refusing to `git add`/`git commit` a binary artifact " +
            "(Wintun .dll / .zip). These are gitignored build artifacts; never stage them."
        )
      }
    },
  }
}) satisfies Plugin