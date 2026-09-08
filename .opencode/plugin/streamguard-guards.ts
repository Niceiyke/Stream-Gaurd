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
  const fmtRe = /\bcargo\s+fmt\b/
  const fmtCheckRe = /^\s*cargo\s+fmt\s+--check(?:\s|$)/
  const sensitiveArtifactRe = /(\.dll|\.zip|\.der|\.pem|\.key|sgcerts|diagnostic|packet[-_ ]?capture)/i
  const destructiveGitRe = /\bgit\s+(?:reset\s+--hard|clean\b|checkout\s+--|restore\b)/

  return {
    "tool.execute.before": async (input, output) => {
      if (input.tool !== "bash") return

      const command: string = output.args?.command ?? ""
      if (!command) return

      for (const segment of command.split(/;|&&|\|\|/)) {
        if (fmtRe.test(segment) && !fmtCheckRe.test(segment)) {
          throw new Error(
            "Blocked: `cargo fmt` is forbidden in stream-guard. The repository is intentionally " +
              "not rustfmt-formatted; only a standalone `cargo fmt --check` inspection is allowed."
          )
        }
      }

      if (destructiveGitRe.test(command)) {
        throw new Error(
          "Blocked: destructive Git commands require direct user handling. Do not reset, clean, " +
            "restore, or checkout-discard a shared StreamGuard worktree."
        )
      }

      if (/\bgit\s+add\b/.test(command) && (sensitiveArtifactRe.test(command) || /\bgit\s+add\s+(?:\.|-A|--all)(?:\s|$)/.test(command))) {
        throw new Error(
          "Blocked: stage explicit reviewed source files only. Never bulk-stage or stage generated " +
            "keys, certificates, binaries, diagnostics, or packet captures."
        )
      }
    },
  }
}) satisfies Plugin
