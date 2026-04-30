/**
 * SecureLoop - AutoFix Tier 2 Context Builder
 * by Jorge Elizalde
 *
 * Builds the minimal context window we send to the LLM for a Tier-2 proposal.
 * Privacy posture for AI review patches:
 *   - Only the target file content within ±WINDOW_LINES of the offending line.
 *   - No full-repo code, no git history, no environment, no secrets metadata
 *     beyond what the finding already contains.
 *   - We strip obvious .env contents from the window before it leaves disk.
 */

import fs from "fs";
import path from "path";

export const WINDOW_LINES = 20;       // lines of context on each side of the hit
export const MAX_FILE_BYTES = 64_000; // hard cap — reject files bigger than this

/**
 * Build a context object for a single Tier-2 finding.
 *
 * @param {object} finding       Scanner finding (see CLAUDE.md Finding schema)
 * @param {string} skillPath     Absolute path to the skill directory
 * @returns {{
 *   ok:        boolean,
 *   reason:    string,              // "ok" | error code
 *   file?:     string,              // absolute path to source file
 *   relFile?:  string,              // path relative to skillPath
 *   line?:     number,
 *   before?:   string,              // window ABOVE the hit
 *   hit?:      string,              // the offending line
 *   after?:    string,              // window BELOW the hit
 *   language?: string,              // "javascript" | "typescript" | "json" | …
 *   redactions?: number,            // count of lines we scrubbed for secrets
 * }}
 */
export function buildTier2Context(finding, skillPath) {
  if (!skillPath) return { ok: false, reason: "no-skill-path" };

  // The static scanner records the file path in finding.detail.
  // Format examples:
  //   "src/lib/keys.ts:42"
  //   "openclaw.plugin.json"
  //   "package.json"
  const detail = finding.detail || "";
  const line   = Number.isInteger(finding.line) ? finding.line : parseLineFromDetail(detail);
  const relFile = parseFileFromDetail(detail);

  if (!relFile) return { ok: false, reason: "no-file-in-detail" };

  const absFile = path.isAbsolute(relFile) ? relFile : path.join(skillPath, relFile);

  // Safety: never read anything outside the skill directory.
  const resolved = path.resolve(absFile);
  if (!resolved.startsWith(path.resolve(skillPath))) {
    return { ok: false, reason: "path-escapes-skill-dir" };
  }

  if (!fs.existsSync(resolved)) return { ok: false, reason: "file-not-found" };

  const stat = fs.statSync(resolved);
  if (stat.size > MAX_FILE_BYTES) return { ok: false, reason: "file-too-large" };
  if (!stat.isFile()) return { ok: false, reason: "not-a-file" };

  const raw = fs.readFileSync(resolved, "utf-8");
  const lines = raw.split(/\r?\n/);

  const hitIndex = Math.max(0, (line || 1) - 1);
  const fromIdx  = Math.max(0, hitIndex - WINDOW_LINES);
  const toIdx    = Math.min(lines.length - 1, hitIndex + WINDOW_LINES);

  const before = lines.slice(fromIdx, hitIndex).join("\n");
  const hit    = lines[hitIndex] ?? "";
  const after  = lines.slice(hitIndex + 1, toIdx + 1).join("\n");

  // Redact any stray high-entropy secrets in the window that are NOT the one
  // we are trying to fix. This is a defense-in-depth scrub, not an auth layer.
  const { redacted: redBefore, count: c1 } = redactSecrets(before);
  const { redacted: redAfter,  count: c2 } = redactSecrets(after);

  return {
    ok: true,
    reason: "ok",
    file: resolved,
    relFile,
    line: hitIndex + 1,
    before: redBefore,
    hit,
    after: redAfter,
    language: languageFor(resolved),
    redactions: c1 + c2,
  };
}

function parseLineFromDetail(detail) {
  const m = /:(\d+)\s*$/.exec(detail);
  return m ? Number(m[1]) : 1;
}

function parseFileFromDetail(detail) {
  if (!detail) return null;
  // strip trailing ":<line>"
  const clean = detail.replace(/:\d+\s*$/, "").trim();
  if (!clean) return null;
  return clean;
}

function languageFor(absFile) {
  const ext = path.extname(absFile).toLowerCase();
  switch (ext) {
    case ".ts":
    case ".tsx":  return "typescript";
    case ".js":
    case ".mjs":
    case ".cjs":
    case ".jsx":  return "javascript";
    case ".json": return "json";
    case ".py":   return "python";
    default:      return "text";
  }
}

/**
 * Crude secret scrubber. Matches the most common high-signal formats the
 * scanner flags. Replaces the middle of the match with "•••" so the line is
 * still syntactically recognizable to the LLM but the secret value is gone.
 */
function redactSecrets(text) {
  const patterns = [
    /sk-[A-Za-z0-9]{20,}/g,                    // OpenAI
    /ghp_[A-Za-z0-9]{20,}/g,                   // GitHub
    /AKIA[0-9A-Z]{16}/g,                       // AWS
    /Bearer\s+[A-Za-z0-9._\-]{20,}/g,          // Bearer tokens
    /["']eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+["']/g, // JWTs in strings
  ];
  let count = 0;
  let redacted = text;
  for (const pat of patterns) {
    redacted = redacted.replace(pat, (m) => {
      count++;
      return m.slice(0, 4) + "•••REDACTED•••" + m.slice(-4);
    });
  }
  return { redacted, count };
}
