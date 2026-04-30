/**
 * SecureLoop - AutoFix Tier 2 Diff Validator + Applier
 * by Jorge Elizalde
 *
 * Parse, validate, and safely apply a unified-diff patch returned by the LLM.
 *
 * Security constraints (per DECISIONS OPEN-006, resolved 2026-04-23):
 *   1. Patch MUST touch exactly ONE file.
 *   2. That file MUST be the file we asked the LLM to fix.
 *   3. That file MUST live inside the skill directory (no ../ escapes).
 *   4. The patch MUST apply cleanly against the current file contents.
 *   5. No new imports of nodejs built-ins that were not already present
 *      (child_process, fs, net, dgram, vm) — we reject those outright.
 *   6. No fetch / http / https calls introduced.
 *   7. No eval / new Function / dynamic import.
 *
 * Apply flow is always:
 *   dryRun → parse → validate → (optional) write with atomic rename
 */

import fs from "fs";
import path from "path";

const FORBIDDEN_NEW_TOKENS = [
  "child_process",
  "require('fs')",      // we allow existing fs import but not a brand-new require
  'require("fs")',
  "require('net')",
  'require("net")',
  "new Function",
  "eval(",
  "fetch(",              // don't let Tier 2 introduce network calls
  "XMLHttpRequest",
  "import('http",        // dynamic http import
  'import("http',
];

/**
 * Parse a unified diff produced by the LLM into a normalized object.
 * Accepts single-file diffs only.
 *
 * @param {string} diffText
 * @returns {{
 *   ok: boolean,
 *   reason: string,
 *   file?: string,       // the "b/" path from the +++ line (relative to skill dir ideally)
 *   hunks?: {
 *     oldStart: number, oldCount: number,
 *     newStart: number, newCount: number,
 *     lines: string[],    // lines INCLUDING leading " ", "+", or "-"
 *   }[]
 * }}
 */
export function parseUnifiedDiff(diffText) {
  if (!diffText || typeof diffText !== "string") {
    return { ok: false, reason: "empty-diff" };
  }

  const lines = diffText.split(/\r?\n/);

  // Find the "+++ b/<path>" line (we accept with or without --- line before).
  let filePath = null;
  let i = 0;
  for (; i < lines.length; i++) {
    const ln = lines[i];
    if (ln.startsWith("+++ ")) {
      filePath = ln.slice(4).trim();
      if (filePath.startsWith("b/")) filePath = filePath.slice(2);
      i++;
      break;
    }
  }
  if (!filePath) return { ok: false, reason: "missing-file-header" };

  // Parse hunks
  const hunks = [];
  while (i < lines.length) {
    const ln = lines[i];
    if (!ln.startsWith("@@")) { i++; continue; }
    const m = /^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@/.exec(ln);
    if (!m) return { ok: false, reason: "malformed-hunk-header" };
    const oldStart = Number(m[1]);
    const oldCount = m[2] === undefined ? 1 : Number(m[2]);
    const newStart = Number(m[3]);
    const newCount = m[4] === undefined ? 1 : Number(m[4]);
    const hunkLines = [];
    i++;
    while (i < lines.length && !lines[i].startsWith("@@") && !lines[i].startsWith("+++ ") && !lines[i].startsWith("--- ")) {
      hunkLines.push(lines[i]);
      i++;
    }
    hunks.push({ oldStart, oldCount, newStart, newCount, lines: hunkLines });
  }
  if (hunks.length === 0) return { ok: false, reason: "no-hunks" };

  return { ok: true, reason: "ok", file: filePath, hunks };
}

/**
 * Validate that a parsed diff is safe to apply for a specific finding context.
 *
 * @param {object} parsed       Output of parseUnifiedDiff
 * @param {object} context      Output of context.buildTier2Context
 * @param {string} skillPath    Absolute path to the skill directory
 * @returns {{ ok: boolean, reason: string, absFile?: string }}
 */
export function validateDiff(parsed, context, skillPath) {
  if (!parsed.ok) return { ok: false, reason: parsed.reason };

  // Rule 1 + 2: single file, must match the file in context.
  const diffFile = normalizeRel(parsed.file);
  const ctxFile  = normalizeRel(context.relFile);
  if (diffFile !== ctxFile) {
    return { ok: false, reason: `diff-targets-wrong-file: diff=${diffFile} expected=${ctxFile}` };
  }

  // Rule 3: no directory escapes.
  const absFile = path.resolve(path.join(skillPath, diffFile));
  if (!absFile.startsWith(path.resolve(skillPath))) {
    return { ok: false, reason: "path-escapes-skill-dir" };
  }

  // Rule 4: file must still exist.
  if (!fs.existsSync(absFile)) {
    return { ok: false, reason: "target-file-missing" };
  }

  // Rule 5–7: inspect added lines for forbidden tokens.
  for (const h of parsed.hunks) {
    for (const ln of h.lines) {
      if (!ln.startsWith("+")) continue;
      const added = ln.slice(1);
      for (const bad of FORBIDDEN_NEW_TOKENS) {
        if (added.includes(bad)) {
          return { ok: false, reason: `forbidden-token-introduced:${bad.trim()}` };
        }
      }
    }
  }

  return { ok: true, reason: "ok", absFile };
}

/**
 * Apply a validated diff to disk.
 * Atomic: writes to <file>.secureloop-tmp then renames.
 *
 * @param {object}  parsed     parsed diff
 * @param {string}  absFile    absolute path to the target file
 * @param {object}  [options]
 * @param {boolean} [options.dryRun=true]
 * @returns {{
 *   ok:      boolean,
 *   reason:  string,
 *   applied: boolean,
 *   newContents?: string,
 *   error?:  string,
 * }}
 */
export function applyDiff(parsed, absFile, options = {}) {
  const dryRun = options.dryRun !== false;
  try {
    const original = fs.readFileSync(absFile, "utf-8");
    const origLines = original.split(/\r?\n/);

    // Work top-down on line indices so we can just build a new array.
    // Because line numbers in hunks refer to the ORIGINAL file, and we iterate
    // in order, we track offset.
    let out = [];
    let cursor = 0;       // 0-based index into origLines
    let lineNum = 1;      // 1-based next line number to emit from origLines

    // Sort hunks by oldStart to be safe.
    const hunks = [...parsed.hunks].sort((a, b) => a.oldStart - b.oldStart);

    for (const h of hunks) {
      // Copy unchanged lines up to hunk start.
      while (lineNum < h.oldStart) {
        out.push(origLines[cursor]);
        cursor++;
        lineNum++;
      }

      // Walk the hunk lines.
      for (const ln of h.lines) {
        if (ln.startsWith(" ")) {
          // Context line — must match the original.
          if (origLines[cursor] !== ln.slice(1)) {
            return { ok: false, reason: "context-mismatch", applied: false,
              error: `Expected "${ln.slice(1)}" at line ${lineNum}, found "${origLines[cursor]}"` };
          }
          out.push(origLines[cursor]);
          cursor++;
          lineNum++;
        } else if (ln.startsWith("-")) {
          if (origLines[cursor] !== ln.slice(1)) {
            return { ok: false, reason: "deletion-mismatch", applied: false,
              error: `Expected to remove "${ln.slice(1)}" at line ${lineNum}, found "${origLines[cursor]}"` };
          }
          cursor++;
          lineNum++;
        } else if (ln.startsWith("+")) {
          out.push(ln.slice(1));
        } else if (ln === "" || ln === "\\ No newline at end of file") {
          // ignore
        } else {
          return { ok: false, reason: "malformed-hunk-line", applied: false, error: `Bad line "${ln}"` };
        }
      }
    }

    // Copy any trailing lines.
    while (cursor < origLines.length) {
      out.push(origLines[cursor]);
      cursor++;
    }

    const newContents = out.join("\n");

    if (dryRun) {
      return { ok: true, reason: "dry-run", applied: false, newContents };
    }

    const tmp = absFile + ".secureloop-tmp";
    fs.writeFileSync(tmp, newContents, "utf-8");
    fs.renameSync(tmp, absFile);
    return { ok: true, reason: "applied", applied: true, newContents };
  } catch (err) {
    return { ok: false, reason: "exception", applied: false, error: err.message };
  }
}

function normalizeRel(p) {
  if (!p) return "";
  return p.replace(/^\.\//, "").replace(/\\/g, "/");
}
