#!/usr/bin/env node

/**
 * Lightweight pre-submission secret sweep.
 *
 * This intentionally scans the working tree, not git history. History scrub
 * remains a separate release task because it rewrites commits.
 */

import fs from "fs";
import path from "path";

const ROOT = path.resolve(new URL("..", import.meta.url).pathname);
const KEY_RE = new RegExp("\\bsk-(?:proj|live|test|svc|ant)-[A-Za-z0-9_-]{20,}\\b", "g");

const SKIP_DIRS = new Set([
  ".git",
  "CONTEXT",
  "context",
  "docs",
  "node_modules",
  "db",
  "logs",
  "coverage",
  ".cache",
  ".next",
  "dist",
]);

const SKIP_EXTS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".pdf",
  ".pptx",
  ".db",
  ".sqlite",
  ".sqlite3",
]);
const OPENAI_PLACEHOLDER = "sk-proj-" + "REPLACE_ME_WITH_YOUR_OWN_OPENAI_KEY";

function shouldSkip(filePath, dirent) {
  if (dirent.isDirectory()) return SKIP_DIRS.has(dirent.name);
  if (dirent.name === ".env") return true;
  return SKIP_EXTS.has(path.extname(filePath).toLowerCase());
}

function allowedMatch(filePath, value) {
  const rel = path.relative(ROOT, filePath);
  if (rel === ".env.example" && value === OPENAI_PLACEHOLDER) return true;
  return false;
}

function* walk(dir) {
  for (const dirent of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, dirent.name);
    if (shouldSkip(full, dirent)) continue;
    if (dirent.isDirectory()) yield* walk(full);
    else if (dirent.isFile()) yield full;
  }
}

const findings = [];

for (const file of walk(ROOT)) {
  let text = "";
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    continue;
  }
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    for (const match of lines[i].matchAll(KEY_RE)) {
      if (allowedMatch(file, match[0])) continue;
      findings.push(`${path.relative(ROOT, file)}:${i + 1}`);
    }
  }
}

if (findings.length) {
  console.error("Potential OpenAI API key(s) found:");
  for (const finding of findings) console.error(`  ${finding}`);
  process.exit(1);
}

console.log("secret sweep ok");
