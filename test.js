/**
 * SecureLoop - Local Test Runner
 * Scans a real installed OpenClaw extension and persists the result
 * through the same code path the slash command uses.
 *
 * Usage:
 *   node test.js                 # scans "clawsaver" and exits
 *   node test.js --dashboard     # also starts the dashboard and stays running
 *   node test.js some-other-skill
 *   node test.js some-other-skill --dashboard
 */

import path from "path";
import os from "os";
import { scanAndSave } from "./lib/scan.js";
import { resolveAuditTarget } from "./lib/targets.js";
import { startDashboard } from "./dashboard/server.js";

// ─── ARGS ─────────────────────────────────────────────────────────────────────
const args          = process.argv.slice(2);
const keepDashboard = args.includes("--dashboard");
const positional    = args.filter(a => !a.startsWith("--"));
const SKILL_NAME    = positional[0] || "clawsaver";
const TARGET        = resolveAuditTarget(SKILL_NAME);
const SKILL_PATH    = TARGET.root || path.join(os.homedir(), ".openclaw", "extensions", SKILL_NAME);

console.log("🛡️  SecureLoop Test Runner\n");
console.log(`📁 Target: ${SKILL_PATH}\n`);

// ─── OPTIONALLY START DASHBOARD ───────────────────────────────────────────────
if (keepDashboard) {
  await startDashboard(false);
  console.log("✅ Dashboard running at http://localhost:3334\n");
}

// ─── RUN SCAN (writes to DB) ──────────────────────────────────────────────────
console.log(`🔍 Running full scan on '${SKILL_NAME}'...\n`);

// respectLists:false — tests always scan, never skip via blocklist/whitelist
const result = await scanAndSave(SKILL_NAME, { respectLists: false });

const { findings, score, level, scanId } = result;

// ─── SUMMARY ──────────────────────────────────────────────────────────────────
console.log("─────────────────────────────────────────");
console.log(`📊 SCAN RESULTS — ${SKILL_NAME}`);
console.log("─────────────────────────────────────────");
console.log(`Scan ID:             #${scanId}  (saved to db/secureloop.db)`);
console.log(`Total findings:      ${findings.length}`);
console.log(`  🔴 critical:       ${findings.filter(f => f.severity === "critical").length}`);
console.log(`  🟠 high:           ${findings.filter(f => f.severity === "high").length}`);
console.log(`  🟡 medium:         ${findings.filter(f => f.severity === "medium").length}`);
console.log(`  🔵 low:            ${findings.filter(f => f.severity === "low").length}`);
console.log("─────────────────────────────────────────\n");

// ─── GROUPED DETAILS ──────────────────────────────────────────────────────────
const byLabel = {
  critical: "🔴 CRITICAL",
  high:     "🟠 HIGH",
  medium:   "🟡 MEDIUM",
  low:      "🔵 LOW",
};

for (const sev of ["critical", "high", "medium", "low"]) {
  const group = findings.filter(f => f.severity === sev);
  if (!group.length) continue;
  console.log(byLabel[sev]);
  group.forEach(f => {
    console.log(`   • ${f.message}`);
    if (f.detail) console.log(`     ${f.detail}`);
  });
  console.log();
}

// ─── RISK SCORE ───────────────────────────────────────────────────────────────
console.log("─────────────────────────────────────────");
console.log(`🎯 RISK SCORE: ${score}/100 — ${level}`);
console.log("─────────────────────────────────────────\n");

if (keepDashboard) {
  console.log("📊 Dashboard staying alive at http://localhost:3334 — press Ctrl+C to exit.\n");
  // Let the event loop keep the dashboard process running.
} else {
  console.log("📊 View dashboard with: node test.js --dashboard\n");
  // Explicit exit — otherwise better-sqlite3's handle keeps Node alive briefly.
  process.exit(0);
}
