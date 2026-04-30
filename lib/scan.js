/**
 * SecureLoop - Shared Scan Orchestrator
 * by Jorge Elizalde
 *
 * Single source of truth for running all scanners in parallel,
 * calculating the risk score, and persisting the scan to SQLite.
 *
 * Used by:
 *   - index.js          (slash command /secureloop-scan)
 *   - test.js           (local test runner)
 *   - (future) CLI, webhook, fs.watch auto-scan
 */

import { StaticScanner }     from "../scanner/static.js";
import { DependencyScanner } from "../scanner/dependencies.js";
import { PermissionAuditor } from "../scanner/permissions.js";
import { NetworkScanner }    from "../scanner/network.js";
import { SystemScanner }     from "../scanner/system.js";
import { BehaviorScanner }   from "../scanner/behavior.js";
import { enrichFindings }    from "./enrichFindings.js";
import db from "./db.js";

// ─── RISK SCORING ─────────────────────────────────────────────────────────────
export const SEVERITY_WEIGHTS = {
  critical: 40,
  high:     25,
  medium:   10,
  low:       5,
};

export function calculateRiskScore(findings) {
  const raw = findings.reduce(
    (sum, f) => sum + (SEVERITY_WEIGHTS[f.severity] || 0),
    0
  );
  return Math.min(raw, 100); // cap at 100 per CLAUDE.md rule
}

export function getRiskLevel(score) {
  if (score >= 70) return "🔴 DANGEROUS";
  if (score >= 40) return "🟡 CAUTION";
  return "🟢 SAFE";
}

// ─── BLOCK / WHITELIST HELPERS ────────────────────────────────────────────────
export function getBlocklistEntry(skillName) {
  return db
    .prepare(`SELECT * FROM blocklist WHERE skill_name = ?`)
    .get(skillName);
}

export function getWhitelistEntry(skillName) {
  return db
    .prepare(`SELECT * FROM whitelist WHERE skill_name = ?`)
    .get(skillName);
}

// ─── CORE SCAN ────────────────────────────────────────────────────────────────
/**
 * Run all scanners and persist the result.
 *
 * @param {string}  skillName               Skill to scan (e.g. "clawsaver")
 * @param {object}  [options]
 * @param {boolean} [options.respectLists=true]  If true, short-circuit on
 *                  blocklist/whitelist hits and do NOT write a scan row.
 * @returns {Promise<{
 *   skillName: string,
 *   findings:  object[],
 *   score:     number,
 *   level:     string,
 *   scanId:    number | null,   // null when skipped via blocklist/whitelist
 *   skipped:   false | "blocked" | "whitelisted",
 *   blockedReason?: string,
 * }>}
 */
export async function scanAndSave(skillName, options = {}) {
  const respectLists = options.respectLists !== false; // default true

  if (respectLists) {
    const blocked = getBlocklistEntry(skillName);
    if (blocked) {
      return {
        skillName,
        findings: [],
        score: 0,
        level: "🚫 BLOCKED",
        scanId: null,
        skipped: "blocked",
        blockedReason: blocked.reason || null,
      };
    }

    const trusted = getWhitelistEntry(skillName);
    if (trusted) {
      return {
        skillName,
        findings: [],
        score: 0,
        level: "✅ TRUSTED",
        scanId: null,
        skipped: "whitelisted",
      };
    }
  }

  // Run all scanners in parallel
  const [staticFindings, depFindings, permFindings, networkFindings, systemFindings, behaviorFindings] = await Promise.all([
    StaticScanner.scan(skillName),
    DependencyScanner.scan(skillName),
    PermissionAuditor.scan(skillName),
    NetworkScanner.scan(skillName),
    SystemScanner.scan(skillName),
    BehaviorScanner.scan(skillName),
  ]);

  const findings = enrichFindings([
    ...staticFindings,
    ...depFindings,
    ...permFindings,
    ...networkFindings,
    ...systemFindings,
    ...behaviorFindings,
  ]);
  const score    = calculateRiskScore(findings);
  const level    = getRiskLevel(score);

  // Persist
  const result = db
    .prepare(
      `INSERT INTO scans (skill_name, risk_score, risk_level, findings)
       VALUES (?, ?, ?, ?)`
    )
    .run(skillName, score, level, JSON.stringify(findings));

  return {
    skillName,
    findings,
    score,
    level,
    scanId: Number(result.lastInsertRowid),
    skipped: false,
  };
}
