/**
 * SecureLoop - Security Policy
 * by Jorge Elizalde
 *
 * Persists the user's organization-level policy:
 *   - risk score thresholds (critical/high/medium cutoffs used by the dashboard)
 *   - severity weights (overrides lib/scan.js defaults for risk calc)
 *   - custom regex patterns for secret detection (organization-specific tokens)
 *   - auto-block threshold (if a skill scores ≥ N, auto-add to blocklist)
 *   - "require-manual-approval-for" tags (categories that can NEVER be Tier-1 auto-fixed)
 *
 * Policy is versioned: every change is stored as a new row, so the dashboard
 * can show an audit trail of policy edits.
 *
 * NEVER mutates lib/scan.js behavior directly — lib/scan.js reads the current
 * policy at scan time via `getActivePolicy()`.
 */

import db from "./db.js";
import { logAudit } from "./audit.js";

db.exec(`
  CREATE TABLE IF NOT EXISTS policy (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    version         INTEGER NOT NULL,
    body            TEXT NOT NULL,
    author          TEXT,
    notes           TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    active          INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_policy_active ON policy(active);
`);

export const DEFAULT_POLICY = Object.freeze({
  thresholds: {
    criticalCutoff: 70,   // risk_score >= this → Dangerous
    cautionCutoff:  40,   // risk_score >= this → Caution (else Safe)
  },
  severityWeights: {
    critical: 40,
    high:     25,
    medium:   10,
    low:      5,
  },
  customSecretPatterns: [
    // Each entry: { name, pattern (source string, no flags), description }
    // Example:
    // { name: "acme-token", pattern: "ACME_[A-Z0-9]{32}", description: "Acme Corp API token" },
  ],
  autoBlockThreshold: null,            // e.g. 90 → any skill ≥ 90 auto-blocks
  requireManualApprovalFor: [],        // e.g. ["dangerous-code", "obfuscation"]
  tier2: {
    enabled: true,
    defaultModel: "gpt-5.3-codex",
    maxPatchesPerRun: 25,
  },
  retention: {
    scansDays:   180,
    auditDays:   365,
    patchesDays: 365,
  },
});

function rowToPolicy(row) {
  if (!row) return null;
  let body;
  try { body = JSON.parse(row.body); } catch { body = { ...DEFAULT_POLICY }; }
  return {
    id: row.id,
    version: row.version,
    author: row.author,
    notes: row.notes,
    createdAt: row.created_at,
    active: !!row.active,
    body: mergeDefaults(body),
  };
}

function mergeDefaults(body) {
  return {
    ...DEFAULT_POLICY,
    ...body,
    thresholds:      { ...DEFAULT_POLICY.thresholds,      ...(body?.thresholds      || {}) },
    severityWeights: { ...DEFAULT_POLICY.severityWeights, ...(body?.severityWeights || {}) },
    tier2:           { ...DEFAULT_POLICY.tier2,           ...(body?.tier2           || {}) },
    retention:       { ...DEFAULT_POLICY.retention,       ...(body?.retention       || {}) },
    customSecretPatterns: Array.isArray(body?.customSecretPatterns) ? body.customSecretPatterns : [],
    requireManualApprovalFor: Array.isArray(body?.requireManualApprovalFor) ? body.requireManualApprovalFor : [],
  };
}

/** Returns the currently-active policy, seeded with defaults if none exists. */
export function getActivePolicy() {
  const row = db.prepare(`SELECT * FROM policy WHERE active = 1 ORDER BY version DESC LIMIT 1`).get();
  if (row) return rowToPolicy(row);

  // Seed default policy as v1.
  const body = JSON.stringify(DEFAULT_POLICY);
  const info = db.prepare(
    `INSERT INTO policy (version, body, author, notes, active) VALUES (1, ?, 'system', 'Seed default policy', 1)`
  ).run(body);
  return rowToPolicy({ id: Number(info.lastInsertRowid), version: 1, body, author: "system", notes: "Seed default policy", created_at: new Date().toISOString(), active: 1 });
}

/** Returns the full version history. */
export function listPolicyVersions({ limit = 50 } = {}) {
  const rows = db.prepare(
    `SELECT * FROM policy ORDER BY version DESC LIMIT ?`
  ).all(Math.min(Math.max(Number(limit) || 50, 1), 500));
  return rows.map(rowToPolicy);
}

/**
 * Validate a policy body. Returns `{ok:true, body}` or `{ok:false, error}`.
 * Rejects malformed thresholds/weights, bad regex patterns, or unreasonable values.
 */
export function validatePolicy(raw) {
  if (!raw || typeof raw !== "object") return { ok: false, error: "Policy must be an object" };
  const body = mergeDefaults(raw);

  const { thresholds, severityWeights, customSecretPatterns, autoBlockThreshold, tier2, retention } = body;

  if (!Number.isInteger(thresholds.criticalCutoff) || thresholds.criticalCutoff < 1 || thresholds.criticalCutoff > 100)
    return { ok: false, error: "thresholds.criticalCutoff must be an integer 1–100" };
  if (!Number.isInteger(thresholds.cautionCutoff) || thresholds.cautionCutoff < 0 || thresholds.cautionCutoff > 100)
    return { ok: false, error: "thresholds.cautionCutoff must be an integer 0–100" };
  if (thresholds.cautionCutoff >= thresholds.criticalCutoff)
    return { ok: false, error: "cautionCutoff must be strictly less than criticalCutoff" };

  for (const k of ["critical", "high", "medium", "low"]) {
    const v = severityWeights[k];
    if (!Number.isFinite(v) || v < 0 || v > 100) return { ok: false, error: `severityWeights.${k} must be 0–100` };
  }
  if (severityWeights.critical < severityWeights.high ||
      severityWeights.high     < severityWeights.medium ||
      severityWeights.medium   < severityWeights.low) {
    return { ok: false, error: "severityWeights must be non-increasing: critical ≥ high ≥ medium ≥ low" };
  }

  if (!Array.isArray(customSecretPatterns)) return { ok: false, error: "customSecretPatterns must be an array" };
  for (let i = 0; i < customSecretPatterns.length; i++) {
    const p = customSecretPatterns[i];
    if (!p || typeof p !== "object") return { ok: false, error: `customSecretPatterns[${i}] must be an object` };
    if (!p.name || !p.pattern) return { ok: false, error: `customSecretPatterns[${i}] requires name & pattern` };
    if (String(p.pattern).length > 500) return { ok: false, error: `customSecretPatterns[${i}].pattern too long (max 500)` };
    try { new RegExp(p.pattern); } catch (e) {
      return { ok: false, error: `customSecretPatterns[${i}].pattern is not a valid regex: ${e.message}` };
    }
  }

  if (autoBlockThreshold !== null && autoBlockThreshold !== undefined) {
    if (!Number.isInteger(autoBlockThreshold) || autoBlockThreshold < 1 || autoBlockThreshold > 100)
      return { ok: false, error: "autoBlockThreshold must be null or an integer 1–100" };
  }

  if (typeof tier2.enabled !== "boolean") return { ok: false, error: "tier2.enabled must be boolean" };
  if (tier2.maxPatchesPerRun != null && (!Number.isInteger(tier2.maxPatchesPerRun) || tier2.maxPatchesPerRun < 0 || tier2.maxPatchesPerRun > 500))
    return { ok: false, error: "tier2.maxPatchesPerRun must be an integer 0–500" };
  if (tier2.defaultModel && typeof tier2.defaultModel !== "string")
    return { ok: false, error: "tier2.defaultModel must be a string" };

  for (const k of ["scansDays", "auditDays", "patchesDays"]) {
    const v = retention[k];
    if (!Number.isInteger(v) || v < 1 || v > 3650) return { ok: false, error: `retention.${k} must be 1–3650` };
  }

  return { ok: true, body };
}

/** Save a new policy version and make it the active one. Returns the new policy. */
export function savePolicy(raw, { author = "dashboard", notes = null } = {}) {
  const v = validatePolicy(raw);
  if (!v.ok) return { ok: false, error: v.error };

  const current = db.prepare(`SELECT MAX(version) AS v FROM policy`).get();
  const nextVersion = (current?.v || 0) + 1;

  db.prepare(`UPDATE policy SET active = 0 WHERE active = 1`).run();
  const info = db.prepare(
    `INSERT INTO policy (version, body, author, notes, active) VALUES (?, ?, ?, ?, 1)`
  ).run(nextVersion, JSON.stringify(v.body), author, notes);

  logAudit({
    actor: author, action: "policy-update", target: "policy",
    meta: { version: nextVersion, notes: notes || null },
  });

  return { ok: true, policy: rowToPolicy({
    id: Number(info.lastInsertRowid), version: nextVersion,
    body: JSON.stringify(v.body), author, notes,
    created_at: new Date().toISOString(), active: 1,
  })};
}

/** Revert to a previous version (as a new version to preserve history). */
export function revertPolicy(version, { author = "dashboard" } = {}) {
  const row = db.prepare(`SELECT * FROM policy WHERE version = ?`).get(Number(version));
  if (!row) return { ok: false, error: "Version not found" };
  const body = JSON.parse(row.body);
  return savePolicy(body, { author, notes: `Revert to v${version}` });
}

export default {
  DEFAULT_POLICY,
  getActivePolicy,
  listPolicyVersions,
  validatePolicy,
  savePolicy,
  revertPolicy,
};
