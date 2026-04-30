/**
 * SecureLoop - AutoFix Orchestrator
 * by Jorge Elizalde
 *
 * Single entry point for the autofix flow. Scans the skill, classifies each
 * finding, applies Tier 1 fixes (dry-run by default), drafts Tier 2 patches
 * via the LLM provider (persisted as PENDING, never auto-applied), and flags
 * Tier 3 for manual review.
 *
 * Used by:
 *   - /secureloop-* slash commands in index.js
 *   - dashboard "Review & Fix" drawer (v2)
 */

import { scanAndSave }       from "../scan.js";
import { resolveSkillPath }  from "../resolveSkill.js";
import { bucketFindings }    from "./classify.js";
import { applyFix }          from "./tier1.js";
import { proposeFix, TIER2_ENABLED } from "./tier2.js";
import { flagForReview }     from "./tier3.js";
import { parseUnifiedDiff, validateDiff, applyDiff } from "./diff.js";
import { buildTier2Context } from "./context.js";
import { logAudit }          from "../audit.js";
import db from "../db.js";

// autofix_runs — history of every autofix pass
// autofix_patches — pending Tier-2 patches awaiting human approval
db.exec(`
  CREATE TABLE IF NOT EXISTS autofix_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER,
    skill_name   TEXT NOT NULL,
    dry_run      INTEGER NOT NULL,
    tier1_total  INTEGER NOT NULL,
    tier1_applied INTEGER NOT NULL,
    tier2_total  INTEGER NOT NULL,
    tier3_total  INTEGER NOT NULL,
    report       TEXT NOT NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS autofix_patches (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER,
    skill_name    TEXT NOT NULL,
    file          TEXT NOT NULL,
    line          INTEGER,
    fix_reason    TEXT NOT NULL,
    severity      TEXT,
    category      TEXT,
    finding_msg   TEXT,
    rationale     TEXT,
    confidence    REAL,
    diff          TEXT NOT NULL,
    env_vars      TEXT,
    model         TEXT,
    status        TEXT NOT NULL DEFAULT 'pending',   -- pending|approved|rejected|applied|failed
    reviewer      TEXT,
    review_notes  TEXT,
    reviewed_at   DATETIME,
    applied_at    DATETIME,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

/**
 * Run a full autofix pass against a skill.
 *
 * @param {string}   skillName
 * @param {object}   [options]
 * @param {boolean}  [options.dryRun=true]       If true, Tier 1 never writes to disk.
 * @param {boolean}  [options.skipScan=false]    Use options.findings instead of scanning.
 * @param {object[]} [options.findings]
 * @param {string[]} [options.onlyReasons]       Filter Tier 1 by reason.
 * @param {boolean}  [options.tier2=TIER2_ENABLED] Call LLM for Tier 2. Default: global flag.
 * @param {string}   [options.apiKey]            Override OPENAI_API_KEY.
 * @param {string}   [options.model]             Override SECURELOOP_TIER2_MODEL.
 * @param {string}   [options.provider]          Override SECURELOOP_TIER2_PROVIDER.
 * @param {string}   [options.reviewer]          Audit attribution.
 * @returns {Promise<object>} report
 */
export async function runAutofix(skillName, options = {}) {
  const dryRun       = options.dryRun !== false;
  const skipScan     = options.skipScan === true;
  const tier2On      = options.tier2 !== false && TIER2_ENABLED;
  const onlyReasons  = Array.isArray(options.onlyReasons) && options.onlyReasons.length > 0
    ? new Set(options.onlyReasons)
    : null;
  const reviewer     = options.reviewer || "cli";

  // 1. Scan (unless caller already has findings)
  let scanResult = null;
  let findings = options.findings;
  if (!skipScan) {
    scanResult = await scanAndSave(skillName, { respectLists: false });
    if (scanResult.skipped) {
      return {
        skillName,
        dryRun,
        error: `Skipped: ${scanResult.skipped}`,
        scan:  scanResult,
      };
    }
    findings = scanResult.findings;
  }
  if (!findings) findings = [];

  const skillPath = resolveSkillPath(skillName);
  if (!skillPath) {
    return { skillName, dryRun, error: "Could not resolve skill path" };
  }

  // 2. Classify findings into tiers
  const { tier1, tier2, tier3 } = bucketFindings(findings);

  // 3. Tier 1 — apply (or preview) deterministic fixes
  const tier1Results = [];
  for (const f of tier1) {
    const expectedReason = f._fixReason;
    if (onlyReasons && !onlyReasons.has(expectedReason)) {
      tier1Results.push({
        finding: summarizeFinding(f),
        applied: false,
        reason: expectedReason,
        changed: [],
        error: `Skipped: reason '${expectedReason}' not in filter [${[...onlyReasons].join(", ")}]`,
      });
      continue;
    }
    const result = await applyFix(f, skillPath, { dryRun });
    tier1Results.push({ finding: summarizeFinding(f), ...result });
  }

  // 4. Tier 2 — call LLM for each; persist PENDING patches. NEVER auto-apply.
  const tier2Results = [];
  for (const f of tier2) {
    let proposal;
    if (!tier2On) {
      proposal = { proposed: false, reason: "tier2-off", error: "Tier 2 disabled for this run" };
    } else {
      proposal = await proposeFix(f, skillPath, {
        apiKey: options.apiKey,
        model:  options.model,
        provider: options.provider,
        fixReason: f._fixReason,
      });
    }
    tier2Results.push({ finding: summarizeFinding(f), ...proposal });
  }

  // 5. Tier 3 — flag only
  const tier3Results = tier3.map((f) => ({
    finding: summarizeFinding(f),
    ...flagForReview(f),
  }));

  const report = {
    skillName,
    skillPath,
    dryRun,
    tier2On,
    scanId: scanResult?.scanId ?? null,
    counts: {
      tier1Total:   tier1.length,
      tier1Applied: tier1Results.filter((r) => r.applied).length,
      tier2Total:   tier2.length,
      tier2Drafted: tier2Results.filter((r) => r.proposed).length,
      tier3Total:   tier3.length,
    },
    tier1: tier1Results,
    tier2: tier2Results,
    tier3: tier3Results,
  };

  // 6. Persist run
  const runInsert = db.prepare(
    `INSERT INTO autofix_runs
       (scan_id, skill_name, dry_run, tier1_total, tier1_applied, tier2_total, tier3_total, report)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    report.scanId,
    skillName,
    dryRun ? 1 : 0,
    report.counts.tier1Total,
    report.counts.tier1Applied,
    report.counts.tier2Total,
    report.counts.tier3Total,
    JSON.stringify(report)
  );
  const runId = Number(runInsert.lastInsertRowid);
  report.runId = runId;

  // 7. Persist Tier-2 pending patches (if any were drafted)
  for (let i = 0; i < tier2Results.length; i++) {
    const t = tier2Results[i];
    if (!t.proposed || !t.diff) continue;
    const f = tier2[i];
    const insert = db.prepare(
      `INSERT INTO autofix_patches
        (run_id, skill_name, file, line, fix_reason, severity, category, finding_msg,
         rationale, confidence, diff, env_vars, model, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`
    ).run(
      runId,
      skillName,
      t.context?.file || f.detail || "",
      t.context?.line || f.line || null,
      f._fixReason || "suggestfix",
      f.severity,
      f.category,
      f.message,
      t.rationale || null,
      t.confidence ?? null,
      t.diff,
      JSON.stringify(t.envVars || []),
      t.model || null
    );
    t.patchId = Number(insert.lastInsertRowid);
  }

  logAudit({
    actor:  reviewer,
    action: "autofix-run",
    target: skillName,
    meta: {
      runId,
      dryRun,
      tier2On,
      tier1Applied: report.counts.tier1Applied,
      tier2Drafted: report.counts.tier2Drafted,
      tier3Total:   report.counts.tier3Total,
    },
  });

  return report;
}

function summarizeFinding(f) {
  return {
    severity: f.severity,
    category: f.category,
    message:  f.message,
    detail:   f.detail,
    package:  f.package,
    fix:      f.fix,
  };
}

/**
 * Run autofix against every installed skill in ~/.openclaw/extensions/.
 */
export async function runAutofixAll(options = {}) {
  const fs   = await import("fs");
  const os   = await import("os");
  const path = await import("path");
  const extensionsDir = path.join(os.homedir(), ".openclaw", "extensions");

  if (!fs.existsSync(extensionsDir)) {
    return {
      skills: [],
      totals: { tier1Total: 0, tier1Applied: 0, tier2Total: 0, tier3Total: 0, errors: 0 },
      error:  `No extensions directory at ${extensionsDir}`,
    };
  }

  const entries = fs.readdirSync(extensionsDir, { withFileTypes: true })
    .filter((e) => e.isDirectory() && !e.name.startsWith("."))
    .map((e) => e.name);

  const results = [];
  const totals  = { tier1Total: 0, tier1Applied: 0, tier2Total: 0, tier3Total: 0, errors: 0 };

  for (const skill of entries) {
    try {
      const report = await runAutofix(skill, options);
      results.push(report);
      if (report.error) {
        totals.errors++;
      } else {
        totals.tier1Total   += report.counts.tier1Total;
        totals.tier1Applied += report.counts.tier1Applied;
        totals.tier2Total   += report.counts.tier2Total;
        totals.tier3Total   += report.counts.tier3Total;
      }
    } catch (err) {
      results.push({ skillName: skill, error: err.message });
      totals.errors++;
    }
  }

  return { skills: results, totals };
}

// ─── TIER 2 APPROVAL / APPLY / REJECT ─────────────────────────────────────────

/**
 * List pending Tier-2 patches. Optionally filter by skill.
 * @param {object} [filters]
 * @param {string} [filters.skillName]
 * @param {string} [filters.status]        pending|approved|rejected|applied|failed
 * @param {number} [filters.limit=100]
 */
export function listTier2Patches(filters = {}) {
  const { skillName, status, limit = 100 } = filters;
  const parts = [];
  const params = [];
  if (skillName) { parts.push("skill_name = ?"); params.push(skillName); }
  if (status)    { parts.push("status = ?");     params.push(status); }
  const where = parts.length ? `WHERE ${parts.join(" AND ")}` : "";
  return db.prepare(
    `SELECT id, run_id, skill_name, file, line, fix_reason, severity, category,
            finding_msg, rationale, confidence, env_vars, model, status,
            reviewer, review_notes, reviewed_at, applied_at, created_at
     FROM autofix_patches ${where}
     ORDER BY created_at DESC
     LIMIT ?`
  ).all(...params, limit);
}

export function getTier2Patch(patchId) {
  return db.prepare(`SELECT * FROM autofix_patches WHERE id = ?`).get(patchId);
}

/**
 * Approve a pending Tier-2 patch and (optionally) apply it immediately.
 * Approval REQUIRES a reviewer string (who approved it). Apply is atomic and
 * uses the same diff validator as the initial proposal.
 *
 * @param {number} patchId
 * @param {object} [options]
 * @param {boolean} [options.apply=false]  if true, write to disk after approval
 * @param {string}  [options.reviewer]
 * @param {string}  [options.notes]
 */
export async function approveTier2Patch(patchId, options = {}) {
  const apply    = options.apply === true;
  const reviewer = options.reviewer || "cli";
  const notes    = options.notes || null;

  const patch = getTier2Patch(patchId);
  if (!patch) return { ok: false, error: "Patch not found" };
  if (patch.status !== "pending" && patch.status !== "approved") {
    return { ok: false, error: `Patch status is '${patch.status}' — cannot approve.` };
  }

  // Mark approved first so the audit trail records the intent even if apply fails.
  db.prepare(
    `UPDATE autofix_patches
     SET status='approved', reviewer=?, review_notes=?, reviewed_at=CURRENT_TIMESTAMP
     WHERE id=?`
  ).run(reviewer, notes, patchId);

  logAudit({
    actor:  reviewer,
    action: "tier2-approve",
    target: patch.skill_name,
    meta:   { patchId, apply, notes },
  });

  if (!apply) {
    return { ok: true, status: "approved", patchId };
  }

  // Resolve skill path and re-validate the stored diff before applying.
  const skillPath = resolveSkillPath(patch.skill_name);
  if (!skillPath) {
    db.prepare(`UPDATE autofix_patches SET status='failed' WHERE id=?`).run(patchId);
    return { ok: false, error: "Could not resolve skill path" };
  }
  const finding = {
    severity: patch.severity, category: patch.category,
    message:  patch.finding_msg, detail: `${patch.file}${patch.line ? `:${patch.line}` : ""}`,
    line:     patch.line,
  };
  const ctx = buildTier2Context(finding, skillPath);
  if (!ctx.ok) {
    db.prepare(`UPDATE autofix_patches SET status='failed' WHERE id=?`).run(patchId);
    return { ok: false, error: `Context rebuild failed: ${ctx.reason}` };
  }
  const parsed = parseUnifiedDiff(patch.diff);
  const valid  = validateDiff(parsed, ctx, skillPath);
  if (!valid.ok) {
    db.prepare(`UPDATE autofix_patches SET status='failed' WHERE id=?`).run(patchId);
    return { ok: false, error: `Diff re-validation failed: ${valid.reason}` };
  }
  const applyRes = applyDiff(parsed, valid.absFile, { dryRun: false });
  if (!applyRes.ok || !applyRes.applied) {
    db.prepare(`UPDATE autofix_patches SET status='failed' WHERE id=?`).run(patchId);
    logAudit({ actor: reviewer, action: "tier2-apply-failed", target: patch.skill_name,
               meta: { patchId, error: applyRes.error || applyRes.reason } });
    return { ok: false, error: `Apply failed: ${applyRes.error || applyRes.reason}` };
  }

  db.prepare(`UPDATE autofix_patches SET status='applied', applied_at=CURRENT_TIMESTAMP WHERE id=?`).run(patchId);
  logAudit({ actor: reviewer, action: "tier2-apply", target: patch.skill_name,
             meta: { patchId, file: valid.absFile } });

  return { ok: true, status: "applied", patchId, file: valid.absFile };
}

export function rejectTier2Patch(patchId, options = {}) {
  const reviewer = options.reviewer || "cli";
  const notes    = options.notes || null;
  const patch = getTier2Patch(patchId);
  if (!patch) return { ok: false, error: "Patch not found" };
  if (patch.status === "applied") {
    return { ok: false, error: "Patch is already applied; cannot reject." };
  }
  db.prepare(
    `UPDATE autofix_patches
     SET status='rejected', reviewer=?, review_notes=?, reviewed_at=CURRENT_TIMESTAMP
     WHERE id=?`
  ).run(reviewer, notes, patchId);
  logAudit({ actor: reviewer, action: "tier2-reject", target: patch.skill_name,
             meta: { patchId, notes } });
  return { ok: true, status: "rejected", patchId };
}
