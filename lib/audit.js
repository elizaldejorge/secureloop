/**
 * SecureLoop - Audit Log
 * by Jorge Elizalde
 *
 * Append-only local audit log of every sensitive action:
 *   - autofix runs (dry-run or not)
 *   - Tier-2 patch approve / reject / apply
 *   - dashboard logins (success / fail)
 *   - policy edits
 *   - export / report generations
 *
 * Stored in the same SQLite db (db/secureloop.db) so it ships with the
 * user's local install. Never leaves the machine.
 *
 * Used by:
 *   - lib/autofix/index.js   (autofix-run, tier2-approve, tier2-apply, tier2-reject)
 *   - lib/auth.js            (login-success, login-fail, logout)
 *   - lib/policy.js          (policy-update)
 *   - lib/reports.js         (report-export)
 *   - dashboard/server.js    (any authenticated mutating endpoint)
 */

import db from "./db.js";

db.exec(`
  CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT,
    meta       TEXT,
    ip         TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_audit_action     ON audit_log(action);
  CREATE INDEX IF NOT EXISTS idx_audit_actor      ON audit_log(actor);
`);

const INSERT = db.prepare(
  `INSERT INTO audit_log (actor, action, target, meta, ip, user_agent)
   VALUES (?, ?, ?, ?, ?, ?)`
);

/**
 * Record an audit entry. Non-throwing: audit failures must never break the
 * calling flow. Errors are swallowed and printed to stderr.
 *
 * @param {object} entry
 * @param {string} entry.actor       who did it (e.g. "cli", "dashboard:jorge", "system")
 * @param {string} entry.action      short verb (e.g. "autofix-run", "tier2-approve", "login")
 * @param {string} [entry.target]    what was acted on (e.g. skill name, patch id, "dashboard")
 * @param {object} [entry.meta]      structured extra data; JSON-stringified
 * @param {string} [entry.ip]        source IP, if available
 * @param {string} [entry.userAgent] user agent, if available
 * @returns {number|null} rowid of inserted log entry, or null on failure
 */
export function logAudit(entry = {}) {
  try {
    const actor     = String(entry.actor || "unknown");
    const action    = String(entry.action || "unknown");
    const target    = entry.target ? String(entry.target) : null;
    const metaJson  = entry.meta  != null ? JSON.stringify(entry.meta) : null;
    const ip        = entry.ip        ? String(entry.ip)        : null;
    const userAgent = entry.userAgent ? String(entry.userAgent) : null;
    const res = INSERT.run(actor, action, target, metaJson, ip, userAgent);
    return Number(res.lastInsertRowid);
  } catch (err) {
    // Audit must never throw — worst case, log to stderr.
    console.error("[secureloop:audit] Failed to write audit entry:", err?.message || err);
    return null;
  }
}

/**
 * Query audit log with simple filters. Intended for dashboard & CLI reporting.
 *
 * @param {object} [filters]
 * @param {string} [filters.actor]
 * @param {string} [filters.action]
 * @param {string} [filters.target]
 * @param {string} [filters.since]  ISO date string, inclusive
 * @param {string} [filters.until]  ISO date string, exclusive
 * @param {number} [filters.limit=200]   capped at 1000
 * @param {number} [filters.offset=0]
 * @returns {object[]}
 */
export function queryAudit(filters = {}) {
  const parts = [];
  const params = [];

  if (filters.actor)  { parts.push("actor = ?");        params.push(filters.actor); }
  if (filters.action) { parts.push("action = ?");       params.push(filters.action); }
  if (filters.target) { parts.push("target = ?");       params.push(filters.target); }
  if (filters.since)  { parts.push("created_at >= ?");  params.push(filters.since); }
  if (filters.until)  { parts.push("created_at < ?");   params.push(filters.until); }

  const where  = parts.length ? `WHERE ${parts.join(" AND ")}` : "";
  const limit  = Math.min(Math.max(Number(filters.limit)  || 200, 1), 1000);
  const offset = Math.max(Number(filters.offset) || 0, 0);

  const rows = db.prepare(
    `SELECT id, actor, action, target, meta, ip, user_agent, created_at
     FROM audit_log ${where}
     ORDER BY created_at DESC, id DESC
     LIMIT ? OFFSET ?`
  ).all(...params, limit, offset);

  return rows.map((r) => ({
    ...r,
    meta: r.meta ? safeParse(r.meta) : null,
  }));
}

/**
 * Count audit entries (optionally filtered). Useful for dashboard pagination.
 */
export function countAudit(filters = {}) {
  const parts = [];
  const params = [];
  if (filters.actor)  { parts.push("actor = ?");        params.push(filters.actor); }
  if (filters.action) { parts.push("action = ?");       params.push(filters.action); }
  if (filters.target) { parts.push("target = ?");       params.push(filters.target); }
  if (filters.since)  { parts.push("created_at >= ?");  params.push(filters.since); }
  if (filters.until)  { parts.push("created_at < ?");   params.push(filters.until); }
  const where = parts.length ? `WHERE ${parts.join(" AND ")}` : "";
  const row = db.prepare(`SELECT COUNT(*) AS n FROM audit_log ${where}`).get(...params);
  return row?.n || 0;
}

/**
 * Summary counts grouped by action, in a time window. Used by the dashboard
 * "activity heat map" widget.
 */
export function summarizeAudit({ since, until } = {}) {
  const parts = [];
  const params = [];
  if (since) { parts.push("created_at >= ?"); params.push(since); }
  if (until) { parts.push("created_at < ?");  params.push(until); }
  const where = parts.length ? `WHERE ${parts.join(" AND ")}` : "";
  return db.prepare(
    `SELECT action, COUNT(*) AS n
     FROM audit_log ${where}
     GROUP BY action
     ORDER BY n DESC`
  ).all(...params);
}

function safeParse(s) {
  try { return JSON.parse(s); } catch { return s; }
}

export default { logAudit, queryAudit, countAudit, summarizeAudit };
