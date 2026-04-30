/**
 * SecureLoop - Dashboard Authentication
 * by Jorge Elizalde
 *
 * Minimal PIN-based gate for the local dashboard. Intentionally simple:
 *   - PBKDF2 (sha512, 210k iters) for PIN hashing
 *   - Sessions are random 32-byte hex tokens stored in SQLite
 *   - Sessions expire after 24h of inactivity (configurable)
 *   - Rate-limit: after 5 failed attempts in 15 min, PIN check returns `locked`
 *
 * First-run experience: if no PIN is set, the dashboard is open but shows a
 * prominent "set a PIN" banner. The user can opt in to a PIN from Settings.
 *
 * NEVER replaces a real IdP. This is a local single-user gate.
 */

import crypto from "crypto";
import db from "./db.js";
import { logAudit } from "./audit.js";

const ITERATIONS   = 210_000;
const KEY_LEN      = 64;
const DIGEST       = "sha512";
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24h
const LOCK_WINDOW_MS = 15 * 60 * 1000;       // 15min
const LOCK_THRESHOLD = 5;

db.exec(`
  CREATE TABLE IF NOT EXISTS auth_config (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    pin_hash     TEXT,
    pin_salt     TEXT,
    iterations   INTEGER,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME
  );

  CREATE TABLE IF NOT EXISTS auth_sessions (
    token        TEXT PRIMARY KEY,
    label        TEXT,
    ip           TEXT,
    user_agent   TEXT,
    role         TEXT DEFAULT 'admin' NOT NULL,
    expires_at   DATETIME,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    revoked_at   DATETIME
  );

  CREATE TABLE IF NOT EXISTS auth_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT,
    success      INTEGER NOT NULL,
    at           DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_auth_attempts_ip_at ON auth_attempts(ip, at);
`);

// Idempotent migrations for upgrades from v1.1/v1.2 without `role` / `expires_at`.
// SQLite rejects duplicate columns; ignore that specific error.
for (const stmt of [
  `ALTER TABLE auth_sessions ADD COLUMN role TEXT DEFAULT 'admin' NOT NULL`,
  `ALTER TABLE auth_sessions ADD COLUMN expires_at DATETIME`,
]) {
  try { db.exec(stmt); } catch (e) {
    if (!/duplicate column name/i.test(e.message || "")) throw e;
  }
}

// ─── ROLE MODEL ──────────────────────────────────────────────────────────────
//
// Four-tier RBAC. Numeric rank is used for `requireRole(min)`: a session
// passes if its role rank is GREATER THAN OR EQUAL to the required rank.
//
//   admin    — everything: PIN, role minting, policy, autofix-apply, deletes
//   operator — scans, autofix proposals, fix application; cannot manage roles
//              or change PIN; cannot edit policy
//   auditor  — read everything + run scans + export reports; no fix application
//   viewer   — read-only: list scans, view findings, view reports
//
export const ROLE_RANK = Object.freeze({
  admin:    40,
  operator: 30,
  auditor:  20,
  viewer:   10,
});
export const ROLES = Object.freeze(Object.keys(ROLE_RANK));

export function isValidRole(r) {
  return typeof r === "string" && Object.prototype.hasOwnProperty.call(ROLE_RANK, r);
}

export function rankOf(role) {
  return ROLE_RANK[role] || 0;
}

/** @returns {boolean} true if a PIN has been set */
export function isPinConfigured() {
  const row = db.prepare(`SELECT pin_hash FROM auth_config WHERE id = 1`).get();
  return !!(row && row.pin_hash);
}

/**
 * Set or replace the dashboard PIN. PIN must be 4–64 chars.
 * Old sessions are revoked for safety.
 */
export function setPin(pin, { actor = "dashboard" } = {}) {
  const s = String(pin || "");
  if (s.length < 4)  return { ok: false, error: "PIN must be at least 4 characters" };
  if (s.length > 64) return { ok: false, error: "PIN must be at most 64 characters" };

  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync(s, salt, ITERATIONS, KEY_LEN, DIGEST).toString("hex");

  const existing = db.prepare(`SELECT id FROM auth_config WHERE id = 1`).get();
  if (existing) {
    db.prepare(
      `UPDATE auth_config SET pin_hash = ?, pin_salt = ?, iterations = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1`
    ).run(hash, salt, ITERATIONS);
  } else {
    db.prepare(
      `INSERT INTO auth_config (id, pin_hash, pin_salt, iterations) VALUES (1, ?, ?, ?)`
    ).run(hash, salt, ITERATIONS);
  }

  // Revoke existing sessions on PIN change.
  db.prepare(`UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE revoked_at IS NULL`).run();

  logAudit({ actor, action: "pin-set", target: "dashboard" });
  return { ok: true };
}

/** Remove PIN gate entirely (dashboard becomes open). Revokes all sessions. */
export function clearPin({ actor = "dashboard" } = {}) {
  db.prepare(`DELETE FROM auth_config WHERE id = 1`).run();
  db.prepare(`UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE revoked_at IS NULL`).run();
  logAudit({ actor, action: "pin-clear", target: "dashboard" });
  return { ok: true };
}

/** @returns {boolean} true if the given IP is temp-locked due to failed attempts */
export function isLocked(ip) {
  if (!ip) return false;
  const since = new Date(Date.now() - LOCK_WINDOW_MS).toISOString();
  const row = db.prepare(
    `SELECT COUNT(*) AS n FROM auth_attempts WHERE ip = ? AND success = 0 AND at >= ?`
  ).get(ip, since);
  return (row?.n || 0) >= LOCK_THRESHOLD;
}

/**
 * Verify PIN and (on success) mint an Admin session token. The master PIN
 * is always the admin role; lower roles are issued via mintDelegatedSession.
 * @returns {{ok:true, token:string, role:string} | {ok:false, error:string, locked?:boolean}}
 */
export function login({ pin, ip, userAgent, label }) {
  if (!isPinConfigured()) return { ok: false, error: "PIN not configured" };
  if (isLocked(ip)) {
    logAudit({ actor: "anon", action: "login-locked", target: "dashboard", ip, userAgent });
    return { ok: false, error: "Too many failed attempts — try again in 15 minutes.", locked: true };
  }

  const row = db.prepare(`SELECT pin_hash, pin_salt, iterations FROM auth_config WHERE id = 1`).get();
  const attempted = crypto.pbkdf2Sync(String(pin || ""), row.pin_salt, row.iterations || ITERATIONS, KEY_LEN, DIGEST).toString("hex");
  const ok = crypto.timingSafeEqual(Buffer.from(attempted, "hex"), Buffer.from(row.pin_hash, "hex"));

  db.prepare(`INSERT INTO auth_attempts (ip, success) VALUES (?, ?)`).run(ip || null, ok ? 1 : 0);

  if (!ok) {
    logAudit({ actor: "anon", action: "login-fail", target: "dashboard", ip, userAgent });
    return { ok: false, error: "Invalid PIN" };
  }

  const token = crypto.randomBytes(32).toString("hex");
  db.prepare(
    `INSERT INTO auth_sessions (token, label, ip, user_agent, role) VALUES (?, ?, ?, ?, ?)`
  ).run(token, label || null, ip || null, userAgent || null, "admin");
  logAudit({ actor: label || "dashboard", action: "login-success", target: "dashboard", ip, userAgent, meta: { token: token.slice(0, 8), role: "admin" } });
  return { ok: true, token, role: "admin" };
}

/**
 * Mint a role-scoped delegated session token. ADMIN-ONLY caller (the
 * dashboard server enforces this via requireRole('admin') on the route).
 *
 * Behaves like AWS STS / GitHub fine-grained PAT / Vault dynamic creds:
 * the master PIN holder issues a short-lived token scoped to a lower role.
 * The token is only returned ONCE — caller must persist it themselves.
 *
 * @param {object} args
 * @param {'admin'|'operator'|'auditor'|'viewer'} args.role
 * @param {string} [args.label]      Human-readable label (e.g., "ci-pipeline").
 * @param {number} [args.ttlHours]   Hours until the session auto-expires (1–720, default 24).
 * @param {string} [args.actor]      Who issued it (admin label).
 * @returns {{ok:true, token:string, role:string, expiresAt:string} | {ok:false, error:string}}
 */
export function mintDelegatedSession({ role, label, ttlHours, actor = "admin", ip, userAgent } = {}) {
  if (!isValidRole(role)) return { ok: false, error: "Invalid role" };
  const ttl = Math.max(1, Math.min(720, Number(ttlHours) || 24));
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + ttl * 60 * 60 * 1000).toISOString();

  db.prepare(
    `INSERT INTO auth_sessions (token, label, ip, user_agent, role, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).run(token, label || null, ip || null, userAgent || null, role, expiresAt);

  logAudit({
    actor,
    action: "session-delegate",
    target: "dashboard",
    meta: { tokenPrefix: token.slice(0, 8), role, label: label || null, ttlHours: ttl },
  });

  return { ok: true, token, role, expiresAt };
}

/** @returns {{ok:boolean, session?:object, expired?:boolean}} */
export function validateSession(token) {
  if (!token) return { ok: false };
  const row = db.prepare(`SELECT * FROM auth_sessions WHERE token = ?`).get(token);
  if (!row) return { ok: false };
  if (row.revoked_at) return { ok: false };

  // Hard expiry on delegated sessions takes precedence over the idle window.
  if (row.expires_at) {
    const exp = new Date(row.expires_at).getTime();
    if (Number.isFinite(exp) && Date.now() > exp) {
      db.prepare(`UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE token = ?`).run(token);
      return { ok: false, expired: true };
    }
  }

  const lastSeen = new Date(row.last_seen_at || row.created_at).getTime();
  if (Number.isFinite(lastSeen) && (Date.now() - lastSeen) > SESSION_TTL_MS) {
    db.prepare(`UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE token = ?`).run(token);
    return { ok: false, expired: true };
  }

  db.prepare(`UPDATE auth_sessions SET last_seen_at = CURRENT_TIMESTAMP WHERE token = ?`).run(token);
  // Normalise role on the returned session (defensive — rows from before the
  // migration default to 'admin' via the column default, but a manually
  // edited DB might have NULL).
  const session = { ...row, role: isValidRole(row.role) ? row.role : "admin" };
  return { ok: true, session };
}

export function logout(token, { actor = "dashboard", ip, userAgent } = {}) {
  if (!token) return { ok: false };
  const info = db.prepare(`UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE token = ? AND revoked_at IS NULL`).run(token);
  logAudit({ actor, action: "logout", target: "dashboard", ip, userAgent });
  return { ok: info.changes > 0 };
}

/** List active sessions (no tokens — only first 8 chars) for the dashboard. */
export function listSessions() {
  const rows = db.prepare(
    `SELECT token, label, ip, user_agent, role, expires_at, created_at, last_seen_at, revoked_at
     FROM auth_sessions
     ORDER BY last_seen_at DESC
     LIMIT 100`
  ).all();
  const now = Date.now();
  return rows.map(r => {
    const role = isValidRole(r.role) ? r.role : "admin";
    const expired = r.expires_at && Number.isFinite(new Date(r.expires_at).getTime())
      ? now > new Date(r.expires_at).getTime()
      : false;
    return {
      id: r.token.slice(0, 8),
      label: r.label,
      ip: r.ip,
      userAgent: r.user_agent,
      role,
      expiresAt: r.expires_at,
      createdAt: r.created_at,
      lastSeenAt: r.last_seen_at,
      revokedAt: r.revoked_at,
      active: !r.revoked_at && !expired,
    };
  });
}

export function revokeSession(tokenPrefix, { actor = "dashboard" } = {}) {
  const row = db.prepare(`SELECT token FROM auth_sessions WHERE token LIKE ? AND revoked_at IS NULL`).get(`${tokenPrefix}%`);
  if (!row) return { ok: false, error: "Session not found or already revoked" };
  db.prepare(`UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE token = ?`).run(row.token);
  logAudit({ actor, action: "session-revoke", target: tokenPrefix });
  return { ok: true };
}

/**
 * Express-style middleware. Attaches req.session, req.role, and 401s if no
 * valid session. If PIN is not configured, requests pass through (open mode)
 * and the implicit role is 'admin'.
 */
export function requireAuth(req, res, next) {
  if (!isPinConfigured()) {
    req.authMode = "open";
    req.role     = "admin";   // open mode = single-user trusted machine
    return next();
  }
  const token = extractToken(req);
  const v = validateSession(token);
  if (!v.ok) {
    res.status(401).json({ error: v.expired ? "Session expired" : "Unauthorized" });
    return;
  }
  req.authMode = "pin";
  req.session  = v.session;
  req.role     = v.session.role;
  next();
}

/**
 * requireRole(min) returns Express middleware that 403s if the caller's
 * role rank is below the required minimum. Usage:
 *
 *   app.post("/api/policy",        requireAuth, requireRole("admin"),    handler)
 *   app.post("/api/scan",          requireAuth, requireRole("operator"), handler)
 *   app.get ("/api/export/sarif",  requireAuth, requireRole("auditor"),  handler)
 *
 * In open mode (no PIN configured), requireAuth has already set req.role
 * to 'admin', so requireRole always passes. This preserves first-run UX.
 */
export function requireRole(minRole) {
  if (!isValidRole(minRole)) throw new Error(`requireRole: unknown role '${minRole}'`);
  const minRank = ROLE_RANK[minRole];
  return function (req, res, next) {
    const role = req.role || "viewer";
    if (rankOf(role) < minRank) {
      logAudit({
        actor:  (req.session && req.session.label) || "anon",
        action: "rbac-deny",
        target: req.originalUrl || req.url || "?",
        ip:     req.ip,
        meta:   { role, required: minRole },
      });
      res.status(403).json({
        error: "Forbidden — your role does not have permission for this action.",
        role,
        required: minRole,
      });
      return;
    }
    next();
  };
}

function extractToken(req) {
  const hdr = req.headers?.authorization || req.headers?.Authorization;
  if (hdr && typeof hdr === "string" && hdr.toLowerCase().startsWith("bearer ")) {
    return hdr.slice(7).trim();
  }
  if (req.cookies && req.cookies.secureloop_session) return req.cookies.secureloop_session;
  // Fall back to a query param for convenience during first-run smoke tests.
  if (req.query && typeof req.query.token === "string") return req.query.token;
  return null;
}

export default {
  isPinConfigured, setPin, clearPin,
  login, logout, validateSession, requireAuth, requireRole,
  listSessions, revokeSession, isLocked,
  mintDelegatedSession, ROLES, ROLE_RANK, isValidRole, rankOf,
};
