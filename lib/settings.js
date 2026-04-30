/**
 * SecureLoop - App Settings
 * by Jorge Elizalde
 *
 * Tiny key-value persistence on top of the SQLite app_settings table.
 * Used for things that don't deserve their own table:
 *   - notifications.webhookUrl, notifications.minSeverity, notifications.enabled
 *   - ai.provider, ai.openaiModel, ai.openaiApiKey (masked on read), ai.ollamaUrl, ai.ollamaModel
 *   - retention.exportLocation
 *
 * Notes:
 *   - Values are stored as JSON strings (so booleans, numbers, objects round-trip).
 *   - Secrets (anything ending in *ApiKey or *Token) are NOT returned to the UI;
 *     `getSafeSettings()` masks them as "********" + last 4 chars.
 *   - This is a LOCAL-FIRST tool. These settings live only on this machine.
 */

import db from "./db.js";
import { logAudit } from "./audit.js";

const SECRET_KEY_PATTERN = /(apikey|api_key|token|secret|password)$/i;

const DEFAULT_SETTINGS = Object.freeze({
  "notifications.enabled": false,
  "notifications.webhookUrl": "",
  "notifications.minSeverity": "high", // critical | high | medium | low
  "notifications.webhookKind": "generic", // generic | slack | teams
  "ai.provider": "auto",                 // auto | local | openai | ollama
  "ai.openaiModel": "gpt-5.3-codex",
  "ai.openaiApiKey": "",
  "ai.ollamaUrl": "http://127.0.0.1:11434/api/chat",
  "ai.ollamaModel": "llama3.1:8b",
  "retention.exportLocation": "local-downloads",
});

export const SETTING_KEYS = Object.freeze(Object.keys(DEFAULT_SETTINGS));

function isSecretKey(k) {
  return SECRET_KEY_PATTERN.test(k);
}

function maskSecret(v) {
  const s = String(v || "");
  if (s.length === 0) return "";
  if (s.length <= 4) return "****";
  return "********" + s.slice(-4);
}

/** Read all settings (with defaults), unmasked — for server-side use only. */
export function getRawSettings() {
  const out = { ...DEFAULT_SETTINGS };
  const rows = db.prepare(`SELECT key, value FROM app_settings`).all();
  for (const r of rows) {
    try { out[r.key] = JSON.parse(r.value); }
    catch { out[r.key] = r.value; }
  }
  return out;
}

/** Read one raw setting value (unmasked). Returns default if missing. */
export function getSetting(key) {
  const row = db.prepare(`SELECT value FROM app_settings WHERE key = ?`).get(key);
  if (!row) return DEFAULT_SETTINGS[key];
  try { return JSON.parse(row.value); }
  catch { return row.value; }
}

/**
 * Read all settings with secret values masked.
 * Use this for any UI / API response that gets sent over the wire.
 */
export function getSafeSettings() {
  const raw = getRawSettings();
  const out = {};
  for (const k of Object.keys(raw)) {
    out[k] = isSecretKey(k) ? maskSecret(raw[k]) : raw[k];
  }
  // Convenience flag the UI can use to know if a key is on file.
  out["ai.openaiApiKeyConfigured"] = !!(raw["ai.openaiApiKey"] && String(raw["ai.openaiApiKey"]).length > 0);
  return out;
}

/** Set one setting. Returns the new safe value. */
export function setSetting(key, value, { actor = "dashboard" } = {}) {
  if (!Object.prototype.hasOwnProperty.call(DEFAULT_SETTINGS, key)) {
    return { ok: false, error: `Unknown setting key: ${key}` };
  }
  const stored = JSON.stringify(value ?? "");
  db.prepare(
    `INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`
  ).run(key, stored);
  // Audit, but never log the secret value itself.
  logAudit({
    actor,
    action: "settings-update",
    target: key,
    meta: isSecretKey(key) ? { masked: true } : { value },
  });
  return { ok: true };
}

/** Bulk-set settings from an object. Unknown keys are ignored (with a warning). */
export function setSettings(patch, opts = {}) {
  const errors = [];
  for (const [k, v] of Object.entries(patch || {})) {
    if (!Object.prototype.hasOwnProperty.call(DEFAULT_SETTINGS, k)) {
      errors.push(`Unknown key: ${k}`);
      continue;
    }
    // Empty string for a secret means "leave as-is"; UI sends "" when the user
    // didn't change a masked field. Otherwise update.
    if (isSecretKey(k) && (v === "" || v === null || v === undefined)) continue;
    setSetting(k, v, opts);
  }
  return { ok: errors.length === 0, errors };
}

const SEVERITY_RANK = Object.freeze({ critical: 4, high: 3, medium: 2, low: 1 });

/**
 * Send a webhook notification if it's enabled, the URL is set, and at least
 * one finding meets/exceeds the minimum severity threshold.
 *
 * Best-effort and non-blocking from the caller's perspective: errors are
 * logged to the audit trail but never thrown to the request handler.
 */
export async function sendWebhookForScan({ scanId, target, score, riskLevel, findings = [] }) {
  const settings = getRawSettings();
  if (!settings["notifications.enabled"]) return { sent: false, reason: "disabled" };
  const url = String(settings["notifications.webhookUrl"] || "").trim();
  if (!url) return { sent: false, reason: "no-url" };
  if (!/^https?:\/\//i.test(url)) {
    logAudit({ actor: "system", action: "webhook-error", target, meta: { reason: "invalid-url" } });
    return { sent: false, reason: "invalid-url" };
  }
  const minRank = SEVERITY_RANK[settings["notifications.minSeverity"]] || SEVERITY_RANK.high;
  const triggers = (findings || []).filter((f) => (SEVERITY_RANK[String(f.severity || "").toLowerCase()] || 0) >= minRank);
  if (triggers.length === 0) return { sent: false, reason: "below-threshold" };

  const kind = settings["notifications.webhookKind"] || "generic";
  const payload = buildWebhookPayload(kind, { scanId, target, score, riskLevel, triggers });

  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    logAudit({
      actor: "system",
      action: "webhook-fire",
      target,
      meta: { scanId, kind, status: resp.status, triggers: triggers.length },
    });
    return { sent: true, status: resp.status };
  } catch (err) {
    logAudit({
      actor: "system",
      action: "webhook-error",
      target,
      meta: { scanId, kind, error: String(err.message || err) },
    });
    return { sent: false, reason: "send-failed", error: String(err.message || err) };
  }
}

function buildWebhookPayload(kind, { scanId, target, score, riskLevel, triggers }) {
  const headline = `SecureLoop · ${riskLevel} · ${target} · score ${score}`;
  const summary = triggers
    .slice(0, 8)
    .map((f) => `• [${(f.severity || "").toUpperCase()}] ${f.title || f.id || f.type || "finding"}`)
    .join("\n");
  if (kind === "slack") {
    return {
      text: headline,
      blocks: [
        { type: "header", text: { type: "plain_text", text: headline.slice(0, 150) } },
        { type: "section", text: { type: "mrkdwn", text: "```\n" + summary + "\n```" } },
        { type: "context", elements: [{ type: "mrkdwn", text: `Scan ${scanId} · ${triggers.length} finding(s) at/above threshold` }] },
      ],
    };
  }
  if (kind === "teams") {
    return {
      "@type": "MessageCard",
      "@context": "http://schema.org/extensions",
      themeColor: riskLevel.includes("DANGEROUS") ? "DC2626" : "F59E0B",
      summary: headline,
      title: headline,
      sections: [
        { activityTitle: target, text: "```\n" + summary + "\n```" },
        { text: `Scan ${scanId} · ${triggers.length} finding(s) at/above threshold` },
      ],
    };
  }
  // generic
  return {
    source: "secureloop",
    event: "scan.threshold",
    scanId, target, score, riskLevel,
    triggers: triggers.map((f) => ({
      id: f.id || null,
      severity: f.severity || null,
      type: f.type || null,
      title: f.title || null,
      file: f.file || null,
    })),
    sentAt: new Date().toISOString(),
  };
}

/**
 * Send a single test webhook ping. Used by the UI "Send test" button.
 */
export async function sendTestWebhook({ url, kind = "generic" } = {}) {
  if (!url || !/^https?:\/\//i.test(url)) {
    return { ok: false, error: "Invalid URL" };
  }
  const payload = buildWebhookPayload(kind, {
    scanId: 0,
    target: "secureloop://test",
    score: 0,
    riskLevel: "TEST",
    triggers: [{ severity: "high", title: "SecureLoop test ping", id: "test" }],
  });
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    return { ok: true, status: resp.status };
  } catch (err) {
    return { ok: false, error: String(err.message || err) };
  }
}

export default {
  SETTING_KEYS,
  getRawSettings,
  getSetting,
  getSafeSettings,
  setSetting,
  setSettings,
  sendWebhookForScan,
  sendTestWebhook,
};
