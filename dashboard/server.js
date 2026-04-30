/**
 * SecureLoop - Dashboard Server (v1.2 Enterprise)
 * by Jorge Elizalde
 *
 * Express server on http://localhost:3334 powering the SecureLoop dashboard.
 * Binds to 127.0.0.1 only (never 0.0.0.0) so nothing leaves the machine.
 *
 * API surface:
 *   Core:       /api/status, POST /api/scan, /api/scans[/:id], /api/scans/skill/:name,
 *               /api/stats, /api/blocklist, /api/whitelist, /api/chart/*
 *   AutoFix:    /api/autofix/runs[/:id], POST /api/autofix/:skill
 *   Tier 2:     GET /api/patches, GET /api/patches/:id,
 *               POST /api/patches/:id/approve|apply|reject,
 *               POST /api/patches/propose/:skill
 *   Auth:       GET /api/auth/status, POST /api/auth/login, POST /api/auth/logout,
 *               POST /api/auth/set-pin, POST /api/auth/clear-pin,
 *               GET /api/auth/sessions, POST /api/auth/sessions/:id/revoke
 *   Audit:      GET /api/audit, GET /api/audit/summary
 *   Policy:     GET /api/policy, POST /api/policy, GET /api/policy/versions,
 *               POST /api/policy/revert/:version
 *   Advisor:    POST /api/copilot
 *   Export:     GET /api/export/scans, /api/export/patches, /api/export/audit
 *               GET /api/export/compliance-report.html
 *
 * Mutating endpoints require a valid session when a PIN is configured.
 * Read-only core endpoints are always reachable so first-run is friction-free.
 */

import express from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import open from "open";

import db from "../lib/db.js";
import { loadEnvFile } from "../lib/env.js";
import { scanAndSave } from "../lib/scan.js";
import {
  runAutofix,
  listTier2Patches, getTier2Patch,
  approveTier2Patch, rejectTier2Patch,
} from "../lib/autofix/index.js";
import {
  isPinConfigured, setPin, clearPin, login, logout,
  requireAuth, requireRole, listSessions, revokeSession,
  mintDelegatedSession, ROLES,
} from "../lib/auth.js";
import { logAudit, queryAudit, countAudit, summarizeAudit } from "../lib/audit.js";
import policyMod from "../lib/policy.js";
import reports from "../lib/reports.js";
import {
  getSafeSettings, getRawSettings, setSettings, sendWebhookForScan, sendTestWebhook,
  SETTING_KEYS,
} from "../lib/settings.js";
import {
  buildAdvisorResponse,
  buildAdvisorInterpretationPrompt,
  buildAdvisorModelPrompt,
} from "../lib/advisor/brain.js";

const { getActivePolicy, listPolicyVersions, savePolicy, revertPolicy } = policyMod;

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, "..");
const DEMO_DIR = path.join(ROOT_DIR, "demo-vulnerable-project");

loadEnvFile(path.join(ROOT_DIR, ".env"));

const app  = express();
const PORT = 3334;
const HOST = "127.0.0.1"; // localhost-only, never public
const OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses";
const OLLAMA_CHAT_URL = process.env.SECURELOOP_OLLAMA_URL || "http://127.0.0.1:11434/api/chat";
const ADVISOR_PROVIDER = process.env.SECURELOOP_ADVISOR_PROVIDER || "auto"; // auto | local | ollama | openai
const ADVISOR_MODEL = process.env.SECURELOOP_ADVISOR_MODEL || process.env.SECURELOOP_COPILOT_MODEL || process.env.SECURELOOP_TIER2_MODEL || "gpt-5.3-codex";
const OLLAMA_MODEL = process.env.SECURELOOP_OLLAMA_MODEL || "llama3.1:8b";
let advisorLastAiError = null;

function getDB() { return db; }

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: "2mb" }));

// Minimal cookie parser — avoids adding cookie-parser as a dep.
app.use((req, _res, next) => {
  req.cookies = {};
  const raw = req.headers?.cookie;
  if (raw) {
    for (const part of raw.split(";")) {
      const [k, ...v] = part.trim().split("=");
      if (k) req.cookies[k] = decodeURIComponent(v.join("="));
    }
  }
  next();
});

app.use(express.static(path.join(__dirname)));

// Restrictive CORS — localhost only, no credentials to third parties.
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin",  "http://localhost:3334");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("X-Content-Type-Options", "nosniff");
  res.header("Referrer-Policy", "no-referrer");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

function actorLabel(req) {
  return req.session?.label ? `dashboard:${req.session.label}` : "dashboard";
}
function clientIp(req) {
  return (req.headers["x-forwarded-for"]?.toString().split(",")[0] || req.ip || "").trim();
}

function latestScanWithFindings() {
  const row = getDB().prepare(`SELECT * FROM scans ORDER BY scanned_at DESC LIMIT 1`).get();
  if (!row) return null;
  row.findings = safeParse(row.findings) || [];
  return row;
}

async function copilotAnswer({ mode, message }) {
  const text = String(message || "").trim();
  const scan = latestScanWithFindings();
  const interpretation = await maybeAIAdvisorInterpretation({ mode, message: text, scan });
  const decision = buildAdvisorResponse({ mode, message: text, scan, interpretation });
  if (!decision.allowPolish) return decision;
  const ai = await maybeAIAdvisor({ mode, message: text, decision });
  return ai || decision;
}

async function maybeAIAdvisorInterpretation({ mode, message, scan }) {
  const provider = ADVISOR_PROVIDER.toLowerCase();
  if (provider === "local") return null;
  if (provider === "ollama" || provider === "auto") {
    const ollama = await maybeOllamaAdvisorInterpretation({ mode, message, scan });
    if (ollama) return ollama;
  }
  return maybeOpenAIAdvisorInterpretation({ mode, message, scan });
}

async function maybeOllamaAdvisorInterpretation({ mode, message, scan }) {
  const provider = ADVISOR_PROVIDER.toLowerCase();
  if (provider === "local" || provider === "openai") return null;
  const { systemPrompt, prompt } = buildAdvisorInterpretationPrompt({ mode, message, hasScan: Boolean(scan) });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4_000);
  try {
    const resp = await fetch(OLLAMA_CHAT_URL, {
      method: "POST",
      signal: controller.signal,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: OLLAMA_MODEL,
        stream: false,
        format: "json",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: JSON.stringify(prompt) },
        ],
        options: { temperature: 0, num_predict: 220 },
      }),
    });
    clearTimeout(timer);
    if (!resp.ok) return null;
    const json = await resp.json().catch(() => ({}));
    const content = String(json?.message?.content || "").trim();
    if (!content) return null;
    const parsed = JSON.parse(content);
    return { ...parsed, provider: "ollama", model: json.model || OLLAMA_MODEL };
  } catch {
    clearTimeout(timer);
    return null;
  }
}

async function maybeOpenAIAdvisorInterpretation({ mode, message, scan }) {
  const provider = ADVISOR_PROVIDER.toLowerCase();
  const enabled = process.env.SECURELOOP_ADVISOR_AI === "true" || process.env.SECURELOOP_COPILOT_AI === "true" || provider === "openai";
  if (!enabled || !process.env.OPENAI_API_KEY) return null;

  const { systemPrompt, prompt } = buildAdvisorInterpretationPrompt({ mode, message, hasScan: Boolean(scan) });
  const body = {
    model: ADVISOR_MODEL,
    input: [
      { role: "system", content: [{ type: "input_text", text: systemPrompt }] },
      { role: "user", content: [{ type: "input_text", text: JSON.stringify(prompt) }] },
    ],
    max_output_tokens: 300,
    text: {
      format: {
        type: "json_schema",
        name: "secureloop_advisor_intent",
        strict: true,
        schema: {
          type: "object",
          additionalProperties: false,
          required: ["intent", "confidence", "view", "target", "reason"],
          properties: {
            intent: {
              type: "string",
              enum: [
                "advisor-identity", "product-overview", "tutorial", "general-help",
                "navigate", "prepare-scan", "report", "remediation", "technical",
                "executive", "no-scan",
              ],
            },
            confidence: { type: "number", minimum: 0, maximum: 1 },
            view: {
              type: "string",
              enum: [
                "", "home", "analytics", "advisor", "guide", "scans", "findings",
                "reports", "autofix", "patches", "policy", "audit", "settings",
              ],
            },
            target: { type: "string" },
            reason: { type: "string" },
          },
        },
      },
    },
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12_000);
  try {
    const resp = await fetch(OPENAI_RESPONSES_URL, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`,
      },
      body: JSON.stringify(body),
    });
    clearTimeout(timer);
    if (!resp.ok) {
      const json = await resp.json().catch(() => ({}));
      rememberAdvisorAiError("interpretation", "openai", resp.status, json?.error);
      return null;
    }
    const json = await resp.json().catch(() => ({}));
    const text = extractOpenAIText(json).trim();
    if (!text) return null;
    const parsed = JSON.parse(text);
    advisorLastAiError = null;
    return { ...parsed, provider: "openai", model: json.model || ADVISOR_MODEL };
  } catch {
    clearTimeout(timer);
    rememberAdvisorAiError("interpretation", "openai", 0, { code: "request_failed", message: "OpenAI interpretation request failed or timed out." });
    return null;
  }
}

async function maybeAIAdvisor({ mode, message, decision }) {
  const provider = ADVISOR_PROVIDER.toLowerCase();
  if (provider !== "openai") {
    const ollama = await maybeOllamaAdvisor({ mode, message, decision });
    if (ollama) return ollama;
  }
  return maybeOpenAIAdvisor({ mode, message, decision });
}

async function maybeOllamaAdvisor({ mode, message, decision }) {
  const provider = ADVISOR_PROVIDER.toLowerCase();
  if (provider === "local" || provider === "openai") return null;

  const { systemPrompt, prompt } = buildAdvisorModelPrompt({ mode, message, decision });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6_000);
  try {
    const resp = await fetch(OLLAMA_CHAT_URL, {
      method: "POST",
      signal: controller.signal,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: OLLAMA_MODEL,
        stream: false,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: JSON.stringify(prompt) },
        ],
        options: { temperature: 0.2, num_predict: 500 },
      }),
    });
    clearTimeout(timer);
    if (!resp.ok) return null;
    const json = await resp.json().catch(() => ({}));
    const reply = String(json?.message?.content || "").trim();
    if (!reply) return null;
    return { ...decision, reply, model: json.model || OLLAMA_MODEL, provider: "ollama", source: "language-polished" };
  } catch {
    clearTimeout(timer);
    return null;
  }
}

async function maybeOpenAIAdvisor({ mode, message, decision }) {
  const provider = ADVISOR_PROVIDER.toLowerCase();
  const enabled = process.env.SECURELOOP_ADVISOR_AI === "true" || process.env.SECURELOOP_COPILOT_AI === "true" || provider === "openai";
  if (!enabled) return null;
  if (!process.env.OPENAI_API_KEY) return null;

  const { systemPrompt, prompt } = buildAdvisorModelPrompt({ mode, message, decision });

  const body = {
    model: ADVISOR_MODEL,
    input: [
      { role: "system", content: [{ type: "input_text", text: systemPrompt }] },
      { role: "user", content: [{ type: "input_text", text: JSON.stringify(prompt) }] },
    ],
    max_output_tokens: 700,
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20_000);
  try {
    const resp = await fetch(OPENAI_RESPONSES_URL, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`,
      },
      body: JSON.stringify(body),
    });
    clearTimeout(timer);
    if (!resp.ok) {
      const json = await resp.json().catch(() => ({}));
      rememberAdvisorAiError("polish", "openai", resp.status, json?.error);
      return null;
    }
    const json = await resp.json().catch(() => ({}));
    const reply = extractOpenAIText(json).trim();
    if (!reply) return null;
    advisorLastAiError = null;
    return { ...decision, reply, model: json.model || ADVISOR_MODEL, provider: "openai", source: "language-polished" };
  } catch {
    clearTimeout(timer);
    rememberAdvisorAiError("polish", "openai", 0, { code: "request_failed", message: "OpenAI polish request failed or timed out." });
    return null;
  }
}

function rememberAdvisorAiError(stage, provider, status, error = {}) {
  advisorLastAiError = {
    stage,
    provider,
    status,
    code: error?.code || error?.type || "unknown",
    message: safeAdvisorErrorMessage(error?.message || `HTTP ${status || 0}`),
  };
}

function safeAdvisorErrorMessage(message) {
  const text = String(message || "");
  if (/quota|billing|insufficient/i.test(text)) return "OpenAI quota or billing is not available for this API key.";
  if (/api key|authentication|unauthorized|invalid/i.test(text)) return "OpenAI authentication failed for the configured API key.";
  if (/model/i.test(text)) return "The configured OpenAI model is not available for this API key.";
  return text.slice(0, 160) || "OpenAI request failed.";
}

function extractOpenAIText(json) {
  if (typeof json.output_text === "string") return json.output_text;
  const parts = [];
  for (const item of json.output || []) {
    for (const content of item.content || []) {
      if (content.type === "output_text" && typeof content.text === "string") parts.push(content.text);
    }
  }
  return parts.join("");
}

function publicAdvisorAnswer(answer) {
  return {
    reply: answer.reply,
    actions: answer.actions || [],
    intent: answer.intent || "general",
    source: answer.source || "secureloop-brain",
    provider: answer.provider || null,
    model: answer.model || null,
    diagnostic: answer.provider ? null : { aiFallback: advisorLastAiError },
  };
}

function resetDemoProject() {
  fs.mkdirSync(path.join(DEMO_DIR, "src"), { recursive: true });
  fs.writeFileSync(path.join(DEMO_DIR, ".gitignore"), "node_modules/\ndist/\n");
  fs.writeFileSync(path.join(DEMO_DIR, "README.md"), `# SecureLoop Guided Audit Target

This folder is intentionally vulnerable for guided audits. It contains fake
sample code, fake tokens, and weak configuration so SecureLoop can demonstrate:

1. A plain-English scan summary.
2. Technical evidence for security reviewers.
3. Safe fix preview.
4. Safe fix apply.
5. Verification rescan.

Do not copy these patterns into a real application.
`);
  fs.writeFileSync(path.join(DEMO_DIR, "package.json"), JSON.stringify({
    name: "secureloop-demo-vulnerable-project",
    version: "0.1.0",
    private: true,
    description: "Harmless vulnerable demo target for SecureLoop.",
    scripts: { start: "node src/server.js" },
    dependencies: { "left-pad": "latest" },
  }, null, 2) + "\n");
  fs.writeFileSync(path.join(DEMO_DIR, "package-lock.json"), JSON.stringify({
    name: "secureloop-demo-vulnerable-project",
    version: "0.1.0",
    lockfileVersion: 3,
    requires: true,
    packages: {
      "": {
        name: "secureloop-demo-vulnerable-project",
        version: "0.1.0",
        dependencies: { "left-pad": "latest" },
      },
      "node_modules/left-pad": {
        version: "1.3.0",
        resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        integrity: "sha512-XI5MPzVNApjAyhQz1gX7pLMKzEzxYtGvO4XOnQZ0I6c8VYtS4v6vYzGg4tyj1mS0PrnSDh1q5bq5jYV+Yh4D4A==",
      },
    },
  }, null, 2) + "\n");
  fs.writeFileSync(path.join(DEMO_DIR, "openclaw.plugin.json"), JSON.stringify({
    name: "secureloop-demo-vulnerable-project",
    version: "0.1.0",
    permissions: ["network", "filesystem", "shell"],
  }, null, 2) + "\n");
  fs.writeFileSync(path.join(DEMO_DIR, "src", "server.js"), `// Intentionally weak demo code for SecureLoop scans. Do not run in production.
import { exec } from "child_process";

const demoApiToken = ["sk", "demo_1234567890abcdef1234567890abcdef"].join("-");

const config = {
  corsOrigin: "*",
  callbackUrl: "http://example.internal/callback",
  tlsVerify: false
};

function startDemoServer(app) {
  app.get("/debug/command", (req, res) => {
    exec(req.query.cmd, () => res.end("debug command finished"));
  });

  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", config.corsOrigin);
    next();
  });

  app.listen(3333, "0.0.0.0", () => {
    console.log("Demo server listening on every network interface");
  });
}

export { demoApiToken, config, startDemoServer };
`);
}

// ─── PUBLIC ROUTES (status + first-run) ──────────────────────────────────────
app.get("/api/status", (_req, res) => {
  res.json({
    status: "online",
    version: "1.3.0",
    pinConfigured: isPinConfigured(),
      advisor: {
        provider: ADVISOR_PROVIDER,
        interpretation: ADVISOR_PROVIDER === "local" ? "secureloop-brain" : "llm-structured-intent",
        freeLocalProvider: "ollama",
        ollamaModel: OLLAMA_MODEL,
        openaiEnabled: Boolean(process.env.OPENAI_API_KEY && (process.env.SECURELOOP_ADVISOR_AI === "true" || ADVISOR_PROVIDER === "openai")),
        lastAiError: advisorLastAiError,
      },
    timestamp: new Date().toISOString(),
  });
});

// Auth status (no auth required — UI needs this to decide whether to show login)
app.get("/api/auth/status", (_req, res) => {
  res.json({ pinConfigured: isPinConfigured() });
});

// Login (public, rate-limited internally)
app.post("/api/auth/login", (req, res) => {
  const pin = req.body?.pin;
  const label = req.body?.label || "jorge";
  const r = login({
    pin, label,
    ip: clientIp(req),
    userAgent: req.headers["user-agent"] || null,
  });
  if (!r.ok) return res.status(r.locked ? 429 : 401).json({ error: r.error });
  res.json({ ok: true, token: r.token });
});

// Logout (needs a valid token to clear it)
app.post("/api/auth/logout", requireAuth, (req, res) => {
  const token = req.session?.token;
  logout(token, { actor: actorLabel(req), ip: clientIp(req), userAgent: req.headers["user-agent"] });
  res.json({ ok: true });
});

// Set PIN — allowed when no PIN exists (first-run) OR with a valid Admin session.
app.post("/api/auth/set-pin", (req, res, next) => {
  if (!isPinConfigured()) return next(); // first-run open
  // Configured: must be authenticated AND admin role.
  return requireAuth(req, res, (err) => {
    if (err) return next(err);
    return requireRole("admin")(req, res, next);
  });
}, (req, res) => {
  const r = setPin(req.body?.pin, { actor: actorLabel(req) });
  if (!r.ok) return res.status(400).json({ error: r.error });
  res.json({ ok: true });
});

app.post("/api/auth/clear-pin", requireAuth, requireRole("admin"), (req, res) => {
  clearPin({ actor: actorLabel(req) });
  res.json({ ok: true });
});

// Identity probe — returns current session's label + role for UI badges.
app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({
    authMode:  req.authMode || "open",
    role:      req.role || "admin",
    label:     req.session?.label || null,
    expiresAt: req.session?.expires_at || null,
  });
});

app.get("/api/auth/sessions", requireAuth, requireRole("admin"), (_req, res) => res.json(listSessions()));

app.post("/api/auth/sessions/:id/revoke", requireAuth, requireRole("admin"), (req, res) => {
  const r = revokeSession(req.params.id, { actor: actorLabel(req) });
  if (!r.ok) return res.status(404).json({ error: r.error });
  res.json({ ok: true });
});

// Issue a role-scoped delegated session token. ADMIN ONLY.
// Returns the token EXACTLY ONCE — caller must persist it.
app.post("/api/auth/sessions/delegate", requireAuth, requireRole("admin"), (req, res) => {
  const role  = String(req.body?.role || "").trim();
  const label = (req.body?.label || "").toString().slice(0, 80);
  const ttlHours = Number(req.body?.ttlHours);
  if (!ROLES.includes(role)) {
    return res.status(400).json({ error: `Invalid role. One of: ${ROLES.join(", ")}` });
  }
  const r = mintDelegatedSession({
    role, label, ttlHours,
    actor: actorLabel(req),
    ip: clientIp(req),
    userAgent: req.headers?.["user-agent"] || null,
  });
  if (!r.ok) return res.status(400).json({ error: r.error });
  // Return token + metadata. UI is responsible for showing it once.
  res.json({ ok: true, token: r.token, role: r.role, expiresAt: r.expiresAt });
});

// ─── CORE READ ENDPOINTS (auth-gated if PIN is set) ──────────────────────────
// We apply requireAuth here — when PIN is not configured it's a no-op.
app.use("/api", requireAuth);

// GET /api/scans?skill=&level=&since=&until=&q=&limit=&offset=
app.get("/api/scans", (req, res) => {
  try {
    const { skill, level, since, until, q } = req.query;
    const limit  = clampInt(req.query.limit, 50, 1, 500);
    const offset = clampInt(req.query.offset, 0, 0, 100000);
    const parts = [], params = [];
    if (skill) { parts.push("skill_name = ?");        params.push(skill); }
    if (level) { parts.push("risk_level LIKE ?");     params.push(`%${level}%`); }
    if (since) { parts.push("scanned_at >= ?");       params.push(since); }
    if (until) { parts.push("scanned_at < ?");        params.push(until); }
    if (q)     { parts.push("(skill_name LIKE ? OR findings LIKE ?)"); params.push(`%${q}%`, `%${q}%`); }
    const where = parts.length ? `WHERE ${parts.join(" AND ")}` : "";
    const scans = getDB().prepare(
      `SELECT id, skill_name, risk_score, risk_level, scanned_at
       FROM scans ${where} ORDER BY scanned_at DESC LIMIT ? OFFSET ?`
    ).all(...params, limit, offset);
    const total = getDB().prepare(`SELECT COUNT(*) as n FROM scans ${where}`).get(...params).n;
    res.json({ total, limit, offset, scans });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/scans/:id", (req, res) => {
  try {
    const scan = getDB().prepare(`SELECT * FROM scans WHERE id = ?`).get(req.params.id);
    if (!scan) return res.status(404).json({ error: "Scan not found" });
    scan.findings = JSON.parse(scan.findings);
    res.json(scan);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/scans/skill/:name", (req, res) => {
  try {
    const scans = getDB().prepare(
      `SELECT * FROM scans WHERE skill_name = ? ORDER BY scanned_at DESC LIMIT 20`
    ).all(req.params.name);
    scans.forEach((s) => (s.findings = JSON.parse(s.findings)));
    res.json(scans);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/scan", requireRole("operator"), async (req, res) => {
  try {
    const target = String(req.body?.target || "").trim();
    if (!target) return res.status(400).json({ error: "target required" });

    const result = await scanAndSave(target, { respectLists: false });
    logAudit({ actor: actorLabel(req), action: "dashboard-scan", target, meta: { scanId: result.scanId, score: result.score }, ip: clientIp(req) });
    // Fire webhook (best-effort; never blocks the response).
    sendWebhookForScan({
      scanId: result.scanId,
      target,
      score: result.score,
      riskLevel: result.riskLevel || result.risk_level || "",
      findings: result.findings || [],
    }).catch(() => { /* already audit-logged */ });
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/demo/reset", requireRole("operator"), (req, res) => {
  try {
    resetDemoProject();
    logAudit({ actor: actorLabel(req), action: "dashboard-demo-reset", target: DEMO_DIR, meta: {}, ip: clientIp(req) });
    res.json({ ok: true, target: "./demo-vulnerable-project" });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/stats — KPIs for the dashboard top panel
app.get("/api/stats", (_req, res) => {
  try {
    const database = getDB();
    const totalScans  = database.prepare(`SELECT COUNT(*) as count FROM scans`).get().count;
    const dangerous   = database.prepare(`SELECT COUNT(*) as count FROM scans WHERE risk_level LIKE '%DANGEROUS%'`).get().count;
    const caution     = database.prepare(`SELECT COUNT(*) as count FROM scans WHERE risk_level LIKE '%CAUTION%'`).get().count;
    const safe        = database.prepare(`SELECT COUNT(*) as count FROM scans WHERE risk_level LIKE '%SAFE%'`).get().count;
    const blocklisted = database.prepare(`SELECT COUNT(*) as count FROM blocklist`).get().count;
    const whitelisted = database.prepare(`SELECT COUNT(*) as count FROM whitelist`).get().count;
    const lastScan    = database.prepare(`SELECT skill_name, risk_score, risk_level, scanned_at FROM scans ORDER BY scanned_at DESC LIMIT 1`).get();

    // AutoFix counts (tables may not exist on very first boot — guard)
    let autofixRuns = 0, patchesPending = 0, patchesApplied = 0;
    try { autofixRuns = database.prepare(`SELECT COUNT(*) as c FROM autofix_runs`).get().c; } catch { /* noop */ }
    try { patchesPending = database.prepare(`SELECT COUNT(*) as c FROM autofix_patches WHERE status='pending'`).get().c; } catch { /* noop */ }
    try { patchesApplied = database.prepare(`SELECT COUNT(*) as c FROM autofix_patches WHERE status='applied'`).get().c; } catch { /* noop */ }

    res.json({
      totalScans, dangerous, caution, safe, blocklisted, whitelisted,
      autofixRuns, patchesPending, patchesApplied,
      lastScan: lastScan || null,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/copilot", async (req, res) => {
  try {
    const mode = String(req.body?.mode || "executive");
    const message = String(req.body?.message || "").slice(0, 2000);
    const answer = await copilotAnswer({ mode, message });
    logAudit({
      actor: actorLabel(req),
      action: "advisor-message",
      target: mode,
      meta: { length: message.length, actions: answer.actions?.map((a) => a.action) || [] },
      ip: clientIp(req),
    });
    res.json(publicAdvisorAnswer(answer));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/blocklist", (_req, res) => {
  try { res.json(getDB().prepare(`SELECT * FROM blocklist ORDER BY blocked_at DESC`).all()); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/blocklist", requireRole("admin"), (req, res) => {
  try {
    const { skill, reason } = req.body || {};
    if (!skill) return res.status(400).json({ error: "skill required" });
    getDB().prepare(`INSERT OR REPLACE INTO blocklist (skill_name, reason) VALUES (?, ?)`).run(skill, reason || null);
    logAudit({ actor: actorLabel(req), action: "blocklist-add", target: skill, meta: { reason }, ip: clientIp(req) });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete("/api/blocklist/:name", requireRole("admin"), (req, res) => {
  try {
    getDB().prepare(`DELETE FROM blocklist WHERE skill_name = ?`).run(req.params.name);
    logAudit({ actor: actorLabel(req), action: "blocklist-remove", target: req.params.name, ip: clientIp(req) });
    res.json({ ok: true, message: `${req.params.name} removed from blocklist` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/whitelist", (_req, res) => {
  try { res.json(getDB().prepare(`SELECT * FROM whitelist ORDER BY added_at DESC`).all()); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/whitelist", requireRole("admin"), (req, res) => {
  try {
    const { skill } = req.body || {};
    if (!skill) return res.status(400).json({ error: "skill required" });
    getDB().prepare(`INSERT OR REPLACE INTO whitelist (skill_name) VALUES (?)`).run(skill);
    logAudit({ actor: actorLabel(req), action: "whitelist-add", target: skill, ip: clientIp(req) });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete("/api/whitelist/:name", requireRole("admin"), (req, res) => {
  try {
    getDB().prepare(`DELETE FROM whitelist WHERE skill_name = ?`).run(req.params.name);
    logAudit({ actor: actorLabel(req), action: "whitelist-remove", target: req.params.name, ip: clientIp(req) });
    res.json({ ok: true, message: `${req.params.name} removed from whitelist` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/chart/severity", (_req, res) => {
  try {
    const scans = getDB().prepare(`SELECT findings FROM scans ORDER BY scanned_at DESC LIMIT 20`).all();
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const scan of scans) {
      const findings = safeParse(scan.findings) || [];
      for (const f of findings) if (counts[f.severity] !== undefined) counts[f.severity]++;
    }
    res.json(counts);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/chart/timeline", (_req, res) => {
  try {
    const scans = getDB().prepare(
      `SELECT skill_name, risk_score, scanned_at FROM scans ORDER BY scanned_at DESC LIMIT 30`
    ).all();
    res.json(scans.reverse());
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// AutoFix history
app.get("/api/autofix/runs", (_req, res) => {
  try {
    const rows = getDB().prepare(
      `SELECT id, scan_id, skill_name, dry_run, tier1_total, tier1_applied,
              tier2_total, tier3_total, created_at
       FROM autofix_runs ORDER BY created_at DESC LIMIT 50`
    ).all();
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/autofix/runs/:id", (req, res) => {
  try {
    const row = getDB().prepare(`SELECT * FROM autofix_runs WHERE id = ?`).get(req.params.id);
    if (!row) return res.status(404).json({ error: "Autofix run not found" });
    row.report = safeParse(row.report);
    res.json(row);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/autofix/:skill", requireRole("operator"), async (req, res) => {
  try {
    const apply = req.query.apply === "1" || req.body?.apply === true;
    const report = await runAutofix(req.params.skill, {
      dryRun: !apply,
      reviewer: actorLabel(req),
    });
    logAudit({ actor: actorLabel(req), action: "dashboard-autofix", target: req.params.skill, meta: { apply }, ip: clientIp(req) });
    res.json(report);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── TIER 2 PATCHES ──────────────────────────────────────────────────────────
app.get("/api/patches", (req, res) => {
  try {
    const { skill, status } = req.query;
    const limit  = clampInt(req.query.limit, 100, 1, 500);
    const rows = listTier2Patches({ skillName: skill, status, limit });
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/patches/:id", (req, res) => {
  try {
    const p = getTier2Patch(Number(req.params.id));
    if (!p) return res.status(404).json({ error: "Patch not found" });
    res.json(p);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/patches/:id/approve", requireRole("operator"), async (req, res) => {
  try {
    const r = await approveTier2Patch(Number(req.params.id), {
      apply: false, reviewer: actorLabel(req), notes: req.body?.notes || null,
    });
    if (!r.ok) return res.status(400).json(r);
    res.json(r);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/patches/:id/apply", requireRole("operator"), async (req, res) => {
  try {
    const r = await approveTier2Patch(Number(req.params.id), {
      apply: true, reviewer: actorLabel(req), notes: req.body?.notes || null,
    });
    if (!r.ok) return res.status(400).json(r);
    res.json(r);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/patches/:id/reject", requireRole("operator"), (req, res) => {
  try {
    const r = rejectTier2Patch(Number(req.params.id), {
      reviewer: actorLabel(req), notes: req.body?.notes || null,
    });
    if (!r.ok) return res.status(400).json(r);
    res.json(r);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/patches/propose/:skill", requireRole("operator"), async (req, res) => {
  try {
    const report = await runAutofix(req.params.skill, {
      dryRun: true, tier2: true, reviewer: actorLabel(req),
    });
    res.json({
      ok: true,
      runId: report.runId,
      drafted: report.counts?.tier2Drafted || 0,
      total:   report.counts?.tier2Total   || 0,
      patches: (report.tier2 || []).filter(t => t.proposed).map(t => ({
        patchId: t.patchId,
        file:    t.context?.relFile || null,
        line:    t.context?.line    || null,
        reason:  t.reason,
        confidence: t.confidence,
      })),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── AUDIT LOG ───────────────────────────────────────────────────────────────
app.get("/api/audit", (req, res) => {
  try {
    const { actor, action, target, since, until } = req.query;
    const limit  = clampInt(req.query.limit, 200, 1, 1000);
    const offset = clampInt(req.query.offset, 0, 0, 100000);
    const rows   = queryAudit({ actor, action, target, since, until, limit, offset });
    const total  = countAudit({ actor, action, target, since, until });
    res.json({ total, limit, offset, rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/audit/summary", (req, res) => {
  try {
    const { since, until } = req.query;
    res.json(summarizeAudit({ since, until }));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── POLICY ─────────────────────────────────────────────────────────────────
app.get("/api/policy", (_req, res) => {
  try { res.json(getActivePolicy()); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/policy/versions", (_req, res) => {
  try { res.json(listPolicyVersions({ limit: 50 })); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/policy", requireRole("admin"), (req, res) => {
  try {
    const r = savePolicy(req.body?.policy, { author: actorLabel(req), notes: req.body?.notes });
    if (!r.ok) return res.status(400).json({ error: r.error });
    res.json(r.policy);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/policy/revert/:version", requireRole("admin"), (req, res) => {
  try {
    const r = revertPolicy(req.params.version, { author: actorLabel(req) });
    if (!r.ok) return res.status(400).json({ error: r.error });
    res.json(r.policy);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── EXPORTS ────────────────────────────────────────────────────────────────
app.get("/api/export/scans", requireRole("auditor"), (req, res) => {
  try {
    const out = reports.exportScans({
      format: req.query.format || "json",
      since:  req.query.since, until: req.query.until,
      actor:  actorLabel(req),
    });
    res.set("Content-Type", out.contentType);
    res.set("Content-Disposition", `attachment; filename="secureloop-scans.${req.query.format === "csv" ? "csv" : "json"}"`);
    res.send(out.body);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/export/patches", requireRole("auditor"), (req, res) => {
  try {
    const out = reports.exportPatches({
      format: req.query.format || "json",
      status: req.query.status, skillName: req.query.skill,
      actor:  actorLabel(req),
    });
    res.set("Content-Type", out.contentType);
    res.set("Content-Disposition", `attachment; filename="secureloop-patches.${req.query.format === "csv" ? "csv" : "json"}"`);
    res.send(out.body);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/export/audit", requireRole("auditor"), (req, res) => {
  try {
    const out = reports.exportAudit({
      format: req.query.format || "json",
      since:  req.query.since, until: req.query.until,
      actor:  actorLabel(req),
    });
    res.set("Content-Type", out.contentType);
    res.set("Content-Disposition", `attachment; filename="secureloop-audit.${req.query.format === "csv" ? "csv" : "json"}"`);
    res.send(out.body);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/export/sarif", requireRole("auditor"), (req, res) => {
  try {
    const out = reports.exportSarif({
      scanId: req.query.scanId ? Number(req.query.scanId) : null,
      actor: actorLabel(req),
    });
    res.set("Content-Type", out.contentType);
    res.set("Content-Disposition", `attachment; filename="secureloop${req.query.scanId ? `-scan-${req.query.scanId}` : "-latest"}.sarif"`);
    res.send(out.body);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/export/scan-report.html", requireRole("auditor"), (req, res) => {
  try {
    const out = reports.buildScanReport({
      scanId: req.query.scanId ? Number(req.query.scanId) : null,
      actor: actorLabel(req),
    });
    res.set("Content-Type", out.contentType);
    res.send(out.body);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/export/compliance-report.html", requireRole("auditor"), (req, res) => {
  try {
    const out = reports.buildComplianceReport({
      since: req.query.since, until: req.query.until,
      title: req.query.title, actor: actorLabel(req),
    });
    res.set("Content-Type", out.contentType);
    res.send(out.body);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Bundled "everything" export — single JSON manifest containing scans, patches,
// audit log, settings (masked), and current policy. Auditor or higher.
app.get("/api/export/all", requireRole("auditor"), (req, res) => {
  try {
    const scans   = reports.exportScans({   format: "json", actor: actorLabel(req) });
    const patches = reports.exportPatches({ format: "json", actor: actorLabel(req) });
    const audit   = reports.exportAudit({   format: "json", actor: actorLabel(req) });
    const sarif   = reports.exportSarif({   actor: actorLabel(req) });
    const policy  = (typeof getActivePolicy === "function") ? getActivePolicy() : null;
    const bundle = {
      tool: "secureloop",
      generatedAt: new Date().toISOString(),
      version: "1.3.0",
      scans:   safeJsonParse(scans.body),
      patches: safeJsonParse(patches.body),
      audit:   safeJsonParse(audit.body),
      sarif:   safeJsonParse(sarif.body),
      policy,
      settings: getSafeSettings(),
    };
    res.set("Content-Type", "application/json");
    res.set("Content-Disposition", `attachment; filename="secureloop-export-all-${Date.now()}.json"`);
    res.send(JSON.stringify(bundle, null, 2));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

function safeJsonParse(s) { try { return JSON.parse(s); } catch { return null; } }

// ─── SETTINGS API ─────────────────────────────────────────────────────────────
// All settings are server-rendered with secrets masked. Admin only for writes.
app.get("/api/settings", requireRole("auditor"), (_req, res) => {
  try {
    res.json(getSafeSettings());
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/settings", requireRole("admin"), (req, res) => {
  try {
    const patch = req.body || {};
    // Whitelist known keys; reject anything unexpected.
    const filtered = {};
    for (const k of Object.keys(patch)) {
      if (SETTING_KEYS.includes(k)) filtered[k] = patch[k];
    }
    const r = setSettings(filtered, { actor: actorLabel(req) });
    if (!r.ok) return res.status(400).json({ error: (r.errors || []).join("; ") });
    res.json(getSafeSettings());
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Send a test webhook to the supplied URL (or the saved URL if none provided).
app.post("/api/settings/notifications/test", requireRole("admin"), async (req, res) => {
  try {
    const raw = getRawSettings();
    const url  = String(req.body?.url || raw["notifications.webhookUrl"] || "").trim();
    const kind = String(req.body?.kind || raw["notifications.webhookKind"] || "generic");
    const r = await sendTestWebhook({ url, kind });
    logAudit({
      actor: actorLabel(req), action: "webhook-test",
      target: url ? "webhook" : "(missing)",
      meta: { ok: r.ok, status: r.status || null, kind, error: r.error || null },
      ip: clientIp(req),
    });
    if (!r.ok) return res.status(400).json({ ok: false, error: r.error });
    res.json({ ok: true, status: r.status });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Probe the configured AI provider. Doesn't return any AI output — just status.
app.post("/api/settings/ai/test", requireRole("admin"), async (_req, res) => {
  try {
    const raw = getRawSettings();
    const provider = raw["ai.provider"] || "auto";
    let target = "local-brain";
    let ok = true;
    let detail = "Local Brain is always available.";
    let status = 200;

    if (provider === "openai" || (provider === "auto" && raw["ai.openaiApiKey"])) {
      target = "openai";
      const key = raw["ai.openaiApiKey"] || process.env.OPENAI_API_KEY;
      if (!key) { ok = false; detail = "No OpenAI API key on file."; status = 400; }
      else {
        try {
          const ctrl = new AbortController();
          const t = setTimeout(() => ctrl.abort(), 5000);
          const probe = await fetch("https://api.openai.com/v1/models", {
            headers: { Authorization: `Bearer ${key}` }, signal: ctrl.signal,
          });
          clearTimeout(t);
          ok = probe.ok; status = probe.status;
          detail = probe.ok ? "OpenAI key validated." : `OpenAI returned ${probe.status}`;
        } catch (e) { ok = false; detail = `OpenAI unreachable: ${String(e.message || e)}`; }
      }
    } else if (provider === "ollama") {
      target = "ollama";
      const url = raw["ai.ollamaUrl"] || "http://127.0.0.1:11434/api/chat";
      try {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), 3000);
        // /api/chat is POST only; use the health endpoint by trimming.
        const base = url.replace(/\/api\/.*$/, "");
        const probe = await fetch(base + "/api/tags", { signal: ctrl.signal });
        clearTimeout(t);
        ok = probe.ok; status = probe.status;
        detail = probe.ok ? "Ollama reachable." : `Ollama returned ${probe.status}`;
      } catch (e) { ok = false; detail = `Ollama unreachable: ${String(e.message || e)}`; }
    }
    logAudit({ actor: "system", action: "ai-provider-test", target, meta: { ok, provider, status } });
    res.json({ ok, provider, target, detail, status });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── SERVE DASHBOARD ─────────────────────────────────────────────────────────
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Global error fallback (keeps stack traces out of responses)
app.use((err, _req, res, _next) => {
  console.error("[secureloop:dashboard]", err);
  res.status(500).json({ error: "Internal server error" });
});

// ─── START SERVER ────────────────────────────────────────────────────────────
export function startDashboard(autoOpen = true) {
  return new Promise((resolve) => {
    app.listen(PORT, HOST, () => {
      console.log(`\n🛡️  SecureLoop Dashboard running at http://localhost:${PORT} (127.0.0.1-only)\n`);
      if (autoOpen) {
        open(`http://localhost:${PORT}`).catch(() => {});
      }
      resolve(PORT);
    });
  });
}

export { app };

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  startDashboard(process.env.SECURELOOP_NO_AUTO_OPEN !== "1").catch((err) => {
    console.error("[secureloop:dashboard]", err);
    process.exit(1);
  });
}

// ─── HELPERS ────────────────────────────────────────────────────────────────
function safeParse(s) { try { return JSON.parse(s); } catch { return null; } }
function clampInt(v, def, min, max) {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.min(Math.max(Math.floor(n), min), max);
}
