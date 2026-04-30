/**
 * SecureLoop - Reports & Exports
 * by Jorge Elizalde
 *
 * Generates structured export payloads for:
 *   - Scans (CSV, JSON)
 *   - AI Review Patch history (CSV, JSON)
 *   - SARIF security findings
 *   - Audit log (CSV, JSON)
 *   - Print-ready HTML compliance report (can be "Print → Save as PDF" in browser)
 *
 * No external PDF dependency — we deliberately use print-ready HTML so the
 * MIT bundle stays small. Users who want real PDF export can run the HTML
 * through headless Chrome.
 *
 * All exports pass through the audit log so we know who exported what.
 */

import db from "./db.js";
import { logAudit, queryAudit, countAudit, summarizeAudit } from "./audit.js";
import { getActivePolicy } from "./policy.js";

// ─── CSV ESCAPING ────────────────────────────────────────────────────────────
function csvCell(v) {
  if (v === null || v === undefined) return "";
  const s = typeof v === "string" ? v : JSON.stringify(v);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}
function toCsv(rows, headers) {
  const head = headers.map(csvCell).join(",");
  const body = rows.map(r => headers.map(h => csvCell(r[h])).join(",")).join("\n");
  return head + "\n" + body + (body ? "\n" : "");
}

// ─── SCANS ───────────────────────────────────────────────────────────────────
export function exportScans({ format = "json", since, until, actor = "dashboard" } = {}) {
  const parts = [];
  const params = [];
  if (since) { parts.push("scanned_at >= ?"); params.push(since); }
  if (until) { parts.push("scanned_at < ?");  params.push(until); }
  const where = parts.length ? `WHERE ${parts.join(" AND ")}` : "";
  const rows = db.prepare(
    `SELECT id, skill_name, risk_score, risk_level, findings, scanned_at
     FROM scans ${where}
     ORDER BY scanned_at DESC`
  ).all(...params);

  logAudit({ actor, action: "export-scans", target: format, meta: { count: rows.length, since, until } });

  if (format === "csv") {
    const flat = rows.map(r => {
      let findings;
      try { findings = JSON.parse(r.findings); } catch { findings = []; }
      const counts = countBySeverity(findings);
      return {
        id: r.id,
        skill_name: r.skill_name,
        risk_score: r.risk_score,
        risk_level: r.risk_level,
        critical: counts.critical,
        high: counts.high,
        medium: counts.medium,
        low: counts.low,
        total_findings: findings.length,
        scanned_at: r.scanned_at,
      };
    });
    return {
      contentType: "text/csv",
      body: toCsv(flat, ["id", "skill_name", "risk_score", "risk_level", "critical", "high", "medium", "low", "total_findings", "scanned_at"]),
    };
  }

  return {
    contentType: "application/json",
    body: JSON.stringify(rows.map(r => ({
      ...r,
      findings: safeParse(r.findings),
    })), null, 2),
  };
}

// ─── AI REVIEW PATCHES ───────────────────────────────────────────────────────
export function exportPatches({ format = "json", status, skillName, actor = "dashboard" } = {}) {
  const parts = [];
  const params = [];
  if (status)    { parts.push("status = ?");     params.push(status); }
  if (skillName) { parts.push("skill_name = ?"); params.push(skillName); }
  const where = parts.length ? `WHERE ${parts.join(" AND ")}` : "";
  const rows = db.prepare(
    `SELECT id, run_id, skill_name, file, line, fix_reason, severity, category,
            finding_msg, rationale, confidence, env_vars, model, status,
            reviewer, review_notes, reviewed_at, applied_at, created_at
     FROM autofix_patches ${where}
     ORDER BY created_at DESC`
  ).all(...params);

  logAudit({ actor, action: "export-patches", target: format, meta: { count: rows.length, status, skillName } });

  if (format === "csv") {
    return {
      contentType: "text/csv",
      body: toCsv(rows, ["id", "run_id", "skill_name", "file", "line", "fix_reason", "severity", "category", "finding_msg", "confidence", "model", "status", "reviewer", "review_notes", "reviewed_at", "applied_at", "created_at"]),
    };
  }

  return { contentType: "application/json", body: JSON.stringify(rows, null, 2) };
}

// ─── AUDIT LOG ───────────────────────────────────────────────────────────────
export function exportAudit({ format = "json", since, until, actor = "dashboard" } = {}) {
  const rows = queryAudit({ since, until, limit: 10_000 });
  logAudit({ actor, action: "export-audit", target: format, meta: { count: rows.length, since, until } });

  if (format === "csv") {
    const flat = rows.map(r => ({
      id: r.id,
      actor: r.actor,
      action: r.action,
      target: r.target,
      ip: r.ip,
      user_agent: r.user_agent,
      meta: r.meta ? JSON.stringify(r.meta) : "",
      created_at: r.created_at,
    }));
    return {
      contentType: "text/csv",
      body: toCsv(flat, ["id", "actor", "action", "target", "ip", "user_agent", "meta", "created_at"]),
    };
  }

  return { contentType: "application/json", body: JSON.stringify(rows, null, 2) };
}

// ─── SARIF ──────────────────────────────────────────────────────────────────
export function exportSarif({ scanId, actor = "dashboard" } = {}) {
  const row = scanId
    ? db.prepare(`SELECT * FROM scans WHERE id = ?`).get(scanId)
    : db.prepare(`SELECT * FROM scans ORDER BY scanned_at DESC LIMIT 1`).get();

  if (!row) {
    return {
      contentType: "application/sarif+json",
      body: JSON.stringify(emptySarif(), null, 2),
    };
  }

  const findings = safeParse(row.findings) || [];
  logAudit({ actor, action: "export-sarif", target: String(row.id), meta: { findings: findings.length } });

  const rules = new Map();
  const results = findings.map((finding, index) => {
    const ruleId = ruleIdFor(finding);
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: finding.message || ruleId,
        shortDescription: { text: finding.message || ruleId },
        fullDescription: { text: finding.detail || finding.message || ruleId },
        properties: {
          category: finding.category || "security",
          confidence: finding.confidence || "medium",
          impact: finding.impact || "Security hygiene",
          exploitability: finding.exploitability?.score ?? null,
        },
      });
    }
    return sarifResult(row.skill_name, finding, ruleId, index);
  });

  return {
    contentType: "application/sarif+json",
    body: JSON.stringify({
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [{
        tool: {
          driver: {
            name: "SecureLoop",
            semanticVersion: "1.2.0",
            informationUri: "https://github.com/elizaldejorge/secureloop",
            rules: Array.from(rules.values()),
          },
        },
        invocations: [{
          executionSuccessful: true,
          startTimeUtc: new Date(row.scanned_at).toISOString(),
          properties: {
            target: row.skill_name,
            riskScore: row.risk_score,
            riskLevel: row.risk_level,
          },
        }],
        results,
      }],
    }, null, 2),
  };
}

// ─── SINGLE SCAN REPORT ──────────────────────────────────────────────────────
export function buildScanReport({ scanId, actor = "dashboard" } = {}) {
  const row = scanId
    ? db.prepare(`SELECT * FROM scans WHERE id = ?`).get(scanId)
    : db.prepare(`SELECT * FROM scans ORDER BY scanned_at DESC LIMIT 1`).get();

  if (!row) {
    return {
      contentType: "text/html; charset=utf-8",
      body: renderEmptyReport("SecureLoop Scan Report", "No scan is available yet."),
    };
  }

  const previous = db.prepare(
    `SELECT id, risk_score, risk_level, scanned_at
     FROM scans
     WHERE skill_name = ? AND id < ?
     ORDER BY id DESC LIMIT 1`
  ).get(row.skill_name, row.id);

  const findings = safeParse(row.findings) || [];
  const counts = countBySeverity(findings);
  const enriched = summarizeFindingsForReport(findings);

  logAudit({
    actor,
    action: "export-scan-report",
    target: String(row.id),
    meta: { target: row.skill_name, findings: findings.length },
  });

  return {
    contentType: "text/html; charset=utf-8",
    body: renderScanReportHtml({
      scan: row,
      previous,
      findings,
      counts,
      enriched,
      generatedAt: new Date().toISOString(),
      generatedBy: actor,
    }),
  };
}

// ─── COMPLIANCE REPORT (print-ready HTML) ────────────────────────────────────
/**
 * Build a self-contained print-ready HTML document summarizing a time window.
 * Intended for browser "Save as PDF" or weasyprint/wkhtmltopdf pipelines.
 */
export function buildComplianceReport({ since, until, title, actor = "dashboard" } = {}) {
  const sinceStr = since || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const untilStr = until || new Date().toISOString();

  const scans = db.prepare(
    `SELECT skill_name, risk_score, risk_level, findings, scanned_at
     FROM scans WHERE scanned_at >= ? AND scanned_at < ?
     ORDER BY scanned_at DESC`
  ).all(sinceStr, untilStr);

  const patches = db.prepare(
    `SELECT id, skill_name, file, line, status, confidence, model, reviewer, created_at
     FROM autofix_patches WHERE created_at >= ? AND created_at < ?
     ORDER BY created_at DESC`
  ).all(sinceStr, untilStr);

  const auditTotals = summarizeAudit({ since: sinceStr, until: untilStr });
  const auditCount  = countAudit({ since: sinceStr, until: untilStr });
  const policy      = getActivePolicy();

  const stats = aggregateScanStats(scans);
  const patchStats = aggregatePatchStats(patches);

  logAudit({ actor, action: "export-compliance-report", target: "html", meta: { since: sinceStr, until: untilStr, scans: scans.length, patches: patches.length } });

  const html = renderComplianceHtml({
    title: title || "SecureLoop Security Compliance Report",
    sinceStr, untilStr,
    scans, stats, patches, patchStats, auditTotals, auditCount, policy,
    generatedAt: new Date().toISOString(),
    generatedBy: actor,
  });

  return { contentType: "text/html; charset=utf-8", body: html };
}

function aggregateScanStats(scans) {
  let c = 0, h = 0, m = 0, l = 0;
  let topScore = 0;
  const perSkill = new Map();
  for (const s of scans) {
    if (s.risk_score > topScore) topScore = s.risk_score;
    const findings = safeParse(s.findings) || [];
    for (const f of findings) {
      if (f.severity === "critical") c++;
      else if (f.severity === "high") h++;
      else if (f.severity === "medium") m++;
      else if (f.severity === "low") l++;
    }
    const prev = perSkill.get(s.skill_name);
    if (!prev || new Date(s.scanned_at) > new Date(prev.scanned_at)) perSkill.set(s.skill_name, s);
  }
  return {
    scans: scans.length,
    uniqueSkills: perSkill.size,
    critical: c, high: h, medium: m, low: l,
    topScore,
    latestPerSkill: Array.from(perSkill.values()).sort((a, b) => b.risk_score - a.risk_score),
  };
}
function aggregatePatchStats(patches) {
  const by = { pending: 0, approved: 0, rejected: 0, applied: 0, failed: 0 };
  for (const p of patches) by[p.status] = (by[p.status] || 0) + 1;
  return { total: patches.length, byStatus: by };
}
function countBySeverity(findings) {
  const r = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings || []) if (r[f.severity] !== undefined) r[f.severity]++;
  return r;
}
function summarizeFindingsForReport(findings) {
  if (!findings.length) {
    return { exploitability: 0, confidence: "high", attackPaths: 0, fixable: 0 };
  }
  const exploitability = Math.max(...findings.map((f) => Number(f.exploitability?.score || 0)));
  const attackPaths = findings.filter((f) => f.category === "attack-path").length;
  const fixable = findings.filter((f) => f.fix || /safe to add|Fix available|pin/i.test(`${f.detail || ""} ${f.message || ""}`)).length;
  const highConfidence = findings.filter((f) => f.confidence === "high").length;
  return {
    exploitability,
    attackPaths,
    fixable,
    confidence: highConfidence >= Math.ceil(findings.length / 2) ? "high" : "medium",
  };
}
function safeParse(s) { try { return JSON.parse(s); } catch { return null; } }
function ruleIdFor(finding) {
  return `secureloop.${String(finding.category || "security").replace(/[^a-z0-9_-]/gi, "-")}.${String(finding.message || "finding").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 80)}`;
}
function sarifLevel(severity) {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}
function sarifResult(target, finding, ruleId, index) {
  const rel = extractFileFromFinding(finding) || target || "target";
  const line = Number(finding.line || 1);
  return {
    ruleId,
    level: sarifLevel(finding.severity),
    message: { text: `${finding.message}${finding.detail ? ` — ${finding.detail}` : ""}` },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: rel },
        region: { startLine: line > 0 ? line : 1 },
      },
    }],
    properties: {
      severity: finding.severity,
      category: finding.category,
      confidence: finding.confidence || "medium",
      exploitability: finding.exploitability || null,
      impact: finding.impact || null,
      evidence: finding.evidence || null,
      ordinal: index + 1,
    },
  };
}
function extractFileFromFinding(finding) {
  const detail = String(finding.detail || "");
  const fileMatch = detail.match(/File:\s*([^—\n]+)/i);
  if (fileMatch) return fileMatch[1].trim();
  const locMatch = detail.match(/^([^:—\n]+\.(?:js|mjs|cjs|ts|tsx|json|ya?ml|toml|conf|config)):(\d+)/i);
  if (locMatch) return locMatch[1].trim();
  return null;
}
function emptySarif() {
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{ tool: { driver: { name: "SecureLoop", semanticVersion: "1.2.0", rules: [] } }, results: [] }],
  };
}
function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function renderEmptyReport(title, message) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${esc(title)}</title></head><body><h1>${esc(title)}</h1><p>${esc(message)}</p></body></html>`;
}

function reportVerdict(scan, counts) {
  if (scan.risk_level === "DANGEROUS") {
    return `SecureLoop found ${counts.critical + counts.high} high-priority issues. This target should not be trusted until the critical and high findings are reviewed.`;
  }
  if (scan.risk_level === "CAUTION") {
    return "SecureLoop found meaningful risk. Review the evidence and apply safe fixes before trusting this target in important workflows.";
  }
  return "SecureLoop did not find high-risk evidence in this scan. Keep monitoring dependencies, permissions, and local posture as the target changes.";
}

function verificationText(scan, previous) {
  if (!previous) return "No earlier scan was found for this target. Run another scan after remediation to verify whether risk changed.";
  const delta = scan.risk_score - previous.risk_score;
  if (delta < 0) return `Risk improved by ${Math.abs(delta)} points since scan #${previous.id}.`;
  if (delta > 0) return `Risk increased by ${delta} points since scan #${previous.id}.`;
  return `Risk score stayed the same as scan #${previous.id}.`;
}

function renderScanReportHtml({ scan, previous, findings, counts, enriched, generatedAt, generatedBy }) {
  const ordered = [...findings].sort((a, b) => Number(b.exploitability?.score || 0) - Number(a.exploitability?.score || 0));
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>SecureLoop Scan Report #${esc(scan.id)}</title>
<style>
  @media print { .no-print { display: none; } body { padding: 0; } .finding { break-inside: avoid; } }
  body { font: 13px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #0f172a; max-width: 980px; margin: 40px auto; padding: 0 32px; }
  h1 { font-size: 25px; margin: 0 0 4px; }
  h2 { font-size: 17px; margin: 30px 0 12px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }
  h3 { font-size: 14px; margin: 0 0 6px; }
  .meta, .muted { color: #64748b; font-size: 12px; }
  .kpi { display: inline-block; vertical-align: top; padding: 10px 14px; border: 1px solid #e2e8f0; border-radius: 6px; margin-right: 8px; margin-bottom: 8px; min-width: 120px; }
  .kpi b { display: block; font-size: 22px; color: #0f172a; }
  .kpi small { color: #64748b; }
  .panel { border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px 14px; margin: 10px 0 14px; background: #f8fafc; }
  .finding { border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px 12px; margin: 8px 0; }
  .badge { display: inline-block; border-radius: 999px; padding: 2px 8px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
  .sev-critical { background: #fee2e2; color: #991b1b; }
  .sev-high { background: #ffedd5; color: #9a3412; }
  .sev-medium { background: #fef3c7; color: #92400e; }
  .sev-low { background: #dbeafe; color: #1e40af; }
  table { border-collapse: collapse; width: 100%; font-size: 12px; }
  th, td { border: 1px solid #e2e8f0; padding: 6px 8px; text-align: left; vertical-align: top; }
  th { background: #f1f5f9; font-weight: 600; }
  code { background: #f1f5f9; padding: 1px 4px; border-radius: 3px; font-size: 11px; }
  .footer { margin-top: 36px; padding-top: 14px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #64748b; }
  .no-print button { padding: 6px 12px; }
</style>
</head><body>
<div class="no-print" style="text-align:right;margin-bottom:8px;">
  <button onclick="window.print()">Print / Save as PDF</button>
</div>
<h1>SecureLoop Scan Report #${esc(scan.id)}</h1>
<div class="meta">
  Target: <code>${esc(scan.skill_name)}</code><br>
  Scanned: ${esc(scan.scanned_at)}<br>
  Generated: ${esc(generatedAt)} by <code>${esc(generatedBy)}</code>
</div>

<h2>Executive Summary</h2>
<div>
  <span class="kpi"><b>${esc(scan.risk_score)}/100</b><small>Risk score</small></span>
  <span class="kpi"><b>${esc(scan.risk_level)}</b><small>Verdict</small></span>
  <span class="kpi"><b>${findings.length}</b><small>Total findings</small></span>
  <span class="kpi"><b>${enriched.exploitability}/100</b><small>Exploitability</small></span>
  <span class="kpi"><b>${enriched.attackPaths}</b><small>Attack paths</small></span>
  <span class="kpi"><b>${esc(enriched.confidence)}</b><small>Confidence</small></span>
</div>
<div class="panel"><b>Plain-English verdict:</b> ${esc(reportVerdict(scan, counts))}</div>

<h2>Verification</h2>
<div class="panel">${esc(verificationText(scan, previous))}</div>

<h2>Finding Breakdown</h2>
<table>
  <tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Fixable hints</th></tr>
  <tr><td>${counts.critical}</td><td>${counts.high}</td><td>${counts.medium}</td><td>${counts.low}</td><td>${enriched.fixable}</td></tr>
</table>

<h2>Prioritized Technical Evidence</h2>
${ordered.map((f, index) => `
  <div class="finding">
    <h3><span class="badge sev-${esc(f.severity || "low")}">${esc(f.severity || "low")}</span> ${index + 1}. ${esc(f.message)}</h3>
    <div class="muted">
      Exploitability: <b>${esc(f.exploitability?.score ?? "n/a")}${f.exploitability ? "/100" : ""}</b>
      ${f.exploitability?.band ? `(${esc(f.exploitability.band)})` : ""}
      · Confidence: <b>${esc(f.confidence || "medium")}</b>
      · Impact: ${esc(f.impact || "Security hygiene")}
      · Evidence: ${esc(f.evidence || "Scanner rule")}
    </div>
    ${f.detail ? `<p><code>${esc(f.detail)}</code></p>` : ""}
    ${f.snippet ? `<p><code>${esc(f.snippet)}</code></p>` : ""}
    ${f.fix ? `<p><b>Fix guidance:</b> ${esc(f.fix)}</p>` : ""}
    ${f.exploitability?.rationale ? `<p><b>Why it matters:</b> ${esc(f.exploitability.rationale)}</p>` : ""}
  </div>`).join("") || `<p class="muted">No findings in this scan.</p>`}

<div class="footer">
  SecureLoop is an ongoing AI-powered cybersecurity audit product by Jorge Elizalde. Reports are evidence for review and verification; final remediation decisions should remain human-approved.
</div>
</body></html>`;
}

function renderComplianceHtml({ title, sinceStr, untilStr, scans, stats, patches, patchStats, auditTotals, auditCount, policy, generatedAt, generatedBy }) {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>${esc(title)}</title>
<style>
  @media print { .no-print { display: none; } body { padding: 0; } }
  body { font: 13px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #0f172a; max-width: 960px; margin: 40px auto; padding: 0 32px; }
  h1 { font-size: 24px; margin: 0 0 4px; }
  h2 { font-size: 17px; margin: 32px 0 12px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }
  h3 { font-size: 14px; margin: 20px 0 8px; color: #334155; }
  .meta { color: #64748b; font-size: 12px; }
  table { border-collapse: collapse; width: 100%; font-size: 12px; margin: 8px 0 16px; }
  th, td { border: 1px solid #e2e8f0; padding: 6px 8px; text-align: left; vertical-align: top; }
  th { background: #f1f5f9; font-weight: 600; }
  .kpi { display: inline-block; padding: 10px 14px; border: 1px solid #e2e8f0; border-radius: 6px; margin-right: 8px; margin-bottom: 8px; min-width: 110px; }
  .kpi b { display: block; font-size: 22px; color: #0f172a; }
  .kpi small { color: #64748b; }
  .sev-critical { color: #b91c1c; font-weight: 600; }
  .sev-high     { color: #c2410c; font-weight: 600; }
  .sev-medium   { color: #a16207; }
  .sev-low      { color: #1d4ed8; }
  .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #64748b; }
  code { background: #f1f5f9; padding: 1px 4px; border-radius: 3px; font-size: 11px; }
  .no-print button { padding: 6px 12px; }
</style>
</head><body>
<div class="no-print" style="text-align:right;margin-bottom:8px;">
  <button onclick="window.print()">Print / Save as PDF</button>
</div>

<h1>${esc(title)}</h1>
<div class="meta">
  Period: <b>${esc(sinceStr)}</b> → <b>${esc(untilStr)}</b><br>
  Generated: ${esc(generatedAt)} by <code>${esc(generatedBy)}</code><br>
  Policy version: v${esc(policy?.version ?? "?")} (${policy?.active ? "active" : "—"})
</div>

<h2>Executive Summary</h2>
<div>
  <span class="kpi"><b>${stats.scans}</b><small>Scans</small></span>
  <span class="kpi"><b>${stats.uniqueSkills}</b><small>Unique skills</small></span>
  <span class="kpi"><b>${stats.topScore}</b><small>Top risk score</small></span>
  <span class="kpi"><b>${stats.critical}</b><small>Critical findings</small></span>
  <span class="kpi"><b>${stats.high}</b><small>High findings</small></span>
  <span class="kpi"><b>${patchStats.total}</b><small>AI patches drafted</small></span>
  <span class="kpi"><b>${patchStats.byStatus.applied || 0}</b><small>Patches applied</small></span>
  <span class="kpi"><b>${auditCount}</b><small>Audit events</small></span>
</div>

<h2>Active Policy</h2>
<table>
  <tr><th>Critical threshold (risk score)</th><td>${esc(policy.body.thresholds.criticalCutoff)}</td></tr>
  <tr><th>Caution threshold (risk score)</th><td>${esc(policy.body.thresholds.cautionCutoff)}</td></tr>
  <tr><th>Severity weights</th><td>critical=${esc(policy.body.severityWeights.critical)}, high=${esc(policy.body.severityWeights.high)}, medium=${esc(policy.body.severityWeights.medium)}, low=${esc(policy.body.severityWeights.low)}</td></tr>
  <tr><th>Auto-block threshold</th><td>${policy.body.autoBlockThreshold ?? "—"}</td></tr>
  <tr><th>Require manual approval for</th><td>${(policy.body.requireManualApprovalFor || []).map(esc).join(", ") || "—"}</td></tr>
  <tr><th>AI Review Patches</th><td>${policy.body.tier2.enabled ? "enabled" : "disabled"} — model <code>${esc(policy.body.tier2.defaultModel)}</code>, max ${esc(policy.body.tier2.maxPatchesPerRun)}/run</td></tr>
  <tr><th>Custom secret patterns</th><td>${(policy.body.customSecretPatterns || []).length}</td></tr>
  <tr><th>Retention</th><td>scans=${esc(policy.body.retention.scansDays)}d, audit=${esc(policy.body.retention.auditDays)}d, patches=${esc(policy.body.retention.patchesDays)}d</td></tr>
</table>

<h2>Latest Scan Per Skill</h2>
<table>
  <thead><tr><th>Skill</th><th>Score</th><th>Level</th><th>When</th></tr></thead>
  <tbody>
    ${stats.latestPerSkill.map(s => `
      <tr>
        <td><code>${esc(s.skill_name)}</code></td>
        <td>${esc(s.risk_score)}/100</td>
        <td>${esc(s.risk_level)}</td>
        <td>${esc(s.scanned_at)}</td>
      </tr>`).join("") || `<tr><td colspan="4" style="text-align:center;color:#64748b">No scans in this window.</td></tr>`}
  </tbody>
</table>

<h2>AI Review Patches</h2>
<table>
  <thead><tr><th>ID</th><th>Skill</th><th>File:Line</th><th>Status</th><th>Confidence</th><th>Model</th><th>Reviewer</th><th>Created</th></tr></thead>
  <tbody>
    ${patches.slice(0, 50).map(p => `
      <tr>
        <td>#${esc(p.id)}</td>
        <td><code>${esc(p.skill_name)}</code></td>
        <td><code>${esc(p.file)}:${esc(p.line ?? "?")}</code></td>
        <td>${esc(p.status)}</td>
        <td>${p.confidence != null ? Math.round(p.confidence * 100) + "%" : "—"}</td>
        <td>${esc(p.model || "—")}</td>
        <td>${esc(p.reviewer || "—")}</td>
        <td>${esc(p.created_at)}</td>
      </tr>`).join("") || `<tr><td colspan="8" style="text-align:center;color:#64748b">No patches in this window.</td></tr>`}
  </tbody>
</table>
${patches.length > 50 ? `<div class="meta">Showing 50 of ${patches.length} patches.</div>` : ""}

<h2>Audit Activity</h2>
<table>
  <thead><tr><th>Action</th><th>Count</th></tr></thead>
  <tbody>
    ${auditTotals.map(a => `<tr><td><code>${esc(a.action)}</code></td><td>${esc(a.n)}</td></tr>`).join("") || `<tr><td colspan="2" style="text-align:center;color:#64748b">No audit events in this window.</td></tr>`}
  </tbody>
</table>

<div class="footer">
  Generated by SecureLoop — local-only security auditor. No data leaves this machine unless a BYOK OpenAI key is set and AI Review Patches are invoked. This report is for internal compliance reference; accuracy depends on scanner rules + active policy at scan time.
</div>
</body></html>`;
}

export default {
  exportScans,
  exportPatches,
  exportAudit,
  exportSarif,
  buildScanReport,
  buildComplianceReport,
};
