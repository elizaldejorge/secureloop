/**
 * SecureLoop - Main Entry Point
 * by Jorge Elizalde
 *
 * AI-powered cybersecurity audit software for OpenClaw skills, project folders,
 * and local machine posture. Scans for malware, secrets, CVEs, risky network
 * exposure, suspicious permissions, and fixable hygiene gaps.
 *
 * Commands:
 *   /secureloop-scan [skill]            Full security audit
 *   /secureloop-status                  Last scan summary
 *   /secureloop-report [skill]          Full findings breakdown
 *   /secureloop-history                 Last 10 scans
 *   /secureloop-block [skill]           Add to blocklist
 *   /secureloop-unblock [skill]         Remove from blocklist
 *   /secureloop-whitelist [skill]       Mark as trusted
 *   /secureloop-unwhitelist [skill]     Un-trust a whitelisted skill
 *   /secureloop-digest                  24h security summary
 *   /secureloop-dashboard               Open dashboard in browser
 *
 *   Fix family:
 *   /secureloop-preview [skill]         Preview safe fixes without writing
 *   /secureloop-autofix [skill]         Preview safe deterministic fixes
 *   /secureloop-autofix-apply [skill]   Apply safe deterministic fixes
 *   /secureloop-fix-all [skill]         Same as autofix-apply (friendly alias)
 *   /secureloop-fix-cves [skill]        Apply only CVE bumps (safest subset)
 *   /secureloop-fix-secrets [skill]     Apply only gitignore-secret-file (zero-risk hygiene)
 *   /secureloop-fix-all-skills          Fix every installed skill (preview by default)
 *   /secureloop-rescan [skill]          Re-scan and show change vs. previous scan
 *
 *   AI Review Patches (BYOK — OPENAI_API_KEY by default):
 *   /secureloop-tier2-propose [skill]   Run scan + draft AI patches for medium findings
 *   /secureloop-tier2-list [skill]      List pending AI patches awaiting approval
 *   /secureloop-tier2-show [id]         Show full diff + rationale for one patch
 *   /secureloop-tier2-approve [id]      Approve a patch (approve only; does NOT write)
 *   /secureloop-tier2-apply [id]        Approve AND apply a patch to disk
 *   /secureloop-tier2-reject [id]       Reject a patch
 */

import chalk from "chalk";

import db              from "./lib/db.js";
import { scanAndSave } from "./lib/scan.js";
import {
  runAutofix, runAutofixAll,
  listTier2Patches, getTier2Patch,
  approveTier2Patch, rejectTier2Patch,
} from "./lib/autofix/index.js";
import { startDashboard } from "./dashboard/server.js";

function getRiskColor(score) {
  if (score >= 70) return chalk.red;
  if (score >= 40) return chalk.yellow;
  return chalk.green;
}

// ─── AUTOFIX REPORT FORMATTER ──────────────────────────────────────────────────────────
function formatAutofixReport(r) {
  if (r.error) return `❌ Fix review error for **${r.skillName}**: ${r.error}`;

  const mode = r.dryRun ? "🔍 PREVIEW (no files modified)" : "✍️ APPLIED";
  let msg = `## 🛡️ SecureLoop Fix Review — ${r.skillName}\n`;
  msg += `**Mode:** ${mode}\n`;
  msg += `**Safe fixes:** ${r.counts.tier1Applied}/${r.counts.tier1Total} applied\n`;
  msg += `**AI review patches:** ${r.counts.tier2Total} drafted or pending\n`;
  msg += `**Manual review:** ${r.counts.tier3Total} flagged\n\n`;

  if (r.tier1.length) {
    msg += `### ✅ Safe fixes\n`;
    for (const t of r.tier1) {
      const icon = t.applied ? "✅" : "⏭️";
      msg += `- ${icon} **${t.reason}** — ${t.finding.message}\n`;
      if (t.changed?.length) msg += `   files: ${t.changed.join(", ")}\n`;
      if (t.diff)            msg += "```diff\n" + t.diff + "\n```\n";
      if (t.error)           msg += `   ⚠️ ${t.error}\n`;
    }
    msg += "\n";
  }

  if (r.tier2.length) {
    msg += `### 🤖 AI review patches\n`;
    for (const t of r.tier2) {
      msg += `- ⏳ **${t.reason || "tier2-disabled"}** — ${t.finding.message}\n`;
    }
    msg += "_AI-drafted patches require human approval before any file is changed._\n\n";
  }

  if (r.tier3.length) {
    msg += `### ⚠️ Manual review required\n`;
    for (const t of r.tier3) {
      msg += `- 🚨 **${t.finding.category}** — ${t.finding.message}\n`;
      if (t.recommendation) msg += `   👉 ${t.recommendation}\n`;
    }
    msg += "\n";
  }

  if (r.dryRun && r.counts.tier1Total > 0) {
    msg += `_Run \`/secureloop-autofix-apply ${r.skillName}\` to apply safe fixes._\n`;
  }
  return msg;
}

function formatAutofixAllReport(r, apply) {
  if (r.error) return `❌ Fix-All-Skills error: ${r.error}`;
  const mode = apply ? "✍️ APPLIED" : "🔍 PREVIEW (no files modified)";
  let msg = `## 🛠️ SecureLoop Fix-All-Skills\n`;
  msg += `**Mode:** ${mode}\n`;
  msg += `**Skills scanned:** ${r.skills.length}\n`;
  msg += `**Safe fixes total:** ${r.totals.tier1Applied}/${r.totals.tier1Total} applied\n`;
  msg += `**AI review flagged:** ${r.totals.tier2Total}\n`;
  msg += `**Manual review flagged:** ${r.totals.tier3Total}\n`;
  if (r.totals.errors) msg += `**Errors:** ${r.totals.errors}\n`;
  msg += "\n| Skill | Safe fixes | AI review | Manual review | Notes |\n|---|---|---|---|---|\n";
  for (const s of r.skills) {
    if (s.error) {
      msg += `| ${s.skillName || "?"} | — | — | — | ⚠️ ${s.error} |\n`;
      continue;
    }
    msg += `| ${s.skillName} | ${s.counts.tier1Applied}/${s.counts.tier1Total} | ${s.counts.tier2Total} | ${s.counts.tier3Total} |  |\n`;
  }
  if (!apply && r.totals.tier1Total > 0) {
    msg += `\n_Run \`/secureloop-fix-all-skills apply=true\` to apply the safe fixes._\n`;
  }
  msg += `\n_Full details in dashboard at http://localhost:3334_`;
  return msg;
}

function formatRescanDelta(skillName, prev, current) {
  if (current.skipped) {
    return `⏭️ Rescan skipped: ${skillName} is ${current.skipped}.`;
  }
  const prevScore = prev?.risk_score ?? null;
  const currScore = current.score;
  const delta = prevScore === null ? null : currScore - prevScore;

  let msg = `## 🔄 SecureLoop Rescan — ${skillName}\n`;
  msg += `**Current:** ${current.level} (${currScore}/100)\n`;
  if (prevScore === null) {
    msg += `_No previous scan to compare against._`;
    return msg;
  }
  msg += `**Previous:** ${prev.risk_level} (${prevScore}/100)\n`;
  if (delta === 0) {
    msg += `**Change:** no change.\n`;
  } else if (delta < 0) {
    msg += `**Change:** ✅ improved by ${-delta} points.\n`;
  } else {
    msg += `**Change:** ⚠️ worse by ${delta} points.\n`;
  }

  const prevFindings = JSON.parse(prev.findings || "[]");
  const key = (f) => `${f.message}│${f.detail || ""}`;
  const prevKeys = new Set(prevFindings.map(key));
  const currKeys = new Set(current.findings.map(key));

  const resolved = prevFindings.filter(f => !currKeys.has(key(f)));
  const newOnes  = current.findings.filter(f => !prevKeys.has(key(f)));

  if (resolved.length) {
    msg += `\n### ✅ Resolved since last scan\n`;
    resolved.slice(0, 10).forEach(f => { msg += `- ${f.message}${f.detail ? ` (${f.detail})` : ""}\n`; });
    if (resolved.length > 10) msg += `_…and ${resolved.length - 10} more._\n`;
  }
  if (newOnes.length) {
    msg += `\n### 🚨 New findings\n`;
    newOnes.slice(0, 10).forEach(f => { msg += `- ${f.message}${f.detail ? ` (${f.detail})` : ""}\n`; });
    if (newOnes.length > 10) msg += `_…and ${newOnes.length - 10} more._\n`;
  }
  return msg;
}

// ─── FULL SCAN ────────────────────────────────────────────────────────────────
async function runFullScan(skillName, reply) {
  reply(`🛡️ **SecureLoop** scanning **${skillName}**...\n_Running static, CVE, permission, network, and local posture audits..._`);

  try {
    const result = await scanAndSave(skillName);

    // Short-circuit: blocklist
    if (result.skipped === "blocked") {
      reply(`🚫 **${skillName}** is on your blocklist.\nReason: ${result.blockedReason || "No reason provided"}\nUse /secureloop-unblock ${skillName} to remove it.`);
      return;
    }

    // Short-circuit: whitelist
    if (result.skipped === "whitelisted") {
      reply(`✅ **${skillName}** is on your whitelist — marked as trusted. Skipping scan.\nUse /secureloop-unwhitelist ${skillName} to remove it.`);
      return;
    }

    const allFindings = result.findings;
    const score       = result.score;
    const level       = result.level;

    // Build report
    const critical = allFindings.filter(f => f.severity === "critical");
    const high     = allFindings.filter(f => f.severity === "high");
    const medium   = allFindings.filter(f => f.severity === "medium");
    const low      = allFindings.filter(f => f.severity === "low");

    let report = `## 🛡️ SecureLoop Scan Report\n`;
    report += `**Target:** \`${skillName}\`\n`;
    report += `**Risk Score:** ${score}/100\n`;
    report += `**Risk Level:** ${level}\n\n`;

    report += `### 📊 Findings Summary\n`;
    report += `| Severity | Count |\n|---|---|\n`;
    report += `| 🔴 Critical | ${critical.length} |\n`;
    report += `| 🟠 High     | ${high.length} |\n`;
    report += `| 🟡 Medium   | ${medium.length} |\n`;
    report += `| 🔵 Low      | ${low.length} |\n`;
    report += `| **Total**   | **${allFindings.length}** |\n\n`;

    // Show critical and high findings in detail
    if (critical.length > 0) {
      report += `### 🔴 Critical Findings\n`;
      critical.forEach(f => {
        report += `- **${f.message}**\n  ${f.detail || ""}\n`;
        if (f.fix) report += `  ✅ ${f.fix}\n`;
        if (f.osvUrl) report += `  🔗 ${f.osvUrl}\n`;
      });
      report += "\n";
    }

    if (high.length > 0) {
      report += `### 🟠 High Findings\n`;
      high.forEach(f => {
        report += `- **${f.message}**\n  ${f.detail || ""}\n`;
        if (f.fix) report += `  ✅ ${f.fix}\n`;
      });
      report += "\n";
    }

    if (medium.length > 0) {
      report += `### 🟡 Medium Findings\n`;
      medium.forEach(f => {
        report += `- **${f.message}**\n  ${f.detail || ""}\n`;
      });
      report += "\n";
    }

    // Recommendation
    report += `### 💡 Recommendation\n`;
    if (score >= 70) {
      report += `⛔ **Do not trust this target yet.** Critical security issues detected.\n`;
      report += `Run \`/secureloop-block ${skillName}\` to prevent accidental use if this is an installable skill.\n`;
    } else if (score >= 40) {
      report += `⚠️ **Proceed with caution.** Review the findings above before installing.\n`;
    } else {
      report += `✅ **Target appears safe.** No major issues detected.\n`;
      report += `Run \`/secureloop-whitelist ${skillName}\` to mark it as trusted.\n`;
    }

    report += `\n_View full history at http://localhost:3334_`;

    reply(report);

  } catch (err) {
    reply(`❌ **SecureLoop scan failed:** ${err.message}`);
    console.error(chalk.red("[SecureLoop] Scan error:"), err);
  }
}

// ─── COMMAND HANDLERS ─────────────────────────────────────────────────────────
function handleStatus(reply) {
  const last = db.prepare(`SELECT * FROM scans ORDER BY scanned_at DESC LIMIT 1`).get();
  if (!last) {
    reply("🛡️ **SecureLoop** is active. No scans run yet.\nUse `/secureloop-scan [skill-name]` to start.");
    return;
  }
  const findings = JSON.parse(last.findings);
  const critical = findings.filter(f => f.severity === "critical").length;
  reply(
    `🛡️ **SecureLoop Status**\n` +
    `Last scan: **${last.skill_name}** — ${last.risk_level} (${last.risk_score}/100)\n` +
    `Critical findings: ${critical}\n` +
    `Scanned: ${new Date(last.scanned_at).toLocaleString()}\n` +
    `Dashboard: http://localhost:3334`
  );
}

function handleHistory(reply) {
  const scans = db.prepare(`SELECT * FROM scans ORDER BY scanned_at DESC LIMIT 10`).all();
  if (!scans.length) {
    reply("🛡️ No scan history yet. Run `/secureloop-scan [skill-name]` to start.");
    return;
  }
  let msg = `## 🛡️ SecureLoop — Last ${scans.length} Scans\n\n`;
  msg += `| Skill | Score | Level | Date |\n|---|---|---|---|\n`;
  scans.forEach(s => {
    msg += `| ${s.skill_name} | ${s.risk_score}/100 | ${s.risk_level} | ${new Date(s.scanned_at).toLocaleDateString()} |\n`;
  });
  reply(msg);
}

function handleBlock(skillName, reason, reply) {
  if (!skillName) { reply("Usage: `/secureloop-block [skill-name] [optional reason]`"); return; }
  try {
    db.prepare(`INSERT OR REPLACE INTO blocklist (skill_name, reason) VALUES (?, ?)`).run(skillName, reason || null);
    reply(`🚫 **${skillName}** has been added to your blocklist.\n${reason ? `Reason: ${reason}` : ""}`);
  } catch (err) {
    reply(`❌ Failed to block skill: ${err.message}`);
  }
}

function handleWhitelist(skillName, reply) {
  if (!skillName) { reply("Usage: `/secureloop-whitelist [skill-name]`"); return; }
  try {
    db.prepare(`INSERT OR REPLACE INTO whitelist (skill_name) VALUES (?)`).run(skillName);
    reply(`✅ **${skillName}** has been added to your whitelist as trusted.`);
  } catch (err) {
    reply(`❌ Failed to whitelist skill: ${err.message}`);
  }
}

function handleDigest(reply) {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const scans = db.prepare(`SELECT * FROM scans WHERE scanned_at >= ? ORDER BY scanned_at DESC`).all(since);

  if (!scans.length) {
    reply("🛡️ **SecureLoop 24h Digest** — No scans in the last 24 hours.");
    return;
  }

  const dangerous = scans.filter(s => s.risk_score >= 70).length;
  const caution   = scans.filter(s => s.risk_score >= 40 && s.risk_score < 70).length;
  const safe      = scans.filter(s => s.risk_score < 40).length;

  let msg = `## 🛡️ SecureLoop — 24h Security Digest\n\n`;
  msg += `**Total scans:** ${scans.length}\n`;
  msg += `🔴 Dangerous: ${dangerous} | 🟡 Caution: ${caution} | 🟢 Safe: ${safe}\n\n`;

  if (dangerous > 0) {
    msg += `### ⛔ Dangerous Skills Detected\n`;
    scans.filter(s => s.risk_score >= 70).forEach(s => {
      msg += `- **${s.skill_name}** — Score: ${s.risk_score}/100\n`;
    });
  }

  msg += `\n_Full report at http://localhost:3334_`;
  reply(msg);
}

// ─── PLUGIN REGISTRATION ──────────────────────────────────────────────────────
export default {
  name: "secureloop",
  version: "1.2.0",
  description: "🛡️ AI cybersecurity auditor for projects, plugins, and local posture",
  author: "Jorge Elizalde",

  async onLoad(plugin) {
    console.log(chalk.cyan("\n🛡️  SecureLoop v1.2.0 loaded"));
    console.log(chalk.gray("   AI cybersecurity auditor for projects, plugins, and local posture\n"));

    // Start dashboard server
    await startDashboard(false); // false = don't auto-open browser on load

    // Register commands
    plugin.registerCommand({
      name: "secureloop-scan",
      description: "Run a full cybersecurity audit on a skill, folder path, or 'system'",
      args: [{ name: "skill", required: true }],
      handler: async ({ args, reply }) => {
        await runFullScan(args.skill, reply);
      },
    });

    plugin.registerCommand({
      name: "secureloop-status",
      description: "Show last scan summary",
      handler: ({ reply }) => handleStatus(reply),
    });

    plugin.registerCommand({
      name: "secureloop-history",
      description: "Show last 10 scans",
      handler: ({ reply }) => handleHistory(reply),
    });

    plugin.registerCommand({
      name: "secureloop-block",
      description: "Add a skill to the blocklist",
      args: [{ name: "skill", required: true }, { name: "reason", required: false }],
      handler: ({ args, reply }) => handleBlock(args.skill, args.reason, reply),
    });

    plugin.registerCommand({
      name: "secureloop-whitelist",
      description: "Mark a skill as trusted",
      args: [{ name: "skill", required: true }],
      handler: ({ args, reply }) => handleWhitelist(args.skill, reply),
    });

    plugin.registerCommand({
      name: "secureloop-digest",
      description: "Show 24-hour security summary",
      handler: ({ reply }) => handleDigest(reply),
    });

    plugin.registerCommand({
      name: "secureloop-dashboard",
      description: "Open the SecureLoop dashboard in your browser",
      handler: async ({ reply }) => {
        const { open } = await import("open");
        await open("http://localhost:3334");
        reply("🛡️ Opening SecureLoop dashboard at http://localhost:3334");
      },
    });

    plugin.registerCommand({
      name: "secureloop-autofix",
      description: "Preview safe fixes for a skill (no disk writes)",
      args: [{ name: "skill", required: true }],
      handler: async ({ args, reply }) => {
        reply(`🛡️ **SecureLoop Fix Preview** scanning **${args.skill}**...`);
        try {
          const r = await runAutofix(args.skill, { dryRun: true });
          reply(formatAutofixReport(r));
        } catch (err) {
          reply(`❌ Fix preview failed: ${err.message}`);
        }
      },
    });

    plugin.registerCommand({
      name: "secureloop-autofix-apply",
      description: "Apply safe fixes to a skill (writes to disk)",
      args: [{ name: "skill", required: true }],
      handler: async ({ args, reply }) => {
        reply(`⚠️ **SecureLoop Apply Safe Fixes** modifying **${args.skill}**...`);
        try {
          const r = await runAutofix(args.skill, { dryRun: false });
          reply(formatAutofixReport(r));
        } catch (err) {
          reply(`❌ Safe fix apply failed: ${err.message}`);
        }
      },
    });

    // Friendly alias: /secureloop-preview -> safe fix preview.
    plugin.registerCommand({
      name: "secureloop-preview",
      description: "Preview what SecureLoop would fix on a skill (no writes)",
      args: [{ name: "skill", required: true }],
      handler: async ({ args, reply }) => {
        reply(`🔍 **SecureLoop Preview** for **${args.skill}**...`);
        try {
          const r = await runAutofix(args.skill, { dryRun: true });
          reply(formatAutofixReport(r));
        } catch (err) {
          reply(`❌ Preview failed: ${err.message}`);
        }
      },
    });

    // Friendly alias: /secureloop-fix-all -> apply every safe fix.
    plugin.registerCommand({
      name: "secureloop-fix-all",
      description: "Apply every safe fix to a skill (CVEs, pins, gitignore)",
      args: [{ name: "skill", required: true }],
      handler: async ({ args, reply }) => {
        reply(`🛠️ **SecureLoop Fix-All** modifying **${args.skill}**...`);
        try {
          const r = await runAutofix(args.skill, { dryRun: false });
          reply(formatAutofixReport(r));
        } catch (err) {
          reply(`❌ Fix-all failed: ${err.message}`);
        }
      },
    });

    // Apply ONLY CVE bumps — the highest-signal, safest fix.
    plugin.registerCommand({
      name: "secureloop-fix-cves",
      description: "Apply only CVE version bumps to a skill (other fixes skipped)",
      args: [{ name: "skill", required: true }],
      handler: async ({ args, reply }) => {
        reply(`💉 **SecureLoop Fix-CVEs** bumping vulnerable deps in **${args.skill}**...`);
        try {
          const r = await runAutofix(args.skill, { dryRun: false, onlyReasons: ["cve-bump"] });
          reply(formatAutofixReport(r));
        } catch (err) {
          reply(`❌ Fix-CVEs failed: ${err.message}`);
        }
      },
    });

    // Apply ONLY gitignore-secret-file — zero-risk hygiene fix.
    plugin.registerCommand({
      name: "secureloop-fix-secrets",
      description: "Add any detected bundled secret files to .gitignore (never deletes)",
      args: [{ name: "skill", required: true }],
      handler: async ({ args, reply }) => {
        reply(`🔒 **SecureLoop Fix-Secrets** hardening .gitignore for **${args.skill}**...`);
        try {
          const r = await runAutofix(args.skill, { dryRun: false, onlyReasons: ["gitignore-secret-file"] });
          reply(formatAutofixReport(r));
        } catch (err) {
          reply(`❌ Fix-Secrets failed: ${err.message}`);
        }
      },
    });

    // Fix every installed skill at once. Dry-run default.
    plugin.registerCommand({
      name: "secureloop-fix-all-skills",
      description: "Preview safe fixes for every installed skill by default. Pass apply=true to write.",
      args: [{ name: "apply", required: false }],
      handler: async ({ args, reply }) => {
        const apply = args.apply === "true" || args.apply === "1" || args.apply === "yes";
        reply(`🛰️ **SecureLoop Fix-All-Skills** ${apply ? "applying fixes" : "(preview only)"} across all installed skills...`);
        try {
          const r = await runAutofixAll({ dryRun: !apply });
          reply(formatAutofixAllReport(r, apply));
        } catch (err) {
          reply(`❌ Fix-All-Skills failed: ${err.message}`);
        }
      },
    });

    // Re-scan and show delta vs. previous scan — "did the fix actually fix it?"
    plugin.registerCommand({
      name: "secureloop-rescan",
      description: "Re-scan a skill and show how findings changed vs. previous scan",
      args: [{ name: "skill", required: true }],
      handler: async ({ args, reply }) => {
        const prev = db
          .prepare(`SELECT risk_score, risk_level, findings FROM scans WHERE skill_name = ? ORDER BY scanned_at DESC LIMIT 1`)
          .get(args.skill);
        reply(`🔄 **SecureLoop Rescan** of **${args.skill}**...`);
        try {
          const result = await scanAndSave(args.skill, { respectLists: false });
          reply(formatRescanDelta(args.skill, prev, result));
        } catch (err) {
          reply(`❌ Rescan failed: ${err.message}`);
        }
      },
    });

    // Un-block and un-whitelist. These were referenced in error messages but didn't exist.
    plugin.registerCommand({
      name: "secureloop-unblock",
      description: "Remove a skill from the blocklist",
      args: [{ name: "skill", required: true }],
      handler: ({ args, reply }) => {
        const info = db.prepare(`DELETE FROM blocklist WHERE skill_name = ?`).run(args.skill);
        reply(info.changes > 0
          ? `✅ **${args.skill}** removed from blocklist.`
          : `ℹ️ **${args.skill}** was not on the blocklist.`);
      },
    });

    plugin.registerCommand({
      name: "secureloop-unwhitelist",
      description: "Remove a skill from the whitelist (it will be scanned again)",
      args: [{ name: "skill", required: true }],
      handler: ({ args, reply }) => {
        const info = db.prepare(`DELETE FROM whitelist WHERE skill_name = ?`).run(args.skill);
        reply(info.changes > 0
          ? `✅ **${args.skill}** removed from whitelist. It will be scanned again next time.`
          : `ℹ️ **${args.skill}** was not on the whitelist.`);
      },
    });

    // ─── AI REVIEW PATCHES ────────────────────────────────────────────────
    plugin.registerCommand({
      name: "secureloop-tier2-propose",
      description: "Scan a skill and draft AI review patches (never writes to disk).",
      args: [{ name: "skill", required: true }],
      handler: async ({ args, reply }) => {
        if (!process.env.OPENAI_API_KEY) {
          reply("❌ `OPENAI_API_KEY` is not set. AI review uses your own OpenAI key (BYOK). Set it and retry.");
          return;
        }
        reply(`🤖 **SecureLoop AI Review** analyzing **${args.skill}**...`);
        try {
          const r = await runAutofix(args.skill, { dryRun: true, tier2: true, reviewer: "cli" });
          const drafted = r.counts?.tier2Drafted ?? 0;
          const total   = r.counts?.tier2Total   ?? 0;
          let msg = `## 🤖 AI Review Patch Drafts — ${args.skill}\n`;
          msg += `**Pending patches drafted:** ${drafted}/${total}\n\n`;
          if (!drafted) {
            msg += `_No patches drafted. Reasons may include: no AI-review-eligible findings, missing API key, model declined, or diff validation failed. See full report below._\n`;
          } else {
            msg += `| Patch ID | File:Line | Confidence | Reason |\n|---|---|---|---|\n`;
            for (const t of r.tier2 || []) {
              if (!t.proposed || !t.patchId) continue;
              const loc = `${t.context?.relFile || "?"}:${t.context?.line ?? "?"}`;
              const conf = typeof t.confidence === "number" ? `${Math.round(t.confidence * 100)}%` : "—";
              msg += `| #${t.patchId} | \`${loc}\` | ${conf} | ${t.reason || "ai-review"} |\n`;
            }
            msg += `\nRun \`/secureloop-tier2-show [id]\` to inspect a specific patch, then \`/secureloop-tier2-apply [id]\` to approve+apply.`;
          }
          reply(msg);
        } catch (err) {
          reply(`❌ AI review failed: ${err.message}`);
        }
      },
    });

    plugin.registerCommand({
      name: "secureloop-tier2-list",
      description: "List pending AI review patches awaiting approval.",
      args: [{ name: "skill", required: false }, { name: "status", required: false }],
      handler: ({ args, reply }) => {
        const filters = {};
        if (args.skill)  filters.skillName = args.skill;
        if (args.status) filters.status    = args.status;
        else             filters.status    = "pending";
        const patches = listTier2Patches(filters);
        if (!patches.length) {
          reply(`_No AI review patches found${args.skill ? ` for ${args.skill}` : ""} with status \`${filters.status}\`._`);
          return;
        }
        let msg = `## 🤖 AI Review Patches — status: ${filters.status}${args.skill ? ` — skill: ${args.skill}` : ""}\n`;
        msg += `| ID | Skill | File:Line | Conf | Reason | Created |\n|---|---|---|---|---|---|\n`;
        for (const p of patches) {
          const conf = typeof p.confidence === "number" ? `${Math.round(p.confidence * 100)}%` : "—";
          msg += `| #${p.id} | ${p.skill_name} | \`${p.file}:${p.line ?? "?"}\` | ${conf} | ${p.fix_reason} | ${p.created_at} |\n`;
        }
        reply(msg);
      },
    });

    plugin.registerCommand({
      name: "secureloop-tier2-show",
      description: "Show full diff + rationale for a pending AI review patch.",
      args: [{ name: "id", required: true }],
      handler: ({ args, reply }) => {
        const p = getTier2Patch(Number(args.id));
        if (!p) { reply(`❌ Patch #${args.id} not found.`); return; }
        const conf = typeof p.confidence === "number" ? `${Math.round(p.confidence * 100)}%` : "—";
        let msg = `## 🤖 AI Review Patch #${p.id}\n`;
        msg += `**Skill:** ${p.skill_name}\n`;
        msg += `**File:** \`${p.file}:${p.line ?? "?"}\`\n`;
        msg += `**Reason:** ${p.fix_reason} | **Severity:** ${p.severity || "?"} | **Category:** ${p.category || "?"}\n`;
        msg += `**Status:** ${p.status}${p.reviewer ? ` by ${p.reviewer}` : ""}${p.reviewed_at ? ` at ${p.reviewed_at}` : ""}\n`;
        msg += `**Confidence:** ${conf} | **Model:** ${p.model || "?"}\n\n`;
        msg += `**Finding:** ${p.finding_msg || "_n/a_"}\n\n`;
        if (p.rationale)    msg += `**Rationale:**\n> ${p.rationale.replace(/\n/g, "\n> ")}\n\n`;
        try {
          const ev = JSON.parse(p.env_vars || "[]");
          if (ev.length) msg += `**Env vars referenced:** ${ev.map(v => `\`${v}\``).join(", ")}\n\n`;
        } catch { /* noop */ }
        msg += `**Diff:**\n\`\`\`diff\n${p.diff}\n\`\`\`\n\n`;
        if (p.status === "pending") {
          msg += `Run \`/secureloop-tier2-approve ${p.id}\` to approve (no write), or \`/secureloop-tier2-apply ${p.id}\` to approve + apply to disk, or \`/secureloop-tier2-reject ${p.id}\` to reject.`;
        }
        reply(msg);
      },
    });

    plugin.registerCommand({
      name: "secureloop-tier2-approve",
      description: "Approve an AI review patch (no disk write). Use tier2-apply to also write.",
      args: [{ name: "id", required: true }, { name: "notes", required: false }],
      handler: async ({ args, reply }) => {
        try {
          const r = await approveTier2Patch(Number(args.id), {
            apply: false, reviewer: "cli", notes: args.notes || null,
          });
          reply(r.ok
            ? `✅ Patch #${args.id} approved (status=${r.status}). Run \`/secureloop-tier2-apply ${args.id}\` to write it to disk.`
            : `❌ Approve failed: ${r.error}`);
        } catch (err) {
          reply(`❌ Approve error: ${err.message}`);
        }
      },
    });

    plugin.registerCommand({
      name: "secureloop-tier2-apply",
      description: "Approve AND apply an AI review patch to disk (re-validates diff first).",
      args: [{ name: "id", required: true }, { name: "notes", required: false }],
      handler: async ({ args, reply }) => {
        try {
          const r = await approveTier2Patch(Number(args.id), {
            apply: true, reviewer: "cli", notes: args.notes || null,
          });
          reply(r.ok
            ? `✍️ Patch #${args.id} applied to \`${r.file}\`. Status: ${r.status}.`
            : `❌ Apply failed: ${r.error}`);
        } catch (err) {
          reply(`❌ Apply error: ${err.message}`);
        }
      },
    });

    plugin.registerCommand({
      name: "secureloop-tier2-reject",
      description: "Reject a pending AI review patch.",
      args: [{ name: "id", required: true }, { name: "notes", required: false }],
      handler: ({ args, reply }) => {
        try {
          const r = rejectTier2Patch(Number(args.id), { reviewer: "cli", notes: args.notes || null });
          reply(r.ok
            ? `🗑️ Patch #${args.id} rejected.`
            : `❌ Reject failed: ${r.error}`);
        } catch (err) {
          reply(`❌ Reject error: ${err.message}`);
        }
      },
    });

    plugin.registerCommand({
      name: "secureloop-report",
      description: "Show full findings for a skill",
      args: [{ name: "skill", required: false }],
      handler: ({ args, reply }) => {
        const scan = args.skill
          ? db.prepare(`SELECT * FROM scans WHERE skill_name = ? ORDER BY scanned_at DESC LIMIT 1`).get(args.skill)
          : db.prepare(`SELECT * FROM scans ORDER BY scanned_at DESC LIMIT 1`).get();

        if (!scan) {
          reply(`No scan found${args.skill ? ` for ${args.skill}` : ""}. Run /secureloop-scan first.`);
          return;
        }

        const findings = JSON.parse(scan.findings);
        let msg = `## 🛡️ Full Report — ${scan.skill_name}\n`;
        msg += `**Score:** ${scan.risk_score}/100 | **Level:** ${scan.risk_level}\n\n`;

        ["critical", "high", "medium", "low"].forEach(sev => {
          const group = findings.filter(f => f.severity === sev);
          if (!group.length) return;
          const icons = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵" };
          msg += `### ${icons[sev]} ${sev.charAt(0).toUpperCase() + sev.slice(1)} (${group.length})\n`;
          group.forEach(f => {
            msg += `- **${f.message}**\n  ${f.detail || ""}\n`;
            if (f.fix) msg += `  ✅ ${f.fix}\n`;
            if (f.osvUrl) msg += `  🔗 ${f.osvUrl}\n`;
          });
          msg += "\n";
        });

        reply(msg);
      },
    });
  },
};
