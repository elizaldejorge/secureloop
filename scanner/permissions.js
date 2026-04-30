/**
 * SecureLoop - Permissions Auditor
 * by Jorge Elizalde
 *
 * Scans a skill's manifest/package.json for:
 * - Excessive permission requests
 * - Dangerous capability declarations
 * - Over-privileged OAuth scopes
 * - Suspicious metadata patterns
 */

import fs from "fs";
import path from "path";
import { resolveAuditTarget } from "../lib/targets.js";

// ─── PERMISSION RISK DEFINITIONS ─────────────────────────────────────────────

const DANGEROUS_PERMISSIONS = [
  { key: "filesystem", label: "Full filesystem access", severity: "critical" },
  { key: "shell", label: "Shell/terminal execution access", severity: "critical" },
  { key: "network.*", label: "Unrestricted network access", severity: "high" },
  { key: "clipboard", label: "Clipboard read/write access", severity: "medium" },
  { key: "camera", label: "Camera access", severity: "high" },
  { key: "microphone", label: "Microphone access", severity: "high" },
  { key: "location", label: "Geolocation access", severity: "medium" },
  { key: "notifications", label: "System notification access", severity: "low" },
  { key: "contacts", label: "Contacts/address book access", severity: "high" },
  { key: "calendar", label: "Calendar access", severity: "medium" },
  { key: "admin", label: "Admin/root privilege request", severity: "critical" },
  { key: "sudo", label: "Sudo privilege request", severity: "critical" },
];

const DANGEROUS_OAUTH_SCOPES = [
  { scope: "repo", label: "Full GitHub repository access", severity: "high" },
  { scope: "delete_repo", label: "GitHub repository deletion", severity: "critical" },
  { scope: "admin:org", label: "GitHub organization admin", severity: "critical" },
  { scope: "write:packages", label: "GitHub package publishing", severity: "high" },
  { scope: "https://mail.google.com/", label: "Full Gmail access", severity: "critical" },
  { scope: "https://www.googleapis.com/auth/drive", label: "Full Google Drive access", severity: "high" },
  { scope: "https://www.googleapis.com/auth/contacts", label: "Google Contacts access", severity: "medium" },
  { scope: "offline_access", label: "Offline/persistent token access", severity: "medium" },
  { scope: "openid profile email", label: "Identity data access", severity: "low" },
];

const SUSPICIOUS_METADATA = [
  { field: "postinstall", label: "postinstall script — runs code on npm install", severity: "high" },
  { field: "preinstall", label: "preinstall script — runs code before install", severity: "high" },
  { field: "install", label: "install script — runs code automatically", severity: "high" },
  { field: "prepare", label: "prepare script — runs on install and pack", severity: "medium" },
];

// ─── PERMISSION AUDITOR ───────────────────────────────────────────────────────
export class PermissionAuditor {
  static async scan(skillName) {
    const findings = [];

    const target = PermissionAuditor.resolveTarget(skillName);
    const skillPath = target.root;
    if (!skillPath) {
      findings.push({
        severity: "low",
        message: `Could not locate audit target: ${skillName}`,
        detail: "Permission audit skipped — path not found.",
        category: "access",
      });
      return findings;
    }

    if (target.type === "system") {
      return findings;
    }

    // 1. Scan package.json
    const pkgFindings = PermissionAuditor.scanPackageJson(skillPath);
    findings.push(...pkgFindings);

    // 2. Scan OpenClaw manifest if present
    const manifestFindings = PermissionAuditor.scanManifest(skillPath);
    findings.push(...manifestFindings);

    // 3. Scan for .env files accidentally included
    const envFindings = PermissionAuditor.scanForEnvFiles(skillPath);
    findings.push(...envFindings);

    return findings;
  }

  // ─── PACKAGE.JSON AUDIT ────────────────────────────────────────────────────
  static scanPackageJson(skillPath) {
    const findings = [];
    const pkgPath = path.join(skillPath, "package.json");

    if (!fs.existsSync(pkgPath)) return findings;

    let pkg;
    try {
      pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
    } catch {
      return findings;
    }

    // Check for dangerous lifecycle scripts
    const scripts = pkg.scripts || {};
    for (const { field, label, severity } of SUSPICIOUS_METADATA) {
      if (scripts[field]) {
        findings.push({
          severity,
          message: `Dangerous lifecycle script: "${field}"`,
          detail: `Script content: ${scripts[field].substring(0, 100)}`,
          category: "permissions",
        });
      }
    }

    // Check for suspicious binary declarations
    if (pkg.bin) {
      findings.push({
        severity: "medium",
        message: "Skill declares executable binaries",
        detail: `Binaries: ${Object.keys(pkg.bin).join(", ")}`,
        category: "permissions",
      });
    }

    // Check for suspicious engines requirements
    if (pkg.engines?.node && pkg.engines.node.includes("*")) {
      findings.push({
        severity: "low",
        message: "Skill accepts any Node.js version",
        detail: "No version constraint — may target vulnerable Node versions.",
        category: "permissions",
      });
    }

    // Check for suspicious funding links
    if (pkg.funding) {
      const fundingUrl = typeof pkg.funding === "string"
        ? pkg.funding
        : pkg.funding?.url || "";

      if (fundingUrl && !fundingUrl.includes("github.com") && !fundingUrl.includes("opencollective")) {
        findings.push({
          severity: "low",
          message: "Unusual funding URL in package.json",
          detail: `Funding URL: ${fundingUrl}`,
          category: "permissions",
        });
      }
    }

    return findings;
  }

  // ─── OPENCLAW MANIFEST AUDIT ───────────────────────────────────────────────
  static scanManifest(skillPath) {
    const findings = [];

    // Check for openclaw.json or skill.json manifest
    const manifestFiles = ["openclaw.plugin.json", "openclaw.json", "skill.json", "manifest.json", "plugin.json"];
    let manifest = null;
    let manifestFile = null;

    for (const file of manifestFiles) {
      const filePath = path.join(skillPath, file);
      if (fs.existsSync(filePath)) {
        try {
          manifest = JSON.parse(fs.readFileSync(filePath, "utf-8"));
          manifestFile = file;
          break;
        } catch {
          continue;
        }
      }
    }

    if (!manifest) return findings;

    // Check declared permissions
    const permissions = manifest.permissions || manifest.capabilities || [];
    for (const permission of permissions) {
      const permStr = typeof permission === "string" ? permission : permission.name || "";

      for (const { key, label, severity } of DANGEROUS_PERMISSIONS) {
        const regex = new RegExp(key.replace("*", ".*"), "i");
        if (regex.test(permStr)) {
          findings.push({
            severity,
            message: `Dangerous permission declared: "${permStr}"`,
            detail: `${label} — found in ${manifestFile}`,
            category: "permissions",
          });
        }
      }
    }

    // Check OAuth scopes
    const scopes = manifest.oauth?.scopes || manifest.scopes || [];
    for (const scope of scopes) {
      for (const { scope: dangerScope, label, severity } of DANGEROUS_OAUTH_SCOPES) {
        if (scope.toLowerCase().includes(dangerScope.toLowerCase())) {
          findings.push({
            severity,
            message: `Dangerous OAuth scope requested: "${scope}"`,
            detail: `${label} — found in ${manifestFile}`,
            category: "permissions",
          });
        }
      }
    }

    // Check for excessive permission count
    if (permissions.length > 10) {
      findings.push({
        severity: "medium",
        message: `Skill requests ${permissions.length} permissions — unusually high`,
        detail: "Legitimate skills rarely need more than 5–6 permissions.",
        category: "permissions",
      });
    }

    // Check for missing author/publisher info
    if (!manifest.author && !manifest.publisher) {
      findings.push({
        severity: "medium",
        message: "No author or publisher declared in manifest",
        detail: "Anonymous skills carry higher risk — no accountability.",
        category: "permissions",
      });
    }

    return findings;
  }

  // ─── ENV FILE SCANNER ──────────────────────────────────────────────────────
  static scanForEnvFiles(skillPath) {
    const findings = [];
    const dangerousFiles = [".env", ".env.local", ".env.production", ".env.development"];

    for (const file of dangerousFiles) {
      const filePath = path.join(skillPath, file);
      if (fs.existsSync(filePath)) {
        findings.push({
          severity: "critical",
          message: `Environment file found in skill package: ${file}`,
          detail: "This file may contain API keys, passwords, or tokens. Never install skills with .env files.",
          category: "permissions",
        });
      }
    }

    // Check for accidentally committed secrets files
    const secretFiles = ["credentials.json", "secrets.json", "config.secret.js", "auth.json"];
    for (const file of secretFiles) {
      const filePath = path.join(skillPath, file);
      if (fs.existsSync(filePath)) {
        findings.push({
          severity: "critical",
          message: `Suspicious credentials file found: ${file}`,
          detail: "This file may contain sensitive authentication data.",
          category: "permissions",
        });
      }
    }

    return findings;
  }

  // ─── TARGET RESOLVER ───────────────────────────────────────────────────────
  static resolveTarget(skillName) {
    return resolveAuditTarget(skillName);
  }
}
