/**
 * SecureLoop - Dependency Scanner
 * by Jorge Elizalde
 *
 * Checks skill dependencies against the OSV.dev vulnerability database
 * https://osv.dev — Google's open-source vulnerability database
 *
 * Detects:
 * - Known CVEs in npm packages
 * - Severity scores (CRITICAL, HIGH, MEDIUM, LOW)
 * - Affected version ranges
 * - Fix availability
 */

import fs from "fs";
import path from "path";
import { resolveAuditTarget } from "../lib/targets.js";

const OSV_API = "https://api.osv.dev/v1/query";
const OSV_BATCH_API = "https://api.osv.dev/v1/querybatch";

const KNOWN_MALICIOUS_PACKAGES = new Set([
  "flatmap-stream",
  "event-stream",
  "crossenv",
  "eslint-scope-malware",
  "coa",
  "rc",
  "ua-parser-js",
]);

// ─── MAIN SCANNER ─────────────────────────────────────────────────────────────
export class DependencyScanner {
  static async scan(skillName) {
    const findings = [];

    // 1. Find the skill's package.json
    const target = DependencyScanner.resolveTarget(skillName);
    const skillPath = target.root;
    if (!skillPath) {
      findings.push({
        severity: "medium",
        message: `Could not locate audit target: ${skillName}`,
        detail: "Target may not exist or path is non-standard.",
        category: "access",
      });
      return findings;
    }

    if (target.type === "system") {
      return findings;
    }

    const pkgPath = path.join(skillPath, "package.json");
    if (!fs.existsSync(pkgPath)) {
      findings.push({
        severity: "low",
        message: "No package.json found in skill directory",
        detail: `Checked: ${pkgPath}`,
        category: "dependencies",
      });
      return findings;
    }

    // 2. Parse dependencies
    let pkg;
    try {
      pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
    } catch (err) {
      findings.push({
        severity: "medium",
        message: "Failed to parse skill package.json",
        detail: err.message,
        category: "dependencies",
      });
      return findings;
    }

    const deps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
    };

    if (!deps || Object.keys(deps).length === 0) {
      return findings; // No dependencies to check
    }

    // 3. Local dependency hygiene checks before external CVE lookup.
    for (const [name, version] of Object.entries(deps)) {
      if (KNOWN_MALICIOUS_PACKAGES.has(name)) {
        findings.push({
          severity: "critical",
          message: `Known malicious or historically compromised package: ${name}`,
          detail: "Remove or replace this dependency before using the target.",
          category: "dependencies",
          package: name,
          version,
        });
      }

      if (/^\s*(\*|latest)\s*$/i.test(String(version))) {
        findings.push({
          severity: "medium",
          message: `Unpinned version declared for ${name}`,
          detail: `package.json uses "${version}" — pin a tested version to reduce supply-chain drift.`,
          category: "dependencies",
          package: name,
          version,
        });
      }
    }

    if (!fs.existsSync(path.join(skillPath, "package-lock.json"))) {
      findings.push({
        severity: "low",
        message: "No lockfile found for npm dependencies",
        detail: "A lockfile makes dependency audits reproducible and safer to AutoFix.",
        category: "dependencies",
      });
    }

    // 4. Build batch query for OSV.dev
    const packages = Object.entries(deps).map(([name, version]) => ({
      package: { name, ecosystem: "npm" },
      version: DependencyScanner.cleanVersion(version),
    }));

    // 5. Query OSV.dev in batches of 20 (API limit)
    const BATCH_SIZE = 20;
    for (let i = 0; i < packages.length; i += BATCH_SIZE) {
      const batch = packages.slice(i, i + BATCH_SIZE);
      const batchFindings = await DependencyScanner.queryOSV(batch);
      findings.push(...batchFindings);
    }

    return findings;
  }

  // ─── OSV BATCH QUERY ────────────────────────────────────────────────────────
  static async queryOSV(packages) {
    const findings = [];

    let response;
    try {
      response = await fetch(OSV_BATCH_API, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ queries: packages }),
        signal: AbortSignal.timeout(10000), // 10s timeout
      });
    } catch (err) {
      findings.push({
        severity: "low",
        message: "OSV.dev API unreachable — skipping dependency check",
        detail: err.message,
        category: "dependencies",
      });
      return findings;
    }

    if (!response.ok) {
      findings.push({
        severity: "low",
        message: `OSV.dev API returned ${response.status}`,
        detail: "Dependency vulnerability check could not complete.",
        category: "dependencies",
      });
      return findings;
    }

    const data = await response.json();

    // 6. Parse results
    data.results?.forEach((result, index) => {
      const pkg = packages[index];
      if (!result.vulns || result.vulns.length === 0) return;

      for (const vuln of result.vulns) {
        const severity = DependencyScanner.getSeverity(vuln);
        const aliases = vuln.aliases?.join(", ") || vuln.id;
        const summary = vuln.summary || "No description available";
        const fixedIn = DependencyScanner.getFixedVersion(vuln, pkg.package.name);

        findings.push({
          severity,
          message: `Vulnerable dependency: ${pkg.package.name}@${pkg.version}`,
          detail: `${aliases} — ${summary}`,
          fix: fixedIn ? `Fix available: upgrade to ${fixedIn}` : "No fix available yet",
          osvId: vuln.id,
          osvUrl: `https://osv.dev/vulnerability/${vuln.id}`,
          category: "dependencies",
          package: pkg.package.name,
          version: pkg.version,
        });
      }
    });

    return findings;
  }

  // ─── HELPERS ────────────────────────────────────────────────────────────────

  // Strip semver range operators (^, ~, >=, etc.)
  static cleanVersion(version) {
    if (!version) return "0.0.0";
    return version.replace(/^[\^~>=<*]+/, "").trim() || "0.0.0";
  }

  // Extract highest severity from CVSS scores
  static getSeverity(vuln) {
    const severities = vuln.severity || [];
    const scores = severities
      .filter((s) => s.type === "CVSS_V3")
      .map((s) => DependencyScanner.extractCvssScore(s.score))
      .filter((s) => !isNaN(s));

    if (scores.length === 0) {
      const named = String(vuln.database_specific?.severity || "").toLowerCase();
      if (["critical", "high", "medium", "low"].includes(named)) return named;
      return "medium";
    }

    const max = Math.max(...scores);
    if (max >= 9.0) return "critical";
    if (max >= 7.0) return "high";
    if (max >= 4.0) return "medium";
    return "low";
  }

  // Find the fixed version for a given package
  static getFixedVersion(vuln, pkgName) {
    for (const affected of vuln.affected || []) {
      if (affected.package?.name?.toLowerCase() !== pkgName.toLowerCase()) continue;
      for (const range of affected.ranges || []) {
        for (const event of range.events || []) {
          if (event.fixed) return event.fixed;
        }
      }
    }
    return null;
  }

  static extractCvssScore(score) {
    if (typeof score === "number") return score;
    const raw = String(score || "");
    const numeric = raw.match(/^\d+(\.\d+)?$/);
    if (numeric) return Number(raw);

    // OSV sometimes returns a CVSS vector instead of the numeric score.
    // Without a full CVSS calculator, classify obviously severe impact vectors
    // conservatively instead of pretending we know the exact number.
    if (/\/C:H\/I:H\/A:H/.test(raw)) return 9.8;
    if (/\/C:H|\/I:H|\/A:H/.test(raw)) return 7.5;
    if (/\/C:L|\/I:L|\/A:L/.test(raw)) return 4.3;
    return NaN;
  }

  // Resolve audit target.
  static resolveTarget(skillName) {
    return resolveAuditTarget(skillName);
  }
}
