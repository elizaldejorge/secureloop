/**
 * SecureLoop - Local System Posture Scanner
 *
 * Passive, privacy-preserving checks for local machine risk. This scanner
 * avoids reading shell history, package-manager token files, or secret values.
 */

import fs from "fs";
import os from "os";
import path from "path";
import { resolveAuditTarget } from "../lib/targets.js";

const SENSITIVE_FILE_NAMES = new Set([
  ".env",
  ".env.local",
  ".env.production",
  "credentials.json",
  "secrets.json",
  "auth.json",
]);

export class SystemScanner {
  static async scan(targetName) {
    try {
      const target = resolveAuditTarget(targetName);
      if (!target.root) {
        return [{
          severity: "low",
          category: "system",
          message: `System audit skipped: could not locate ${targetName}`,
          detail: "Provide an installed skill name, folder path, or 'system'.",
        }];
      }

      const findings = [];
      findings.push(...SystemScanner.scanSensitiveFileNames(target));
      findings.push(...SystemScanner.scanSshKeyPermissions(target));
      findings.push(...SystemScanner.scanProjectGitignore(target));
      return findings;
    } catch (err) {
      return [{
        severity: "low",
        category: "system",
        message: "System posture scanner failed safely",
        detail: err.message,
      }];
    }
  }

  static scanSensitiveFileNames(target) {
    const findings = [];
    if (target.type === "system") {
      return findings;
    }

    for (const file of SystemScanner.findFiles(target.root, 4)) {
      const name = path.basename(file);
      if (!SENSITIVE_FILE_NAMES.has(name)) continue;

      findings.push({
        severity: name === ".env" ? "critical" : "high",
        category: "system",
        message: `Sensitive configuration file present: ${name}`,
        detail: `${path.relative(target.root, file)} — SecureLoop does not read the file; verify it is not committed or shared.`,
      });
    }

    return findings;
  }

  static scanSshKeyPermissions(target) {
    if (target.type !== "system") return [];

    const findings = [];
    const sshDir = path.join(os.homedir(), ".ssh");
    if (!fs.existsSync(sshDir)) return findings;

    for (const keyName of ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]) {
      const keyPath = path.join(sshDir, keyName);
      if (!fs.existsSync(keyPath)) continue;

      const mode = fs.statSync(keyPath).mode & 0o777;
      if ((mode & 0o077) !== 0) {
        findings.push({
          severity: "high",
          category: "system",
          message: `SSH private key permissions are too open: ${keyName}`,
          detail: `Mode is ${mode.toString(8)}; recommended is 600. File contents were not read.`,
          fix: `Run: chmod 600 ${keyPath}`,
        });
      }
    }

    return findings;
  }

  static scanProjectGitignore(target) {
    if (target.type === "system") return [];

    const findings = [];
    const gitignorePath = path.join(target.root, ".gitignore");
    if (!fs.existsSync(gitignorePath)) {
      findings.push({
        severity: "medium",
        category: "system",
        message: "Project has no .gitignore",
        detail: "Add .env, logs, local databases, build output, and OS metadata to reduce accidental leaks.",
      });
      return findings;
    }

    let gitignore = "";
    try {
      gitignore = fs.readFileSync(gitignorePath, "utf-8");
    } catch {
      return findings;
    }

    const ignored = gitignore.split(/\r?\n/).map((line) => line.trim().replace(/\/$/, ""));
    for (const required of [".env", "*.log", "node_modules", "db"]) {
      if (!ignored.some((line) => line === required || line === `${required}/*` || line === `${required}/**`)) {
        findings.push({
          severity: "low",
          category: "system",
          message: `.gitignore missing recommended entry: ${required}`,
          detail: "This is safe to add with Apply Safe Fixes.",
          package: required,
        });
      }
    }

    return findings;
  }

  static findFiles(root, maxDepth) {
    const results = [];
    const skip = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage"]);

    const walk = (dir, depth) => {
      if (depth > maxDepth) return;
      let entries = [];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (!skip.has(entry.name)) walk(full, depth + 1);
        } else if (entry.isFile()) {
          results.push(full);
        }
      }
    };

    walk(root, 0);
    return results;
  }
}
