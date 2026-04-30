/**
 * SecureLoop - Network Exposure Scanner
 *
 * Looks for risky local service exposure patterns in project source/config.
 * This scanner is intentionally passive: it does not port-scan the user's
 * network and never sends packets. It audits what the target is configured to do.
 */

import fs from "fs";
import os from "os";
import path from "path";
import { resolveAuditTarget } from "../lib/targets.js";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage"]);
const NETWORK_FILES = /\.(js|mjs|cjs|ts|tsx|json|env|yaml|yml|toml|conf|config)$/i;

const NETWORK_PATTERNS = [
  {
    pattern: /listen\s*\([^)]*0\.0\.0\.0/i,
    severity: "high",
    message: "Service binds to all network interfaces",
    advice: "Bind local dashboards and admin tools to 127.0.0.1 unless they must be reachable from the LAN.",
  },
  {
    pattern: /host\s*[:=]\s*['"]0\.0\.0\.0['"]/i,
    severity: "high",
    message: "Configuration exposes host 0.0.0.0",
    advice: "Use 127.0.0.1 for local-only tools.",
  },
  {
    pattern: /Access-Control-Allow-Origin['"]?\s*,?\s*['"]\*/i,
    severity: "high",
    message: "Wildcard CORS origin allows any website to call this service",
    advice: "Restrict CORS to the exact local or trusted origin.",
  },
  {
    pattern: /cors\s*\(\s*\)/i,
    severity: "medium",
    message: "Default CORS middleware may allow broader access than intended",
    advice: "Configure an explicit origin allowlist.",
  },
  {
    pattern: /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/i,
    severity: "medium",
    message: "Hardcoded IP address in network call",
    advice: "Move network targets into config and document why the address is trusted.",
  },
  {
    pattern: /http:\/\/(?!localhost|127\.0\.0\.1)/i,
    severity: "medium",
    message: "Plain HTTP endpoint detected",
    advice: "Use HTTPS for remote traffic whenever possible.",
  },
  {
    pattern: /rejectUnauthorized\s*:\s*false/i,
    severity: "critical",
    message: "TLS certificate verification disabled",
    advice: "Remove rejectUnauthorized:false and fix the certificate chain instead.",
  },
  {
    pattern: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/i,
    severity: "critical",
    message: "TLS verification disabled by environment",
    advice: "Do not disable TLS validation globally.",
  },
];

export class NetworkScanner {
  static async scan(targetName) {
    const findings = [];

    try {
      const target = resolveAuditTarget(targetName);
      if (!target.root) {
        return [{
          severity: "low",
          category: "network",
          message: `Network audit skipped: could not locate ${targetName}`,
          detail: "Provide an installed skill name, folder path, or 'system'.",
        }];
      }

      if (target.type === "system") {
        return NetworkScanner.scanSystemNetworkHints();
      }

      for (const file of NetworkScanner.walkFiles(target.root)) {
        let content;
        try {
          content = fs.readFileSync(file, "utf-8");
        } catch {
          continue;
        }

        const lines = content.split(/\r?\n/);
        lines.forEach((line, index) => {
          const trimmed = line.trim();
          if (NetworkScanner.shouldSkipLine(trimmed)) return;

          for (const check of NETWORK_PATTERNS) {
            if (!check.pattern.test(line)) continue;
            findings.push({
              severity: check.severity,
              category: "network",
              message: check.message,
              detail: `${path.relative(target.root, file)}:${index + 1} — ${check.advice}`,
              line: index + 1,
              snippet: trimmed.substring(0, 120),
            });
          }
        });
      }

      return findings;
    } catch (err) {
      return [{
        severity: "low",
        category: "network",
        message: "Network exposure scanner failed safely",
        detail: err.message,
      }];
    }
  }

  static walkFiles(root) {
    const files = [];
    const walk = (dir) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (!SKIP_DIRS.has(entry.name)) walk(full);
        } else if (entry.isFile() && NETWORK_FILES.test(entry.name)) {
          files.push(full);
        }
      }
    };
    walk(root);
    return files;
  }

  static scanSystemNetworkHints() {
    const findings = [];
    const sshDir = path.join(os.homedir(), ".ssh");
    const sshConfig = path.join(sshDir, "config");

    if (fs.existsSync(sshConfig)) {
      const text = fs.readFileSync(sshConfig, "utf-8");
      if (/StrictHostKeyChecking\s+no/i.test(text)) {
        findings.push({
          severity: "high",
          category: "network",
          message: "SSH host key checking is disabled",
          detail: "~/.ssh/config contains StrictHostKeyChecking no, which weakens man-in-the-middle protection.",
        });
      }
      if (/UserKnownHostsFile\s+\/dev\/null/i.test(text)) {
        findings.push({
          severity: "medium",
          category: "network",
          message: "SSH known-host tracking is disabled",
          detail: "~/.ssh/config sends known hosts to /dev/null, reducing auditability.",
        });
      }
    }

    return findings;
  }

  static shouldSkipLine(trimmed) {
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) return true;
    if (/^\{\s*pattern:\s*\//.test(trimmed)) return true;
    if (/^(message|advice):\s*["'`]/.test(trimmed)) return true;
    return false;
  }
}
