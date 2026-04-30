/**
 * SecureLoop - Behavior / Attack Path Scanner
 *
 * Looks for vulnerability chains, not just isolated suspicious strings. This
 * is still passive static analysis: it reads project files and never executes
 * target code.
 */

import fs from "fs";
import path from "path";
import { resolveAuditTarget } from "../lib/targets.js";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage"]);
const CODE_FILES = /\.(js|mjs|cjs|ts|tsx)$/i;

const SOURCE_RE = /\b(req\.(query|body|params|headers)|request\.(query|body|params|headers)|process\.argv|URLSearchParams|searchParams\.get)\b/i;
const SHELL_SINK_RE = /\b(exec|execSync|spawn|spawnSync)\s*\(/;
const EVAL_SINK_RE = /\b(eval|Function)\s*\(/;
const FETCH_SINK_RE = /\b(fetch|axios\.(get|post|request)|request\s*\()\s*\(/;
const FILE_SINK_RE = /\bfs\.(readFileSync|readFile|writeFileSync|writeFile|appendFile|createReadStream|createWriteStream)\s*\(/;
const LISTEN_ALL_RE = /listen\s*\([^)]*0\.0\.0\.0|host\s*[:=]\s*['"]0\.0\.0\.0['"]/i;
const ROUTE_RE = /\.(get|post|put|patch|delete|all)\s*\(\s*['"`][^'"`]+['"`]/;
const ADMIN_ROUTE_RE = /\.(get|post|put|patch|delete|all)\s*\(\s*['"`][^'"`]*(admin|debug|internal|dev|shell|exec|command)[^'"`]*['"`]/i;

export class BehaviorScanner {
  static async scan(targetName) {
    const target = resolveAuditTarget(targetName);
    if (!target.root || target.type === "system") return [];

    const findings = [];
    const facts = {
      listensAll: [],
      shellCapability: [],
      routeHandlers: [],
      adminRoutes: [],
      requestToShell: [],
      requestToEval: [],
      requestToFetch: [],
      requestToFile: [],
      weakCrypto: [],
      unsafeJwt: [],
    };

    for (const file of BehaviorScanner.walkFiles(target.root)) {
      const rel = path.relative(target.root, file);
      let text = "";
      try { text = fs.readFileSync(file, "utf-8"); } catch { continue; }

      const lines = text.split(/\r?\n/);
      lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (BehaviorScanner.shouldSkipLine(trimmed)) return;

        const loc = `${rel}:${idx + 1}`;
        const hasSource = SOURCE_RE.test(line);
        const hasShell = SHELL_SINK_RE.test(line);
        const hasEval = EVAL_SINK_RE.test(line);

        if (LISTEN_ALL_RE.test(line)) facts.listensAll.push({ loc, line: trimmed });
        if (hasShell) facts.shellCapability.push({ loc, line: trimmed });
        if (ROUTE_RE.test(line)) facts.routeHandlers.push({ loc, line: trimmed });
        if (ADMIN_ROUTE_RE.test(line)) facts.adminRoutes.push({ loc, line: trimmed });

        if (hasSource && hasShell) facts.requestToShell.push({ loc, line: trimmed });
        if (hasSource && hasEval) facts.requestToEval.push({ loc, line: trimmed });
        if (hasSource && FETCH_SINK_RE.test(line)) facts.requestToFetch.push({ loc, line: trimmed });
        if (hasSource && FILE_SINK_RE.test(line)) facts.requestToFile.push({ loc, line: trimmed });
        if (/crypto\.createHash\s*\(\s*['"](md5|sha1)['"]\s*\)/i.test(line)) facts.weakCrypto.push({ loc, line: trimmed });
        if (/jwt\.verify\s*\([^)]*ignoreExpiration\s*:\s*true/i.test(line)) facts.unsafeJwt.push({ loc, line: trimmed });
      });
    }

    for (const hit of facts.requestToShell) {
      findings.push(BehaviorScanner.finding("critical", "Request input can reach shell execution", hit,
        "User-controlled request data appears in a command-execution call. Replace shell execution with safe APIs or strict allowlisted arguments."));
    }
    for (const hit of facts.requestToEval) {
      findings.push(BehaviorScanner.finding("critical", "Request input can reach dynamic code execution", hit,
        "User-controlled input appears in eval/new Function. Remove dynamic code execution."));
    }
    for (const hit of facts.requestToFetch) {
      findings.push(BehaviorScanner.finding("high", "Request input may control an outbound network request", hit,
        "This can become SSRF if URLs are user-controlled. Restrict destinations with an allowlist."));
    }
    for (const hit of facts.requestToFile) {
      findings.push(BehaviorScanner.finding("high", "Request input may control filesystem access", hit,
        "Validate and normalize paths against a fixed base directory to prevent traversal or arbitrary writes."));
    }
    for (const hit of facts.weakCrypto) {
      findings.push(BehaviorScanner.finding("medium", "Weak hash algorithm used", hit,
        "Use SHA-256 or stronger for integrity checks, and a password-hashing algorithm for passwords."));
    }
    for (const hit of facts.unsafeJwt) {
      findings.push(BehaviorScanner.finding("critical", "JWT expiration validation is disabled", hit,
        "Do not ignore token expiration in authentication or authorization paths."));
    }

    if (facts.listensAll.length && facts.shellCapability.length) {
      findings.push({
        severity: "critical",
        category: "attack-path",
        message: "Attack path: network-exposed service with command execution capability",
        detail: `${facts.listensAll[0].loc} exposes the service; ${facts.shellCapability[0].loc} can spawn commands. Verify this cannot be reached remotely.`,
        confidence: "medium",
      });
    }

    if (facts.adminRoutes.length && (facts.shellCapability.length || facts.requestToFile.length)) {
      const sink = facts.shellCapability[0] || facts.requestToFile[0];
      findings.push({
        severity: "high",
        category: "attack-path",
        message: "Attack path: sensitive admin/debug route near privileged behavior",
        detail: `${facts.adminRoutes[0].loc} defines a sensitive route; ${sink.loc} performs privileged behavior. Require authentication and strict input validation.`,
        confidence: "medium",
      });
    }

    return BehaviorScanner.dedupe(findings);
  }

  static finding(severity, message, hit, fix) {
    return {
      severity,
      category: "attack-path",
      message,
      detail: `${hit.loc} — ${fix}`,
      line: Number(hit.loc.split(":").pop()) || undefined,
      snippet: hit.line.substring(0, 120),
      confidence: "high",
    };
  }

  static walkFiles(root) {
    const files = [];
    const walk = (dir) => {
      let entries = [];
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (!SKIP_DIRS.has(entry.name)) walk(full);
        } else if (entry.isFile() && CODE_FILES.test(entry.name)) {
          files.push(full);
        }
      }
    };
    walk(root);
    return files;
  }

  static shouldSkipLine(trimmed) {
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("*")) return true;
    if (/^\{\s*pattern:\s*\//.test(trimmed)) return true;
    if (/^(const|let|var)\s+\w+\s*=\s*\/.+\/[a-z]*[;,]?$/.test(trimmed)) return true;
    if (/^(message|advice|rationale|error):\s*["'`]/.test(trimmed)) return true;
    return false;
  }

  static dedupe(findings) {
    const seen = new Set();
    return findings.filter((finding) => {
      const key = `${finding.severity}|${finding.message}|${finding.detail}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
}
