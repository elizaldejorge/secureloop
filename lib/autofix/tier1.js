/**
 * SecureLoop - AutoFix Tier 1
 * by Jorge Elizalde
 *
 * Deterministic, safe, no-AI fixes. Never calls an LLM. Never sends code
 * to a third party. Runs entirely on the user's machine.
 *
 * Implemented fixes:
 *   - cve-bump              → bump vulnerable dependency to fixed version in package.json
 *   - pin-version           → replace "*" or "latest" with current declared version
 *   - gitignore-secret-file → append bundled secret file to .gitignore (never delete)
 *   - gitignore-entry       → append a recommended hygiene entry to .gitignore
 *   - regen-lockfile        → no-op placeholder (would shell out to npm); logged, not shipped
 *
 * Contract:
 *   applyFix(finding, skillPath, {dryRun}) → {applied, changed: string[], diff, error}
 *   - applied=true only when files on disk were modified (or would be, in dry-run).
 *   - dryRun=true is DEFAULT and never writes to disk.
 *   - Always returns an object; never throws.
 */

import fs from "fs";
import path from "path";
import { classifyFinding } from "./classify.js";

/**
 * Apply a single Tier-1 fix.
 *
 * @param {object}  finding
 * @param {string}  skillPath            Absolute path to the skill directory.
 * @param {object}  [options]
 * @param {boolean} [options.dryRun=true] If true, do not write to disk.
 * @returns {Promise<{
 *   applied:  boolean,        // true when a change was (or would be) made
 *   reason:   string,         // classify() reason code
 *   changed:  string[],       // relative paths touched (or planned)
 *   diff?:    string,         // optional unified-diff-ish preview
 *   error?:   string,         // set when the fix could not be attempted
 * }>}
 */
export async function applyFix(finding, skillPath, options = {}) {
  const dryRun = options.dryRun !== false; // default true

  const { tier, reason } = classifyFinding(finding);
  if (tier !== "autofix") {
    return {
      applied: false,
      reason,
      changed: [],
      error: `Finding is tier ${tier}, not tier1 — applyFix refused.`,
    };
  }

  try {
    switch (reason) {
      case "cve-bump":              return fixCveBump(finding, skillPath, dryRun);
      case "pin-version":           return fixPinVersion(finding, skillPath, dryRun);
      case "gitignore-secret-file": return fixGitignoreSecretFile(finding, skillPath, dryRun);
      case "gitignore-entry":       return fixGitignoreEntry(finding, skillPath, dryRun);
      case "regen-lockfile":        return fixRegenLockfile(finding, skillPath, dryRun);
      default:
        return { applied: false, reason, changed: [], error: `Unknown tier1 reason: ${reason}` };
    }
  } catch (err) {
    return { applied: false, reason, changed: [], error: err.message };
  }
}

// ─── FIX: cve-bump ────────────────────────────────────────────────────────────
// Parse the OSV fix hint ("Fix available: upgrade to 4.17.21") and write that
// version into package.json. Preserves the original semver operator (^, ~) when
// possible. Does NOT shell out to npm install — that's the user's choice.
function fixCveBump(finding, skillPath, dryRun) {
  const pkgName = finding.package;
  const pkgJsonPath = path.join(skillPath, "package.json");

  if (!pkgName) {
    return { applied: false, reason: "cve-bump", changed: [], error: "Finding missing package name" };
  }
  if (!fs.existsSync(pkgJsonPath)) {
    return { applied: false, reason: "cve-bump", changed: [], error: `No package.json at ${pkgJsonPath}` };
  }

  // Extract target version from fix hint: "Fix available: upgrade to X.Y.Z"
  const match = /upgrade to\s+([^\s,]+)/i.exec(finding.fix || "");
  if (!match) {
    return { applied: false, reason: "cve-bump", changed: [], error: "No fix version found in finding.fix" };
  }
  const targetVersion = match[1].trim();

  const raw = fs.readFileSync(pkgJsonPath, "utf-8");
  const pkg = JSON.parse(raw);

  let section = null;
  if (pkg.dependencies     && pkgName in pkg.dependencies)     section = "dependencies";
  else if (pkg.devDependencies && pkgName in pkg.devDependencies) section = "devDependencies";
  if (!section) {
    return {
      applied: false,
      reason: "cve-bump",
      changed: [],
      error: `${pkgName} not in dependencies or devDependencies`,
    };
  }

  const previous = pkg[section][pkgName];
  const leading = /^[\^~>=<]+/.exec(previous)?.[0] || "^";
  const updated = `${leading}${targetVersion}`;

  if (previous === updated) {
    return { applied: false, reason: "cve-bump", changed: [], error: "Already at target version" };
  }

  pkg[section][pkgName] = updated;

  const diff = `- "${pkgName}": "${previous}"\n+ "${pkgName}": "${updated}"`;

  if (!dryRun) {
    const newContents = JSON.stringify(pkg, null, 2) + "\n";
    fs.writeFileSync(pkgJsonPath, newContents, "utf-8");
  }

  return {
    applied: true,
    reason: "cve-bump",
    changed: ["package.json"],
    diff,
  };
}

// ─── FIX: pin-version ────────────────────────────────────────────────────────
// Placeholder: replacing "*" or "latest" without a lockfile lookup is unsafe.
// We defer this to a follow-up by reading package-lock.json when available.
function fixPinVersion(finding, skillPath, dryRun) {
  const pkgName = finding.package;
  const pkgJsonPath    = path.join(skillPath, "package.json");
  const lockfilePath   = path.join(skillPath, "package-lock.json");

  if (!pkgName || !fs.existsSync(pkgJsonPath) || !fs.existsSync(lockfilePath)) {
    return {
      applied: false,
      reason: "pin-version",
      changed: [],
      error: "Need package.json + package-lock.json to safely pin a version",
    };
  }

  const pkg  = JSON.parse(fs.readFileSync(pkgJsonPath,  "utf-8"));
  const lock = JSON.parse(fs.readFileSync(lockfilePath, "utf-8"));

  // package-lock v2/v3 stores resolved versions under "packages" keyed by path.
  const lockEntry = lock.packages?.[`node_modules/${pkgName}`];
  if (!lockEntry?.version) {
    return {
      applied: false,
      reason: "pin-version",
      changed: [],
      error: `Could not resolve concrete version for ${pkgName} from lockfile`,
    };
  }

  const target = `^${lockEntry.version}`;
  let section = null;
  if (pkg.dependencies     && pkgName in pkg.dependencies)     section = "dependencies";
  else if (pkg.devDependencies && pkgName in pkg.devDependencies) section = "devDependencies";
  if (!section) {
    return {
      applied: false,
      reason: "pin-version",
      changed: [],
      error: `${pkgName} not in dependencies or devDependencies`,
    };
  }

  const previous = pkg[section][pkgName];
  if (previous === target) {
    return { applied: false, reason: "pin-version", changed: [], error: "Already pinned" };
  }

  pkg[section][pkgName] = target;
  const diff = `- "${pkgName}": "${previous}"\n+ "${pkgName}": "${target}"  # pinned from lockfile`;

  if (!dryRun) {
    fs.writeFileSync(pkgJsonPath, JSON.stringify(pkg, null, 2) + "\n", "utf-8");
  }

  return { applied: true, reason: "pin-version", changed: ["package.json"], diff };
}

// ─── FIX: gitignore-secret-file ──────────────────────────────────────────────
// Append the detected secret file pattern to .gitignore. NEVER delete the file.
// If .gitignore does not exist, create it. Idempotent: skips duplicates.
function fixGitignoreSecretFile(finding, skillPath, dryRun) {
  // Try to pull a filename out of finding.detail; fall back to a conservative default.
  const detail = finding.detail || "";
  const fileMatch = /(\.env[^\s]*|credentials\.json|secrets\.json|firebase-adminsdk[^\s]*)/i.exec(detail);
  const target = fileMatch?.[1] || ".env";

  const gitignorePath = path.join(skillPath, ".gitignore");
  const existing = fs.existsSync(gitignorePath) ? fs.readFileSync(gitignorePath, "utf-8") : "";

  const lines = existing.split(/\r?\n/);
  if (lines.some((l) => l.trim() === target)) {
    return { applied: false, reason: "gitignore-secret-file", changed: [], error: "Already in .gitignore" };
  }

  const addition =
    (existing && !existing.endsWith("\n") ? "\n" : "") +
    `\n# SecureLoop AutoFix — bundled secret file detected\n${target}\n`;

  const diff = `+ ${target}  (appended to .gitignore)`;

  if (!dryRun) {
    fs.writeFileSync(gitignorePath, existing + addition, "utf-8");
  }

  return { applied: true, reason: "gitignore-secret-file", changed: [".gitignore"], diff };
}

// ─── FIX: gitignore-entry ───────────────────────────────────────────────────
// Append a recommended hygiene entry produced by scanner/system.js. Safe,
// idempotent, and non-destructive.
function fixGitignoreEntry(finding, skillPath, dryRun) {
  const match = /recommended entry:\s*([^\s]+)/i.exec(finding.message || "");
  const target = match?.[1]?.trim();
  if (!target) {
    return { applied: false, reason: "gitignore-entry", changed: [], error: "Could not parse .gitignore entry" };
  }

  const gitignorePath = path.join(skillPath, ".gitignore");
  const existing = fs.existsSync(gitignorePath) ? fs.readFileSync(gitignorePath, "utf-8") : "";
  const lines = existing.split(/\r?\n/);
  if (lines.some((l) => l.trim() === target)) {
    return { applied: false, reason: "gitignore-entry", changed: [], error: "Already in .gitignore" };
  }

  const addition =
    (existing && !existing.endsWith("\n") ? "\n" : "") +
    `\n# SecureLoop AutoFix — recommended local security hygiene\n${target}\n`;
  const diff = `+ ${target}  (appended to .gitignore)`;

  if (!dryRun) {
    fs.writeFileSync(gitignorePath, existing + addition, "utf-8");
  }

  return { applied: true, reason: "gitignore-entry", changed: [".gitignore"], diff };
}

// ─── FIX: regen-lockfile ─────────────────────────────────────────────────────
// Intentionally NOT shelling out to npm from the scanner for the MVP.
// Returns a non-applied, no-error result with a human-readable suggestion.
function fixRegenLockfile(_finding, _skillPath, _dryRun) {
  return {
    applied: false,
    reason: "regen-lockfile",
    changed: [],
    error: "Not auto-executed in MVP. Run `npm install --package-lock-only` manually.",
  };
}
