/**
 * SecureLoop - AutoFix Classification
 * by Jorge Elizalde
 *
 * Classifies each finding into one of three fix tiers:
 *
 *   tier1  — "autofix"     → safe, deterministic, no external services, no AI
 *   tier2  — "suggestfix"  → AI-drafted patch, human must approve (LLM call)
 *   tier3  — "neverfix"    → flag only; we will not attempt automated remediation
 *
 * See CONTEXT/AUTOFIX_DESIGN.md for the rationale and the business decisions
 * that gate Tier 2 (pricing, liability, licensing, SOC 2 scope, privacy).
 *
 * This module has ZERO external dependencies and makes ZERO network calls.
 * It is safe to import from anywhere.
 */

/**
 * @typedef {object} Finding  (see CLAUDE.md for the full spec)
 * @property {string} severity
 * @property {string} category
 * @property {string} message
 * @property {string} [detail]
 * @property {string} [package]
 * @property {string} [version]
 * @property {string} [fix]       OSV "fix available in X" text, when present
 * @property {string} [cve]
 * @property {string} [osvUrl]
 */

/**
 * @typedef {"autofix" | "suggestfix" | "neverfix"} FixTier
 */

/**
 * Classify a single finding.
 *
 * @param {Finding} finding
 * @returns {{tier: FixTier, reason: string}}
 */
export function classifyFinding(finding) {
  const { category, message = "", fix } = finding;

  // ── Tier 1: deterministic, safe autofixes ──────────────────────────────────

  // Dependency CVEs with a known fix version → bump the version in package.json
  if (category === "dependencies" && finding.package && fix && /upgrade to /i.test(fix)) {
    return { tier: "autofix", reason: "cve-bump" };
  }

  // Unpinned versions (* or latest) → pin to a concrete version
  if (category === "dependencies" && /unpinned version/i.test(message)) {
    return { tier: "autofix", reason: "pin-version" };
  }

  // Stale/missing lockfile → regenerate via `npm install --package-lock-only`
  if (category === "dependencies" && /missing.*lock|no lockfile/i.test(message)) {
    return { tier: "autofix", reason: "regen-lockfile" };
  }

  // Bundled secret files (.env, credentials.json, etc.) → add to .gitignore,
  // do NOT delete. Deletion is destructive; gitignore is safe.
  if (category === "permissions" && /bundled secret|\.env |credentials\.json|secrets\.json/i.test(message)) {
    return { tier: "autofix", reason: "gitignore-secret-file" };
  }

  // Missing .gitignore hygiene entries are deterministic and safe to append.
  if (category === "system" && /\.gitignore missing recommended entry/i.test(message)) {
    return { tier: "autofix", reason: "gitignore-entry" };
  }

  // Dangerous lifecycle scripts (postinstall, preinstall, prepare) are not
  // safely auto-fixable in general (they might be legitimate). Flag only.
  // (Intentionally falls through to Tier 3.)

  // ── Tier 2: AI-drafted, human-approved ─────────────────────────────────────

  // Hardcoded secrets in source code — rewriting to process.env.X changes
  // runtime behavior and needs review. Good Tier-2 candidate.
  if (category === "secrets") {
    return { tier: "suggestfix", reason: "rewrite-hardcoded-secret" };
  }

  // OAuth scope narrowing — same pattern; AI drafts a narrower scope, user approves.
  if (category === "permissions" && /oauth scope|scope/i.test(message)) {
    return { tier: "suggestfix", reason: "narrow-oauth-scope" };
  }

  // Network hardening is a good AI-assisted candidate, but still requires
  // human approval because changing bind hosts/CORS/TLS can alter connectivity.
  if (category === "network" && /0\.0\.0\.0|CORS|TLS|HTTP|interfaces/i.test(message)) {
    return { tier: "suggestfix", reason: "harden-network-exposure" };
  }

  // ── Tier 3: never auto-fix, flag only ──────────────────────────────────────

  // Dynamic code execution (eval/exec/child_process) — often intentional,
  // rewriting is application-specific. Manual review only.
  if (category === "dangerous-code") {
    return { tier: "neverfix", reason: "dangerous-code-needs-human" };
  }

  // Obfuscation — if code is obfuscated we do not try to "un-obfuscate" it.
  // Correct response is quarantine + manual review, not auto-repair.
  if (category === "obfuscation") {
    return { tier: "neverfix", reason: "obfuscation-needs-human" };
  }

  // Credential access patterns (ssh keys, AWS keychain, cookies) — if the skill
  // actually needs that access the fix is a human judgment call.
  if (category === "access") {
    return { tier: "neverfix", reason: "access-pattern-needs-human" };
  }

  if (category === "system") {
    return { tier: "neverfix", reason: "system-posture-needs-human" };
  }

  // Anything we haven't recognized defaults to neverfix — safer than guessing.
  return { tier: "neverfix", reason: "unclassified" };
}

/**
 * Bucket a batch of findings by tier.
 *
 * @param {Finding[]} findings
 * @returns {{tier1: Finding[], tier2: Finding[], tier3: Finding[]}}
 */
export function bucketFindings(findings) {
  const tier1 = [];
  const tier2 = [];
  const tier3 = [];
  for (const f of findings) {
    const { tier } = classifyFinding(f);
    if (tier === "autofix")     tier1.push({ ...f, _fixTier: 1, _fixReason: classifyFinding(f).reason });
    else if (tier === "suggestfix") tier2.push({ ...f, _fixTier: 2, _fixReason: classifyFinding(f).reason });
    else                            tier3.push({ ...f, _fixTier: 3, _fixReason: classifyFinding(f).reason });
  }
  return { tier1, tier2, tier3 };
}
