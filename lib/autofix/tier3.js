/**
 * SecureLoop - AutoFix Tier 3 (Flag-only)
 * by Jorge Elizalde
 *
 * For findings that we deliberately refuse to auto-fix, even with AI:
 *   - Dynamic code (eval, exec, child_process)  → may be intentional
 *   - Obfuscation (hex, base64 payloads, _0x…)  → possibly malware
 *   - Credential access (ssh, keychain, AWS)    → app-specific intent
 *
 * Correct response is flag + recommend quarantine, not patch.
 */

/**
 * Produce a structured "requires manual review" record for a Tier-3 finding.
 *
 * @param {object} finding
 * @returns {{
 *   quarantined: boolean,     // always false — we do not auto-quarantine either
 *   reason:      string,
 *   recommendation: string,
 * }}
 */
export function flagForReview(finding) {
  const category = finding.category || "unknown";

  const recommendations = {
    "dangerous-code":
      "Review this call site manually. If the skill legitimately needs shell/eval access, whitelist it; otherwise uninstall.",
    "obfuscation":
      "Possible malware. Do not install. Report to ClawHub via /secureloop-block and quarantine the extension directory.",
    "access":
      "Skill requests access to credentials or private keys. Verify this matches the skill's stated purpose before trusting.",
    "secrets":
      "Hardcoded secret — Tier 2 AI-assisted fix can draft a patch once enabled. Until then, rotate the credential and move to env vars manually.",
  };

  return {
    quarantined: false,
    reason: `tier3:${category}`,
    recommendation:
      recommendations[category] ||
      "Manual review required. SecureLoop will not attempt to auto-fix this finding.",
  };
}
