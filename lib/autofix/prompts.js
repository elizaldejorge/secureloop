/**
 * SecureLoop - AutoFix Tier 2 Prompts
 * by Jorge Elizalde
 *
 * Prompt builders for the LLM. Two templates:
 *   1. rewrite-hardcoded-secret   — move a literal credential to process.env.X
 *   2. narrow-oauth-scope         — narrow an overly broad OAuth scope list
 *   3. harden-network-exposure    — restrict local service/network exposure
 *
 * Every prompt instructs the model to return a STRICT JSON object with a
 * unified diff — no prose — so we can validate the result deterministically.
 *
 * The JSON contract the model must return:
 *
 *   {
 *     "rationale":  "<= 280 chars, why this change is safe",
 *     "confidence": 0..1,
 *     "diff":       "<a unified diff against the single file only>",
 *     "envVars":    [{ "name": "OPENAI_API_KEY", "hint": "OpenAI key" }]   // optional
 *   }
 */

export const SYSTEM_PROMPT = `You are SecureLoop's Tier-2 security fix proposer.
You will receive ONE security finding and a small code window around the offending line.
Your job is to propose the smallest possible unified-diff patch that fixes the finding
WITHOUT changing behavior outside the intent of the fix.

CRITICAL OUTPUT CONTRACT:
- Return ONLY a single JSON object, no prose before or after.
- The JSON must have exactly these fields: rationale, confidence, diff, envVars (optional).
- "diff" must be a unified diff that applies cleanly to the single file shown.
- The diff must touch ONLY the file shown — never create new files, never reference other files.
- The diff must not add any network calls, file system access, or process spawning.
- The diff must not import new packages. Only use built-ins and packages already imported in the file window.
- If you cannot produce a safe fix, return { "rationale": "<why>", "confidence": 0, "diff": "" }.
- "confidence" is your own estimate from 0 to 1 that the patch is behavior-preserving and correct.
- Never include real API keys or secrets in the output.
- Keep "rationale" under 280 characters.`;

/**
 * Build the per-finding user prompt.
 *
 * @param {object} finding         (see CLAUDE.md Finding schema)
 * @param {object} context         (see context.js buildTier2Context)
 * @param {string} fixReason       one of classify.js _fixReason values
 * @returns {string}
 */
export function buildUserPrompt(finding, context, fixReason) {
  const intent = FIX_INTENTS[fixReason] || FIX_INTENTS.default;

  const header =
    `# Finding\n` +
    `- severity: ${finding.severity}\n` +
    `- category: ${finding.category}\n` +
    `- message:  ${finding.message}\n` +
    `- detail:   ${finding.detail || "(none)"}\n` +
    (finding.snippet ? `- snippet:  ${truncate(finding.snippet, 200)}\n` : "") +
    `\n# Fix intent\n${intent}\n`;

  const body =
    `# File\n` +
    `- path: ${context.relFile}\n` +
    `- language: ${context.language}\n` +
    `- target line: ${context.line}\n\n` +
    "```" + context.language + "\n" +
    `/* --- lines above --- */\n` +
    context.before + "\n" +
    `/* --- TARGET LINE ${context.line} --- */\n` +
    context.hit + "\n" +
    `/* --- lines below --- */\n` +
    context.after + "\n" +
    "```\n";

  const tail =
    `\n# Output\n` +
    `Return ONE JSON object per the contract. Nothing else.`;

  return header + "\n" + body + tail;
}

const FIX_INTENTS = {
  "rewrite-hardcoded-secret":
    "Replace the hardcoded secret with a reference to process.env.<NAME>. " +
    "Choose <NAME> from the secret's obvious provider (e.g. OPENAI_API_KEY, " +
    "GITHUB_TOKEN, AWS_ACCESS_KEY_ID). If a value is missing at runtime, " +
    "throw a clear Error so it fails loudly. Do not change control flow " +
    "otherwise. Include the envVars array with the variable you introduced.",

  "narrow-oauth-scope":
    "Narrow the OAuth scope(s) to the minimum that still satisfies the " +
    "visible usage in the window. Prefer read-only scopes when writes are " +
    "not visibly required. Do not remove scopes that are clearly used.",

  "harden-network-exposure":
    "Reduce network exposure with the smallest behavior-preserving change. " +
    "Prefer localhost/127.0.0.1 for local dashboards, explicit CORS origins " +
    "instead of '*', HTTPS instead of HTTP for remote endpoints, and restored " +
    "TLS verification. If the safe value cannot be inferred, return confidence " +
    "0 and an empty diff.",

  "default":
    "Propose the smallest patch that resolves the finding while preserving " +
    "behavior. If unsure, return confidence 0 and an empty diff.",
};

function truncate(s, n) {
  if (!s) return "";
  return s.length > n ? s.slice(0, n) + "…" : s;
}
