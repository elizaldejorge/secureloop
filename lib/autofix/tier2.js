/**
 * SecureLoop - AutoFix Tier 2 (AI-assisted, human-approved)
 * by Jorge Elizalde
 *
 * AI patching guardrails:
 *   OPEN-005 → BYOK only (user sets OPENAI_API_KEY by default)
 *   OPEN-006 → Dry-run + explicit human approval + ToS disclaimer
 *   OPEN-007 → OpenAI Responses API for AI review patches
 *   OPEN-008 → Tier 2 ships under MIT open-core (moved to BSL if/when bundled billing ships)
 *   OPEN-009 → Opt-in per-scan, local audit log
 *
 * Contract:
 *   proposeFix(finding, skillPath, { dryRun, apiKey, model })
 *     → returns a structured proposal with a unified diff.
 *     → NEVER auto-applies; apply flows through /secureloop-tier2-apply
 *       after an explicit human approval click in the dashboard or slash command.
 */

import { buildTier2Context }   from "./context.js";
import { SYSTEM_PROMPT, buildUserPrompt } from "./prompts.js";
import { parseUnifiedDiff, validateDiff } from "./diff.js";
import { OpenAIProvider }      from "./providers/openai.js";

// Kill-switch for the AI review path in case egress needs to be disabled quickly.
export const TIER2_ENABLED = true;

/**
 * Propose an AI-drafted fix for a Tier-2 finding.
 *
 * @param {object} finding
 * @param {string} skillPath
 * @param {object} [options]
 * @param {string} [options.apiKey]       override provider env key
 * @param {string} [options.model]        override env SECURELOOP_TIER2_MODEL
 * @param {string} [options.provider]     reserved; OpenAI is the supported provider
 * @param {string} [options.fixReason]    classify.js _fixReason (defaults from finding)
 * @returns {Promise<{
 *   proposed:   boolean,
 *   reason:     string,
 *   rationale?: string,
 *   confidence?: number,
 *   diff?:      string,
 *   envVars?:   {name:string, hint?:string}[],
 *   model?:     string,
 *   usage?:     object,
 *   context?:   { file:string, line:number, redactions:number },
 *   error?:     string,
 * }>}
 */
export async function proposeFix(finding, skillPath, options = {}) {
  if (!TIER2_ENABLED) {
    return {
      proposed: false,
      reason:   "tier2-disabled",
      error:    "Tier 2 disabled by kill-switch. Set TIER2_ENABLED=true to re-enable.",
    };
  }

  const fixReason = options.fixReason || finding._fixReason || "default";

  // 1. Build minimal code window around the finding.
  const ctx = buildTier2Context(finding, skillPath);
  if (!ctx.ok) {
    return { proposed: false, reason: `context:${ctx.reason}`,
      error: `Could not build context: ${ctx.reason}` };
  }

  // 2. Build prompts.
  const userPrompt = buildUserPrompt(finding, ctx, fixReason);

  // 3. Call OpenAI. The model drafts a patch; SecureLoop validates it before a
  // human can approve and apply it.
  const providerName = "openai";
  const provider = new OpenAIProvider({ apiKey: options.apiKey, model: options.model });
  if (!provider.hasKey()) {
    return {
      proposed: false,
      reason:   "no-api-key",
      error:    "OPENAI_API_KEY is not set. AI review patches are BYOK — " +
                "set the env var to enable AI-drafted patches.",
      context:  { file: ctx.relFile, line: ctx.line, redactions: ctx.redactions },
    };
  }

  const res = await provider.complete(SYSTEM_PROMPT, userPrompt);
  if (!res.ok) {
    return {
      proposed: false,
      reason:   "provider-error",
      error:    `${providerName} API: ${res.error || "unknown"}`,
      context:  { file: ctx.relFile, line: ctx.line, redactions: ctx.redactions },
    };
  }

  // 4. Parse JSON envelope.
  const parsed = safeJsonExtract(res.text);
  if (!parsed.ok) {
    return {
      proposed: false,
      reason:   "bad-model-output",
      error:    `Model did not return valid JSON: ${parsed.error}`,
      context:  { file: ctx.relFile, line: ctx.line, redactions: ctx.redactions },
    };
  }
  const envelope = parsed.value;

  const diff = typeof envelope.diff === "string" ? envelope.diff : "";
  if (!diff.trim()) {
    return {
      proposed:  false,
      reason:    "no-diff",
      rationale: envelope.rationale || "(no rationale)",
      confidence: Number(envelope.confidence) || 0,
      error:     "Model returned an empty diff.",
      model:     res.model,
      usage:     res.usage,
      context:   { file: ctx.relFile, line: ctx.line, redactions: ctx.redactions },
    };
  }

  // 5. Parse + validate the diff.
  const diffParsed = parseUnifiedDiff(diff);
  const diffValid  = validateDiff(diffParsed, ctx, skillPath);
  if (!diffValid.ok) {
    return {
      proposed:  false,
      reason:    `diff-invalid:${diffValid.reason}`,
      rationale: envelope.rationale,
      confidence: Number(envelope.confidence) || 0,
      diff,
      error:     `Rejected patch: ${diffValid.reason}`,
      model:     res.model,
      usage:     res.usage,
      context:   { file: ctx.relFile, line: ctx.line, redactions: ctx.redactions },
    };
  }

  // 6. Return a structured proposal. CALLERS MUST NOT AUTO-APPLY.
  return {
    proposed:   true,
    reason:     "ai-patch",
    rationale:  envelope.rationale || "(no rationale)",
    confidence: clampConfidence(envelope.confidence),
    diff,
    envVars:    Array.isArray(envelope.envVars) ? envelope.envVars : [],
    model:      res.model,
    provider:   providerName,
    usage:      res.usage,
    context:    {
      file:       ctx.relFile,
      line:       ctx.line,
      redactions: ctx.redactions,
    },
  };
}

/**
 * Extract a JSON object from a model response. Handles code-fence wrapping
 * and leading/trailing prose gracefully.
 */
function safeJsonExtract(text) {
  if (!text) return { ok: false, error: "empty" };
  // Strip common code-fence wrappers.
  let t = text.trim();
  const fenced = /^```(?:json)?\s*([\s\S]*?)\s*```$/m.exec(t);
  if (fenced) t = fenced[1].trim();

  // Find the first { and the matching closing } (naive but good enough
  // because we asked the model for a single JSON object only).
  const start = t.indexOf("{");
  const end   = t.lastIndexOf("}");
  if (start < 0 || end < start) return { ok: false, error: "no-braces" };
  const slice = t.slice(start, end + 1);
  try {
    return { ok: true, value: JSON.parse(slice) };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

function clampConfidence(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return 0;
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}
