/**
 * SecureLoop - Tier 2 OpenAI Provider Adapter
 *
 * BYOK OpenAI Responses API client for Codex-native remediation. The safety
 * contract stays strict: model drafts only, human approves, scanner rescans.
 */

const DEFAULT_MODEL = "gpt-5.3-codex";
const API_URL = "https://api.openai.com/v1/responses";
const DEFAULT_MAX_TOKENS = 2048;
const DEFAULT_TIMEOUT_MS = 30_000;

export class OpenAIProvider {
  /**
   * @param {object} [options]
   * @param {string} [options.apiKey]    overrides env OPENAI_API_KEY
   * @param {string} [options.model]     overrides env SECURELOOP_TIER2_MODEL
   * @param {number} [options.timeoutMs]
   */
  constructor(options = {}) {
    this.apiKey = options.apiKey || process.env.OPENAI_API_KEY || "";
    this.model = options.model || process.env.SECURELOOP_TIER2_MODEL || DEFAULT_MODEL;
    this.timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  }

  hasKey() {
    return Boolean(this.apiKey && this.apiKey.trim().length > 0);
  }

  async complete(systemPrompt, userPrompt, options = {}) {
    if (!this.hasKey()) {
      return { ok: false, error: "no-api-key", status: 0 };
    }

    const body = {
      model: options.model || this.model,
      input: [
        { role: "system", content: [{ type: "input_text", text: systemPrompt }] },
        { role: "user", content: [{ type: "input_text", text: userPrompt }] },
      ],
      max_output_tokens: options.maxTokens || DEFAULT_MAX_TOKENS,
      text: {
        format: {
          type: "json_schema",
          name: "secureloop_tier2_patch",
          strict: true,
          schema: {
            type: "object",
            additionalProperties: false,
            required: ["rationale", "confidence", "diff", "envVars"],
            properties: {
              rationale: { type: "string" },
              confidence: { type: "number", minimum: 0, maximum: 1 },
              diff: { type: "string" },
              envVars: {
                type: "array",
                items: {
                  type: "object",
                  additionalProperties: false,
                  required: ["name", "hint"],
                  properties: {
                    name: { type: "string" },
                    hint: { type: "string" },
                  },
                },
              },
            },
          },
        },
      },
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const resp = await fetch(API_URL, {
        method: "POST",
        signal: controller.signal,
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify(body),
      });

      clearTimeout(timer);

      const json = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        const msg = json?.error?.message || `HTTP ${resp.status}`;
        return { ok: false, status: resp.status, error: msg };
      }

      return {
        ok: true,
        text: extractOutputText(json),
        model: json.model || body.model,
        usage: json.usage,
        status: resp.status,
      };
    } catch (err) {
      clearTimeout(timer);
      if (err.name === "AbortError") {
        return { ok: false, error: "timeout", status: 0 };
      }
      return { ok: false, error: err.message, status: 0 };
    }
  }
}

function extractOutputText(json) {
  if (typeof json.output_text === "string") return json.output_text;

  const parts = [];
  for (const item of json.output || []) {
    for (const content of item.content || []) {
      if (content.type === "output_text" && typeof content.text === "string") {
        parts.push(content.text);
      }
    }
  }
  return parts.join("");
}

export default OpenAIProvider;
