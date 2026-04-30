/**
 * SecureLoop - Finding Enrichment
 *
 * Adds exploitability and confidence metadata to scanner findings. This keeps
 * raw scanner rules simple while giving the dashboard/reporting layer a more
 * security-review-friendly interpretation.
 */

const SEVERITY_BASE = {
  critical: 85,
  high: 68,
  medium: 42,
  low: 18,
};

const CATEGORY_BONUS = {
  "attack-path": 14,
  "secrets": 10,
  "network": 8,
  "dangerous-code": 7,
  "permissions": 5,
  "dependencies": 4,
  "system": 2,
  "obfuscation": 6,
  "access": 5,
};

export function enrichFindings(findings = []) {
  return findings.map((finding) => {
    const exploitability = calculateExploitability(finding);
    const confidence = normalizeConfidence(finding.confidence, finding);
    return {
      ...finding,
      exploitability,
      confidence,
      impact: finding.impact || impactLabel(finding),
      evidence: finding.evidence || evidenceLabel(finding),
    };
  });
}

export function summarizeEnrichedFindings(findings = []) {
  if (!findings.length) {
    return { exploitabilityIndex: 0, confidence: "high", attackPaths: 0, fixable: 0 };
  }

  const top = Math.max(...findings.map((f) => Number(f.exploitability?.score || 0)));
  const attackPaths = findings.filter((f) => f.category === "attack-path").length;
  const fixable = findings.filter((f) => f.fix || /safe to add|Fix available|pin/i.test(f.detail || f.message || "")).length;
  const confidenceCounts = findings.reduce((acc, f) => {
    acc[f.confidence || "medium"] = (acc[f.confidence || "medium"] || 0) + 1;
    return acc;
  }, {});

  const confidence = confidenceCounts.high >= confidenceCounts.medium ? "high" : "medium";
  return { exploitabilityIndex: top, confidence, attackPaths, fixable };
}

function calculateExploitability(finding) {
  let score = SEVERITY_BASE[finding.severity] ?? 25;
  score += CATEGORY_BONUS[finding.category] ?? 0;

  const text = `${finding.message || ""} ${finding.detail || ""} ${finding.snippet || ""}`.toLowerCase();
  if (text.includes("request input") || text.includes("user-controlled")) score += 12;
  if (text.includes("0.0.0.0") || text.includes("network-exposed") || text.includes("all network interfaces")) score += 10;
  if (text.includes("exec") || text.includes("shell") || text.includes("dynamic code")) score += 10;
  if (text.includes("critical") || text.includes("credential") || text.includes("token") || text.includes("api key")) score += 8;
  if (finding.line) score += 3;
  if (finding.fix) score -= 4;
  if (finding.severity === "low") score = Math.min(score, 35);

  score = clamp(score, 0, 100);
  return { score, band: exploitabilityBand(score), rationale: exploitabilityRationale(finding, score) };
}

function normalizeConfidence(value, finding) {
  if (value === "high" || value === "medium" || value === "low") return value;
  if (typeof value === "number") {
    if (value >= 0.75) return "high";
    if (value >= 0.45) return "medium";
    return "low";
  }
  if (finding.category === "attack-path") return "high";
  if (finding.line || finding.package || finding.osvUrl) return "high";
  if (finding.category === "network" || finding.category === "system") return "medium";
  return "medium";
}

function impactLabel(finding) {
  if (finding.category === "attack-path") return "Exploit chain";
  if (finding.category === "secrets") return "Credential exposure";
  if (finding.category === "dependencies") return "Known vulnerability";
  if (finding.category === "permissions") return "Privilege exposure";
  if (finding.category === "network") return "Network exposure";
  if (finding.category === "system") return "Local posture";
  if (finding.category === "dangerous-code") return "Code execution risk";
  return "Security hygiene";
}

function evidenceLabel(finding) {
  if (finding.osvUrl) return "OSV advisory";
  if (finding.line) return "Source line";
  if (finding.package) return "Package metadata";
  if (finding.detail) return "Configuration evidence";
  return "Scanner rule";
}

function exploitabilityBand(score) {
  if (score >= 85) return "Very High";
  if (score >= 65) return "High";
  if (score >= 40) return "Moderate";
  if (score > 0) return "Low";
  return "None";
}

function exploitabilityRationale(finding, score) {
  if (finding.category === "attack-path") return "Multiple risky conditions are connected into a plausible attack path.";
  if (score >= 85) return "High-impact finding with concrete evidence or reachable behavior.";
  if (score >= 65) return "Risky behavior with enough evidence to prioritize review.";
  if (score >= 40) return "Potentially risky configuration or code pattern.";
  return "Low-risk hygiene or contextual note.";
}

function clamp(n, min, max) {
  return Math.min(Math.max(Math.round(n), min), max);
}
