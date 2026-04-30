/**
 * SecureLoop Advisor Brain
 *
 * Owns Advisor's security judgment: intent detection, scan summaries,
 * remediation priority, allowed actions, and model context. Optional language
 * models may polish wording, but this module decides what is true and allowed.
 */

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

const INTERPRETATION_INTENTS = new Set([
  "advisor-identity",
  "product-overview",
  "tutorial",
  "general-help",
  "navigate",
  "prepare-scan",
  "report",
  "remediation",
  "technical",
  "executive",
  "no-scan",
]);

export function buildAdvisorResponse({ mode = "executive", message = "", scan = null, interpretation = null } = {}) {
  const text = String(message || "").trim();
  const lower = text.toLowerCase();
  const interpreted = normalizeInterpretation(interpretation);
  const interpretedIntent = interpreted?.intent || "";

  if (!text) {
    return localResponse(
      "Ask me about the latest scan, what to fix first, what the risk means, or type a target like `scan system` to prepare a scan action. You can also ask: `Start tutorial`.\n\nNo execution: I’m not going to let free-form chat silently apply fixes or change policy.",
      [],
      { intent: "empty", allowPolish: false },
    );
  }

  if (/^(hi|hello|hey|yo)\b/i.test(lower)) {
    return localResponse(
      "Hi, I’m SecureLoop Advisor. I can explain the latest scan, walk you through the dashboard, prioritize fixes, open reports, or prepare an explicit scan like `scan system`.\n\nNo execution: I’m not going to let free-form chat silently apply fixes or change policy.",
      [
        { label: "Start tutorial", action: "ask", prompt: "Start tutorial" },
        { label: "Explain latest scan", action: "ask", prompt: "Explain the latest scan in simple terms" },
      ],
      { intent: "greeting", allowPolish: true },
    );
  }

  if (interpretedIntent === "advisor-identity" || /who are you|what are you|your name|are you an ai|what can you do|help me|help$/i.test(lower)) {
    return localResponse(
      [
        "I’m SecureLoop Advisor, the assistant built into SecureLoop.",
        "",
        "I can explain what SecureLoop does, walk you through the dashboard, summarize the latest scan, pull up safe dashboard pages like Scan History or Reports, prioritize fixes, and prepare explicit scan actions like `scan system`.",
        "",
        "I do not make security decisions on my own. SecureLoop’s local Advisor Brain decides facts, priorities, and allowed actions. Local or API models may only help with wording.",
        "",
        "No execution: I’m not going to let free-form chat silently apply fixes or change policy.",
      ].join("\n"),
      [
        { label: "Start tutorial", action: "ask", prompt: "Start tutorial" },
        { label: "What does SecureLoop do?", action: "ask", prompt: "What does this software do?" },
        ...(scan ? [{ label: "Explain latest scan", action: "ask", prompt: "Explain the latest scan in simple terms" }] : []),
      ],
      { intent: "advisor-identity", allowPolish: true },
    );
  }

  if (interpretedIntent === "general-help" || /should i .*tutorial|should .*tutorial|do i need .*tutorial|how can you help/i.test(lower)) {
    return localResponse(
      [
        "I can help in two ways: explain SecureLoop in plain English, or act like a guided security console for the latest scan.",
        "",
        "For a first run, yes, the tutorial is useful. It shows the full loop: run an audit, understand the risk, inspect evidence, preview fixes, and verify after remediation.",
        "",
        "You can also ask me to open safe dashboard pages like Scan History, Reports, Findings, Policy, or Guided Audit.",
        "",
        "No execution: I’m not going to let free-form chat silently apply fixes or change policy.",
      ].join("\n"),
      [
        { label: "Start tutorial", action: "ask", prompt: "Start tutorial" },
        { label: "Open Guided Audit", action: "view", view: "guide" },
        ...(scan ? [{ label: "Explain latest scan", action: "ask", prompt: "Explain the latest scan in simple terms" }] : []),
      ],
      { intent: "general-help", allowPolish: true },
    );
  }

  if (interpretedIntent === "tutorial" || /^(start|open|show|run|begin|launch)\b.*\b(tutorial|intro|walk.?through|getting started)\b|^(tutorial|intro|walk.?through|getting started)$/i.test(lower)) {
    return localResponse(
      [
        "SecureLoop Advisor tutorial:",
        "1. Start on Home and run an audit against `system`, a folder path, or the Guided Audit sample.",
        "2. Open Scan Details to see the plain-English summary, Exploitability Index, Attack Paths, and technical evidence.",
        "3. Ask me for an Executive explanation when you want simple language, or Technical mode when you want evidence and line-level detail.",
        "4. Use Preview Fixes before applying anything. AI Review Patches require human approval.",
        "5. Export a Scan Report or SARIF when you need evidence for review.",
        "",
        "No execution: I’m not going to let free-form chat silently apply fixes or change policy.",
      ].join("\n"),
      [
        { label: "Open Guided Audit", action: "view", view: "guide" },
        { label: "Explain latest scan", action: "ask", prompt: "Explain the latest scan in simple terms" },
        ...(scan ? [{ label: "Open latest report", action: "open-report", scanId: scan.id }] : []),
      ],
      { intent: "tutorial", allowPolish: false },
    );
  }

  if (interpretedIntent === "product-overview" || /what (is|does).*secureloop|what (does|is).*software|what (does|is).*app|what (does|is).*product|explain.*software|explain.*secureloop|what.*used for|what.*built for/i.test(lower)) {
    return localResponse(
      [
        "SecureLoop is an AI-powered cybersecurity audit console.",
        "",
        "It scans local projects, software/plugins, OpenClaw skills, network exposure, and privacy-preserving system posture. Then it explains the risk in plain English, shows technical evidence, prioritizes what to fix first, previews safe fixes, supports human-approved AI Review Patches, and rescans to verify whether the issue was actually fixed.",
        "",
        "The key idea is the loop: find risk, explain exploitability, fix safely, verify, and export evidence.",
        "",
        "No execution: I’m not going to let free-form chat silently apply fixes or change policy.",
      ].join("\n"),
      [
        { label: "Start tutorial", action: "ask", prompt: "Start tutorial" },
        { label: "Explain latest scan", action: "ask", prompt: "Explain the latest scan in simple terms" },
        ...(scan ? [{ label: "Open latest report", action: "open-report", scanId: scan.id }] : []),
      ],
      { intent: "product-overview", allowPolish: true },
    );
  }

  if (scan && /\b(open|show|pull up|go to|take me to|bring up|navigate|view)\b.*\b(latest|last|newest|recent)\s+scan\b/i.test(lower)) {
    return localResponse(
      "Opening latest scan details.",
      [{ label: "Open latest scan", action: "open-scan", scanId: scan.id }],
      { intent: "navigate", allowPolish: false },
    );
  }

  const navigation = interpretedIntent === "navigate" ? navigationFromInterpretation(interpreted) : navigationIntent(lower);
  if (navigation) {
    return localResponse(
      `Opening ${navigation.name}.`,
      [{ label: `Open ${navigation.name}`, action: "view", view: navigation.view }],
      { intent: "navigate", allowPolish: false },
    );
  }

  const scanMatch = text.match(/^scan\s+(.+)/i);
  if (scanMatch) {
    const target = scanMatch[1].trim().replace(/^["']|["']$/g, "");
    return localResponse(
      `I can run an audit for \`${target}\`. This will create a new local scan record and update the dashboard history.`,
      [{ label: `Run audit: ${target}`, action: "run-scan", target }],
      { intent: "prepare-scan", allowPolish: false },
    );
  }

  if (interpretedIntent === "prepare-scan" && interpreted.target) {
    const target = interpreted.target.trim().replace(/^["']|["']$/g, "");
    return localResponse(
      `I can run an audit for \`${target}\`. This will create a new local scan record and update the dashboard history.`,
      [{ label: `Run audit: ${target}`, action: "run-scan", target }],
      { intent: "prepare-scan", allowPolish: false },
    );
  }

  if (!scan) {
    return localResponse(
      "I do not have a scan to explain yet. Run a Guided Audit or ask me to scan a target, for example `scan system` or `scan ./demo-vulnerable-project`.",
      [
        { label: "Open Guided Audit", action: "view", view: "guide" },
        { label: "Scan computer", action: "run-scan", target: "system" },
      ],
      { intent: "no-scan", allowPolish: false },
    );
  }

  const summary = summarizeFindings(scan.findings);
  const top = topFindings(scan.findings);
  const target = scan.skill_name;
  const scoreLine = `Latest scan: \`${target}\` scored ${scan.risk_score}/100 (${scan.risk_level}) with ${summary.total} findings.`;
  const actions = [
    { label: "Open scan details", action: "open-scan", scanId: scan.id },
    { label: "Open scan report", action: "open-report", scanId: scan.id },
    { label: "Preview fixes", action: "preview-fixes", target },
  ];

  if (interpretedIntent === "report" || /report|export|pdf|sarif/i.test(lower)) {
    return localResponse(
      `${scoreLine}\n\nBest next export: open the Scan Report for a readable PDF-style summary, or SARIF if you want enterprise/code-scanning ingestion.`,
      [
        { label: "Open scan report", action: "open-report", scanId: scan.id },
        { label: "Download latest SARIF", action: "download", path: "/api/export/sarif" },
      ],
      { intent: "report", scan, summary, top, allowPolish: true },
    );
  }

  if (interpretedIntent === "remediation" || /fix|patch|remediate|what.*first|priority/i.test(lower)) {
    const first = top[0];
    const lines = top.map((f, i) => `${i + 1}. ${f.message} — ${f.severity}, exploitability ${f.exploitability?.score ?? "n/a"}/100`).join("\n");
    return localResponse(
      `${scoreLine}\n\nFix priority:\n${lines || "No findings to prioritize."}\n\nStart with ${first ? `\`${first.message}\`` : "the highest severity item"}. Use Preview Fixes first; apply only deterministic safe fixes or human-approved AI Review Patches.`,
      actions,
      { intent: "remediation", scan, summary, top, allowPolish: true },
    );
  }

  if (interpretedIntent === "technical" || /technical|evidence|line|why|details/i.test(lower)) {
    const lines = top.map((f, i) => `${i + 1}. ${f.message}\n   Severity: ${f.severity}; category: ${f.category || "security"}; exploitability: ${f.exploitability?.score ?? "n/a"}/100; evidence: ${f.evidence || "scanner rule"}; detail: ${f.detail || "n/a"}`).join("\n");
    return localResponse(
      `${scoreLine}\n\nTechnical evidence, prioritized:\n${lines}`,
      actions,
      { intent: "technical", scan, summary, top, allowPolish: true },
    );
  }

  if (interpretedIntent === "executive" || /latest scan|last scan|scan result|scan summary|risk mean|risk score|non.?technical|simple|explain|summary|executive|business/i.test(lower)) {
    const severity = summary.critical + summary.high;
    const plain = scan.risk_score >= 70
      ? `This target is not ready to trust. SecureLoop found ${severity} high-priority issues, including attack paths or privileged behavior that could matter in a real environment.`
      : scan.risk_score >= 40
        ? "This target needs review before trust. The risk is not automatically catastrophic, but there are enough warning signs to slow down and fix the important ones."
        : "This target looks comparatively healthy in this scan, but it should still be rescanned after meaningful changes.";
    return localResponse(
      `${scoreLine}\n\n${plain}\n\nMost important signal: exploitability ${summary.exploitability}/100 and ${summary.attackPaths} attack-path finding(s).`,
      actions,
      { intent: "executive", scan, summary, top, allowPolish: true },
    );
  }

  return localResponse(
    [
      "I can help with SecureLoop questions and safe dashboard actions.",
      "",
      "Try asking: “what does this software do?”, “pull up scan history”, “explain latest scan”, “technical evidence”, “what should I fix first?”, or `scan system`.",
      "",
      "No execution: I’m not going to let free-form chat silently apply fixes or change policy.",
    ].join("\n"),
    [
      { label: "Start tutorial", action: "ask", prompt: "Start tutorial" },
      { label: "Explain latest scan", action: "ask", prompt: "Explain the latest scan in simple terms" },
      { label: "Open Scan History", action: "view", view: "scans" },
    ],
    { intent: "general-help", scan, summary, top, allowPolish: true },
  );
}

export function buildAdvisorInterpretationPrompt({ mode, message, hasScan = false } = {}) {
  const systemPrompt = [
    "You classify a SecureLoop Advisor chat message into a safe intent schema.",
    "Return JSON only. Do not answer the user.",
    "Do not request actions that change files, apply fixes, edit policy, delete data, share data, or approve patches.",
    "If the user asks what the assistant can do, asks for help, or asks whether they should take the tutorial, use general-help unless they explicitly say to start/open the tutorial.",
  ].join(" ");

  const prompt = {
    mode,
    hasLatestScan: Boolean(hasScan),
    userMessage: String(message || ""),
    allowedIntents: [...INTERPRETATION_INTENTS],
    allowedViews: [
      "home", "analytics", "advisor", "guide", "scans", "findings",
      "reports", "autofix", "patches", "policy", "audit", "settings",
    ],
    outputShape: {
      intent: "one allowed intent",
      confidence: "number from 0 to 1",
      view: "only for navigate",
      target: "only for prepare-scan",
      reason: "short classification reason",
    },
  };

  return { systemPrompt, prompt };
}

export function normalizeInterpretation(raw) {
  if (!raw || typeof raw !== "object") return null;
  const intent = String(raw.intent || "").trim();
  const confidence = Number(raw.confidence ?? 0);
  if (!INTERPRETATION_INTENTS.has(intent) || confidence < 0.55) return null;
  const out = { intent, confidence };
  if (typeof raw.view === "string") out.view = raw.view.trim();
  if (typeof raw.target === "string") out.target = raw.target.trim();
  if (typeof raw.reason === "string") out.reason = raw.reason.trim();
  return out;
}

function navigationIntent(lower) {
  const routes = [
    { view: "scans", name: "Scan History", patterns: [/scan history/, /scan list/, /show scans/, /pull up scans/, /open scans/, /latest scans/, /previous scans/, /history/] },
    { view: "findings", name: "Findings Explorer", patterns: [/findings/, /evidence explorer/, /issues/, /vulnerabilities/] },
    { view: "reports", name: "Reports & Export", patterns: [/reports?/, /exports?/, /sarif/, /compliance/] },
    { view: "advisor", name: "Advisor", patterns: [/advisor/, /chat/] },
    { view: "guide", name: "Guided Audit", patterns: [/guided audit/, /demo/, /walkthrough/] },
    { view: "analytics", name: "Analytics", patterns: [/analytics/, /charts?/, /metrics/, /trend/] },
    { view: "autofix", name: "Fix History", patterns: [/fix history/, /autofix runs?/, /fixes/] },
    { view: "patches", name: "AI Review Patches", patterns: [/patches/, /ai review/] },
    { view: "policy", name: "Policy", patterns: [/policy/, /thresholds?/] },
    { view: "audit", name: "Audit Log", patterns: [/audit log/, /activity log/] },
    { view: "settings", name: "Settings", patterns: [/settings/, /pin/, /environment/] },
    { view: "home", name: "Home", patterns: [/home/, /dashboard/] },
  ];
  const wantsNavigation = /\b(open|show|pull up|go to|take me to|bring up|navigate|view)\b/.test(lower);
  for (const route of routes) {
    if (route.patterns.some((pattern) => pattern.test(lower)) && (wantsNavigation || route.view === "scans")) {
      return route;
    }
  }
  return null;
}

function navigationFromInterpretation(interpreted) {
  const views = {
    home: "Home",
    analytics: "Analytics",
    advisor: "Advisor",
    guide: "Guided Audit",
    scans: "Scan History",
    findings: "Findings Explorer",
    reports: "Reports & Export",
    autofix: "Fix History",
    patches: "AI Review Patches",
    policy: "Policy",
    audit: "Audit Log",
    settings: "Settings",
  };
  const view = interpreted?.view;
  if (!view || !views[view]) return null;
  return { view, name: views[view] };
}

export function buildAdvisorModelPrompt({ mode, message, decision }) {
  const scan = decision.scan || null;
  const prompt = {
    mode,
    userQuestion: String(message || ""),
    intent: decision.intent,
    secureLoopDraftAnswer: decision.reply,
    allowedActions: decision.actions || [],
    latestScan: scan ? {
      id: scan.id,
      target: scan.skill_name,
      riskScore: scan.risk_score,
      riskLevel: scan.risk_level,
      scannedAt: scan.scanned_at,
      summary: decision.summary,
      topFindings: (decision.top || []).map((f) => ({
        severity: f.severity,
        category: f.category,
        message: f.message,
        detail: f.detail,
        exploitability: f.exploitability,
        confidence: f.confidence,
        impact: f.impact,
        evidence: f.evidence,
      })),
    } : null,
  };

  const systemPrompt = [
    "You are SecureLoop Advisor, a cybersecurity audit assistant inside Jorge Elizalde's SecureLoop product.",
    "SecureLoop's deterministic brain already decided the facts, priority, and allowed actions.",
    "Rewrite or lightly improve the draft answer only. Do not invent files, scan results, CVEs, or actions.",
    "Preserve the meaning, safety stance, and remediation limits.",
    "Never claim fixes were applied. Recommend Preview Fixes or human-approved AI Review Patches for remediation.",
    "Keep answers concise and useful for a dashboard chat.",
  ].join(" ");

  return { systemPrompt, prompt };
}

export function summarizeFindings(findings = []) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  let exploitability = 0;
  let attackPaths = 0;
  for (const finding of findings || []) {
    if (counts[finding.severity] !== undefined) counts[finding.severity]++;
    exploitability = Math.max(exploitability, Number(finding.exploitability?.score || 0));
    if (finding.category === "attack-path") attackPaths++;
  }
  return { ...counts, exploitability, attackPaths, total: (findings || []).length };
}

export function topFindings(findings = [], limit = 5) {
  return [...(findings || [])]
    .sort((a, b) => {
      const ex = Number(b.exploitability?.score || 0) - Number(a.exploitability?.score || 0);
      if (ex) return ex;
      return (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
    })
    .slice(0, limit);
}

function localResponse(reply, actions, meta = {}) {
  return { reply, actions, ...meta, source: "secureloop-brain" };
}
