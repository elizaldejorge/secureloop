# SecureLoop Pitch

SecureLoop is an ongoing AI-powered cybersecurity audit project. The contest version (**v1.3**) is the public reveal, not the project's reason for existing. The pitch frame, per `CONTEXT/Shared/DECISIONS.md` DECISION-044, is **"AI on a Leash"** — an AI security tool whose AI is structurally incapable of lying about facts or silently changing your code. v1.3 adds the AI Advisor as a first-class citizen, four-tier RBAC, light/dark theming, webhook notifications, and a configurable AI provider — the things enterprise reviewers expect to see in a security tool before they trust it.

## 30-Second Pitch

Most AI security tools either drown you in CVE noise or let an LLM silently rewrite your codebase. SecureLoop does neither. Six parallel scanners find risk; a deterministic Advisor Brain decides what's true and what actions are allowed; Codex (`gpt-5.3-codex` via the OpenAI Responses API) only explains findings in plain English and drafts patches that a human must approve before any disk write. The result: a closed loop — find, explain, fix, verify, export evidence — for developers, students, plugin marketplaces, and small teams who need real security review without enterprise overhead.

## 3-Minute Pitch Structure

### 0:00–0:25 — Problem

Static scanners are useful but they leave users with a list and no clear next step. AI security tools go the other way and let the model drive — which is fine until it hallucinates a CVE, fabricates a fix, or silently rewrites a file. Both failure modes hurt the people who need security tooling the most: students, small teams, plugin ecosystems, and operators who have to decide whether software is safe before they trust it.

### 0:25–0:55 — Product

SecureLoop is a local, open-source cybersecurity audit console that lives entirely on your machine. Six scanners run in parallel — `static`, `dependencies`, `permissions`, `network`, `system` (privacy-preserving posture), and `behavior` (attack paths) — and feed a deterministic risk engine that produces a 0–100 risk score, a verdict, and prioritized findings with confidence, impact, evidence, and an Exploitability Index. The dashboard binds to `127.0.0.1:3334` behind a PIN, with a floating **AI Advisor** chat window for plain-English explanations and four enterprise-grade roles (Admin / Operator / Auditor / Viewer) so a single security lead can hand a read-only token to their team without giving up the master PIN. Light + Dark themes, configurable AI provider (OpenAI or fully-local Ollama), Slack/Teams/generic webhooks on critical findings, and a one-click "Export everything" for SIEM ingest round out the v1.3 release.

### 0:55–1:35 — The "AI on a Leash" Architecture (signature differentiator)

This is what makes SecureLoop different from other Codex-powered submissions:

- SecureLoop's **deterministic Advisor Brain** (`lib/advisor/brain.js`) decides facts, intent, fix priority, and allowed actions across 11 distinct intents.
- **Codex / Ollama only polish.** The system prompt explicitly says "Do not invent files, scan results, CVEs, or actions" and "Never claim fixes were applied."
- **Every Advisor turn is audit-logged** to the `audit_log` table — actor, action (`advisor-message`), target, metadata.
- **Every AI Review Patch passes through forbidden-token regex, single-file scope, path-escape guard, atomic `.secureloop-tmp` rename, and explicit human approval** before any disk write.

The AI cannot lie about facts and cannot silently change a file. That is the entire pitch.

### 1:35–2:15 — Demo

Run the Guided Audit. Show:

- Risk score and verdict on `demo-vulnerable-project`
- Exploitability Index and Attack Paths
- Advisor Executive mode ("Explain the latest scan in simple terms")
- Advisor Technical mode ("Give me the technical evidence from the latest scan")
- Preview Fixes (no disk writes)
- Apply Safe Fixes (deterministic Tier-1 only)
- Verification rescan with before/after diff
- Scan Report export and SARIF 2.1.0 export

### 2:15–2:45 — Why It Matters

The closed loop — find, explain, fix, verify, export — is what makes security review actually completable. SecureLoop is useful for cybersecurity students learning to read scanner output, plugin marketplaces vetting third-party code, small teams that want SOC-2-adjacent evidence without the enterprise tax, and any developer who wants to know whether a folder is safe to run before they run it.

### 2:45–3:00 — Close

SecureLoop is not a contest demo. It's a project I plan to keep building into a serious AI-powered cybersecurity audit product, with Codex as the remediation brain and the user always in the approval loop.

## What's Next — v1.4 "SecureLoop Mesh"

The v1.3 console is intentionally locked to `127.0.0.1` because a security tool that exposes its admin port to the public internet has lost the plot. v1.4 adds **fleet auditing** without breaking that property. The pattern: each audited computer keeps its localhost-only dashboard, plus a small `secureloop-agent` process that dials *out* to a SecureLoop relay over an encrypted WebSocket. The user logs into a single web console with their account (passkey/WebAuthn), picks which host they want to audit from a Host dropdown, and the relay pages requests through to that host's agent. No inbound port is ever opened on the audited machine. The same four-tier RBAC carries over: a token can say "auditor on host laptop-01 only," and the relay enforces that scope before any byte reaches the local SecureLoop. This is the same trust model Tailscale and Cloudflare Tunnel use — the relay is treated as untrusted infrastructure, the agent and console negotiate a session key on connect, and scan output never traverses the relay in plaintext. See `CONTEXT/Shared/DECISIONS.md` DECISION-047 for the full design.

Practical scenario: you're traveling, a teammate spots a suspicious dependency on the office server, you log in from a hotel laptop, pick the office machine from the Host picker, run the audit, approve a Tier-1 fix, watch the verification rescan, export a SARIF report, and sign out — all without ever opening a port on the office network or trusting any of the relay infrastructure with raw scan data.

## Local-First, Always

How to get it running today: clone the repo, `npm install`, `npm start`. The dashboard opens at `http://localhost:3334`. Nothing leaves your computer unless you explicitly turn on the OpenAI provider (BYOK) or a notification webhook. The SQLite database lives at `db/secureloop.db`. To export everything for backup or SIEM ingest, **Settings → Data Retention & Export → Export all data**. That's the entire onboarding.

## Built With Codex (verifiable)

Both claims about Codex are true and grounded in the source tree:

1. **Codex co-authored the code.** Scanners, dashboard, Advisor brain, and AutoFix tiers were written in collaboration with Codex.
2. **Codex runs inside the product.** `lib/autofix/providers/openai.js` and the Advisor's two-phase flow (`dashboard/server.js` + `lib/advisor/brain.js`) call the OpenAI Responses API with `gpt-5.3-codex`.

## Round-1 Rubric Map

Each weighted axis has at least one explicit hook in the pitch above:

- **Clarity (15%):** lead with the closed loop and "AI on a leash"; product overview in 30 seconds.
- **Usefulness (25%):** named users (students, small teams, plugin marketplaces); concrete saved step (verification rescan replaces manual rescanning).
- **Creativity (20%):** deterministic-brain + LLM-polish architecture; six-scanner parallel design; per-finding Exploitability Index and Attack Paths.
- **Execution (25%):** v1.3.0 ships every feature in this pitch; live `gpt-5.3-codex` integration; demo flows end-to-end on `demo-vulnerable-project`; four-tier RBAC enforced server-side (not just UI gating); webhook + AI provider config persisted; export-all bundle for SIEM ingest.
- **Polish (15%):** PIN-gated dashboard, audit-logged Advisor, atomic patch rename, SARIF + Scan Report export, README quick start, `.env.example` placeholder discipline, light/dark theme with FOUC-free bootstrap, sidebar role badge, secrets masked on read.

## Things to Avoid Saying (per `DEMO_SCRIPT.md`)

- Don't say SecureLoop was built only for the competition.
- Don't imply AI fixes are applied without human approval.
- Don't claim perfect vulnerability detection.
- Don't claim it replaces a professional security review.
