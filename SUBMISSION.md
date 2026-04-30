# SecureLoop Submission Notes

SecureLoop is an ongoing cybersecurity project by Jorge Elizalde. The OpenAI x Handshake Codex Creator Challenge is a milestone for the project's public reveal, not the reason it exists. **v1.3.0** is the contest-ready release. v1.3 adds the AI Advisor as a first-class feature, four-tier RBAC, light/dark theming, configurable AI provider, webhook notifications, an export-all data bundle, and a clearly-stubbed v1.4 fleet roadmap.

Source-of-truth references in this repo:

- `CONTEXT/Shared/CONTEST.md` — full contest rules digest, eligibility, rubric, prize tiers, license grant.
- `CONTEXT/Shared/DECISIONS.md` — DECISION-042 (locked description), DECISION-043 (48-hour strategy lock), DECISION-044 ("AI on a leash" pitch frame).
- `CONTEXT/Technical/SECURITY.md` — INCIDENT-001 record for the `.env.example` API-key exposure and required follow-ups.

## Project Title (Handshake submission field)

`SecureLoop`

(Optional longer subtitle for visibility in the Handshake gallery: `SecureLoop — AI cybersecurity console`. The canonical product name remains `SecureLoop`.)

## 500-Character Description — LOCKED (DECISION-042)

Verbatim text to paste into the Handshake description field:

> SecureLoop is an open-source AI cybersecurity console that finds, explains, fixes, and verifies risk in real codebases. Six parallel scanners surface CVEs, attack paths, and policy violations; Codex (gpt-5.3-codex via the OpenAI Responses API) explains each finding in plain English and drafts human-approved patches. I built it because static scanners drown teams in noise. Built with Codex end-to-end — Codex co-wrote the scanners, dashboard, and the deterministic Advisor that keeps the AI on a leash.

Character count: **499 / 500**. Held-back variants (Option B safety-first, Option C compliance-first) live in `CONTEXT/Shared/CONTEST.md` and are reserved for any second entry.

## What It Is

A local, open-source cybersecurity audit console that scans:

- local project folders
- software / plugin folders
- OpenClaw skills
- network exposure signals
- privacy-preserving system posture
- AI / local-model directories as filesystem targets

Six scanners run in parallel via `lib/scan.js` — `static`, `dependencies`, `permissions`, `network`, `system`, and `behavior` (attack paths) — and feed a deterministic risk engine that produces a 0–100 risk score, a verdict (DANGEROUS / CAUTION / SAFE), and prioritized findings annotated with confidence, impact, evidence, and an Exploitability Index.

## Why I Built It

Security tools usually stop at "here is a problem." SecureLoop is built around the next two questions: "What should I do now?" and "How do I know it actually worked?" The product is meant to help students, small teams, plugin marketplaces, and operators who need practical security review without enterprise overhead — and who cannot afford to let an AI silently rewrite their code on their behalf.

## How It Was Built — Codex End-to-End

"Built with Codex" is true in two distinct, both-verifiable ways:

1. **Codex co-authored the source.** SecureLoop's scanners, dashboard, Advisor brain, and three-tier AutoFix system were written in collaboration with Codex.
2. **Codex runs inside the product at runtime.**
   - `lib/autofix/providers/openai.js` calls the OpenAI Responses API with `gpt-5.3-codex` to draft AI Review Patches.
   - `dashboard/server.js` + `lib/advisor/brain.js` route Advisor chat through Codex in two phases: structured-output JSON intent classification, then wording polish — never authoritative reasoning.

Both claims can be checked directly in the source tree.

## Differentiator — "AI on a Leash"

This is the positioning frame that distinguishes SecureLoop from naive LLM-agent submissions and is the required pitch lead per DECISION-044:

- **SecureLoop's deterministic Advisor Brain decides.** `lib/advisor/brain.js` owns intent classification, scan summaries, fix priority, allowed actions, and the safety stance.
- **Codex / Ollama only polish.** The system prompt explicitly says "Do not invent files, scan results, CVEs, or actions" and "Never claim fixes were applied."
- **Every Advisor turn is audit-logged.** `audit_log` records actor, action (`advisor-message`), target, and metadata for every chat exchange.
- **Every AI Review Patch is gated.** Forbidden-token regex, single-file scope, path-escape guard, atomic `.secureloop-tmp` rename, and explicit human approval before any disk write.

The result: an AI security tool whose AI cannot lie about facts and cannot silently change a file.

## Demo Flow

1. Launch `SecureLoop.command` (macOS) or run `npm start`.
2. Open `http://localhost:3334` (PIN-gated; first run is pass-through).
3. Click **Guided Audit** and run the sample scan against `demo-vulnerable-project`.
4. Open **Scan Details** and walk through:
   - Plain-English Summary
   - Exploitability Index
   - Attack Paths
   - Technical Evidence
5. Open **Advisor**. Ask "Explain the latest scan in simple terms," then switch to Technical mode and ask "Give me the technical evidence from the latest scan."
6. Click **Preview Fixes**. Show that AI Review Patches require human approval.
7. Click **Apply Safe Fixes** (deterministic Tier-1 only). Watch the verification rescan.
8. Open **Reports & Export**. Show the print-ready Scan Report and SARIF 2.1.0 export.
9. Open **Settings → Roles & Access**. Issue a delegated **Auditor** token with a 24-hour TTL; copy it. Open a private window, log in with the token, and try to apply a fix — the server returns `403 Forbidden` with `{ role: "auditor", required: "operator" }`. (This is the v1.3 RBAC headline.)
10. Open **Settings → Notifications**. Paste a Slack/Teams/generic webhook URL, click *Send test ping*, then re-run the demo scan and watch the webhook fire on critical findings.
11. Open **Settings → Data Retention & Export → Export all data**. The download is a single JSON manifest containing scans, patches, audit log, latest SARIF, active policy, and (masked) settings.

Reset the demo target between runs with `POST /api/demo/reset`.

## How To Get It Running (Local-First)

```bash
git clone https://github.com/elizaldejorge/secureloop.git
cd secureloop
npm install
npm start            # opens http://localhost:3334
```

The dashboard binds to `127.0.0.1` only. Nothing leaves the machine unless the user explicitly turns on the OpenAI provider (BYOK in `.env`) or a notification webhook. The SQLite database lives at `db/secureloop.db`. To export everything for backup or SIEM ingest: **Settings → Data Retention & Export → Export all data**.

## What's Next — v1.4 SecureLoop Mesh / Fleet (roadmap, not in submission)

A common ask after the v1.3 walkthrough is: "I'm in another country, can I audit a machine back home from this same web console?" v1.4 will add that without breaking the localhost-only bind that makes SecureLoop credible as a security tool. Each audited host runs a small `secureloop-agent` that dials *out* over an encrypted WebSocket to a SecureLoop relay; a single web console pages those agents through the relay; the same v1.3 RBAC tokens carry per-host scope (e.g. *auditor on host laptop-01 only*); scan output never traverses the relay in plaintext (Noise-style session key on connect). No inbound port is ever opened. Full design lives in `CONTEXT/Shared/DECISIONS.md` DECISION-047. v1.3 ships a single-entry "Host" picker stub in the sidebar so the multi-host hook is visible today.

## Project URL

Public repository: `https://github.com/elizaldejorge/secureloop`

⚠️ Per `CONTEXT/Technical/SECURITY.md` INCIDENT-001, the original `.env.example` contained a real-shaped `OPENAI_API_KEY`. The key was **rotated on 2026-04-28** (confirmed by Jorge), so the prior value is now revoked at the OpenAI side. **Do not paste this URL into the Handshake submission until** git history is scrubbed or a clean public repo is set up per CONTEST-Q1 in `CONTEXT/Shared/CONTEST.md` — otherwise judges (and any crawler) can still see the pre-rotation value in the repo's commit history.

Current local check on 2026-04-30: this working tree's local git history has no `.env.example` commits and `git log --all -S'sk-proj' -- .` returns no matches. The current `origin` remote is `https://github.com/elizaldejorge/clawguard.git`, so set or create the final public SecureLoop repo before pasting the project URL.

## Final Submission Checklist

- [x] Eligibility confirmed (Jorge: US resident, 18+, active Handshake account, US college undergrad/alumnus)
- [x] Round-1 description locked (Option A, 499 chars) per DECISION-042
- [x] `.env.example` placeholder fix landed
- [x] `npm test` now includes `scripts/check-secrets.js` so real-shaped OpenAI keys fail the pre-submission check
- [x] Repo-wide secret sweep clean (only intentional bait token remains in `demo-vulnerable-project/src/server.js`)
- [x] Decisions, incident, changelog, and contest digest logged in CONTEXT/
- [x] Leaked OpenAI key **ROTATED** at https://platform.openai.com/api-keys *(confirmed by Jorge 2026-04-28)*
- [ ] OpenAI usage dashboard reviewed for unfamiliar requests during the exposure window
- [ ] Git history scrubbed OR clean public repo created per CONTEST-Q1 (currently: scrub-before-submitting)
- [x] Demo flow verified end-to-end locally (`node test.js demo-vulnerable-project --dashboard` → 17 findings, risk 100/100 DANGEROUS)
- [ ] README quick start tested on a fresh clone
- [x] Dashboard HTTP load verified at `http://localhost:3334` (`GET /` 200, `/api/status` reports v1.3.0 online)
- [ ] Handshake project title set: `SecureLoop`
- [ ] Handshake description pasted (Option A, 499 chars; copied verbatim from this file)
- [ ] "Built with Codex" checkbox selected
- [ ] Project URL submitted (only after rotation + scrub complete)
- [ ] Multiple-entry decision (CONTEST-Q2) made: file second entry under Option B/C, or stick with single entry?
- [ ] Pitch-video plan ready in case of Round 3 (CONTEST-Q3): solo Jorge or Jorge + Javier?

## Round-1 Rubric Hooks

Where each weighted axis lands in the submission package:

- **Clarity (15%):** opening 500-char description; "What It Is" section; product overview in `README.md`.
- **Usefulness / Value (25%):** "Why I Built It"; closed-loop find→fix→verify; SARIF 2.1.0 export for enterprise / code-scanning workflows; PDF-ready Scan Reports for non-technical audiences.
- **Creativity (20%):** "AI on a Leash" differentiator; six-scanner parallel architecture; deterministic-brain + LLM-polish split; per-finding Exploitability Index and Attack Paths.
- **Execution (25%):** working demo via `demo-vulnerable-project`; v1.3.0 ships every feature described; live `gpt-5.3-codex` integration; PIN-gated dashboard; SQLite persistence; six scanners + AutoFix Tier 1/2/3; four-tier RBAC enforced server-side; configurable AI provider; webhook notifications; export-all data bundle.
- **Polish (15%):** audit-logged Advisor; atomic patch rename; forbidden-token safety regex; localhost-only network binding; `.env.example` placeholder discipline; SARIF + Scan Report export; README quick start; clear "no execution" Advisor copy; light/dark theme with FOUC-free bootstrap; sidebar role badge; secrets masked on read; v1.4 fleet roadmap stubbed in the UI so users can see what's coming.

## Round-3 Pitch-Video Plan (only if needed)

`DEMO_SCRIPT.md` is the working storyboard. The 3-minute video adds a 1–5 bonus on top of the Round-2 score, so cut precisely:

1. **0:00–0:20** — Problem framing.
2. **0:20–0:50** — Live demo: scan `demo-vulnerable-project`, show risk score + Exploitability + Attack Paths.
3. **0:50–1:30** — Advisor Executive mode → Technical mode (Codex polishing the brain's draft).
4. **1:30–2:10** — Preview Fixes → Apply Safe Fixes → verification rescan → diff view.
5. **2:10–2:40** — "AI on a Leash" architecture slide (one diagram).
6. **2:40–3:00** — SARIF + Scan Report export, close on the closed loop.
