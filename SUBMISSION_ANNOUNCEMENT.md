# SecureLoop — Submission Announcement Posts

Drafts for announcing the SecureLoop submission to the **OpenAI x Handshake Codex Creator Challenge**. Pick the variant for the platform you're posting to. Edit before sending.

---

## LinkedIn (recommended primary)

I just submitted **SecureLoop** to the OpenAI x Handshake Codex Creator Challenge.

SecureLoop is an open-source AI cybersecurity console I've been building. It scans your code, your dependencies, and your local machine for malware patterns, secrets, CVEs, risky network exposure, and bad permissions — then explains every finding in plain English and drafts human-approved fixes. Six scanners run in parallel; every fix goes through atomic file rename + a forbidden-token regex; every Advisor turn is audit-logged. The pitch frame is "AI on a Leash": the AI cannot lie about facts and cannot silently change a file.

A few details I'm especially proud of in v1.3:

• Built end-to-end with **Codex** (`gpt-5.3-codex` via the OpenAI Responses API) — Codex co-authored the source AND runs inside the product.
• A deterministic Advisor Brain owns the security judgment; the LLM only polishes wording.
• Four-tier RBAC with delegated tokens — share a read-only auditor token instead of the master PIN.
• 100% local-first. The dashboard binds to `127.0.0.1` only. Nothing leaves your computer unless you turn on the BYOK OpenAI provider or a webhook.
• SARIF 2.1.0 export, print-ready Scan Reports, Slack/Teams/generic webhooks on critical findings.

Next milestone (v1.4) is **SecureLoop Mesh** — audit any computer from anywhere over an outbound-tunneled agent. No inbound ports ever opened. Same RBAC tokens carry per-host scope.

If you scan untrusted code regularly — students, plugin reviewers, small teams without an enterprise security stack — I'd love your feedback.

→ github.com/elizaldejorge/secureloop

#OpenAI #Codex #Cybersecurity #OpenSource #Handshake

---

## X / Twitter (single tweet, ~280 chars)

Just submitted **SecureLoop** to the @OpenAI x @Handshake Codex Creator Challenge.

Open-source AI cybersecurity console. Six scanners → deterministic risk engine → Codex-drafted fixes → human approval → verification rescan.

"AI on a leash": the AI can't lie or silently change your code.

🔗 github.com/elizaldejorge/secureloop

---

## X / Twitter — thread variant (5 tweets)

1/ Just submitted **SecureLoop** to the @OpenAI x @Handshake Codex Creator Challenge 🛡️

Open-source AI cybersecurity console. Six scanners. Deterministic risk engine. Codex-drafted fixes. Human approval. Verification rescan.

→ github.com/elizaldejorge/secureloop

2/ The pitch: "AI on a Leash."

A deterministic Advisor Brain decides what's true and what actions are allowed. The LLM (Codex `gpt-5.3-codex` via the Responses API) only polishes wording. Every Advisor turn is audit-logged. Every patch is forbidden-token-checked + atomically renamed.

3/ v1.3 ships:
• 4-tier RBAC w/ delegated tokens (share a read-only auditor token, not the master PIN)
• Light + Dark themes (FOUC-free)
• Configurable AI provider (OpenAI or fully-local Ollama)
• Slack/Teams webhooks on critical findings
• SARIF 2.1.0 export + one-click Export-All bundle

4/ It's 100% local-first. The dashboard binds to 127.0.0.1 only. Nothing leaves your computer unless you turn on BYOK OpenAI or a webhook. SQLite for storage. No telemetry.

5/ Next: **SecureLoop Mesh** (v1.4). Audit any computer from anywhere over an outbound-tunneled agent. Same RBAC tokens carry per-host scope. *No inbound port is ever opened on the audited machine.*

If you scan untrusted code regularly, I'd love your feedback. 🙌

---

## Instagram / Threads / Facebook (warmer, less technical)

I just submitted my project **SecureLoop** to the OpenAI x Handshake Codex Creator Challenge 🛡️

It's an open-source AI cybersecurity tool that lives on your computer. You point it at a folder, a plugin, or your whole system, and it tells you what's risky, why it's risky, and what to do about it — in plain English. The AI explains every finding and can draft fixes, but it never changes your files without you saying yes.

I built it because most security tools either drown people in alerts or let an AI rewrite code on its own. Neither is good for the people who actually need this — students, small teams, anyone reviewing third-party plugins.

Built with Codex. Open-source. Free. Runs on your machine, not the cloud.

Repo + screenshots: github.com/elizaldejorge/secureloop

---

## Discord / Slack / Group Chat (casual)

ok so I just submitted **SecureLoop** to the OpenAI Codex challenge 🥹

it's an AI cybersecurity console — six scanners + a Codex-powered Advisor that explains findings and drafts fixes you have to approve before anything touches disk. all local, all open-source. four-tier RBAC, light/dark theme, the works.

repo: github.com/elizaldejorge/secureloop

if you scan sketchy code/plugins/projects, give it a spin and tell me what breaks 🙏

---

## Email / Newsletter (long-form, professional)

**Subject:** SecureLoop is live — and I just submitted it to the OpenAI Codex Creator Challenge

Hi friends,

Quick update: I just submitted **SecureLoop** to the OpenAI x Handshake Codex Creator Challenge. SecureLoop is an open-source AI cybersecurity console I've been building, and v1.3 is the public reveal.

**What it does.** Point SecureLoop at a project folder, a plugin, or your whole machine. Six scanners run in parallel — static code analysis, vulnerable dependencies (via OSV.dev), permissions auditing, network exposure, privacy-preserving system posture, and behavior/attack-path analysis. A deterministic risk engine produces a 0–100 score and a verdict (DANGEROUS / CAUTION / SAFE). The dashboard explains every finding in plain English, can draft fixes via Codex (`gpt-5.3-codex`), and only writes to disk after you approve. Then it re-scans automatically to verify the fix worked.

**Why it's different.** The pitch frame is *"AI on a Leash."* A deterministic Advisor Brain owns the security judgment — what's true, what actions are allowed, what fixes have priority. Codex only polishes wording. Every Advisor turn is audit-logged. Every patch goes through forbidden-token regex + atomic rename + explicit human approval. The AI cannot lie about facts and cannot silently change a file.

**What v1.3 adds.** Four-tier RBAC (Admin / Operator / Auditor / Viewer) with delegated tokens — you can hand a read-only auditor token to a teammate without giving up the master PIN. Light + dark themes. Configurable AI provider (OpenAI or fully-local Ollama). Webhook notifications on critical findings (Slack, Teams, generic JSON). One-click "Export everything" for SIEM ingest.

**Local-first by design.** The dashboard binds to `127.0.0.1` only. Nothing leaves your computer unless you explicitly turn on the OpenAI provider (BYOK) or a webhook. SQLite for storage. No telemetry.

**What's next.** v1.4 will add **SecureLoop Mesh** — audit any computer from anywhere over an outbound-tunneled agent. Same RBAC tokens carry per-host scope. No inbound port ever opened on the audited machine.

If you have a moment to clone the repo and tell me what's confusing or what breaks, I'd be very grateful.

Repo: https://github.com/elizaldejorge/secureloop
30-second pitch: see `PITCH.md`
Submission notes + demo flow: see `SUBMISSION.md`
Quick start: `git clone … && npm install && npm start` (opens http://localhost:3334)

Thanks for reading,
Jorge

---

## One-line bio for any platform (drop in wherever)

> Jorge Elizalde — building **SecureLoop**, an open-source AI cybersecurity console with Codex on a leash. github.com/elizaldejorge/secureloop

---

## Notes for Jorge before posting

1. **Wait until the rotation+scrub steps are done** before pasting the GitHub URL anywhere public. Per `CONTEXT/Technical/SECURITY.md` INCIDENT-001, the original `.env.example` had a real-shaped key. The key was rotated on 2026-04-28, but until git history is scrubbed (or a clean public repo is set up), the pre-rotation value is still browseable in the commit log. The rotation makes it harmless to OpenAI — but it still looks bad to a casual judge or reader who clicks "View raw" on an old commit.
2. **Don't quote dollar amounts or claim winning.** The contest is judged in three rounds; current state is "submitted Round 1."
3. **Don't promise v1.4 ship dates publicly.** "Next" or "the next milestone" is fine; specific dates are a hostage.
4. **The "AI on a Leash" frame is the differentiator** — don't bury it in the third paragraph. Lead with it on every variant where space allows.
