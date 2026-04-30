# SecureLoop — Codex Creator Challenge Submission Copy

Drop-in text for the submission form fields. Pick one option per field.
Word counts and character counts shown so you can match whatever limit the
form imposes.

---

## TITLE

Pick one. The first option is the recommended primary.

**Recommended:**
> SecureLoop — AI cybersecurity console, on a leash

**Alternates:**
> SecureLoop: scan, fix, and verify your code with Codex
>
> SecureLoop — local-first AI security audits with human-approved fixes
>
> SecureLoop: an open-source AI security console built with Codex

---

## SCREENSHOT

Use **`SecureLoop_Hero.svg`** at the repo root for the README and project
preview when SVG is accepted. It is a restrained enterprise product graphic:
dashboard-first, accurate to the demo flow, and intentionally light on claims.

If the form requires PNG/JPG, use a real screenshot of the running dashboard
after the Guided Audit instead of the old generated hero image.

If the form lets you upload more than one and you want a second slot, take a
real screenshot of your running dashboard at `http://localhost:3334` after
running Guided Audit. Best candidates:
1. The overview page right after a guided scan completes (rich finding list).
2. The Scan Details view with the AI Advisor open in Executive mode.
3. The Settings → Roles & Access card with the delegate-token UI visible.

---

## DESCRIPTION

Three lengths. Pick whichever fits the form's word limit.

### Short (≈70 words — for tight character limits)

SecureLoop is an open-source, local-first AI cybersecurity console built with
Codex. Point it at a folder, plugin, or your whole machine. It finds risk in
six dimensions, explains every finding in plain English, drafts fixes you
approve, and rescans to verify each fix actually worked. Codex polishes the
words; a deterministic Advisor Brain owns the truth, the actions, and the
audit trail. The AI cannot lie about facts, and cannot silently change a file.

### Medium (≈180 words — recommended default)

SecureLoop is an open-source, local-first AI cybersecurity console you run on
your own computer. Point it at a folder, an OpenClaw plugin, or your entire
system. It scans in six dimensions in parallel — static, dependencies,
permissions, network, system, behavior — and produces a single
Exploitability Index plus prioritized findings.

For each finding, the AI Advisor explains what it means in three modes
(Executive, Technical, Remediation) and proposes one of three tiers of fix:
deterministic safe patches, AI-drafted patches that need human approval, or
a clear "do not auto-fix" verdict. Every approved patch is verified by an
auto-rescan.

The differentiator is "AI on a Leash." A deterministic Advisor Brain owns
intent classification, allowed actions, and evidence; Codex (gpt-5.3-codex)
only polishes wording and drafts patches for human review. The AI cannot
invent files or CVEs, claim a fix was applied that wasn't, or silently
write to disk.

v1.3 ships four-tier RBAC, configurable AI provider (OpenAI BYOK or local
Ollama), webhook notifications, and one-click export of every artifact.

### Long (≈300 words — for forms with no/loose limits)

SecureLoop is an open-source, local-first AI cybersecurity console built with
Codex. You run it on your own computer — `npm install && npm start` — and
point it at a folder, an OpenClaw plugin, your `~/Downloads`, or your
entire system. Six scanners run in parallel (static, dependencies,
permissions, network, system, behavior) and produce a single Exploitability
Index plus prioritized findings with attack-path narratives and evidence.

For each finding, the AI Advisor explains what it means in three switchable
modes — Executive (for stakeholders), Technical (for engineers),
Remediation (step-by-step) — and proposes one of three fix tiers: a
deterministic safe patch (auto-applicable), an AI Review Patch that needs
explicit human approval, or a clear "do not auto-fix" verdict with reasoning.
Every approved patch triggers an auto-rescan that confirms the issue is
actually gone before the loop closes.

The architectural differentiator is "AI on a Leash." A deterministic Advisor
Brain owns intent classification, allowed actions, evidence, and the audit
log. Codex (gpt-5.3-codex via the OpenAI Responses API) only polishes
wording and drafts minimal patches for human review. The AI cannot invent
files or CVEs, cannot claim a fix was applied that wasn't, and cannot
silently write to disk — every patch passes a forbidden-token regex, an
atomic-rename gate, and a human approval before touching the filesystem.

v1.3 ships four-tier RBAC (Admin/Operator/Auditor/Viewer) with delegated
time-bound tokens, configurable AI provider (OpenAI BYOK or fully-local
Ollama), Slack/Teams/generic webhooks on critical findings, light + dark
themes, and a one-click "export everything" JSON manifest for backup or
SIEM ingest. The dashboard binds to 127.0.0.1 only. Nothing leaves your
machine unless you explicitly turn it on.

---

## CALL-TO-ACTION ONE-LINER (for any "URL" or "links" field)

> github.com/elizaldejorge/secureloop · MIT licensed · Node 18+

---

## TAGS / KEYWORDS (if there's a field for these)

> security, cybersecurity, ai, codex, openai, dashboard, audit, scanner,
> autofix, sarif, rbac, local-first, byok, openclaw, plugin

---

## NOTES TO YOU BEFORE PASTING

1. The submission title field should be 60-80 chars or less if possible. The
   recommended title above is 53 chars — safe for any limit.
2. If the description field is plain-text (no markdown), the medium version
   reads cleanly without any markdown stripping.
3. Avoid the old `SecureLoop_Hero.png` unless you regenerate it from the new
   enterprise visual or replace it with a real dashboard screenshot.
4. Don't paste the headers (TITLE / SHORT / etc.) — those are for you. Just
   copy the text under each one.
