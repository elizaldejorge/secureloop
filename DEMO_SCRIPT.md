# SecureLoop Demo Script

This script is for product demos, including the Creator Challenge submission. Keep the tone focused on SecureLoop as an ongoing cybersecurity product.

## Setup

```bash
npm install
npm test
npm start
```

Open:

```text
http://localhost:3334
```

## Demo Path

1. Start on **Home**.
   - Say: “SecureLoop is a local AI-powered cybersecurity audit console.”
   - Point out quick scans for computer, current project, AI model folder, and guided audit.

2. Open **Guided Audit**.
   - Run the sample audit against `demo-vulnerable-project`.
   - Say: “This target is intentionally vulnerable so the remediation loop is visible.”

3. Open **Scan Details**.
   - Show the risk score.
   - Show **Plain-English Summary**.
   - Show **Exploitability** and **Attack Paths**.
   - Show **Technical Evidence**.

4. Open **Advisor**.
   - Ask: “Explain the latest scan in simple terms.”
   - Switch to Technical mode.
   - Ask: “Give me the technical evidence from the latest scan.”

5. Explain the loop.
   - “SecureLoop does not only find issues. It explains what matters, recommends the next step, drafts or applies the safe fix path, and verifies with another scan.”

6. Preview fixes.
   - Use **Preview Fixes** first.
   - Explain that AI Review Patches require human approval.

7. Apply safe fixes.
   - Use **Apply Safe Fixes** only for deterministic safe changes.
   - Show the verification rescan afterward.

8. Open **Reports & Export**.
   - Open **Latest Scan Report**.
   - Show that the report includes non-technical summary plus technical evidence.
   - Mention SARIF export for enterprise/code-scanning workflows.

## Things To Avoid Saying

- Do not say the product was built only for the competition.
- Do not imply AI fixes are applied blindly.
- Do not claim perfect vulnerability detection.
- Do not claim it replaces professional security review.

## Strong Closing Line

“SecureLoop is a closed-loop security auditor: it finds risk, explains exploitability, helps fix it with Codex, and verifies the result.”
