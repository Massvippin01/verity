# VERITY 2.0 | Final Demonstration Checklist & Execution Log

**Document Version:** 1.0.0  
**Date:** October 2026  
**Auditor / Verification Lead:** Principal Engineer  
**Target Environment:** Local Node.js v20.19.0 / Chrome Browser (Headless & Interactive)  
**Server URL:** `http://localhost:8080/mobile-scanner/index.html`  
**Execution Status:** **ALL 5 SCRIPTED JOURNEYS VERIFIED & REPRODUCIBLE**

---

## 1. Demo Pre-Flight Verification

| Check Item | Command / Procedure | Expected Result | Observed Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Demo Server** | `node verity_demo_server.js` | HTTP 200 on port 8080 | HTTP 200 returned on `/mobile-scanner/index.html` (Process running on PID background task) | **PASS** |
| **Core Engine Sync** | `npm run build:mobile` | 16 modules synced to `mobile-scanner/core/` | 16 modules synchronized, icons generated | **PASS** |
| **Automated Suite** | `npm test` | 422 passing tests, 0 failures | 422 tests passed, 0 failures, 0 skipped (~6.4s) | **PASS** |
| **Browser Console** | Chrome DevTools Subagent | 0 uncaught errors, 0 network leaks | 0 console errors logged; zero user data egress | **PASS** |

---

## 2. Minute-by-Minute Demonstration Execution Matrix

### Minute 1: Upfront Privacy Disclosure & Vernacular Localization

- **Action 1.1:** Navigate to `http://localhost:8080/mobile-scanner/index.html`.
  - *Expected Result:* Interface loads with mobile-first viewport, displaying the Upfront Privacy Banner: *"100% On-Device Inspection: Your messages, passwords, and banking inputs never leave your device."*
  - *Observed Result:* Banner visible at the top of the interface. Zero external tracking requests fired.
- **Action 1.2:** Click the **`தமிழ்`** language toggle button (`#btn-lang-ta`).
  - *Expected Result:* DOM headers, tabs, safety rules, and buttons translate into Tamil instantly on-device without page reload or network socket.
  - *Observed Result:* Golden Rule updates to *"பொன் விதி: அவசரம் எப்போதும் மோசடிக்கு சமம்"*. UI labels switch cleanly.
- **Action 1.3:** Click **`EN`** language toggle (`#btn-lang-en`).
  - *Expected Result:* Interface reverts smoothly to English.
  - *Observed Result:* Reverted to English immediately.

---

### Minute 2: Detect & Explain — Digital Arrest Extortion (Journey A)

- **Action 2.1:** Switch to the **"💬 Message & SMS"** tab (`#tab-btn-message`).
  - *Expected Result:* Text scanner area becomes active with synthetic scenario chips.
  - *Observed Result:* Tab switched cleanly with preset chips visible.
- **Action 2.2:** Click preset chip: **"👮 CBI Digital Arrest Extortion"** (or paste synthetic notice):
  ```text
  FINAL NOTICE: CBI Officer Rajesh Kumar. A non-bailable arrest warrant has been issued against you under PMLA Act for money laundering. Contact Cyber Crime Cell immediately on WhatsApp +91-9988776655 to verify your Aadhaar or face immediate police detention.
  ```
  - *Expected Result:* Text populates textarea `#scan-input-text`.
  - *Observed Result:* Input populated exactly.
- **Action 2.3:** Click **"Verify Message & Intent"** (`#btn-check`).
  - *Expected Result:* Subword NLP and coercion heuristics evaluate in < 2ms. Action card appears with `🔴 DANGER (85-100/100)`, Category `DIGITAL ARREST EXTORTION`, and guidance: *"Law enforcement agencies in India NEVER conduct arrests or interrogations over WhatsApp, Skype, or phone calls."*
  - *Observed Result:* Score: `85/100`, Category: `DIGITAL ARREST EXTORTION`, exact safe action guidance displayed.

---

### Minute 3: Post-Compromise Recovery & Sanitized Receipt Export (Journey D)

- **Action 3.1:** On the Action Card, click **"🚨 Already Acted or Sent Money? Open Recovery Guide"** (`#btn-open-recovery`).
  - *Expected Result:* Smooth transition to the **"🆘 Recovery & 1930"** tab. Prominent callout displays **"📞 Call 1930"** with direct dialer link.
  - *Observed Result:* Recovery Advisor active; 1930 banner displayed with Golden Hour advisory.
- **Action 3.2:** Select scenario chip **"👮 Digital Arrest / Extortion Threat"**.
  - *Expected Result:* Checklist presents 4 prioritized actions: (1) Cut communication, (2) Dial 1930, (3) Capture chat logs, (4) Inform family.
  - *Observed Result:* Exact 4-step protocol rendered with checkbox indicators.
- **Action 3.3:** Click **"📋 Generate Sanitized Evidence Receipt"** (`#btn-generate-receipt`).
  - *Expected Result:* Modal opens displaying formatted incident receipt. Synthetic Aadhaar numbers are masked (`XXXX-XXXX-0123`), `secretsRedacted: true`, and forensic indicators listed.
  - *Observed Result:* Modal popped up. Zero personal credentials visible in receipt text.
- **Action 3.4:** Click **"📋 Copy to Clipboard"** (and test **"⬇️ Download (.md)"**).
  - *Expected Result:* Receipt copied to clipboard without error; download triggers markdown file.
  - *Observed Result:* Clipboard write succeeded; modal closed cleanly with `✕`.

---

### Minute 4: UPI Collect Deduction Trap vs Benign Control (Journey B)

- **Action 4.1:** Switch to the **"💳 UPI & QR"** tab (`#tab-btn-payment`).
  - *Expected Result:* Payment forensics UI becomes active.
  - *Observed Result:* UPI & QR inputs and scenario buttons displayed.
- **Action 4.2:** Click scenario chip **"💸 OLX UPI Receive Trap (Scam)"** (`upi://pay?pa=buyer99@ybl&am=25000&tn=OLX+advance`).
  - *Expected Result:* Evaluates NPCI collect parameters. Card displays `🔴 DANGER (85-90/100)` with warning: *"⚠️ UPI DEDUCTION TRAP: Scanning this QR or approving this request will DEDUCT money from your account, not credit it!"*
  - *Observed Result:* Danger card rendered with explicit deduction warning.
- **Action 4.3:** Click scenario chip **"☕ Merchant Store QR (Safe)"** (`upi://pay?pa=merchant@icici&pn=CoffeeShop&am=250`).
  - *Expected Result:* Evaluates verified merchant pattern without conversational NLP false-positive. Card displays `🟢 SAFE (0/100)`: *"Interaction appears consistent with known legitimate patterns. Proceed normally."*
  - *Observed Result:* Safe card rendered with Score 0/100. Confirms zero false alarms on legitimate commerce.

---

### Minute 5: Ambiguous Input & Honest Abstention (Journey E)

- **Action 5.1:** Switch back to the **"💬 Message & SMS"** tab.
  - *Expected Result:* Message scanner re-activates.
  - *Observed Result:* Tab active.
- **Action 5.2:** Enter ambiguous text: `hello please call me`. Click **"Verify Message & Intent"**.
  - *Expected Result:* Verdict Contract detects insufficient evidence and emits explicit `ABSTAIN` verdict. UI renders `⚪ INSUFFICIENT EVIDENCE (UNVERIFIED)`.
  - *Observed Result:* Verdict card shows `⚪ INSUFFICIENT EVIDENCE (UNVERIFIED)` with guidance: *"Insufficient evidence to verify this interaction. Exercise caution and verify identity directly before proceeding."* Proves VERITY never invents a false clean bill of health.

---

## 3. Discovered Defects & Remediation Status

During demonstration rehearsals and baseline verification, the following defects were encountered and resolved:

| Defect ID | Component | Root Cause | Remediation Applied | Verification |
| :--- | :--- | :--- | :--- | :--- |
| **DEF-01** | `online-scam-verifier.js:877` | ReferenceError on `isInsufficientEvidence` | Declared `let isInsufficientEvidence = false;` in local scope | `online_verifier.test.js` PASS |
| **DEF-02** | `text-scanner.js:231` | UPI Intent protocol string (`upi://pay?`) flagged by text NLP | Added `isPureProtocolUri` guard to bypass conversational text subwords on raw URIs | `citizen_journeys_e2e.test.js` PASS |
| **DEF-03** | `recovery-advisor.js:464` | `secretsRedacted` flag omitted; snippet truncated at 300 chars | Added `secretsRedacted: boolean` and expanded capacity to 2,000 characters | `recovery_advisor.test.js` PASS |
| **DEF-04** | `recovery-advisor.js:231` | Missing "freeze" terminology in OTP compromise step | Added "block and freeze your netbanking and debit card" | `recovery_advisor.test.js` PASS |
| **DEF-05** | `verity_demo_server.js:827` | SyntaxError: missing closing brace before static handler | Added closing brace `}` | Server runs stably on :8080 |
| **DEF-06** | `verity_demo_server.js` | CommonJS `require` collision with root `"type": "module"` | Converted to native ES module imports with `fileURLToPath` | Clean startup without ESM warning |

---

## 4. Overall Demonstration Sign-Off

- **Script Reproducibility:** 100% reproducible on local server (`http://localhost:8080`).
- **Defects Blocking Demo:** **0** (All critical and minor defects resolved).
- **Presentation Readiness:** **APPROVED FOR LIVE PRESENTATION & SCREENCAST RECORDING**.
