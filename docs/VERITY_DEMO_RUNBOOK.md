# VERITY 2.0 | Reproducible Demonstration Runbook

**Document Version:** 2.0.0  
**Target Environment:** Local Node.js v20+ / Chrome Browser / Android PWA  
**Demo Server Port:** `http://localhost:8080`  
**Mobile Scanner URL:** `http://localhost:8080/mobile-scanner/index.html`  
**Safety Classification:** Strictly Synthetic / Fictional Entities Only

---

## 1. Prerequisites & Startup Commands

Ensure you are in the workspace root (`c:\PROJECTS\verity_v2-main\verity_v2-main`).

### 1.1 Run the Automated Test Suite (Sanity Check)
```powershell
npm test
```
*Expected Output:* `pass 422, fail 0, cancelled 0, skipped 0 (duration ~6.4s)`

### 1.2 Build & Synchronize Mobile Core Engine
```powershell
npm run build:mobile
```
*Expected Output:* `Mobile core engine build complete! 16 files copied + icons generated.`

### 1.3 Start the Local Verity Demo Server
```powershell
node verity_demo_server.js
```
*Expected Output:*
```text
=======================================================
🚀 Verity Demo Server running at http://localhost:8080
=======================================================
```

---

## 2. Five-Minute Live Demonstration Script

Open your browser to: **`http://localhost:8080/mobile-scanner/index.html`**

```
+-----------------------------------------------------------------------------------------+
|                                5-MINUTE CITIZEN DEMO                                    |
|                                                                                         |
|  [00:00 - 01:00]  Upfront Privacy & Multilingual Tamil/English Switching                |
|  [01:00 - 02:00]  Scenario 1: Digital Arrest Coercion -> Action Card                    |
|  [02:00 - 03:00]  Post-Compromise Recovery: Golden Hour 1930 & Sanitized Receipt Export  |
|  [03:00 - 04:00]  Scenario 2: UPI Deduction Trap vs Benign Coffee Shop Control          |
|  [04:00 - 04:45]  Scenario 3: Suspicious KYC Link vs Official .sbi Whitelist            |
|  [04:45 - 05:00]  Scenario 4: Ambiguous Input & First-Class ABSTAIN State               |
+-----------------------------------------------------------------------------------------+
```

### Minute 1: Privacy Disclosure & Vernacular Accessibility
1. Show the **Upfront Privacy Banner** at the top of the interface:
   > *"100% On-Device Inspection: Your messages, passwords, and banking inputs never leave your device. Anonymous DNS checks are only used for unfamiliar links."*
2. Click the language buttons in the top navbar:
   - Click **`தமிழ்`**: Notice how headers, button labels, and guidance update instantly without a page reload or server request.
   - Click **`EN`**: Switch back to English for the remainder of the presentation.

---

### Minute 2: Detect & Explain — Digital Arrest Extortion
1. Click the **"💬 Message & SMS"** navigation tab (`#tab-btn-message`).
2. Click the preset scenario chip: **"👮 CBI Digital Arrest Extortion"** (or paste the synthetic text below):
   ```text
   FINAL NOTICE: CBI Officer Rajesh Kumar. A non-bailable arrest warrant has been issued against you under PMLA Act for money laundering. Contact Cyber Crime Cell immediately on WhatsApp +91-9988776655 to verify your Aadhaar or face immediate police detention.
   ```
3. Click **"Verify Message & Intent"** (`#btn-check`).
4. **Observe the Explainable Scam Action Card**:
   - **Verdict Banner:** `🔴 DANGER` (Score: `85-100/100`)
   - **Threat Category Badge:** `DIGITAL ARREST EXTORTION`
   - **Recommended Safe Next Step:**
     > *"Do not approve this request, enter passwords, or install downloads. Law enforcement agencies in India NEVER conduct arrests or interrogations over WhatsApp, Skype, or phone calls."*

---

### Minute 3: Recover & Evidence Generation
1. On the Action Card, click: **"🚨 Already Acted or Sent Money? Open Recovery Guide"** (`#btn-open-recovery`).
   - The app switches to the **"🆘 Recovery & 1930"** tab.
   - Notice the prominent emergency callout: **"📞 Call 1930"** linking directly to the Indian Cyber Crime Coordination Centre (I4C).
2. Click the scenario chip: **"👮 Digital Arrest / Extortion Threat"**:
   - The priority checklist updates with 4 actionable steps:
     1. Cut all communication with the extortionist immediately.
     2. Dial 1930 immediately to report the digital arrest threat.
     3. Take screenshots of chat logs and fake arrest documents.
     4. Inform family members to prevent secondary extortion.
3. Click **"📋 Generate Sanitized Evidence Receipt"** (`#btn-generate-receipt`).
4. **Inspect the Evidence Receipt Modal**:
   - Notice that personal numbers are automatically masked (e.g. `Aadhaar XXXX-XXXX-0123`).
   - Technical forensic signatures are enumerated with timestamp and scan ID.
   - Click **"📋 Copy to Clipboard"** (or **"⬇️ Download (.md)"**) to show how a victim can attach this receipt directly to an official police report on `cybercrime.gov.in`.
   - Click **"✕"** to close the modal.

---

### Minute 4: UPI Collect Deduction Trap vs Benign Control
1. Switch to the **"💳 UPI & QR"** tab (`#tab-btn-payment`).
2. Click the scenario chip: **"💸 OLX UPI Receive Trap (Scam)"**:
   - Input populates with: `upi://pay?pa=buyer99@ybl&am=25000&tn=OLX buyer advance refund claim`
   - Scan executes.
   - **Observe:** Card shows `🔴 DANGER (85-90/100)` with warning:
     > *"⚠️ UPI DEDUCTION TRAP: Scanning this QR or approving this request will DEDUCT money from your account, not credit it!"*
3. Now test the **Benign Control**:
   - Click scenario chip: **"☕ Merchant Store QR (Safe)"** (or paste `upi://pay?pa=merchant@icici&pn=CoffeeShop&am=250`).
   - Click **"Verify Payment & UPI Safety"**.
   - **Observe:** Card switches to `🟢 SAFE (0/100)`:
     > *"Interaction appears consistent with known legitimate patterns. Proceed normally."*
   - Proves VERITY does **not** generate false alarms on legitimate merchant payments.

---

### Minute 5: Ambiguous Input & Honest Abstention
1. Switch back to the **"💬 Message & SMS"** tab.
2. In the text area, type an ambiguous short message: `hello please call me`.
3. Click **"Verify Message & Intent"**.
4. **Observe the Verdict Card**:
   - **Status:** `⚪ INSUFFICIENT EVIDENCE (UNVERIFIED)` (Badge: `ABSTAIN`)
   - **Threat Category:** `INSUFFICIENT FORENSIC EVIDENCE`
   - **Guidance:**
     > *"Insufficient evidence to verify this interaction. Exercise caution and verify identity directly before proceeding."*
   - Proves VERITY adheres to the Verdict Contract: **Missing evidence is never converted into a false clean bill of health.**

---

## 3. Features Demonstrated vs Not Demonstrated

| Capability | Demonstration Status | Verification Method |
| :--- | :--- | :--- |
| **On-Device Heuristic Scam Detection** | **DEMONSTRATED** | Live PWA scan on Digital Arrest, KYC, and UPI traps. |
| **Explainable Scam Action Card** | **DEMONSTRATED** | Live UI traffic light card with specific next-step guidance. |
| **Post-Incident Recovery Mode & 1930** | **DEMONSTRATED** | Live navigation, 10 scenario selectors, and official emergency links. |
| **Sanitized Evidence Receipt Export** | **DEMONSTRATED** | Live modal with zero-secret PII redaction and Markdown/JSON export. |
| **Multilingual UI (EN, TA, HI, TE)** | **DEMONSTRATED** | Real-time DOM switching between English and Tamil. |
| **Honest Verdict Contract & ABSTAIN** | **DEMONSTRATED** | Explicit abstention on ambiguous text (`"hello please call me"`). |
| **Zero False Alarms on Benign Merchant UPI**| **DEMONSTRATED** | Verified clean evaluation of legitimate payment links. |
| **Live Camera QR Viewfinder Fallback** | **DEMONSTRATED** | Tested permission rejection handling without unhandled exceptions. |
| **Native Android Background SMS Scraping** | **NOT DEMONSTRATED** | **Prohibited by Android Sandbox.** (Disclosed in UI & docs). |
| **Automated Bank Account Freezing** | **NOT DEMONSTRATED** | **Excluded.** Requires official banking switch integration; routes to 1930. |
| **Automated Police Complaint Filing** | **NOT DEMONSTRATED** | **Excluded.** Generates evidence receipt for citizen to attach manually. |
| **Real Malware/Phishing Link Execution** | **NOT DEMONSTRATED** | **Prohibited by Absolute Rules.** Uses `.invalid` domains only. |
