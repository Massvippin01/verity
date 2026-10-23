# 🛡️ Verity 2.0 (Bharat Shield) — 3-Minute Grand Jury Demo Script

> **Session Duration**: Exactly 3 Minutes (180 Seconds)  
> **Target Audience**: Hackathon Grand Jury & Technical Evaluators  
> **Prerequisites**:  
> 1. Start demo server: `npm run demo` (or `node verity_demo_server.js`) on `http://localhost:8080`.  
> 2. Chrome browser running with Verity 2.0 unpacked extension loaded from `verity-extension/`.  
> 3. Open `http://localhost:8080` in the main presentation window.

---

## ⏱️ Minute-by-Minute Presentation Choreography

### 🕒 Minute 0:00 – 1:00: Problem Context & Scenario 1 (Fake SBI KYC + Telegram Webhook)

#### 0:00 – 0:25: The Bharat Cyber Safety Crisis & Verity Philosophy
- **Presenter Statement**:
  > *"Respected Judges, cyber fraud in India has evolved into an industrialized crisis. Per official Ministry of Home Affairs data, Indian citizens reported losses of ₹22,845 Crore across 36 Lakh fraud complaints in 2024 alone, with over ₹1,750 Crore lost in the first four months. Centralized blocklists fail because phishing sites have a median lifespan of just 4 to 8 hours. Verity 2.0 is a 100% on-device, zero-telemetry defense shield operating inside Manifest V3 in under 1.8 milliseconds."*
- **Action**: Point to the live metric pills on `http://localhost:8080` (`< 1.8ms scan latency`, `100% On-Device Privacy`, `0.00% False Positives`).

#### 0:25 – 1:00: Scenario 1 — Fake SBI KYC + Telegram Exfiltration
- **Target URL**: `http://localhost:8080/demo/sbi-kyc-telegram`
- **Action**: Click the large button labeled **"🚀 Launch Scenario 1: Fake SBI KYC"**.
- **Presenter Statement**:
  > *"A citizen receives an urgent SMS: 'Your SBI NetBanking account will be blocked within 24 hours. Update PAN & KYC.' The victim lands on an SBI credential harvester that exfiltrates usernames, passwords, and OTPs directly to a rogue Telegram Bot webhook."*
- **Expected On-Screen Visual Output**:
  1. **Instant Red Blocking Shield**: Verity immediately intercepts navigation and renders the full-bleed red warning screen before credentials can be stolen.
  2. **Plain Citizen Bullets**: The page clearly states:
     - ❌ *Impersonating State Bank of India on an unverified domain.*
     - ❌ *Urgent account suspension threat demanding PAN and NetBanking passwords.*
     - ❌ *Covert data exfiltration channel communicating with an unauthorized Telegram bot endpoint.*
  3. **Golden Rule Card**: *"Never share passwords, PINs, or SMS OTPs with anyone. Real banks never ask for them."*
  4. **Interactive X-Ray Teaching Quiz**: Click *"🤔 How did we catch this?"* to reveal the educational micro-quiz. Click the correct answer to demonstrate instant green feedback reinforcement.

---

### 🕒 Minute 1:00 – 2:00: Scenario 2 (OLX UPI Trap) & Scenario 3 (CBI Digital Arrest)

#### 1:00 – 1:30: Scenario 2 — OLX UPI Collect Trap (Reverse-Charge Scam)
- **Target URL**: `http://localhost:8080/demo/olx-upi`
- **Action**: Switch back to launcher tab and click **"🚀 Launch Scenario 2: OLX UPI Trap"**.
- **Presenter Statement**:
  > *"In online marketplaces like OLX, scammers pose as buyers agreeing to purchase an item, claiming: 'I have transferred ₹15,000 into escrow. Click accept or scan this QR code to receive the money.' In reality, the `upi://pay` URI contains `am=15000` — an extortionate collect debit request."*
- **Expected On-Screen Visual Output**:
  1. The simulated OLX escrow page displays a QR code and an *"Accept ₹15,000"* button.
  2. **Verity In-Page Protection**: Verity detects the reverse-charge debit intent (`SIG_UPI_QR_COLLECT_TRAP`) paired with receive-money lures.
  3. **Extension Popup Demonstration**: Click the Verity Shield extension icon in the toolbar. The 340px citizen popup displays:
     - 🔴 **DANGER: SCAM DETECTED** banner.
     - Detected Threat: *"Deceptive UPI payment request disguised as received money."*
     - Citizen Golden Rule: *"You NEVER need to enter your UPI PIN or scan a QR code to receive money. Entering your PIN always deducts funds from your account."*
  4. **Instant Language Switching**: Click the **தமிழ்** (Tamil) or **हिं** (Hindi) language pill in the popup header; all explanations update instantly without page reloads.

#### 1:30 – 2:00: Scenario 3 — CBI Digital Arrest Video Extortion
- **Target URL**: `http://localhost:8080/demo/cbi-digital-arrest`
- **Action**: Click **"🚀 Launch Scenario 3: CBI Digital Arrest"**.
- **Presenter Statement**:
  > *"Scammers pose as CBI or Customs officers, terrifying victims with claims that an illegal narcotics parcel was seized in their name and placing them under 'Digital Arrest' to extort lakhs in 'verification clearance fees'."*
- **Expected On-Screen Visual Output**:
  1. The page simulates high-pressure law enforcement intimidation: *Supreme Court notice, virtual court warrant, Skype video call demand*.
  2. **Instant Red Block Shield**: Verity triggers `SIG_DIGITAL_ARREST_EXTORTION` in under 2ms.
  3. **Citizen Advisory**: *"Government agencies, Police, and Courts NEVER place citizens under digital arrest or conduct interrogations over Skype/WhatsApp. No official agency asks for clearance payments to verify innocence."*
  4. **Emergency Helpline Link**: Direct button to dial **1930** (National Cyber Crime Reporting Helpline) or report to `cybercrime.gov.in`.

---

### 🕒 Minute 2:00 – 2:40: Scenario 4 (Malicious APK Dropper) & Zero-Install Mobile PWA

#### 2:00 – 2:20: Scenario 4 — RTO_Challan.apk Malicious Dropper
- **Target URL**: `http://localhost:8080/demo/rto-apk`
- **Action**: Click **"🚀 Launch Scenario 4: RTO Challan APK"**, then click **"📥 Download Official RTO_Challan.apk"**.
- **Presenter Statement**:
  > *"Citizens receive SMS notifications of a speed violation fine directing them to download an 'e-Challan APK'. This APK contains surveillance spyware that steals SMS OTPs."*
- **Expected On-Screen Visual Output**:
  1. Click download; the 5 MB APK stream begins downloading from `localhost:8080/downloads/RTO_Challan.apk`.
  2. **In-Flight Stream Pausing**: Chrome's download bar shows the download instantly **PAUSED** by Verity before the bytes touch the disk.
  3. **Verity Download Interceptor Notification**: Displays alert: *Critical Threat — Untrusted Android Package (`RTO_Challan.apk`) detected from an unverified host.*
  4. **1-Click Safe Cancel**: Allows user to immediately cancel and purge the stream.

#### 2:20 – 2:40: Mobile PWA "Share-to-Verify" (Android Zero-Install)
- **Target URL**: Open `mobile-scanner/index.html` (or pre-warmed mobile tab)
- **Presenter Statement**:
  > *"Because over 80% of Indian scam links are opened on Android via WhatsApp or SMS, we compiled the exact same heuristic and brand engine into a zero-install Mobile Progressive Web App with zero external dependencies."*
- **Action**:
  1. Paste a suspicious WhatsApp message into the input box:  
     `"Notice: CBI cyber crime digital arrest warrant issued. Connect to video call immediately."`
  2. Click **"Verify Text / Link"**.
  3. Show the instant red warning card, plain explanation, and Golden Rule card rendered completely on-device.

---

### 🕒 Minute 2:40 – 3:00: Grand Jury Conclusion & Privacy Assurance

- **Presenter Closing Statement**:
  > *"To summarize: Verity 2.0 delivers Bitdefender-tier cyber safety for 1.4 billion citizens across all 4 top cyber fraud vectors:*
  > 1. *Zero-day banking phishing & webhook exfiltration*
  > 2. *UPI reverse-charge collect traps*
  > 3. *High-pressure digital arrest extortion scripts*
  > 4. *Malicious drive-by APK droppers*
  >
  > *And it achieves this with 100% on-device privacy, zero telemetry, sub-2ms latency, and zero false positives on India's top critical portals. Thank you."*

---

## 🛡️ Fallback Execution Plan (If Extension Fails to Load)

If Chrome encounters an unexpected extension loading failure, corrupt profile, or environment issue during judging, immediately pivot to the following deterministic fallbacks:

### Fallback Option A: Standalone Mobile PWA Engine (Zero Setup)
1. **Trigger**: Extension fails to intercept or icon is missing.
2. **Action**: Immediately open `http://localhost:8080/mobile-scanner/index.html` (or local file `mobile-scanner/index.html`).
3. **Show Judges**: The Mobile PWA runs the **identical core detection engine** (`mobile-scanner/core/`) with zero browser APIs.
4. **Execution**:
   - Click the 4 preset quick-test buttons on the PWA:
     1. *Fake SBI KYC*
     2. *CBI Digital Arrest*
     3. *OLX UPI Trap*
     4. *RTO Challan APK*
   - Demonstrate the exact verdicts, danger score (85-100), and multilingual translations in real time.

### Fallback Option B: Automated Benchmark & Test Suite Evidence
1. **Trigger**: Browser display or network port contention.
2. **Action**: Open terminal and run:
   ```bash
   node --test tests/sample_data.test.js
   ```
3. **Show Judges**:
   - The test runner executes all **30 curated Indian Cyber Fraud cases**.
   - Displays the real-time summary:
     ```text
     ===============================================================
     📊 VERITY SAMPLE DATASET EVALUATION SUMMARY
     ===============================================================
     Total Cases Evaluated: 30
     Scams Detected:       22 / 22 (100.0%)
     Legitimate Portals:   8
     False Positives:       0 / 8 (Target: 0)
     ===============================================================
     ```
   - Confirms deterministic, repeatable algorithmic rigor.

### Fallback Option C: Fast Extension Reload (10 Seconds)
1. Open a new tab to `chrome://extensions`.
2. Toggle Developer Mode **ON**.
3. Locate **Verity 2.0 (Bharat Shield)** and click the **Reload icon (🔄)**.
4. Return to `http://localhost:8080` and refresh.
