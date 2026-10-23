# 🛡️ Verity 2.0 (Bharat Shield) — Official Hackathon Submission Packet

> **Competition Track**: Digital Safety & Cyber Fraud Awareness  
> **Target Award**: Rank #1 State / National Grand Jury Selection  
> **Repository Ground Truth**: Verified Against Codebase (290 Automated Tests, 0 Failures)  
> **License**: MIT (Open Source)

---

## 📋 SECTION 1: OFFICIAL SUBMISSION FORM FIELDS

All character counts have been strictly measured and validated to conform to character limits.

### 1.1 Project Title (Max 100 Characters)
```text
Verity (Bharat Shield): Real-Time On-Device Cyber Defense & Financial Fraud Prevention
```
*(Character count: 86 / 100)*

### 1.2 Theme Alignment & UN SDGs (Max 500 Characters)
```text
Theme: Digital Safety & Cyber Fraud Awareness.
UN Sustainable Development Goals (SDGs) Alignment:
• SDG 16.4: Significantly reduce illicit financial flows & combat organized cybercrime.
• SDG 9: Resilient digital infrastructure protecting UPI & banking adoption.
• SDG 10: Reduce inequality by shielding first-time smartphone users, pensioners, & rural citizens.
• SDG 4: Universal digital literacy via in-situ vernacular micro-quizzes (Hindi, Tamil, Telugu, English).
```
*(Character count: 468 / 500)*

### 1.3 Problem Statement (Max 500 Characters)
```text
Per MHA data to Lok Sabha (July 2025), Indians reported ₹22,845 Cr lost across 36 Lakh fraud complaints in 2024 (206% surge), with >₹1,750 Cr lost in early 2024. Phishing sites have a median lifespan of 4-8 hours (APWG/Unit 42), rendering cloud blocklists too slow for first-wave victims. Scammers exploit rural citizens, seniors, and non-English speakers via fake bank KYC alerts, deceptive UPI collect traps, CBI Digital Arrest extortion, and malicious APK droppers (RTO challan, PM-Kisan).
```
*(Character count: 492 / 500)*

### 1.4 Approach, Tech Stack & Impact (Max 500 Characters)
```text
Verity provides 100% on-device, zero-telemetry defense executing in <0.5ms in Manifest V3 & mobile PWA. Tech stack: pure-JS heuristics, 16 rules, 26.88KB ONNX model, MAIN-world WebRTC/exfil traps, & 9 Bharat detectors (NPCI UPI protocol forensics, brand asset theft, live Luhn keylogger honey-token poisoner, Digital Arrest surveillance trap). Impact: Stops fraud pre-navigation with 0% false positives on official portals, instant 4-language visual switching, & in-situ Golden Rules. 290 tests.
```
*(Character count: 493 / 500)*

---

## 📽️ SECTION 2: 8-SLIDE OFFICIAL GRAND JURY PRESENTATION DECK

Each slide corresponds to an official PowerPoint / PDF slide formatted with exact titles, high-density bullets, architectural diagrams, and verbatim presenter scripts.

```
========================================================================================
SLIDE 1: TITLE & EXECUTIVE VISION
========================================================================================
Title: VERITY 2.0 (BHARAT SHIELD)
Subtitle: Real-Time, On-Device Client Defense Against Indian Cyber Financial Fraud
Track: Digital Safety & Cyber Fraud Awareness
Team: [Team Name / College / State]

Visual Elements:
- Large glowing Shield logo with tricolor accent (Saffron/White/Green)
- Live Metric Badges:
  • 290 Automated Tests (100% Pass across 39 suites)
  • 0.08ms Heuristic Engine Latency
  • 26.88 KB On-Device ONNX AI Model
  • 100% Zero-Telemetry Browsing Privacy

Speaker Note (Presenter Script):
"Respected Grand Jury, digital payments have transformed India through UPI, but cyber fraud 
has grown into a national crisis. Traditional defenses rely on remote cloud blacklists that 
update too late. Verity 2.0 is Bharat Shield—an open-source, client-side cybersecurity 
engine operating in under 0.5 milliseconds directly on user devices to neutralize fraud 
before citizens lose a single rupee."
========================================================================================
```

```
========================================================================================
SLIDE 2: THE NATIONAL EMERGENCY (WHY CLOUD BLOCKLISTS FAIL)
========================================================================================
Title: The Bharat Cyber Safety Crisis
Key Institutional Facts (Government of India / MHA / I4C Data):
• ₹22,845 Crore Reported Losses: Over 36 Lakh citizen complaints lodged in 2024 alone 
  (206% surge from ₹7,465 Cr in 2023), per MHA Lok Sabha Reply (July 2025).
• Over ₹1,750 Crore Lost in Jan–April 2024 Baseline per I4C NCRP telemetry.
• Proactive Defense Saves Crores: While I4C's CFCFRMS (1930 Helpline) saved ₹8,690+ Cr 
  and blocked 12.94 Lakh SIMs (PIB PRID 2241344), post-facto reporting cannot replace 
  point-of-attack interception.

The Cloud Blocklist Failure Mode:
• 4 to 8 Hour Active Lifespan: APWG & Unit 42 document that modern phishing domains 
  are abandoned or rotated within hours.
• The Victim Window: By the time Google Safe Browsing or antivirus crawlers flag a domain, 
  thousands of first-wave victims have already entered credentials or approved UPI debits.

Speaker Note:
"Cloud blacklists fail because scammers spin up disposable domains on free hosting that live 
for only 4 to 8 hours. Centralized crawlers take 12 to 48 hours to discover them. The first 
victims are left defenseless. We need deterministic, client-side detection that intercepts 
the scam the exact millisecond the user visits the page."
========================================================================================
```

```
========================================================================================
SLIDE 3: TARGETED INDIAN THREAT VECTORS
========================================================================================
Title: Localized Threats Requiring Bharat-Specific Defenses

Threat Taxonomy Matrix:
1. Fake Bank KYC Phishing (e.g. sbi-kyc-verification-portal.com):
   - Attack: Urgent SMS scaring users with netbanking suspension to steal OTPs.
   - Verity Countermeasure: Levenshtein brand distance, brand-in-path detection, and 
     credential harvesting traps.
2. Deceptive UPI Collect & QR Reverse-Charge Traps:
   - Attack: Posing as OLX buyer or cashback lottery sending `upi://pay?am=15000` collect links.
   - Verity Countermeasure: Deep-link inspection (`parseUpiString`) checking debit amounts 
     paired with receive-money lures (`SIG_UPI_QR_COLLECT_TRAP`).
3. "Digital Arrest" & Legal Intimidation Scams:
   - Attack: Impersonating CBI/ED/Police demanding Skype video calls and bail transfers.
   - Verity Countermeasure: Multilingual text scanner (`detectDigitalArrestAndApkScams`) 
     matching enforcement lures + demand terms across 4 Indian languages.
4. Malicious Android APK Droppers:
   - Attack: Masquerading as `RTO_Challan.apk` or `PM_Kisan.apk` carrying SMS-forwarding RATs.
   - Verity Countermeasure: Automated download pause, double-extension detection, and APK 
     dropper signature interception.
5. Illegal In-Browser UPI PIN Interception:
   - Attack: Phishing forms prompting users for 4- or 6-digit UPI PINs directly in browsers.
   - Verity Countermeasure: Zero-trust invariant: web forms are NEVER authorized to collect UPI PINs.

Speaker Note:
"Western security tools know nothing about UPI collect requests, RTO challan APKs, or 
Digital Arrests. Verity was engineered from the ground up for Bharat's distinct fraud 
threat vectors with zero-tolerance rules for illegal web PIN and reverse-charge prompts."
========================================================================================
```

```
========================================================================================
SLIDE 4: ARCHITECTURAL BLUEPRINT (TWO COMPLEMENTARY SURFACES)
========================================================================================
Title: Client-Side Architecture: Manifest V3 & Mobile PWA

Architecture Diagram:
+---------------------------------------------------------------------------------------+
| ACTIVE BROWSER TAB / CLIENT APP                                                       |
| • MAIN-World Interceptor (Hooks fetch, XHR, sendBeacon, WebSocket to kill exfil)      |
| • Isolated Content Script (Pierces Shadow DOM, inspects forms, injects warning cards) |
+---------------------------------------------------------------------------------------+
                                   │ Message Passing (GET_TAB_VERDICT)
                                   ▼
+---------------------------------------------------------------------------------------+
| BACKGROUND SERVICE WORKER (MV3)                                                       |
| • Declarative Net Request (Pre-navigation domain blocklist)                           |
| • Heuristic Rule Engine (16 synchronous URL rules, 0.08ms latency)                    |
| • Brand Typosquatting Matcher (Public Suffix List + Levenshtein distance)             |
| • Adaptive Risk Engine (Category caps, diminishing returns, score 0-100)             |
+---------------------------------------------------------------------------------------+
               │                                      │
               ▼                                      ▼
+───────────────────────────────+      +────────────────────────────────────────────────+
| OFFSCREEN DOCUMENT            |      | STANDALONE MOBILE PWA                          |
| • ONNX Runtime Web (WASM)     |      | • Web Share Target for WhatsApp messages       |
| • 26.88 KB Shipped Model      |      | • Camera QR Code Quishing Scanner              |
| • 18 Rich Feature Inferences  |      | • Shared Pure-JS Core Engine                   |
+───────────────────────────────+      +────────────────────────────────────────────────+

Speaker Note:
"Verity deploys across two unified surfaces: a Manifest V3 browser extension and a 
mobile PWA. In desktop browsers, our service worker analyzes URLs pre-navigation, our 
offscreen WASM runs an 18-feature ONNX model, and our MAIN-world interceptor cuts off 
Telegram/Discord credential exfiltration webhooks in real time. On mobile, our PWA uses 
Android Web Share Target to analyze suspicious WhatsApp forwards with the exact same engine."
========================================================================================
```

```
========================================================================================
SLIDE 5: DETECTION ENGINE & MATHEMATICAL RIGOR
========================================================================================
Title: Multi-Layered Deterministic Detection Engine

1. 16 Lexical & Structural URL Rules:
   - IP hosts, missing HTTPS, excessive subdomains, brand-in-subdomain/path, punycode spoofing, 
     financial keywords on unauthorized hosts, AiTM reverse-proxy paths (`/common/oauth2/`).

2. Shipped Machine Learning Model:
   - File Size: 26.88 KB (`phishing_model_v2.onnx`).
   - Dimension: Exactly 18 numerical lexical/domain features.
   - Training: Trained on 4,750 balanced URLs with 98.97% test accuracy (0.9897 F1).

3. Adaptive Risk Formula:
   - Diminishing Weight Summation: Total Score = Base + Sum(Weight_i * decay_factor^i).
   - Category Caps: Individual signal categories are strictly capped (Phishing: 70, 
     Malware: 70, Scam/Fraud: 65, Suspicious: 40) preventing isolated quirks from blocking.
   - Critical Invariants: BitB spoofing, AiTM proxies, and Illegal UPI PIN requests trigger 
     immediate >= 90 danger thresholds.
   - Enterprise Allowlist Exemptions: Zero false positives guaranteed on verified IdPs 
     (Google, Microsoft, Okta, SBI, IRCTC, DigiLocker).

Speaker Note:
"We don't use slow, non-deterministic LLM wrappers. Verity uses an ultra-fast, deterministic 
scoring formula combining 16 lexical rules, category caps that prevent false positives, and 
a 26.88 KB 18-feature ONNX neural network running locally inside WASM in 0.45 milliseconds."
========================================================================================
```

```
========================================================================================
SLIDE 6: CITIZEN-CENTRIC VERNACULAR UX
========================================================================================
Title: Vernacular Interface & In-Situ Digital Literacy

Design Principles:
• Traffic-Light Model:
  🟢 Safe (0–34)  |  🟡 Caution (35–69)  |  🔴 Danger (70–100)
• Plain Language — No Jargon:
  Scanners usually output confusing technical alerts like 'Entropy 4.8'. Verity translates 
  threats into plain citizen alerts: '❌ Unverified web page asking for your UPI PIN.'
• Instant 4-Language Visual Switching:
  Synchronously switches entire UI between English, हिन्दी (Hindi), தமிழ் (Tamil), 
  and తెలుగు (Telugu) without network calls or layout shifts.
• Spot-The-Scam Micro-Quiz:
  Turns blocked fraud pages into teachable moments via interactive 1-question quizzes 
  reinforcing recognition of genuine vs. fake domain suffixes.
• Golden Safety Rules:
  Always provides an actionable, memorable safety rule for every threat vector:
  '⚡ Golden Rule: Never enter your UPI PIN to receive money. PIN is only for sending.'

Speaker Note:
"Cyber safety fails when warnings are written in complex English jargon that rural citizens 
cannot understand. Verity provides crystal-clear visual alerts in Hindi, Tamil, Telugu, and 
English, accompanied by memorable Golden Rules and micro-quizzes that build long-term digital resilience."
========================================================================================
```

```
========================================================================================
SLIDE 7: VERIFIED TECHNICAL MEASUREMENTS
========================================================================================
Title: Measured Performance & Experimental Validation

+-----------------------------------------+---------------------------------------------+
| Metric Category                         | Verified Measured Value                     |
+-----------------------------------------+---------------------------------------------+
| Automated Unit & Integration Tests      | 290 Passed (0 Failed, 0 Skipped)            |
| Test Suite Execution Duration           | ~1070 ms across 39 comprehensive suites      |
| URL Evaluation Latency (Native Node)    | 0.08 ms mean per URL scan                   |
| Full Extension Pipeline Latency (WASM)  | 0.45 ms mean scan time                      |
| Shipped ONNX Model Size                 | 26.88 KB (phishing_model_v2.onnx)           |
| Extension UI Package Weight             | Popup: 24.38 KB  |  Blocked Page: 18.60 KB   |
| Real-World False Positive Rate          | 0.00% across 50+ Top Indian Portals         |
| Indian Cyber Fraud Sample Payloads      | 100% Detection (25 of 25 Test Payloads)     |
+-----------------------------------------+---------------------------------------------+

Speaker Note:
"Every number we present is measured directly from the code. All 290 unit and integration 
tests pass cleanly in ~1 second across 39 test suites. URL evaluation takes 0.08 milliseconds—fast enough 
to run before the browser even opens a socket connection. And on official Indian portals 
like onlinesbi.sbi and digilocker.gov.in, our false positive rate is exactly zero."
========================================================================================
```

```
========================================================================================
SLIDE 8: SOCIAL CAUSE IMPACT & THE ROAD AHEAD
========================================================================================
Title: Empowering 1.4 Billion Digital Citizens

Impact Alignment:
• Protects Bharat's UPI Revolution: Shields first-time smartphone users from irreversible 
  savings liquidation.
• 100% Privacy Preservation: Zero browsing history, URLs, or personal data ever leaves the 
  user's device. Complete compliance with India's Digital Personal Data Protection (DPDP) Act.
• Accessible to Low-End Hardware: Sub-1MB total engine footprint runs smoothly on low-cost 
  smartphones and budget laptops without battery drain.
• Open-Source Public Good: Published under the MIT License for integration into community 
  browsers, educational institutions, and state cyber cells.

Future Roadmap (Next 90 Days):
• Quantized 26-Feature NextGen Neural Model deployment.
• Direct Android Accessibility Service integration for system-wide SMS/WhatsApp auto-scanning.
• Deep integrations with State Cyber Police 1930 reporting APIs.

Speaker Note:
"Verity is not another commercial software or cloud-dependent tool. It is an open-source public 
shield engineered to defend the dignity and financial security of ordinary Indian families. 
Thank you, and we welcome your questions."
========================================================================================
```

---

## 🎬 SECTION 3: 3-MINUTE LIVE VIDEO RECORDING SCRIPT

> **Total Duration**: Exactly 180 Seconds (3 Minutes 00 Seconds)  
> **Camera / Screen Setup**:  
> • Left 65%: Chrome Browser window with Verity 2.0 unpacked extension loaded.  
> • Right 35%: Developer Tools / Terminal showing test execution and zero network traffic.  
> • Presenter Mic: Clear audio, energetic and authoritative delivery.

### ⏱️ Timestamped Click-by-Click Choreography

| Timestamp | Screen Action | Exact Input / URL | Presenter Script | Key On-Screen Visuals |
| :--- | :--- | :--- | :--- | :--- |
| **0:00 – 0:30** | Wide view of desktop with demo server at `http://localhost:8080`. | `http://localhost:8080` | *"Respected judges, in 2024 Indian citizens lost ₹22,845 Crore across 36 Lakh fraud complaints per official MHA data. Centralized blocklists fail because phishing domains last only 4 to 8 hours. Meet Verity 2.0—Bharat Shield. A 100% on-device, sub-millisecond defense shield operating directly inside the browser."* | Live demo dashboard with metric pills: `290 Tests Passing`, `< 0.5ms Scan Time`, `Zero Telemetry`. |
| **0:30 – 1:15** | Click **"🚀 Launch Scenario 1: Fake SBI KYC"**. | `http://localhost:8080/demo/sbi-kyc-telegram` | *"A citizen receives an urgent SMS: 'SBI NetBanking blocked within 24 hours. Update PAN now.' When the victim clicks, Verity immediately intercepts navigation before credentials can be entered or exfiltrated to Telegram."* | **Full-bleed red warning screen**. Shows plain citizen bullets: *"❌ Fake website impersonating State Bank of India"*, Golden Rule card, and Spot-The-Scam Micro-Quiz. Click the correct answer to show instant green celebration feedback. |
| **1:15 – 1:55** | Open extension icon in toolbar; paste malicious UPI collect string. | `upi://pay?pa=olx_buyer@okhdfcbank&am=15000&tn=OLX+Payment+Accept` | *"Now look at our Extension Popup Quick Checker. Scammers pose as OLX buyers sending fake payment acceptance QR codes with a debit intent of ₹15,000. We paste the string and instantly get a Danger Red Card: 'Never enter your UPI PIN to receive money.' Watch our vernacular switcher: click Tamil, Hindi, or Telugu—the entire UI updates synchronously with zero network requests!"* | Popup switches instantly to 🔴 DANGER card (Score: 85/100). Language pills switch seamlessly between English, தமிழ், हिन्दी, and తెలుగు. |
| **1:55 – 2:30** | Switch to Mobile PWA tab; paste Digital Arrest WhatsApp message. | `"URGENT NOTICE: CBI cyber crime investigation. You are placed under digital arrest for illegal narcotics parcel seized at airport. Connect to video call on Skype immediately."` | *"On mobile, our PWA provides the exact same engine via Android Web Share Target. When a citizen forwards a terrifying CBI Digital Arrest extortion threat, Verity detects legal intimidation patterns across Hindi, Tamil, Telugu, and English, advising the citizen that real police never arrest over video calls."* | Mobile PWA displays full-width warning card highlighting `SIG_DIGITAL_ARREST_EXTORTION` with vernacular guidance. |
| **2:30 – 3:00** | Bring VS Code Terminal to full focus; run live test command. | `npm test` inside `verity-extension/` | *"Finally, our technical rigor. We run npm test live on camera: 290 unit and integration tests passing in ~1 second with zero failures across 39 test suites. Zero telemetry, zero cloud dependencies, 100% open-source defense for Bharat. Thank you."* | Terminal shows all 39 test suites executing: `ℹ tests 290, ℹ pass 290, ℹ fail 0, ℹ duration_ms ~1070ms`. Camera fades out on GitHub repository URL. |

---

## 🏁 SECTION 4: FINAL SUBMISSION CHECKLIST

- [x] **Repository Root README**: High-quality overview, install guide, architecture, and verified citations.
- [x] **Technical Design Doc**: [docs/TECHNICAL_DESIGN.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/docs/TECHNICAL_DESIGN.md) completely detailed with exact math and formulas.
- [x] **Master AI Project Brief**: [docs/PROJECT_BRIEF_FOR_AI.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/docs/PROJECT_BRIEF_FOR_AI.md) self-contained, fact-verified, and citation-complete.
- [x] **Sample Cyber Fraud Payloads**: [sample_data/indian_cyber_fraud_test_cases.json](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/sample_data/indian_cyber_fraud_test_cases.json) with 25 test cases achieving 100% scam detection and 0% false positives.
- [x] **Automated Test Suite**: 290 passing unit and integration tests across 39 suites running in ~1,070 ms with 0 failures.
- [x] **Open Source License**: Root [LICENSE](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/LICENSE) (MIT License).
- [x] **Interactive Demo Server**: [verity_demo_server.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity_demo_server.js) serving 10+ live scenarios on port 8080.
- [x] **Submission Packet**: [docs/SUBMISSION_PACKET.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/docs/SUBMISSION_PACKET.md) complete with form fields, 8-slide PPT content, and 3-minute video script.
