# Verity (Bharat Shield)

> **Real-time, on-device cyber defense and financial fraud protection.**  
> Protects users against phishing, brand typosquatting, deceptive UPI collect traps, "Digital Arrest" extortion, malicious APK droppers, and malvertising before harm occurs.

---

## The Problem

Digital payments and internet adoption have expanded rapidly across India, but cyber fraud has surged at an alarming rate. According to official **Ministry of Home Affairs (MHA) data presented to the Lok Sabha (July 2025)**, Indian citizens reported losses of **₹22,845 Crore across 36 Lakh cyber financial fraud complaints in 2024** alone (a 206% surge from ₹7,465 Crore in 2023), with over **₹1,750 Crore** lost in the first four months of 2024 alone per Indian Cyber Crime Coordination Centre (I4C) NCRP telemetry. While I4C's Citizen Financial Cyber Fraud Reporting and Management System (CFCFRMS / 1930 Helpline) has proactively saved **₹8,690+ Crore across 24.65 Lakh complaints** up to January 31, 2026, and blocked **12.94 Lakh SIM cards** and **3.03 Lakh IMEIs** (PIB / MHA Release PRID 2241344), preventative client-side defense remains critical.

According to research from the **Anti-Phishing Working Group (APWG)** and **Palo Alto Networks Unit 42**, the median active lifespan of a phishing site is just **4 to 8 hours** (with over 70% expiring within 24 hours). This makes reactive cloud reputation blocklists inadequate for protecting first-wave victims against zero-day campaigns:
- **Digital Arrest Scams**: Fraudsters pose as police, customs, or federal investigative agencies (CBI, ED), threatening victims with imminent arrest unless money is transferred.
- **Deceptive UPI Collect & QR Traps**: Exploiting user confusion between "sending" and "receiving" money by generating `upi://pay` deep-links and fake cashback QR codes that debit the victim's account.
- **Illegal In-Browser UPI PIN Collection**: Deceptive web forms asking users to enter their confidential 4- or 6-digit UPI PIN or ATM PIN directly into a browser.
- **Malicious APK Droppers**: Links masquerading as official transport department traffic challans (`RTO_Challan.apk`) or utility bill arrears that install remote access trojans (RATs).

---

## What Verity Is

**Verity** is an open-source, client-side security platform that analyzes web pages, payment flows, and messages in real time directly on the user's device. Rather than relying solely on remote cloud blacklists, Verity performs on-device heuristic pattern matching, Levenshtein brand distance calculation, DOM structural analysis, and lightweight machine learning inference in sub-millisecond execution time.

### Two Protection Surfaces

1. **Browser Extension (Manifest V3)**:
   - Compatible with Google Chrome, Microsoft Edge, Brave, and Chromium-based browsers.
   - Fully compatible with mobile browsers that support extensions, such as **Firefox for Android**.
   - Features real-time pre-navigation URL analysis, declarative network interception (Declarative Net Request), MAIN-world network exfiltration traps, DOM credential inspection, and isolated Shadow DOM warning overlays.

2. **Installable Progressive Web App (PWA) / Mobile Scanner**:
   - Built for smartphones and devices without extension access.
   - Shares the exact same core engine (`rules.js`, `legit-domains.js`, `psl.js`, `messages.js`, and `text-scanner.js`).
   - Supports camera QR code scanning, manual message/URL pasting, and Android **Web Share Target** integration (allowing citizens to share suspicious SMS or WhatsApp messages directly into Verity for instant safety verdicts).

---

## Comparison: Verity vs. Traditional Defenses

| Capability | Google Safe Browsing / Cloud Blocklists | Truecaller / Caller ID Apps | Verity (Bharat Shield) |
| :--- | :--- | :--- | :--- |
| **Detection Basis** | Known domain blocklists and cloud crawlers | User-reported phone number database | On-device heuristics, DOM analysis, and 18-feature ML |
| **Zero-Day Links** | Newly registered domains may not be listed yet | Limited to phone call and SMS metadata | Analyzes structural URL patterns and DOM context on first load |
| **In-Browser Credential Inspection** | Limited to flagged URLs; no dynamic DOM checks | No browser DOM capability | Discovers fake password, CVV, OTP, and UPI PIN fields |
| **Indian Fraud Specialization** | Generic global phishing models | Flags spam phone numbers | Native detectors for Digital Arrest, fake APKs, and UPI collect traps |
| **Browsing Privacy** | Hashes or URLs checked against remote cloud API | Contact books and metadata synced to servers | **Strictly on-device**: browsing history never leaves the device |
| **Latency Overhead** | Remote API network round-trip | Network query per call/SMS | Sub-millisecond synchronous execution (< 0.5 ms) |

---

## Machine Learning Architecture

Verity uses an **18-feature on-device machine learning model** (LightGBM converted to ONNX, running via ONNX Runtime Web WASM in an offscreen document). The model extracts 18 lexical and domain features (including Shannon entropy, vowel-to-consonant ratios, token lengths, brand Levenshtein distances, sensitive directory keywords, and port anomalies) to assess zero-day URLs in ~0.02 ms without sending user URLs to an external server.

---

## Privacy Statement

> **Browsing data stays on device; only unfamiliar hostnames go to Cloudflare/Quad9 via DNS-over-HTTPS; threat feed sync is a read-only download.**

Verity is designed in strict alignment with India's **Digital Personal Data Protection (DPDP) Act 2023**:
- No user accounts, telemetry trackers, or search history logging.
- Form inputs and keystrokes are never recorded or stored.
- Threat intelligence queries use DNS-over-HTTPS (`1.1.1.2`) transmitting hostnames only — full paths, query strings, and auth tokens are never transmitted.

---

## Installation & Setup

### Prerequisites
- Node.js (v18.0.0 or higher)
- npm (v9.0.0 or higher)

### 1. Browser Extension
1. Clone the repository:
   ```bash
   git clone https://github.com/verity-shield/verity.git
   cd verity
   ```
2. Open your Chromium-based browser (Chrome, Edge, Brave) and navigate to:
   ```
   chrome://extensions
   ```
3. Enable **Developer mode** (toggle in the top-right corner).
4. Click **Load unpacked** and select the `verity-extension/` directory.
5. *(Optional - Firefox for Android)*: Use `about:debugging` or a custom Firefox Nightly Add-on Collection to load the extension.

### 2. Standalone Mobile Scanner (PWA)
1. Build the mobile core distribution:
   ```bash
   npm run build:mobile
   ```
2. Serve the `mobile-scanner/` directory locally or over HTTPS:
   ```bash
   npx serve mobile-scanner -l 8080
   ```
3. Open `http://localhost:8080` (or your local network IP) on your mobile device.
4. Tap your browser's menu and select **"Add to Home Screen"** or **"Install Verity Scanner"**.

---

## Verification & Commands

```bash
# Run the complete test suite (234 unit, integration, and security tests)
npm test

# Launch the interactive local test server demonstrating 10+ real-world scam scenarios
npm run demo

# Execute the 1,000-iteration performance benchmark suite
npm run benchmark

# Re-build the standalone PWA distribution
npm run build:mobile
```

---

## Project Tree

```
verity/
├── docs/                               # System documentation & technical designs
│   ├── archive/                        # Archived design notes and hackathon briefs
│   ├── BENCHMARKS.md                   # Machine benchmarks and latency budgets
│   ├── KNOWN_LIMITATIONS.md            # Transparent threat surface and limitation analysis
│   └── TECHNICAL_DESIGN.md             # Complete system architecture and math specification
├── mobile-scanner/                     # Standalone installable PWA application
│   ├── core/                           # Synchronized shared engine modules
│   ├── manifest.json                   # Web App Manifest & Web Share Target config
│   └── index.html                      # Mobile scanner interface (camera, text, share)
├── sample_data/                        # Curated cyber fraud test cases (English & Indic languages)
├── scripts/                            # Operational and evaluation scripts
│   ├── bench.js                        # 1,000-iteration benchmark harness
│   └── build-mobile-core.js            # PWA core builder and synchronizer
├── verity-extension/                   # Browser extension root (MV3)
│   ├── background/                     # Service worker, rules engine, and risk engine
│   │   ├── model/                      # On-device ONNX machine learning models
│   │   ├── risk-engine.js              # Adaptive risk engine & diminishing weights
│   │   ├── rules.js                    # 16 synchronous heuristic rules
│   │   └── dnr-blocker.js              # Declarative Net Request fast-path blocker
│   ├── content/                        # Isolated and MAIN world content scripts
│   │   ├── bharat-scam-detectors.js    # Digital Arrest, APK dropper, and UPI detectors
│   │   ├── content-script.js           # DOM traversal, shadow piercing, overlays
│   │   ├── main-world-interceptor.js   # MAIN world fetch, XHR, sendBeacon, WebSocket traps
│   │   └── search/                     # Real-time search engine result safety badging
│   ├── popup/                          # Extension toolbar popup interface
│   ├── shared/                         # Cross-surface libraries (PSL, Allowlist, Messages)
│   ├── tests/                          # 290 automated tests (node:test)
│   ├── ui/                             # Zero-latency block screen (blocked.html)
│   └── manifest.json                   # MV3 Extension Manifest
├── verity_demo_server.js               # Interactive evaluation and demo HTTP server
├── LICENSE                             # MIT License
├── package.json                        # Root workspace configuration
└── README.md                           # Project documentation
```

---

## United Nations Sustainable Development Goals (UN SDGs)

Verity contributes directly to four United Nations Sustainable Development Goals:

- **SDG 16.4 (Peace, Justice and Strong Institutions)**: Combats illicit financial flows and organized cybercrime by preventing online extortion, banking fraud, and credential theft.
- **SDG 9 (Industry, Innovation and Infrastructure)**: Strengthens public digital infrastructure resilience with client-side, zero-latency security running transparently across open standards.
- **SDG 10 (Reduced Inequalities)**: Protects vulnerable populations — including rural citizens, non-English speakers, and elderly first-time digital payment users — from predatory social engineering and financial loss.
- **SDG 4 (Quality Education)**: Enhances digital literacy by providing transparent, localized explanations in clear language whenever a deceptive threat is intercepted.

---

## Team & Roles

| Role | Name / Identifier | Primary Responsibilities |
| :--- | :--- | :--- |
| **Lead Architect & Security Engineer** | Contributor One (Placeholder) | System architecture, risk engine math, MAIN-world interceptors |
| **Machine Learning Engineer** | Contributor Two (Placeholder) | 18-feature lexical dataset, GroupKFold validation, ONNX export |
| **Full-Stack & Mobile Developer** | Contributor Three (Placeholder) | PWA implementation, Web Share Target, search result badging |
| **Threat Research & Localization** | Contributor Four (Placeholder) | Bharat scam heuristics, multilingual dictionaries (Hindi/Tamil/Telugu) |

---

## Roadmap

- Optional vernacular voice alerts (code present in shared/vernacular-coach.js, not enabled in the UI).
- Expanded regional language coverage for text scanner heuristics.
- Quantized INT8 v3 ONNX model integration for lower-end Android hardware.

---

## Contributing

Contributions are welcome! To contribute:
1. Fork the repository and create a descriptive feature branch (`git checkout -b feature/new-detector`).
2. Ensure all tests pass: `npm test`.
3. Adhere to zero-telemetry and privacy-first architectural guidelines.
4. Submit a Pull Request with complete test coverage.

---

## License

This project is licensed under the [MIT License](LICENSE) - Copyright (c) 2026 Verity Bharat Shield contributors.
