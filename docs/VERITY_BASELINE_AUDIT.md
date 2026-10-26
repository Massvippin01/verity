# VERITY 2.0 (Bharat Shield) — Baseline Engineering & System Audit

**Audit Date**: October 2026  
**Auditor**: Principal Engineering, Cybersecurity Architect, Reliability & QA Lead  
**Baseline Commit/State**: Workspace Root `verity_v2-main`  
**Evaluation Standard**: Absolute Zero-Fabrication Operating Rules  

---

## 1. Executive Summary & Verified Baseline

VERITY 2.0 (codenamed *Bharat Shield*) is designed as an on-device citizen cyber-safety and fraud prevention assistant tailored for the Indian digital ecosystem. It provides real-time client-side analysis of web pages, messaging links, UPI payment intents, and APK droppers without relying on centralized surveillance or mandatory cloud classification.

### Empirical Test & Build Baseline
All tests and builds were executed directly within the active environment. The results are recorded below:

* **Automated Unit & Integration Test Suite** (`npm test`):
  * **Command**: `node --test tests/**/*.test.js tests/**/verify_*.js` (in `verity-extension`)
  * **Status**: **PASS** (Exit Code: `0`)
  * **Metrics**: **402 passing tests**, `0` failing, `0` cancelled, `0` skipped.
  * **Duration**: ~6,637 ms.
* **Mobile Scanner Build Pipeline** (`npm run build:mobile`):
  * **Command**: `node verity-extension/scripts/build-mobile-core.js`
  * **Status**: **PASS** (Exit Code: `0`)
  * **Artifacts generated**: 16 engine modules synchronized into `mobile-scanner/core/`, maskable PWA icons (192px and 512px) generated via pure Node buffers.
* **Core Benchmark Suite** (`npm run benchmark`):
  * **Command**: `node scripts/bench.js` (1,000 iterations per benchmark target)
  * **Status**: **PASS** (Exit Code: `0`)
  * **Empirical Measurements**:
    * Allowlist Check: Mean `0.0195 ms`, p50 `0.0133 ms`, p95 `0.0306 ms`
    * 16 Synchronous Heuristic Rules: Mean `1.1172 ms`, p50 `0.6317 ms`, p95 `3.2946 ms`
    * 18-Feature Lexical Extraction: Mean `0.0113 ms`, p50 `0.0079 ms`, p95 `0.0192 ms`
    * Full Synchronous Pipeline: Mean `1.0563 ms`, p50 `0.7619 ms`, p95 `2.8982 ms`
    * `scanText` (500-char message): Mean `1.2643 ms`, p50 `1.0291 ms`, p95 `2.7750 ms`
* **Judge Live Evaluation Harness** (`npm run judge`):
  * **Command**: `node verity-extension/scripts/judge_live_evaluation.js`
  * **Status**: **18 PASS / 1 FAIL** (Total: 19 checks)
  * **Failing Check**: `✖ FAIL | [LATENCY] Sub-millisecond execution capable (Best run: 1.381ms)`. This failure honestly reflects real machine execution times (averaging 2.805 ms rather than sub-millisecond on cold hardware).

---

## 2. Repository Architecture & Layout

The codebase is organized into modular directories reflecting different deployment targets and shared forensic modules:

```
verity_v2-main/
├── package.json                         # Root orchestration scripts (test, build:mobile, judge, benchmark, demo)
├── README.md                            # High-level architecture, problem statement, threat model
├── LICENSE                              # MIT License
├── verity_demo_server.js                # Local HTTP test server (:8080) for testing synthetic threat vectors
├── test_server.js                       # Multi-port redirect chaining test server (:3000 - :3003)
├── sample_data/                         # Synthetic Indian cyber fraud test fixtures
│   ├── README.md
│   └── indian_cyber_fraud_test_cases.json # 30 synthetic fixtures (URL, UPI, SMS, APK)
├── docs/                                # Technical design, benchmark logs, and known limitations
│   ├── BENCHMARKS.md                    # Generated benchmark report
│   ├── KNOWN_LIMITATIONS.md             # Transparent threat surface analysis
│   ├── TECHNICAL_DESIGN.md              # System design and mathematical weighting specification
│   ├── SUBMISSION_PACKET.md             # Project summary and role inventory
│   └── VERITY_2.0_MASTER_PROJECT_OVERVIEW.md
├── scripts/
│   └── bench.js                         # Root benchmark harness (1,000 iterations)
├── android-app/                         # Native Android wrapper assets and Capacitor configuration
│   ├── BUILD_APK_GUIDE.md               # Android Studio / Gradle CLI build instructions
│   ├── capacitor.config.json            # Capacitor bridge configuration
│   └── android/                         # Android Studio Gradle project structure
├── mobile-scanner/                      # Standalone Installable PWA (Citizen Cyber Lab)
│   ├── index.html                       # 3-shield responsive web application interface
│   ├── scanner.js                       # Client-side UI controller and Android Bridge handler
│   ├── app.css                          # Modern dark-mode forensic styling
│   ├── manifest.json                    # Web App Manifest (POST-based share target)
│   ├── manifest.webmanifest             # Web App Manifest (GET-based share target for static PWA)
│   ├── sw.js                            # Offline caching service worker
│   └── core/                            # Synchronized engine core built by build-mobile-core.js
├── verity-cloud/                        # Optional Enterprise FastAPI backend (opt-in only)
│   ├── requirements.txt                 # FastAPI, uvicorn, pydantic, httpx
│   └── app/main.py                      # Threat intel aggregator (URLhaus, SafeBrowsing)
└── verity-extension/                    # Manifest V3 Chromium Extension
    ├── manifest.json                    # MV3 manifest with DeclarativeNetRequest, offscreen, webRequest
    ├── service_worker.js                # Background orchestrator and webNavigation lifecycle listener
    ├── background/                      # Background engines
    │   ├── rules.js                     # 16 synchronous heuristic URL inspection rules
    │   ├── risk-engine.js               # Category-capped scoring engine with diminishing weights
    │   ├── brand-detector.js            # Brand recognition & Levenshtein distance matching
    │   ├── enterprise-whitelist.js      # Enterprise SSO / Federated login bypass verification
    │   ├── favicon-matcher.js           # MurmurHash3 visual favicon spoofing detector
    │   ├── homograph-detector.js        # Cyrillic/Greek IDN confusable character normalizer
    │   ├── reputation.js                # Dual-Engine DoH threat resolver (Cloudflare 1.1.1.2 + Quad9)
    │   ├── rdap-sentinel.js             # ICANN RDAP domain registration age inspector
    │   ├── offscreen.js                 # ONNX Runtime Web worker for ML inference
    │   ├── model/                       # ONNX models, schemas, and feature definitions
    │   │   ├── feature_order.json
    │   │   ├── feature_schema.json
    │   │   ├── phishing_model.onnx      # Baseline Logistic Regression model (35 KB)
    │   │   ├── phishing_model_v2.onnx   # LightGBM converted model (27 KB)
    │   │   └── rich_features.json
    │   └── dnr-blocker.js               # Chrome Declarative Net Request dynamic rules manager
    ├── content/                         # In-page content scripts
    │   ├── main-world-interceptor.js    # MAIN-world JS prototype traps (fetch, XHR, sendBeacon, WebSocket)
    │   ├── content-script.js            # Shadow DOM piercing DOM heuristic scanner & warning overlay
    │   ├── bharat-scam-detectors.js     # Specialized Indian cyber-fraud detectors (Digital Arrest, APK, UPI)
    │   └── search/                      # Search engine real-time safety badging
    ├── shared/                          # Portable universal modules
    │   ├── text-scanner.js              # Pure portable text, UPI, and URL parser
    │   ├── upi-forensics.js             # NPCI UPI deep-link intent forensic analyzer
    │   ├── citizen-messages.js          # Multilingual plain-language advisories (EN, TA, HI, TE)
    │   ├── legit-domains.js             # Local legitimate domain allowlist (1,000+ domains)
    │   ├── psl.js                       # Compact Public Suffix List implementation
    │   ├── online-scam-verifier.js      # Keyless public online intelligence pipeline
    │   ├── secv-intent-engine.js        # Psycholinguistic urgency and coercion detector
    │   ├── xray-educator.js             # Explainable scam cards & spot-the-scam challenges
    │   └── file-magic-inspector.js      # Binary header magic byte inspector (.apk vs .exe)
    └── tests/                           # 47 comprehensive automated test files (402 test cases)
```

---

## 3. Actual User-Facing Entry Points

1. **Standalone Mobile Scanner / PWA (`mobile-scanner/index.html`)**:
   - Primary citizen touchpoint that runs without requiring a browser extension.
   - Three operational tabs: Website Deep-Scanner, WhatsApp & SMS Scam Verifier, and UPI & Payment Safety Verifier.
   - Input modalities: Manual URL typing, multi-line SMS/message pasting, `upi://pay` strings, camera QR code scanner, file dropzone for QR screenshots, and Android Web Share Target (`ACTION_SEND`).
2. **Browser Extension Popup (`verity-extension/popup/popup.html`)**:
   - Toolbar popup displaying active site safety grade, risk score, detected signals, technical breakdown, and quick text/link check input.
3. **Browser In-Page Overlay (`verity-extension/content/content-script.js`)**:
   - High-contrast, accessibility-aware warning modal injected directly into blocked or dangerous web pages via closed Shadow DOM (`#verity-security-host`).
4. **Network Navigation Fast-Path Block Screen (`verity-extension/ui/blocked.html`)**:
   - Zero-latency block landing page redirected via Chrome Declarative Net Request for known malicious domains.
5. **Native Android APK Bridge (`android-app/`)**:
   - WebView-hosted PWA communicating via `window.VerityAndroidBridge.onIncomingIntent(payload)` receiving Android system share and deep-link intents.

---

## 4. Implemented Feature Inventory

| Subsystem | Component | Implementation Status | Notes |
| :--- | :--- | :--- | :--- |
| **URL Heuristics** | 16 Synchronous Rules (`rules.js`) | **Verified / Shipped** | Evaluates raw IP, missing HTTPS, excessive subdomains, brand collision, typosquatting, DGA entropy, malvertising rotators, and suspicious TLDs. |
| **Brand Protection** | Brand Detector (`brand-detector.js`) | **Verified / Shipped** | 350+ indexed Indian and global brands in `brands.json`, Levenshtein distance calculations, sub-token collision guards. |
| **Brand Protection** | Favicon MurmurHash3 (`favicon-matcher.js`) | **Verified / Shipped** | Detects visual brand impersonation via exact MurmurHash3 favicon matching and cross-origin CDN hotlink abuse. |
| **Indian Fraud** | Digital Arrest Extortion (`bharat-scam-detectors.js`) | **Verified / Shipped** | Identifies CBI, ED, Police, and Customs video call coercion, bogus arrest warrants, and camera surveillance traps. |
| **Indian Fraud** | Malicious APK Droppers (`bharat-scam-detectors.js`) | **Verified / Shipped** | Flags RTO Challan, PM Kisan, Wedding Card APK lures and executable double-extension masquerades (`.mp4.exe`). |
| **Indian Fraud** | UPI Collect Traps (`upi-forensics.js`) | **Verified / Shipped** | Parses `upi://pay` URIs, flags unsigned P2P collect requests masquerading as refunds or cashback credits. |
| **Zero-Trust Web** | MAIN-World Interceptor (`main-world-interceptor.js`) | **Verified / Shipped** | Hooks `window.fetch`, `XMLHttpRequest`, `sendBeacon`, and `WebSocket` at `document_start` to intercept credential exfiltration (Discord, Telegram, Webhooks). |
| **Zero-Trust Web** | BitB & AiTM Proxy Traps (`content-script.js`) | **Verified / Shipped** | Detects Browser-in-the-Browser fake OAuth popup windows and Adversary-in-the-Middle reverse proxy patterns. |
| **On-Device ML** | ONNX Runtime Web WASM (`offscreen.js`) | **Partially Active** | 18-feature LightGBM model exists. Shipped default is `ML_WEIGHT = 0.0` or advisory due to lexical false-positive trade-offs documented in Stage 2 research. |
| **Online Intel** | Keyless Online Verifier (`online-scam-verifier.js`) | **Verified / Shipped** | Raced lookups against Cloudflare 1.1.1.2 DoH, Quad9 DoH, ICANN RDAP, and Wikidata P856 official entity verification under a strict 950ms budget. |
| **Localization** | Citizen Messages (`citizen-messages.js`) | **Verified / Shipped** | Plain-language advisories in English, Tamil, Hindi, and Telugu. |
| **Reporting / Recovery** | Recovery Mode | **Missing / Gap** | No structured decision flow for victims who already entered passwords, transferred funds, or installed APKs. |
| **Data Contract** | Standard Verdict Schema | **Missing / Gap** | Disparate return shapes across engines; lacks explicit abstentions (`UNABLE_TO_DETERMINE`, `INSUFFICIENT_EVIDENCE`). |
| **Citizen Privacy** | Redacted Evidence Export | **Missing / Gap** | No one-click sanitized evidence receipt for filing complaints with National Cyber Crime Reporting Portal (1930). |

---

## 5. Detection Pipeline & Supported Input Types

```
[Citizen Input] ──> Modality Classification
                       ├── URL / Website Navigation
                       │     └── Domain Parsing (PSL) ──> Allowlist Check (0.01ms)
                       │           ├── If Match: Fast-path ALLOW (Score: 0)
                       │           └── If Unmatched:
                       │                 ├── 16 Heuristic Rules (rules.js)
                       │                 ├── Lexical Features & ML Scorer (offscreen.js)
                       │                 ├── Dual DoH Sinkhole Check (Cloudflare / Quad9)
                       │                 ├── RDAP Domain Age & CNAME Cloak Inspection
                       │                 └── DOM Form / Credential Inspection (content-script.js)
                       ├── WhatsApp / SMS / Plain Text
                       │     └── text-scanner.js
                       │           ├── URL Extraction & Canonicalization
                       │           ├── Psycholinguistic Coercion Analysis (SECV Intent Engine)
                       │           ├── Bharat Scam Keyword & Regex Rules (Digital Arrest / APK)
                       │           └── Subword NLP Classification
                       ├── UPI Payment Intent (upi://pay...)
                       │     └── upi-forensics.js
                       │           ├── Parameter Extraction (pa, pn, am, tn, mc, sign)
                       │           ├── P2P vs Verified Merchant Classification
                       │           └── Collect/Debit vs Credit Deception Analysis
                       └── QR Code Image / Camera Stream
                             └── BarcodeDetector API ──> Extracts Payload String ──> Routes to URL / UPI
```

---

## 6. Permission & Privacy Analysis

### Extension Host Permissions (`verity-extension/manifest.json`)
* `host_permissions: ["<all_urls>"]`:
  * *Necessity*: Required for pre-navigation safety checks, MAIN-world exfiltration traps, and DOM credential theft detection across arbitrary visited sites.
  * *Privacy Boundary*: Browsing activity is analyzed locally in memory. URLs are never logged to remote cloud infrastructure.
* API Permissions: `webNavigation`, `webRequest`, `storage`, `offscreen`, `downloads`, `declarativeNetRequest`.
  * `offscreen`: Used specifically to isolate ONNX Runtime Web WASM execution without freezing the browser's UI thread.
  * `downloads`: Used to inspect file download metadata (e.g. intercepting `.apk` masquerading as documents).

### Network Telemetry & Data Exfiltration Review
* **Local In-Memory Cache**: Threat feeds are pre-indexed in memory (`threat_intel_seed.js`). Lookups against this database generate **0 outbound network calls**.
* **External Network Calls**:
  1. **Dual DNS-over-HTTPS (DoH)**: Queries `https://cloudflare-dns.com/dns-query` and `https://dns.quad9.net/dns-query`.
     * *Transmitted Data*: Hostname only (e.g. `example-suspicious.xyz`). Full paths, query parameters, authorization headers, and user identities are stripped before dispatch.
  2. **ICANN RDAP**: Queries `https://rdap.org/domain/{domain}`.
     * *Transmitted Data*: Registered base domain only.
  3. **Wikidata Public Knowledge Base**: Queries `https://www.wikidata.org/w/api.php`.
     * *Transmitted Data*: Brand entity name string (e.g. `State Bank of India`).
  4. **Public Community Scam Search**: Queries `https://www.reddit.com/search.json`.
     * *Privacy Finding*: Identified bug where raw input could be passed if no entity or domain was extracted. Requires strict containment and domain-only scoping.

---

## 7. Reproducible Bugs & Deficiencies

### Finding 1: Unsanitized Query Fallback in Public Community Corroboration
* **File**: `verity-extension/shared/online-scam-verifier.js` (Line 680)
* **Evidence**:
  ```javascript
  const queryStr = candidateEntity || hostname || input.slice(0, 40);
  if (queryStr) {
    onlinePromises.push(checkRedditScamCorroboration(queryStr, queryOptions));
  }
  ```
* **Defect**: When an unrecognized text message is scanned without an extracted URL or brand entity, `input.slice(0, 40)` is forwarded to Reddit's public search endpoint. If the user pasted an SMS containing personal information (such as an Aadhaar number, phone number, or name), the first 40 characters are transmitted externally.
* **Severity**: High (Privacy violation against zero-telemetry citizen contract).
* **Mitigation**: Constrain corroboration search strictly to confirmed brand entities or extracted domains; never transmit arbitrary raw user input strings.

### Finding 2: Inconsistent Verdict Return Shapes Across Surfaces
* **Files**: `risk-engine.js`, `text-scanner.js`, `online-scam-verifier.js`
* **Evidence**:
  * `risk-engine.js` returns `{ score, riskScore, severity, action, reasons, signals, categories }`.
  * `text-scanner.js` returns `{ verdict, score, signals, extracted, aiNlp, secv, goldenRuleKey }`.
  * `online-scam-verifier.js` returns `{ url, inputText, score, severity, action, signals, onlineProofSteps }`.
* **Defect**: No unified versioned schema (`VerdictContract`). Downstream consumers and UI layers must maintain custom normalization logic, and there is no representation for explicit abstention states (`UNABLE_TO_DETERMINE`, `INSUFFICIENT_EVIDENCE`).
* **Severity**: Medium (Reliability and integration fragility).

### Finding 3: Lack of Citizen Post-Incident Recovery Workflow
* **Files**: `mobile-scanner/index.html`, `mobile-scanner/scanner.js`
* **Defect**: The current mobile UI terminates at detection. If a citizen has already approved a collect request, entered their netbanking password, or installed an APK, there is no actionable recovery flow or guided emergency assistance (such as calling the National Cyber Crime Helpline `1930`, reporting on `cybercrime.gov.in`, or freezing accounts).
* **Severity**: High (Product mission deficiency).

### Finding 4: Absence of Sanitized Local Evidence Receipts
* **Files**: `mobile-scanner/index.html`
* **Defect**: Citizens filing police or bank complaints must manually transcribe fraud evidence. VERITY does not provide an on-device downloadable or exportable Evidence Receipt that redacts sensitive credentials (passwords, OTPs, full payment details) while preserving forensic indicators (URLs, hostnames, VPAs, timestamps).
* **Severity**: Medium (High user value gap).

---

## 8. Highest-Priority Technical and Product Risks

1. **Over-reliance on Detection vs. Recovery**: Prevention is never 100% effective against zero-day social engineering. Without a dedicated recovery module, victims who use VERITY after falling for a scam are left without clear next steps.
2. **Third-Party Rate Limits on Public Keyless APIs**: Free endpoints (Wikidata, RDAP, DoH) could rate-limit or fail during high-volume spikes. The system must degrade gracefully to pure offline heuristics without delaying the user experience.
3. **PWA Sandbox Constraints**: Progressive Web Apps cannot intercept native SMS, WhatsApp notifications, or other browser apps without explicit citizen action (sharing or pasting). This platform boundary must be clearly communicated to prevent a false sense of security.
4. **Machine Learning False Positives on Non-English URLs**: URL-only lexical models without DOM context carry false-positive risks on regional or government domain structures. Keeping heuristic rules as the authoritative arbiter is critical for zero false positives on benign portals.

---

## 9. Distinction Between Verified Facts and Assumptions

* **Verified Fact**: 402 test cases pass in Node.js test runner covering 16 rules, UPI collect traps, Digital Arrest patterns, BitB, AiTM, and allowlist collision guards.
* **Verified Fact**: Allowlist lookups execute in 0.013 ms, and full synchronous heuristic scans execute in ~1.05 ms on standard developer hardware.
* **Verified Fact**: Browsing history is not sent to any Verity server; `verity-cloud` is completely decoupled and inactive in shipping code.
* **Verified Fact**: ONNX model v2 exists in `background/model/`, but runtime inference in Chrome requires an offscreen document and is bypassed in the shipping heuristic path.
* **Assumption (to be avoided)**: Assuming a passing test suite means every citizen scam variant in India is detected. Real-world fraud techniques mutate daily; coverage must be mapped explicitly across a scenario taxonomy.
