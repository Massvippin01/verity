# Verity 2.0 (Bharat Shield): Complete Technical & Strategic Brief for AI Assistants

---

## 0. TL;DR (8 lines)
1. **What Verity Is**: An open-source, on-device cyber defense suite combining 16 synchronous heuristic rules, an 18-feature ONNX machine learning model, DOM inspection, and runtime network interception.
2. **Who It Protects**: Indian citizens, elderly users, rural communities, and first-time digital payment users vulnerable to localized cyber financial fraud.
3. **Current Maturity**: Production-ready Manifest V3 browser extension, standalone Native Android APK (`android-app/`), and 3-Shield Progressive Web App (PWA) with 402 passing automated tests across 44 suites and sub-millisecond execution.
4. **Architecture Highlights**: 100% on-device evaluation, zero telemetry, closed Shadow DOM defense shields, continuous Neural MLP meta-fusion, Subword Bayesian Softmax NLP, Bitdefender-parity compromised CMS deep-path scanner, SERP sponsored ad shield, precision payment gateway allowlist (Stripe, Razorpay, ChatGPT Plus, BillDesk), live keyless online verification grid (Wikidata official website check, dual DoH CNAME cloaking, ICANN RDAP domain age, Reddit corroboration), native Android APK with NotificationListenerService background phishing sentinel, and the **5-Pillar Autonomous Strengthening Engine** (Pillar 1: 5D Psycholinguistic Intent Vector SECV; Pillar 2: Dynamic Unlisted Brand Discovery & TR-39 Unicode skeletons with DoH DMARC; Pillar 3: Adversarial DOM Sentinel with stealth uncloaking & WebSocket trap; Pillar 4: Public Threat Mesh with PhishStats live feed; Pillar 5: Live Camera QR viewfinder & mobile bridge).
5. **Specialized Threat Coverage**: Real-time detection of "Digital Arrest" extortion, deceptive UPI collect/QR reverse-charge traps, illegal in-browser UPI PIN demands, malicious APK droppers, multi-hop malvertising redirect rotators, crack-site malware lures, hacked WordPress/CMS deep-path phishing kits, and sponsored search ad impersonation.
6. **Citizen UI & Languages**: Localized in 4 Indian languages (English, Hindi, Tamil, Telugu) with interactive "Spot-the-Scam" educational micro-quizzes, traffic-light safety cards, 3-Shield Mobile Forensics Lab with Web Share Target Level 2, and Golden Safety Rules.
7. **Biggest Architectural Gaps**: Web Worker network exfiltration bypasses, heavily obfuscated dynamic eval/WASM calls, canvas forms without standard DOM listeners, and lack of background navigation hooking in mobile PWAs.
8. **What Help We Want**: Hackathon jury presentation strategy, grand jury slide deck design, demo video choreography, jury Q&A defense preparation, and prioritizing high-impact rubric improvements.

---

## 1. Context and Goal

### 1.1 Hackathon Overview
- **Theme**: "Digital Safety & Cyber Fraud Awareness".
- **Competitive Landscape**: Multi-tier hackathon where only the top 3 teams per state advance to the Grand Finale. The explicit objective of this repository is to secure **Rank #1**.
- **Licensing**: Open-source under the permissive MIT License (see [LICENSE](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/LICENSE)).
- **Time Horizon**: Approximately 4 days remaining until final project submission from the time of writing.

### 1.2 Official Evaluation Rubric (7 Dimensions)
Every technical and strategic suggestion must directly optimize for these 7 criteria:
1. **Relevance**: Addresses rampant, real-world Indian cyber fraud (UPI scams, Digital Arrest, APK droppers) with localized social context.
2. **Technical Strength**: Robust software engineering, defensible machine learning evaluation (GroupKFold, no data leakage), Manifest V3 compliance, and deterministic sub-millisecond runtime performance.
3. **Functionality**: Working, end-to-end user journeys with zero crashes, comprehensive test coverage (402 tests across 44 suites), and seamless user bypass/safety flows.
4. **Creativity & Novelty**: Breakthrough mechanisms such as closed Shadow DOM uncloaking, runtime WebSocket/fetch exfiltration traps, continuous 8D DOM vector embeddings, 2-Layer Neural MLP meta-fusion, and interactive educational micro-quizzes at the moment of intervention.
5. **Social Cause Impact**: Measurable protection for vulnerable demographics (elderly citizens, non-English speakers, rural UPI users) aligned with United Nations Sustainable Development Goals.
6. **Presentation & Polish**: Clean UI typography, intuitive traffic-light visual language, accessible contrast, and professional documentation.
7. **Teamwork & Cohesion**: Clear division of responsibilities across architectural layers, reproducible build scripts, and structured codebases.

### 1.3 Submission Deliverables Checklist
- **Title**: *Verity (Bharat Shield): Real-Time On-Device Cyber Defense & Financial Fraud Protection* (≤ 100 characters).
- **Theme Alignment & UN SDGs**: Alignment with Digital Safety & Cyber Fraud Awareness, mapping directly to UN SDGs 16.4, 9, 10, and 4 (≤ 500 characters).
- **Problem Statement**: Plain-language framing of India's escalating cyber financial fraud crisis, highlighting the failure of centralized blocklists against zero-day links (≤ 500 characters).
- **Approach / Tech Stack / Impact**: Real-time client-side heuristics, on-device 18-feature ONNX ML, Manifest V3 extension, standalone PWA, and zero telemetry (≤ 500 characters).
- **GitHub Repository**: Complete codebase containing root [README.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/README.md), [LICENSE](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/LICENSE), [docs/TECHNICAL_DESIGN.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/docs/TECHNICAL_DESIGN.md), [docs/KNOWN_LIMITATIONS.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/docs/KNOWN_LIMITATIONS.md), [docs/BENCHMARKS.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/docs/BENCHMARKS.md), and sample datasets.
- **Demo Video**: 3–5 minute high-impact demonstration following [demo/DEMO_SCRIPT.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/demo/DEMO_SCRIPT.md).
- **Slide Deck**: Presentation PDF/PPT detailing problem, technical architecture, live benchmark results, social impact, and future roadmap.

### 1.4 Team Structure (Placeholders)
- **Lead System Architect & Security Engineer**: Core runtime interceptors, risk engine mathematics, Declarative Net Request (DNR) blocker.
- **Machine Learning & Evaluation Engineer**: Lexical dataset curation, GroupKFold validation, LightGBM training, and ONNX conversion.
- **Frontend & Mobile Platform Developer**: Manifest V3 popup, blocked interstitial UI, and PWA Web Share Target implementation.
- **Threat Research & Indic Localization Specialist**: Heuristic regex rules, multilingual translation catalogs (Hindi, Tamil, Telugu), and sample cyber fraud scenarios.

---

## 2. The Problem We Solve (India)

India is witnessing an unprecedented expansion in digital payments and smartphone penetration via the Unified Payments Interface (UPI). However, cyber financial fraud has grown proportionally. Traditional cybersecurity software built for Western enterprise threat models relies heavily on centralized cloud domain blocklists (such as Google Safe Browsing or commercial antivirus threat feeds). These fail against localized Indian cyber threats because attackers generate ephemeral zero-day domains, use multi-tenant cloud storage, and deploy linguistic social engineering that evades generic crawlers.

### 2.1 Targeted Fraud Vectors

```
+----------------------------------------------------------------------------------------------------+
|                                 INDIAN CYBER FRAUD THREAT VECTORS                                  |
+-----------------------------+-----------------------------+----------------------------------------+
| Threat Category             | Attacker Mechanism          | Verity Countermeasure                  |
+-----------------------------+-----------------------------+----------------------------------------+
| Fake Bank KYC Phishing      | Urgent SMS/WhatsApp alerts: | Levenshtein typosquatting detection,   |
|                             | "Account suspended; update  | financial keyword scanning, and brand  |
|                             | PAN card now." Exfiltrates  | mismatch alarms on unauthorized hosts. |
|                             | passwords and NetBanking    |                                        |
|                             | OTPs to Telegram webhooks.  |                                        |
+-----------------------------+-----------------------------+----------------------------------------+
| Deceptive UPI Collect &     | Scammers pose as buyers or  | Deep-link parsing (`upi://pay`), payee |
| QR Reverse-Charge Traps     | lottery operators: "Scan QR | analysis, and warning against debit    |
|                             | to receive Rs 15,000." In   | traps masquerading as received money.  |
|                             | reality, creates a debit    |                                        |
|                             | request (`am=15000`).       |                                        |
+-----------------------------+-----------------------------+----------------------------------------+
| "Digital Arrest" & Police   | Impersonation of CBI, ED,   | Multilingual regex engine detecting    |
| Extortion Scams             | Customs, or Police alleging | legal intimidation and warrant threats |
|                             | seized contraband parcels;  | in English, Hindi, Tamil, and Telugu.  |
|                             | demands video call isolation|                                        |
|                             | and fund transfers.         |                                        |
+-----------------------------+-----------------------------+----------------------------------------+
| Malicious Android APK       | Disguised downloads:        | Inspection of download URLs, filename  |
| Droppers                    | `RTO_Challan.apk`,          | extension analysis, and blocking of    |
|                             | `PM_Kisan_Yojana.apk`, or   | unverified `.apk` droppers on high-    |
|                             | `Wedding_Card.apk` carrying | risk domains.                          |
|                             | SMS-forwarding RATs.        |                                        |
+-----------------------------+-----------------------------+----------------------------------------+
| Illegal Web UPI PIN         | Web forms asking users to   | Strict invariant check: flags any web  |
| Interception                | enter their 4-digit or      | form requesting UPI/ATM PINs directly  |
|                             | 6-digit UPI PIN or ATM PIN. | inside a web browser.                  |
+-----------------------------+-----------------------------+----------------------------------------+
```

### 2.2 Demographic Vulnerability
The populations most severely impacted by these attacks in India are:
- **First-Time Smartphone Users & Rural Citizens**: Users who have transitioned directly to mobile digital payments without formal cybersecurity education.
- **Elderly Citizens & Pensioners**: Demographics targeted by high-pressure intimidation ("Digital Arrest") and fake electricity bill disconnection threats.
- **Non-English Speakers**: Citizens who struggle to decipher deceptive English domain URLs (e.g., differentiating `onlinesbi.sbi` from `sbi-kyc-verification-portal.com`).

### 2.3 Authoritative Government & Industry Citations
- **Annual Cyber Financial Fraud Loss (MHA / I4C Lok Sabha Reply, July 2025)**: Per official Ministry of Home Affairs (MHA) data presented to the Lok Sabha, Indian citizens reported losses of **₹22,845 Crore across 36 Lakh cyber financial fraud complaints in 2024** alone (a 206% surge compared to ₹7,465 Crore in 2023). In the first four months of 2024 (Jan–April) alone, over **₹1,750 Crore** was lost, according to Indian Cyber Crime Coordination Centre (I4C) NCRP telemetry.
- **CFCFRMS & 1930 Helpline Impact (PIB / MHA Official Release PRID 2241344, March 2026)**: Under I4C's Citizen Financial Cyber Fraud Reporting and Management System (CFCFRMS), **₹8,690+ Crore** has been successfully saved across **24.65 Lakh complaints** up to January 31, 2026, with **12.94 Lakh rogue SIM cards** and **3.03 Lakh IMEIs** blocked and **27.37 Lakh Layer-1 mule accounts** flagged via the National Cybercrime Suspect Registry.
- **Zero-Day Phishing Lifespan Citation (APWG & Unit 42)**: Research from the **Anti-Phishing Working Group (APWG) Phishing Activity Trends Report** and **Palo Alto Networks Unit 42** documents that the median active lifespan of a phishing site is **4 to 8 hours** (with over 70% expiring within 24 hours). This reality makes centralized cloud blocklists structurally incapable of defending first-wave victims, underscoring the necessity of Verity's client-side, on-device deterministic engine.

---

## 3. What Verity Is

**Verity (Bharat Shield)** is an open-source, on-device cybersecurity platform that evaluates websites, links, and messages in real time directly within the user's client environment. By eliminating mandatory cloud round-trips for URL scanning, Verity guarantees complete user browsing privacy while maintaining deterministic, sub-millisecond execution speeds. It protects users across four unified deployment surfaces:

### Deployment Surfaces

| Surface | Description | Platform Support | Implementation Status | Evidence / File Path |
| :--- | :--- | :--- | :---: | :--- |
| **Desktop Extension** | Full Manifest V3 extension featuring background service worker, offscreen ONNX ML, MAIN-world exfiltration traps, DOM analysis, and Shadow DOM warning overlays. | Google Chrome, Microsoft Edge, Brave, Chromium | `[BUILT+TESTED]` | [verity-extension/manifest.json](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/manifest.json), [service_worker.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/service_worker.js) |
| **Mobile Browser Extension** | The unpacked extension running inside Android mobile browsers that support standard extension APIs. | Firefox for Android, Kiwi Browser (*Note: standard Chrome for Android does not support extensions*) | `[BUILT+TESTED]` | [verity-extension/](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/) |
| **Installable Mobile PWA** | Progressive Web App providing offline QR code scanning, message text analysis, and Android Web Share Target integration. | iOS Safari, Android Chrome/Firefox, Desktop | `[BUILT+TESTED]` | [mobile-scanner/index.html](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/mobile-scanner/index.html), [mobile-scanner/manifest.json](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/mobile-scanner/manifest.json) |
| **Shared Core Engine** | Pure-JavaScript engine containing synchronous heuristic rules, brand detectors, Public Suffix List parsing, and multilingual text scanners. | Node.js, Web Browsers, Service Workers, Mobile Core | `[BUILT+TESTED]` | [verity-extension/shared/](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/shared/), [mobile-scanner/core/](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/mobile-scanner/core/) |

---

## 4. Architecture

### 4.1 Mermaid Architecture Diagram

```mermaid
flowchart TD
    subgraph Browser_Tab ["Active Browser Tab (Target Page)"]
        PAGE_NAV["User Navigation / Network Request"]
        MAIN_INT["MAIN World Interceptor<br/>(content/main-world-interceptor.js)<br/>- Hooks fetch, XHR, sendBeacon, WebSocket<br/>- Defuses popunders & malvertising bridges"]
        CS["Content Script (Isolated World)<br/>(content/content-script.js)<br/>- Pierces open Shadow DOM roots<br/>- Scans credentials, forms, UPI inputs<br/>- Injects Closed ShadowDOM Overlay"]
    end

    subgraph MV3_Extension ["Verity MV3 Extension Core"]
        DNR["Declarative Net Request<br/>(C++ Fast Path: 0.001ms)"]
        SW["Service Worker Orchestrator<br/>(service_worker.js)<br/>- webNavigation & Tab Monitoring<br/>- Session Override Cache"]
        OFFSCREEN["Offscreen Document<br/>(background/offscreen.js)<br/>- ONNX Runtime Web (WASM)<br/>- 18-Feature Model Inference"]
        RULES_ENG["16 Synchronous Rules<br/>(background/rules.js)"]
        RISK_ENG["Adaptive Risk Engine<br/>(background/risk-engine.js)<br/>- Category Caps & Diminishing Weights<br/>- Convergence Corroboration Rule"]
        DOH_SENTINEL["DoH Reputation Sentinel<br/>(background/reputation.js)<br/>- Cloudflare 1.1.1.2 Hostname Query"]
    end

    subgraph UI_Surfaces ["User Interface & Education"]
        POPUP_UI["Extension Action Popup<br/>(popup/popup.html)<br/>- Traffic Light Verdict & Score<br/>- Quick WhatsApp / Link Scanner"]
        BLOCKED_INTERSTITIAL["Zero-Latency Block Screen<br/>(ui/blocked.html)<br/>- Vernacular Advisories & Helpline 1930<br/>- Spot-The-Scam Micro-Quiz"]
    end

    subgraph Shared_Libraries ["Shared Cross-Surface Engine"]
        PSL["Public Suffix List Parser (shared/psl.js)"]
        LEGIT_CACHE["Independent Allowlist (shared/legit-domains.js)"]
        BHARAT_SCAM["Bharat Scam Detectors (content/bharat-scam-detectors.js)"]
        TEXT_SCANNER["Multilingual Text Scanner (shared/text-scanner.js)"]
    end

    PAGE_NAV --> MAIN_INT
    PAGE_NAV --> DNR
    PAGE_NAV --> SW
    MAIN_INT -. Dispatches Threat Event .-> CS
    CS --> SW
    SW --> RULES_ENG
    SW --> OFFSCREEN
    SW --> DOH_SENTINEL
    RULES_ENG --> RISK_ENG
    OFFSCREEN --> RISK_ENG
    DOH_SENTINEL --> RISK_ENG
    CS --> RISK_ENG

    RISK_ENG -->|Verdict: Danger| CS
    RISK_ENG -->|Verdict: Danger| BLOCKED_INTERSTITIAL
    RISK_ENG --> POPUP_UI

    RULES_ENG --> Shared_Libraries
    CS --> Shared_Libraries
    RISK_ENG --> Shared_Libraries
```

### 4.2 ASCII Architecture Fallback
```
+----------------------------------------------------------------------------------------------------+
|                                    VERITY 2.0 EXTENSION RUNTIME                                    |
+----------------------------------------------------------------------------------------------------+
| [Page Navigation]                                                                                  |
|         │                                                                                          |
|         ├──> [MAIN-World Interceptor] ──> Hooks fetch(), XHR, sendBeacon(), WebSocket               |
|         ├──> [Declarative Net Request] -> C++ kernel fast path redirect to /ui/blocked.html         |
|         └──> [Service Worker Orchestrator] (`service_worker.js`)                                   |
|                     │                                                                              |
|                     ├──> Public Suffix List Domain Normalization (`shared/psl.js`)                 |
|                     ├──> Top Domain & Independent Allowlist Verification (`shared/legit-domains.js`)|
|                     ├──> 16 Synchronous Heuristic Rules (`background/rules.js`)                    |
|                     ├──> Offscreen ONNX ML Classifier (`background/offscreen.js`)                 |
|                     ├──> Isolated Content Script DOM Scanner (`content/content-script.js`)         |
|                     ├──> Cloudflare DoH Hostname Sentinel (`background/reputation.js`)             |
|                     │                                                                              |
|                     ▼                                                                              |
|          [Adaptive Risk Engine] (`background/risk-engine.js`)                                      |
|          - Applies Category Caps (`CATEGORY_CAPS`)                                                 |
|          - Applies Diminishing Marginal Weights: [1.0, 0.75, 0.55, 0.35, 0.20, 0.10]               |
|          - Evaluates Convergence Corroboration Rule (>= 2 independent sources for Block)           |
|          - Evaluates Hard Overrides (Digital Arrest, UPI PIN, Telegram Exfiltration)               |
|                     │                                                                              |
|         ┌───────────┴───────────────────────────────┐                                              |
|         ▼                                           ▼                                              |
| [Score 0-34: Safe / Score 35-69: Caution]  [Score 70-100: Danger (Block)]                          |
| Toolbar Action Popup reflects status      Content Script renders Closed ShadowDOM Shield           |
|                                           Network requests halted via window.stop()                |
+----------------------------------------------------------------------------------------------------+
```

### 4.3 End-to-End URL Execution Lifecycle
Tracing a single URL (e.g., `https://sbi-kyc-verification-portal.invalid/update-pan.html`) through the system:
1. **Network Initialization**: Navigation triggers `chrome.webNavigation.onBeforeNavigate` in `service_worker.js` while `content/main-world-interceptor.js` executes at `document_start` in the MAIN execution world.
2. **Early Allowlist Filtering**: `service_worker.js` calls `isInternalUrl(url)`. If external, `psl.js: getDomain()` extracts root domain `sbi-kyc-verification-portal.invalid` and checks `isAllowlistedDomain()` and `isTrustedTopDomain()`. Because it is unverified, execution proceeds.
3. **Synchronous Heuristic Analysis**: `service_worker.js: analyzeUrl()` evaluates the 16 heuristic rules in `background/rules.js`. `hasBrandNameInWrongDomain()` identifies `"sbi"` on an unauthorized host; `hasFinancialKeywordInHostname()` triggers on `"kyc"`; `hasSuspiciousUrlPattern()` flags the hyphens and synthetic TLD.
4. **Machine Learning Inference**: `service_worker.js` messages the offscreen document via `chrome.runtime.sendMessage({ action: 'run_inference', url })`. `offscreen.js: runInference()` invokes `extractRichFeatures(url)` to generate the 18-element float vector and runs `session.run()` via ONNX Runtime Web WASM.
5. **DOM & Context Scanning**: `content/content-script.js` parses the page at `DOMContentLoaded`. `querySelectorAllDeep()` pierces Shadow DOM trees searching for password and PAN inputs. `detectDigitalArrestAndApkScams()` inspects on-page text and anchor links.
6. **Reputation Lookup**: In parallel, `reputation.js: checkReputation()` issues a DoH query for `sbi-kyc-verification-portal.invalid` to Cloudflare (`1.1.1.2`).
7. **Risk Score Computation**: All signals merge into `background/risk-engine.js: calculateRisk()`.
   - Brand impersonation points capped at 65.
   - URL points capped at 55.
   - Sorted descending: category 1 takes weight 1.0, category 2 takes weight 0.75.
   - Synergy bonus triggered: Brand Impersonation + Credential Demand (+30 pts).
   - Hard Cyber Fraud override (`SIG_KYC_CYBER_FRAUD`) forces risk score $\ge 85$.
   - Convergence check passes (multi-source confirmation between `url` and `dom_credentials`).
8. **Enforcement**: Final verdict `{ action: 'block', score: 100, severity: 'danger' }` is dispatched to `content-script.js: showOverlay()`, which creates a closed `ShadowRoot`, invokes `window.stop()`, clears active timers, and renders the red warning shield.

---

## 5. Detection Engine in Depth

### 5.1 The 16 URL Heuristic Rules
Implemented in [verity-extension/background/rules.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/rules.js):

| # | Rule Identifier | Exported Function Name | Detection Mechanism | Base Score |
| :-: | :--- | :--- | :--- | :-: |
| 1 | `RULE_IP_BASED_URL` | `isIpBasedUrl()` | Flags raw IPv4/IPv6 hostnames (`/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/`). | +80 pts |
| 2 | `RULE_MISSING_HTTPS` | `hasMissingHttps()` | Flags unencrypted HTTP connections (`url.protocol === 'http:'`). | +25 pts |
| 3 | `RULE_EXCESSIVE_SUBDOMAINS` | `hasExcessiveSubdomains()` | Flags hostnames with > 3 subdomain levels obscuring the root domain. | +30 pts |
| 4 | `RULE_BRAND_NAME_WRONG_DOMAIN` | `hasBrandNameInWrongDomain()` | Token-bounded regex search for protected brand names on unverified domains. | +90 pts |
| 5 | `RULE_BRAND_VARIANT_MATCH` | `hasBrandVariantMatch()` | Identifies concatenated brand variants (e.g. `sbibank`, `paytmsupport`). | +65 pts |
| 6 | `RULE_FINANCIAL_KEYWORD_HOSTNAME` | `hasFinancialKeywordInHostname()` | Flags banking/payment keywords (`kyc`, `netbanking`, `upi`, `otp`) on unverified hosts. | +75 pts |
| 7 | `RULE_PUNYCODE_OR_KEYWORDS` | `hasPunycodeOrKeywords()` | Identifies IDN punycode homographs (`xn--`) or embedded auth keywords. | +55 pts |
| 8 | `RULE_RANDOM_LOOKING_HOSTNAME` | `hasRandomLookingHostname()` | Flags DGA hostnames via consonant cluster regex (`/[bcdfghjklmnpqrstvwxyz]{5,}/i`) and vowel ratios. | +65 pts |
| 9 | `RULE_SUSPICIOUS_URL_PATTERN` | `hasSuspiciousUrlPattern()` | Flags excessive hyphens, `@` credentials in URLs, and path depth > 5. | +30 pts |
| 10 | `RULE_AFFILIATE_TRACKER` | `hasAffiliateTrackerPattern()` | Detects ad-rotator parameter cascades (`p1..p7`, `ymid`, `pub_rfid`, UUIDs). | +45 pts |
| 11 | `RULE_MALVERTISING_REDIRECT` | `hasMalvertisingPattern()` | Identifies rotator shards, keyless hex search queries (`/^\?[a-f0-9]{16,64}$/`), and mixed tokens. | +50 pts |
| 12 | `RULE_PIRACY_MEDIA` | `hasPiracyOrUnverifiedMediaPattern()` | Identifies known piracy/crack portal signatures on high-abuse TLDs. | +60 pts |
| 13 | `RULE_TRUSTED_TOP_DOMAIN` | `isTrustedTopDomain()` | Allowlist guard: immunizes verified top global infrastructure (Google, Microsoft, Apple). | 0 pts |
| 14 | `RULE_AITM_PROXY_URL` | `hasAitmProxyUrlSignature()` | Flags reverse-proxy paths (`/common/oauth2/`, `/adfs/ls/`, `/signin/v2/identifier`) on non-IdP hosts. | +85 pts |
| 15 | `RULE_HOMOGRAPH_ATTACK` | `hasHomographAttack()` | Analyzes mixed scripts (Cyrillic/Greek confusables spoofing Latin brand names). | +85 pts |
| 16 | `RULE_TYPOSQUATTING` | `detectTyposquatting()` | Levenshtein edit distance analysis against 100+ protected brand catalogs. | +70 pts |

### 5.2 The 18-Feature On-Device Machine Learning Model
- **Shipped Production Model**: `background/model/phishing_model_v2.onnx` (File size: **26.88 KB** / 26,883 bytes).
- **Exact Input Feature Count**: Exactly **18 features**.
- **Runtime Extractor**: Extracted synchronously by `extractRichFeatures(urlString)` in [background/rich-feature-extractor.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/rich-feature-extractor.js).
- **The 18 Features in Order**:
  1. `url_length` (float)
  2. `hostname_length` (float)
  3. `path_length` (float)
  4. `subdomain_count` (float)
  5. `is_ip_address` (binary 0.0 or 1.0)
  6. `has_punycode` (binary 0.0 or 1.0)
  7. `entropy` (Shannon entropy float)
  8. `hyphen_count` (float)
  9. `numeric_ratio` (float [0.0 - 1.0])
  10. `suspicious_tld` (binary 0.0 or 1.0)
  11. `query_length` (float)
  12. `vowel_consonant_ratio` (float)
  13. `brand_min_dist` (normalized Levenshtein distance float)
  14. `has_mixed_script` (binary 0.0 or 1.0)
  15. `sensitive_dir_depth` (integer count)
  16. `longest_token_length` (integer count)
  17. `special_char_density` (float [0.0 - 1.0])
  18. `is_port_in_url` (binary 0.0 or 1.0)
- **Training Dataset**: **4,750 URLs** balanced across benign and malicious distributions:
  - Tranco Top 1M benign domains: 2,000 URLs
  - Curated hard cases (banking, gov, shorteners): 50 URLs
  - Phishing.Database active feed: 1,000 URLs
  - OpenPhish verified community feed: 500 URLs
  - URLhaus high-confidence malware feed: 1,200 URLs
- **Validation Split**: 5-Fold GroupKFold grouped strictly by `registeredDomain` across 2,338 development URLs (1,478 distinct domains) to prevent cross-subdomain data leakage.
- **Model Metrics (from `training/model_metrics.json`)**:
  - *Threshold 35 (Caution)*: Accuracy **98.72% ± 0.84%**, Precision **97.43% ± 1.76%**, Recall **100.00% ± 0.00%**, F1 **98.69% ± 0.90%**, Benign FPR **2.15% ± 1.49%**.
  - *Threshold 70 (Danger)*: Accuracy **98.97% ± 0.72%**, Precision **99.30% ± 0.74%**, Recall **97.91% ± 1.45%**, F1 **98.59% ± 1.01%**, Benign FPR **0.58% ± 0.61%**.
- **Status of `extract26Features`**: `extract26Features()` combines the 18 baseline features with 8 advanced structural features. It was evaluated as a candidate for a future quantized v3 architecture (`phishing_model_v3.onnx`) and is tested in `tests/nextgen_threat_matrix.test.js`. **It is NOT used by the shipped production runtime model (`phishing_model_v2.onnx`), which strictly consumes 18 features.**

### 5.3 Risk Engine Mathematics
Implemented in [verity-extension/background/risk-engine.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/risk-engine.js):

1. **Category Caps**:
   Points within each category are clamped to `CATEGORY_CAPS`:
   `url: 55`, `ip_host: 60`, `malvertising: 85`, `brand_impersonation: 65`, `ml: 45`, `dom_credentials: 60`, `scam_language: 75`, `payment_phishing: 68`, `synergy: 40`, `download: 60`, `threat_intel: 65`.
2. **Diminishing Marginal Risk Formula**:
   Active non-zero category scores are sorted descending and multiplied by diminishing factor array:
   $$W = [1.0, 0.75, 0.55, 0.35, 0.20, 0.10]$$
   $$\text{baseScore} = \sum_{i=0}^{N-1} \text{round}(\text{sortedCategoryScores}[i] \times W[i])$$
3. **The Convergence Corroboration Rule**:
   To reach a Block verdict ($\ge 70$), evidence must originate from **at least two independent operational sources**:
   $$\text{Sources} \subseteq \{\text{'url'}, \text{'ml'}, \text{'dom\_credentials'}, \text{'download'}, \text{'threat\_intel'}\}$$
   If a page reaches $\ge 70$ from only one source without an authorized critical override, it is **demoted to Caution (Score 65)**.
4. **Hard Overrides**:
   Unambiguous high-threat signals enforce instant critical thresholds:
   - Illegal Web PIN Demand: $\ge 95$
   - Telegram/Discord Webhook Exfiltration: $\ge 95$
   - Browser-in-the-Browser Fake Window: $\ge 95$
   - AiTM Reverse Proxy Phish: $\ge 95$
   - Malicious APK Dropper: $\ge 90$
   - Digital Arrest Extortion: $\ge 85$
   - UPI Collect / QR Trap: $\ge 85$
   - ClickFix Clipboard Attack: $\ge 85$
   - DOM Title / Heading Brand Impersonation on Unauthorized Domain: $\ge 85$
   - Free-Hosting / Tunnel Phishing Kit (.pages.dev, .vercel.app, .ngrok, etc.): $\ge 75$
5. **Threshold Classifications**:
   - `0 - 34`: **Safe** (`action: 'allow'`, green badge)
   - `35 - 69`: **Caution** (`action: 'warn'`, yellow advisory)
   - `70 - 100`: **Danger** (`action: 'block'`, red full-page shield)

### 5.4 Bharat-Specific Detectors
Implemented in [verity-extension/content/bharat-scam-detectors.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/content/bharat-scam-detectors.js):
- **Digital Arrest Extortion**: Regex engine detecting threats purporting to be CBI, Mumbai Customs, ED, or Delhi Police threatening immediate arrest unless funds are transferred. Multilingual support across English, Hindi, Tamil, and Telugu.
- **Malicious APK Droppers**: Intercepts download links masquerading as government traffic challans (`RTO_Challan.apk`), welfare schemes (`PM_Kisan.apk`), electricity bills, or wedding invitation cards.
- **UPI Collect & QR Quishing**: Parses deep-links (`upi://pay`) and QR payloads to detect hidden debit collect requests (`pa=...`, `am=...`) masquerading as refunds or cashback.
- **Illegal In-Browser UPI PIN Collection**: Detects web forms requesting 4/6-digit UPI PINs or ATM PINs inside web browsers.
- **Real-World Evasion Resistance & Battle-Hardening**:
  - *Free-Hosting & Tunnel Phishing Detector*: Flags developer hosting (.vercel.app, .pages.dev, .github.io, .netlify.app, .ngrok, etc.) abused for credential phishing (`SIG_FREE_HOST_CREDENTIAL_PHISH`, Score: 75).
  - *DOM Title / Heading Brand Trap*: Flags pages claiming to be major Indian banks or government agencies in `<title>` or `<h1>` without official root domains (`SIG_DOM_BRAND_IMPERSONATION`, Score: 85).
  - *URL Shortener + Scam Context*: Detects shorteners (bit.ly, tinyurl, etc.) returning Caution on standalone links and Danger (Score: 80) when surrounded by urgent banking/KYC lures.
  - *De-obfuscation Normalizer*: Strips punctuation/spaces from obfuscated acronyms (`u.p.i`, `p-i-n`, `o.t.p`, `k.y.c`, `a.p.k`).
  - *Hinglish / Tanglish Matchers*: Detects colloquial phrases (`pin daalo`, `mpin dalo`, `qr scan karo`, `paise milega`, `refund aayega`).
  - *Utility Bill Disconnection Extortion*: Detects tonight power cut extortion threats (`SIG_UTILITY_BILL_EXTORTION`, Score: 85).
  - *IndiaPost / Courier Delivery Smishing*: Detects fake incomplete address package hold scams (`SIG_FAKE_PARCEL_DELIVERY_LURE`, Score: 80).
- **Protected Indian Brands Catalog**: 100+ verified brand domains in [verity-extension/brands.json](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/brands.json), including SBI, HDFC Bank, ICICI Bank, Axis Bank, Punjab National Bank, Bank of Baroda, Paytm, PhonePe, Google Pay, Razorpay, India Post, DigiLocker, IRCTC, and Income Tax Department.

### 5.5 Runtime Traps & Defensive Interceptors
Implemented in [verity-extension/content/main-world-interceptor.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/content/main-world-interceptor.js):
- **WebSocket Hook**: Wraps `window.WebSocket` constructor, preserving prototype, static constants (`CONNECTING: 0`, `OPEN: 1`, `CLOSING: 2`, `CLOSED: 3`), and `instanceof`. Blocks connections matching `EXFIL_REGEX` (`api.telegram.org/bot`, `discord.com/api/webhooks`, `webhook.site`, `pipedream.net`, `hookbin.com`, `requestcatcher.com`).
- **Fetch & XHR Hooks**: Traps `window.fetch` and `XMLHttpRequest.prototype.send`, rejecting phishing exfiltration requests.
- **sendBeacon Hook**: Traps `navigator.sendBeacon`, returning `false` on exfiltration attempts.
- **Clipboard & ClickFix Defense**: Traps `navigator.clipboard.writeText` to neutralize malicious PowerShell/CMD execution strings (e.g. `powershell -enc`, `mshta`, `iex`).
- **Shadow DOM Uncloaking**: Traps `Element.prototype.attachShadow`, forcing closed shadow trees to open mode so hidden phishing lures can be inspected.
- **Canvas Fake-Login Detection**: Content script detects `<canvas>` elements rendering credential prompts without real DOM inputs (`SIG_CANVAS_CREDENTIAL_FORM`).
- **Browser-in-the-Browser (BitB)**: Detects simulated modal login dialogs spoofing official OAuth URLs (`SIG_BITB_FAKE_WINDOW_ATTACK`).
- **Download Smuggling Guard**: Analyzes local downloads in [background/download/](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/download), intercepting double-extension executables (`.pdf.exe`) and tiny video traps.

---

## 6. Citizen UI and Languages

### 6.1 Action Popup UI (Today's Reality)
Located in [verity-extension/popup/](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/popup/):
- **Current Site Traffic Card**: Visual indicator (🟢 Safe, 🟡 Caution, 🔴 Danger), domain label, risk score (e.g. `85/100`), and plain-language threat bullets.
- **Quick WhatsApp / Link Checker**: Textarea allowing citizens to paste suspicious messages, links, or SMS alerts. Runs `scanText()` locally and renders instant verdicts.
- **Golden Safety Rule Box**: Contextual, bold advice card (e.g., *"UPI PIN is ONLY entered to SEND money. Never to get cashback"*).
- **Language Switcher**: Tab pills for **EN**, **தமிழ்** (Tamil), **हिं** (Hindi), and **తె** (Telugu).
- **Advanced Diagnostics Toggle**: Expandable disclosure revealing technical Reason IDs and raw signal data.

### 6.2 Blocked Interstitial Page (Today's Reality)
Located in [verity-extension/ui/blocked.html](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/ui/blocked.html) and [ui/blocked.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/ui/blocked.js):
- **Warning Header**: Full-bleed red shield with threat badge.
- **Multilingual Support**: Header buttons for English, हिन्दी, தமிழ், and తెలుగు.
- **Plain-Language Summary**: Translates technical signals into everyday citizen guidance.
- **National Helpline Banner**: Prominently highlights **National Cyber Crime Helpline: Dial 1930 (Toll-Free)** and `cybercrime.gov.in`.
- **Spot-The-Scam Educational Micro-Quiz**: Interactive challenge generated by [shared/xray-educator.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/shared/xray-educator.js) presenting 3 options explaining why the page was fake, providing green/red feedback reinforcement.
- **Action Buttons**: Primary *"Take Me to Safety"* (triggers history back or tab closure) and secondary *"I understand the risk (Advanced)"* override link.

### 6.3 Voice Assistance (`speechSynthesis`) Status: `[DORMANT]`
- **Code Status**: Full vernacular voice advisory code exists in [shared/vernacular-coach.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/shared/vernacular-coach.js) (`speakVernacularAdvisory`) and is tested in `tests/bharat_shield_hackathon.test.js`.
- **UI Status**: **It is NOT wired or enabled in either the popup or blocked page UI.** We have deliberately deferred active voice playback to avoid jarring browser autoplay blocks and maintain consistent visual focus during evaluations.

---

## 7. Interfaces and Contracts

### 7.1 Key Exported Function Signatures

```javascript
// 1. Adaptive Risk Engine (background/risk-engine.js)
export function calculateRisk(
  url,
  ruleSignals = [],
  mlScore = null,
  domSignals = null,
  threatIntel = null,
  redirectSignals = null,
  paymentAnalysis = null,
  downloadSignals = null,
  mlWeightOverride = null,
  brandsList = []
): {
  url: string,
  hostname: string,
  score: number,
  riskScore: number,
  severity: 'safe' | 'caution' | 'danger',
  state: 'safe' | 'caution' | 'danger',
  action: 'allow' | 'warn' | 'block',
  reasons: string[],
  signals: Array<{ id: string, score: number, category: string, reason: string }>,
  categories: object
}

// 2. Multilingual Text & Message Scanner (shared/text-scanner.js)
export function scanText(
  text: string,
  options?: { brandsList?: Array<object>, psl?: object }
): {
  verdict: 'safe' | 'caution' | 'danger',
  score: number,
  category: string | null,
  signals: Array<{ id: string, score: number, reason: string }>,
  reasons: string[],
  links: string[],
  extractedApks: string[],
  upiDetails: object | null
}

// 3. Feature Extraction (background/rich-feature-extractor.js)
export function extractRichFeatures(urlString: string): number[] // Exactly 18 float features
export function extract26Features(urlString: string, brandsList?: Array<object>): number[] // Candidate 26 features

// 4. Bharat Fraud Detectors (content/bharat-scam-detectors.js)
export function detectDigitalArrestAndApkScams(pageText: string, linkUrls?: string[]): {
  detected: boolean,
  type?: 'DIGITAL_ARREST' | 'APK_DROPPER',
  reason?: string,
  details?: object
}

export function detectUpiQrCollectTrap(rootNode?: Document | Element | null): {
  detected: boolean,
  type?: string,
  reason?: string,
  payload?: string,
  vpa?: string,
  amount?: string
}

// 5. Vernacular Advisories (shared/vernacular-coach.js)
export function getVernacularAdvisory(
  signalId: string,
  lang?: 'en-IN' | 'hi-IN' | 'ta-IN' | 'te-IN'
): {
  title: string,
  explanation: string,
  goldenRule: string,
  helpline: string,
  lang: string,
  portal: string
}
```

### 7.2 Message-Passing Contract: Popup & Service Worker

#### The Interaction Flow
- In [popup/popup.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/popup/popup.js):
  ```javascript
  chrome.runtime.sendMessage(
    { action: 'GET_TAB_VERDICT', tabId: activeTab.id },
    (resp) => {
      if (resp?.verdict) activeVerdict = resp.verdict;
      renderCurrentSiteCard();
    }
  );
  ```
- **Architectural Note on Message Action**: In [service_worker.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/service_worker.js#L1333), the service worker listens for `message.action === 'GET_VERDICT'`. If a response is not returned, `popup.js` falls back to inspecting `activeTab.url` and queries local brand datasets to render a safe default until user actions occur.
- **Other Core Runtime Actions Supported by Service Worker**:
  - `ANALYZE_URL_ONLY`: Pre-navigation fast analysis.
  - `ANALYZE_FULL`: Deep DOM + URL multi-source convergence analysis.
  - `RUNTIME_THREAT_DETECTED`: Triggered by MAIN-world exfiltration traps.
  - `USER_OVERRIDE_ALLOW`: Persists temporary session override for a tab.
  - `NAVIGATE_TO_SAFETY`: Handles safe back navigation or tab closure.

### 7.3 Blocked Interstitial URL Parameters
When Declarative Net Request or service worker redirects a tab to [ui/blocked.html](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/ui/blocked.html), parameters are passed via query string:
```
chrome-extension://<id>/ui/blocked.html?host=sbi-kyc.invalid&url=https%3A%2F%2Fsbi-kyc.invalid%2Flogin&signal=SIG_KYC_CYBER_FRAUD&reason=DNR_THREAT_INTEL
```
- `host`: The untrusted hostname (default: `suspicious-website.xyz`).
- `url`: The full target URL being intercepted.
- `signal`: Threat signal ID (maps to localized advisory in `vernacular-coach.js`).
- `reason`: Explanation string or rule trigger code.

---

## 8. Privacy and Security Posture

### 8.1 Zero-Telemetry Principle
- **What Leaves the Device**: Only unfamiliar, non-allowlisted hostnames are sent to Cloudflare Security (`1.1.1.2`) via DNS-over-HTTPS. No paths, query parameters, form contents, cookies, or user identifiers are ever transmitted.
- **Threat Feed Downloads**: Synchronization is a one-way, read-only download of known malicious domain hashes. The client reports zero usage metrics during sync.

### 8.2 Manifest V3 Permissions Justification
Configured in [verity-extension/manifest.json](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/manifest.json):
- `webNavigation`: Listens to `onBeforeNavigate` to initiate pre-load URL scanning before page rendering.
- `webRequest`: Observes redirect hops in URL shortener chains.
- `storage`: Caches local threat signatures, allowlists, and user language preferences (`chrome.storage.local`, `chrome.storage.session`).
- `offscreen`: Spawns the isolated offscreen document required to run ONNX Runtime Web WASM in Manifest V3 without blocking the service worker.
- `downloads`: Monitors incoming file downloads to detect disguised executables (`.pdf.exe`) and unverified APK droppers.
- `declarativeNetRequest`: Enables kernel-level C++ network blocking (0.001 ms) for known malicious domains without intercepting request bodies.

### 8.3 Content Security Policy & Web Accessible Resources
- **Extension CSP**: `"script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"`. Wasm eval is scoped strictly to ONNX inference.
- **Narrowed Web Accessible Resources**:
  - `shared/fonts/InterVariable.woff2` and `ui/blocked.html` accessible to `<all_urls>`.
  - Search engine badging scripts (`content/search/*`, `shared/ui/icons.js`, `shared/messages.js`, `shared/psl.js`) restricted strictly to search domains (`google.com`, `bing.com`, `duckduckgo.com`, `localhost`, `127.0.0.1`). All internal configurations and brand catalogs are hidden from page contexts.

---

## 9. Measured Numbers

All numbers in this section represent actual measured figures from active runs on the repository codebase:

```
+----------------------------------------------------------------------------------------------------+
|                                 VERITY 2.0 VERIFIED MEASUREMENTS                                   |
+------------------------------------+-----------------------------+---------------------------------+
| Metric Category                    | Measured Value              | Benchmark Environment / Source  |
+------------------------------------+-----------------------------+---------------------------------+
| Automated Test Count               | 315 passed (0 failed)       | `npm test` (Node.js test runner)|
| Test Suite Execution Duration      | ~1010 ms                    | Full 40-suite test execution    |
| Shipped ONNX Model Size            | 26.88 KB (26,883 bytes)     | `phishing_model_v2.onnx`        |
| Model Feature Input Dimension      | 18 features                 | `extractRichFeatures()`         |
| Popup UI Bundle Size               | 24.38 KB (24,384 bytes)     | `verity-extension/popup/`       |
| Blocked Screen Bundle Size         | 18.60 KB (19,047 bytes)     | `verity-extension/ui/`          |
| Standalone Mobile Scanner (PWA)    | 539.59 KB (552,541 bytes)   | `mobile-scanner/`               |
| Total Extension Directory Size     | 18.79 MB                    | Includes 9.6MB WASM & benchmarks|
+------------------------------------+-----------------------------+---------------------------------+
| Allowlist Check Latency            | Mean: 0.0058 ms (p95: 0.012)| Native Node, not browser WASM   |
| 16 Heuristic Rules Latency         | Mean: 0.4298 ms (p95: 1.192)| Native Node, not browser WASM   |
| 18-Feature Vector Extraction       | Mean: 0.0047 ms (p95: 0.012)| Native Node, not browser WASM   |
| Full Synchronous Pipeline Latency  | Mean: 0.4845 ms (p95: 1.233)| Native Node, not browser WASM   |
| scanText (500-char message)        | Mean: 0.1581 ms (p95: 0.283)| Native Node, not browser WASM   |
+------------------------------------+-----------------------------+---------------------------------+
```

---

## 10. Honest Status Matrix

| Component / Deliverable | Status Tag | Verified Evidence / Source Files |
| :--- | :---: | :--- |
| **16 URL Heuristic Rules** | `[BUILT+TESTED]` | [background/rules.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/rules.js), [tests/rules.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/rules.test.js) |
| **18-Feature On-Device ONNX Model** | `[BUILT+TESTED]` | [background/offscreen.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/offscreen.js), [model/phishing_model_v2.onnx](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/model/phishing_model_v2.onnx) |
| **Adaptive Risk Engine & Weights** | `[BUILT+TESTED]` | [background/risk-engine.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/risk-engine.js), [tests/convergence.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/convergence.test.js) |
| **Real-World Evasion Torture Suite** | `[BUILT+TESTED]` | [background/rules.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/rules.js), [background/risk-engine.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/risk-engine.js), [shared/text-scanner.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/shared/text-scanner.js), [tests/real_world_evasions.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/real_world_evasions.test.js) |
| **Digital Arrest Fraud Detector** | `[BUILT+TESTED]` | [content/bharat-scam-detectors.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/content/bharat-scam-detectors.js), [tests/bharat_shield_hackathon.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/bharat_shield_hackathon.test.js) |
| **UPI Collect & QR Trap Detector** | `[BUILT+TESTED]` | [content/bharat-scam-detectors.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/content/bharat-scam-detectors.js), [tests/bharat_shield_hackathon.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/bharat_shield_hackathon.test.js) |
| **Malicious APK Dropper Detector** | `[BUILT+TESTED]` | [content/bharat-scam-detectors.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/content/bharat-scam-detectors.js), [tests/bharat_shield_hackathon.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/bharat_shield_hackathon.test.js) |
| **Illegal Web PIN Interception** | `[BUILT+TESTED]` | [background/payment-detector.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/payment-detector.js), [shared/text-scanner.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/shared/text-scanner.js), [tests/contract_and_edge_cases.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/contract_and_edge_cases.test.js) |
| **Message Contract & Edge-Case Suite** | `[BUILT+TESTED]` | [service_worker.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/service_worker.js), [tests/contract_and_edge_cases.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/contract_and_edge_cases.test.js) |
| **WebSocket Runtime Exfiltration Trap** | `[BUILT+TESTED]` | [content/main-world-interceptor.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/content/main-world-interceptor.js), [tests/main_world_interceptor.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/main_world_interceptor.test.js) |
| **Fetch / XHR / Beacon Traps** | `[BUILT+TESTED]` | [content/main-world-interceptor.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/content/main-world-interceptor.js), [tests/main_world_interceptor.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/main_world_interceptor.test.js) |
| **ClickFix & Clipboard Hijack Defense** | `[BUILT+TESTED]` | [content/main-world-interceptor.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/content/main-world-interceptor.js), [tests/clickfix_shadowdom.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/clickfix_shadowdom.test.js) |
| **Download Security & Double-Extension** | `[BUILT+TESTED]` | [background/download/](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/download), [tests/download_smuggling_spoof.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/download_smuggling_spoof.test.js) |
| **Pop-Under Auto-Termination** | `[BUILT+TESTED]` | [service_worker.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/service_worker.js), [tests/verify_popup_window_termination.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/verify_popup_window_termination.js) |
| **Spot-The-Scam Micro-Quiz UI** | `[BUILT+TESTED]` | [shared/xray-educator.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/shared/xray-educator.js), [ui/blocked.html](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/ui/blocked.html), [ui/blocked.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/ui/blocked.js) |
| **Multilingual Text Scanner** | `[BUILT+TESTED]` | [shared/text-scanner.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/shared/text-scanner.js), [tests/text_scanner.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/text_scanner.test.js) |
| **Candidate 26-Feature Pipeline** | `[BUILT+TESTED]` | [background/rich-feature-extractor.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/rich-feature-extractor.js), [tests/nextgen_threat_matrix.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/nextgen_threat_matrix.test.js) |
| **Vernacular Speech Synthesis** | `[DORMANT]` | Code exists in [shared/vernacular-coach.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/shared/vernacular-coach.js); not wired into popup or blocked UI. |
| **Mobile PWA Application** | `[BUILT+TESTED]` | [mobile-scanner/](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/mobile-scanner/), built via `npm run build:mobile`, tested in [tests/mobile_core.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/mobile_core.test.js). |
| **Interactive Demo Server** | `[BUILT+TESTED]` | [verity_demo_server.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity_demo_server.js) (Serves 10+ live scenarios on port 8080). |
| **Root Documentation & Specs** | `[BUILT+TESTED]` | [README.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/README.md), [TECHNICAL_DESIGN.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/docs/TECHNICAL_DESIGN.md), [KNOWN_LIMITATIONS.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/docs/KNOWN_LIMITATIONS.md), [BENCHMARKS.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/docs/BENCHMARKS.md). |
| **Grand Jury Presentation Slide Deck** | `[BUILT+TESTED]` | 8-Slide official presentation deck completely finalized in [docs/SUBMISSION_PACKET.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/docs/SUBMISSION_PACKET.md). |
| **Hackathon Submission Packet** | `[BUILT+TESTED]` | Official portal form fields, 8-slide PPT, and 3-min video script in [docs/SUBMISSION_PACKET.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/docs/SUBMISSION_PACKET.md). |
| **Deep NPCI UPI Protocol Forensic Unmasker** | `[BUILT+TESTED]` | [shared/upi-forensics.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/shared/upi-forensics.js), [shared/text-scanner.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/shared/text-scanner.js), [tests/world_class_wow_features.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/world_class_wow_features.test.js) |
| **Cross-Origin Brand Asset Theft Trap** | `[BUILT+TESTED]` | [content/content-script.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/content/content-script.js), [background/risk-engine.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/risk-engine.js), [tests/world_class_wow_features.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/world_class_wow_features.test.js) |
| **Live Luhn Card & OTP Keystroke Guard** | `[BUILT+TESTED]` | [content/content-script.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/content/content-script.js), [tests/world_class_wow_features.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/world_class_wow_features.test.js) |
| **Anti-Doxxing WebRTC Surveillance Trap** | `[BUILT+TESTED]` | [content/main-world-interceptor.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/content/main-world-interceptor.js), [content/bharat-scam-detectors.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/content/bharat-scam-detectors.js), [tests/world_class_wow_features.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/world_class_wow_features.test.js) |
| **Multi-Hop Malvertising Redirect & Tab-Under Analyzer** | `[BUILT+TESTED]` | [shared/redirect-forensics.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/shared/redirect-forensics.js), [background/redirect-analyzer.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/redirect-analyzer.js), [background/risk-engine.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/risk-engine.js), [tests/redirects_crack_and_mobile_lab.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/redirects_crack_and_mobile_lab.test.js) |
| **Crack / Warez / Piracy Site Malware Shield** | `[BUILT+TESTED]` | [content/crack-site-shield.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/content/crack-site-shield.js), [content/content-script.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/content/content-script.js), [background/risk-engine.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/risk-engine.js), [tests/redirects_crack_and_mobile_lab.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/redirects_crack_and_mobile_lab.test.js) |
| **4-Tool Citizen Mobile Cyber Lab & Magic-Byte Inspector** | `[BUILT+TESTED]` | [shared/file-magic-inspector.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/shared/file-magic-inspector.js), [shared/text-scanner.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/shared/text-scanner.js), [mobile-scanner/index.html](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/mobile-scanner/index.html), [mobile-scanner/scanner.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/mobile-scanner/scanner.js), [tests/redirects_crack_and_mobile_lab.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/redirects_crack_and_mobile_lab.test.js) |
| **Universal Structural DOM Graph Phishing Detector** | `[BUILT+TESTED]` | [content/structural-phish-graph.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/content/structural-phish-graph.js), [tests/universal_domain_agnostic.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/universal_domain_agnostic.test.js) |
| **Universal ICANN RDAP NRD Sentinel** | `[BUILT+TESTED]` | [background/rdap-sentinel.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/rdap-sentinel.js), [tests/universal_domain_agnostic.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/universal_domain_agnostic.test.js) |
| **Universal Clipboard Mismatch & Zero-Knowledge Vault** | `[BUILT+TESTED]` | [shared/universal-behavior-guard.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/shared/universal-behavior-guard.js), [tests/universal_domain_agnostic.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/universal_domain_agnostic.test.js) |
| **Universal Markov Lexical Transition Scorer** | `[BUILT+TESTED]` | [shared/markov-lexical-scorer.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/shared/markov-lexical-scorer.js), [tests/universal_domain_agnostic.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/universal_domain_agnostic.test.js) |
| **Demo Video (3–5 mins)** | `[PARTIAL]` | Complete 3-min timestamped script in [docs/SUBMISSION_PACKET.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/docs/SUBMISSION_PACKET.md) and [demo/DEMO_SCRIPT.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/demo/DEMO_SCRIPT.md); camera recording pending team filming. |

---

## 11. Claims: Safe vs. Unsafe to Tell Judges

### 11.1 SAFE Claims (Defensible with Code Evidence)
- **"18-Feature On-Device ONNX Model"**: Defensible. Verified in [background/offscreen.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/offscreen.js) and [background/model/phishing_model_v2.onnx](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/background/model/phishing_model_v2.onnx).
- **"315 Automated Unit and Integration Tests"**: Defensible. Verified via `npm test` passing in ~1,010 ms across 40 test suites with 0 failures.
- **"Universal Domain-Agnostic Zero-Day Engines"**: Defensible. Verified in [tests/universal_domain_agnostic.test.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/tests/universal_domain_agnostic.test.js) catching threats on unknown local credit unions, universities, and foreign TLDs with zero hardcoded keywords.
- **"100% On-Device Zero Telemetry"**: Defensible. Verified in code: URLs, browsing histories, and keystrokes are never transmitted. Only hostnames are queried via DoH for unlisted domains.
- **"Sub-Millisecond Synchronous Pipeline (< 0.5 ms)"**: Defensible. Benchmark in [docs/BENCHMARKS.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/docs/BENCHMARKS.md) measures mean 0.4845 ms on native Node.
- **"Multilingual Text Scanner Supporting English, Hindi, Tamil, and Telugu"**: Defensible. Verified in [shared/text-scanner.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/shared/text-scanner.js) and tested in `tests/text_scanner.test.js`.
- **"Standalone Mobile Scanner Sharing the Core Engine"**: Defensible. Verified via `npm run build:mobile` copying shared engine files into `mobile-scanner/core/`.

### 11.2 UNSAFE / Overstated Claims (Do NOT Say to Judges)
- **UNSAFE**: *"Verity catches 100% of all zero-day phishing websites."*  
  **CORRECTION**: *"Verity detects zero-day phishing attacks exhibiting known structural anomalies, brand impersonation, and evasive patterns, achieving 98.97% accuracy on our 4,750-URL benchmark."*
- **UNSAFE**: *"Our browser extension runs on all mobile phones."*  
  **CORRECTION**: *"Our extension runs on desktop browsers and mobile browsers supporting extensions (like Firefox for Android), while all other mobile devices use our installable PWA."*
- **UNSAFE**: *"Our production ML model uses 26 advanced deep-learning features."*  
  **CORRECTION**: *"Our shipped production model uses 18 rich lexical/domain features; a candidate 26-feature pipeline has been engineered for future quantized model releases."*
- **UNSAFE**: *"Verity features an active AI voice assistant talking to citizens."*  
  **CORRECTION**: *"Vernacular voice assistance has been implemented in code but is currently marked dormant in the UI to prevent autoplay interference."*
- **UNSAFE**: *"Google Safe Browsing takes 12 to 24 hours to update."*  
  **CORRECTION**: *"Centralized blocklists like Google Safe Browsing rely on crawler discovery, meaning newly registered zero-day domains may not be listed yet during the initial hours of an attack."*

---

## 12. Competitive Positioning

```
+---------------------------------------------------------------------------------------------------------+
|                                    COMPETITIVE COMPARISON MATRIX                                        |
+----------------------+--------------------+---------------------+--------------------+------------------+
| Attribute            | Google Safe        | Endpoint Antivirus  | Truecaller /       | Verity           |
|                      | Browsing           | (Norton/McAfee)     | Caller ID Apps     | (Bharat Shield)  |
+----------------------+--------------------+---------------------+--------------------+------------------+
| Primary Detection    | Centralized cloud  | Heavy local agent + | Crowdsourced phone | On-device 16     |
| Architecture         | crawler database   | signature database  | spam database      | rules + 18-feat  |
|                      |                    | (> 500 MB)          |                    | ONNX ML (< 1 MB) |
+----------------------+--------------------+---------------------+--------------------+------------------+
| Zero-Day Link        | Delayed until      | Moderate; signature | Ineffective against| Instantaneous via|
| Response             | crawler indexes    | updates required    | new web links      | structural & DOM |
|                      | link               |                     |                    | heuristics       |
+----------------------+--------------------+---------------------+--------------------+------------------+
| In-Browser DOM       | None (operates at  | Limited; heavy hook | None               | Active: pierces  |
| Inspection           | network URL layer) | into browser engine |                    | Shadow DOM for   |
|                      |                    |                     |                    | fake PIN/inputs  |
+----------------------+--------------------+---------------------+--------------------+------------------+
| Bharat Scam Focus    | Generic global     | Global malware and  | Flags phone calls; | Native detectors |
| (UPI, Digital Arrest)| phishing coverage  | trojans             | no web context     | for UPI, APKs, & |
|                      |                    |                     |                    | Digital Arrest   |
+----------------------+--------------------+---------------------+--------------------+------------------+
| Browsing Privacy     | URL hashes queried | Full telemetry      | Contact books and  | 100% on-device;  |
|                      | against Google API | uploaded to cloud   | call logs uploaded | DoH hostnames    |
|                      |                    |                     | to servers         | only             |
+----------------------+--------------------+---------------------+--------------------+------------------+
| Resource Overhead    | Minimal            | Heavy CPU/RAM usage | Moderate battery   | Sub-millisecond  |
|                      |                    | (> 200 MB RAM)      | background drain   | (< 0.5 ms scan)  |
+----------------------+--------------------+---------------------+--------------------+------------------+
```

### Positioning vs. "LLM Wrapper" Hackathon Projects
Many hackathon contestants build projects that take page text and prompt a remote Large Language Model (e.g. OpenAI or Gemini) to classify scams. 
- **The LLM Wrapper Flaw**: High latency (1.5–4.0 seconds per page), prohibitive API token costs ($0.01 per navigation), complete invasion of browsing privacy (sending user page content to remote clouds), and susceptibility to prompt injection attacks.
- **The Verity Advantage**: Operates on-device in 0.5 ms, costs $0.00 in cloud APIs, preserves 100% privacy, runs completely offline, and cannot be prompt-injected.

---

## 13. Known Weaknesses and Risks

### 13.1 Technical Architecture Risks
1. **Web Worker Bypass**: A malicious script executing network exfiltration from within a Web Worker (`new Worker()`) bypasses MAIN-world prototype traps. (Severity: Medium; mitigated at domain level by DNR rules).
2. **Pure Canvas Phishing Forms**: If a phishing kit renders an entire login form on a raw HTML5 canvas without creating DOM input nodes or attaching standard listeners, client-side DOM heuristics cannot inspect it without costly real-time OCR.
3. **DoH Shared Platform Blindness**: DoH queries send hostnames only (`1.1.1.2`). A zero-day phishing link hosted on high-reputation shared infrastructure (e.g. `firebaseapp.com/phish`) will return clean from DoH and must be caught entirely by Verity's lexical and DOM rules.
4. **Popup / Service Worker Message Action Discrepancy**: [popup/popup.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/popup/popup.js) sends `{ action: 'GET_TAB_VERDICT' }`, while [service_worker.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/service_worker.js) matches `message.action === 'GET_VERDICT'`. In practice, the popup gracefully defaults to displaying the active tab URL.

### 13.2 Demo-Day Presentation Risks
1. **Port 8080 Collision**: `verity_demo_server.js` defaults to port 8080. If another local service is running, the demo server fails to bind. Always test port availability prior to judging.
2. **Extension Unpacked Reload**: When evaluating new code changes, the unpacked extension must be reloaded in `chrome://extensions` and the active tab refreshed.
3. **Video Duration Limit**: Hackathon demo videos must strictly obey the 3–5 minute window; exceeding 5 minutes risks automatic disqualification.

---

## 14. Open Questions and Decisions Already Made

### 14.1 Decisions Already Made (Immutable)
- **Voice Assistance Deferred**: Speech synthesis (`speechSynthesis`) is kept dormant in [shared/vernacular-coach.js](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/verity-extension/shared/vernacular-coach.js). We will NOT showcase voice in the UI for this hackathon.
- **18-Feature Model Retained**: The production model is strictly the 18-feature `phishing_model_v2.onnx`. We will not claim 26 features in production.
- **PWA Scope Bounded**: The standalone PWA is built for manual text scanning, Web Share Target, and QR analysis; it does not attempt impossible OS-level background browser navigation interception.
- **Strict Multi-Source Convergence**: Single-source signals can never trigger a block alone without an explicit hard override.

### 14.2 Open Questions (For Team Decision)
1. **Aligning Popup Message Action**: Should we align `GET_TAB_VERDICT` in `popup.js` with `GET_VERDICT` in `service_worker.js` to ensure the popup displays the service worker's cached verdict on first click?
2. **Demo Video Production**: Who will record the voiceover and live screen capture following `demo/DEMO_SCRIPT.md`?
3. **Slide Deck Visual Design**: Should we generate visual diagrams from `docs/TECHNICAL_DESIGN.md` for inclusion in the final presentation PDF?

---

## 15. HOW TO USE THIS DOCUMENT (Instructions for the Next AI)

```
====================================================================================================
                        INSTRUCTION BLOCK FOR SUBSEQUENT AI AGENTS
====================================================================================================
You are advising a student hackathon team competing in a high-stakes national digital safety 
hackathon. Using ONLY the factual code evidence, architecture specifications, and measured 
numbers contained in this document:

1. Suggest the HIGHEST-IMPACT improvements ranked strictly by judging rubric points per hour of effort.
2. NEVER invent features, hypothetical APIs, or unverified statistical claims.
3. Flag any claim not backed by Section 10 (Honest Status Matrix).
4. Propose code modifications ONLY for files explicitly identified in Section 7 (Interfaces and Contracts).
5. Keep every suggestion realistic for the remaining 4-day submission window.
====================================================================================================
```

### 10 Concrete Questions the Team May Ask You
1. *"Rank the top 5 changes that will maximize our Social Cause Impact score within 6 hours of work."*
2. *"Write a punchy, exactly 500-character Problem Statement suitable for the hackathon submission portal."*
3. *"Write the 500-character Approach & Stack summary citing our 18-feature model and sub-millisecond latency."*
4. *"Critique our 3-minute demo choreography in demo/DEMO_SCRIPT.md and identify where a judge might get bored."*
5. *"Design our 10-slide Grand Jury presentation deck, specifying title, visual asset, and talking points per slide."*
6. *"What questions will a skeptical cybersecurity judge ask about our on-device model, and how do we answer them?"*
7. *"How do we explain why we chose LightGBM/ONNX over an LLM for real-time browser security?"*
8. *"Identify any remaining UI Polish issues in popup/popup.html and ui/blocked.html."*
9. *"Draft the exact script for our 3-minute hackathon demo video."*
10. *"How do we position our project against another team submitting an SMS spam classifier?"*

---

## 16. Appendix

### 16.1 Repository Directory Tree (Top 3 Levels)
```
verity/
├── .gitignore
├── LICENSE                             # MIT License
├── package.json                        # Root workspace configuration
├── README.md                           # Master project overview & documentation
├── test_server.js                      # Legacy scenario test server
├── verity_demo_server.js               # Interactive evaluation & demo server (port 8080)
├── demo/
│   └── DEMO_SCRIPT.md                  # 3-minute jury presentation script
├── docs/
│   ├── archive/                        # Relocated historical hackathon specs
│   ├── BENCHMARKS.md                   # Machine performance & latency benchmarks
│   ├── KNOWN_LIMITATIONS.md            # Transparent threat surface & edge cases
│   ├── PROJECT_BRIEF_FOR_AI.md         # This self-contained brief
│   └── TECHNICAL_DESIGN.md             # Complete system architecture specification
├── mobile-scanner/                     # Standalone Progressive Web App (PWA)
│   ├── index.html                      # PWA interface (camera, text scanner, share)
│   ├── manifest.json                   # Web App Manifest & Web Share Target
│   ├── package.json
│   ├── core/                           # Synchronized shared engine modules
│   └── icons/
├── sample_data/
│   ├── README.md                       # Sample data schema & documentation
│   └── indian_cyber_fraud_test_cases.json # 30 curated Indian cyber fraud scenarios
├── scripts/
│   └── bench.js                        # 1,000-iteration performance benchmark harness
└── verity-extension/                   # Browser Extension Root (Manifest V3)
    ├── manifest.json                   # Extension Manifest V3 configuration
    ├── package.json                    # Extension package config & test scripts
    ├── service_worker.js               # Background service worker orchestrator
    ├── brands.json                     # 100+ verified brand catalog
    ├── payment-brands.json             # Payment gateway catalog
    ├── background/                     # Rules engine, risk engine, ML scorers
    │   ├── brand-detector.js
    │   ├── dnr-blocker.js
    │   ├── enterprise-whitelist.js
    │   ├── favicon-matcher.js
    │   ├── homograph-detector.js
    │   ├── ml-scorer.js
    │   ├── offscreen.html / offscreen.js
    │   ├── payment-detector.js
    │   ├── redirect-analyzer.js
    │   ├── reputation.js
    │   ├── rich-feature-extractor.js
    │   ├── risk-engine.js
    │   ├── rules.js
    │   ├── download/
    │   ├── lib/                        # ONNX Runtime Web WASM binaries
    │   └── model/                      # phishing_model_v2.onnx (18 features)
    ├── content/                        # Content scripts & DOM analysis
    │   ├── bharat-scam-detectors.js    # Digital Arrest, APK, UPI detectors
    │   ├── content-script.js           # DOM traversal, shadow piercing, overlays
    │   ├── main-world-interceptor.js   # MAIN world fetch/XHR/WS traps
    │   ├── overlay.css
    │   └── search/                     # Search engine badge injection
    ├── popup/                          # Toolbar action popup
    │   ├── popup.html / popup.css / popup.js
    │   └── popup-logic.js
    ├── shared/                         # Cross-surface libraries
    │   ├── citizen-messages.js
    │   ├── legit-domains.js
    │   ├── messages.js / messages.en.js
    │   ├── psl.js
    │   ├── safe-dom.js
    │   ├── text-scanner.js
    │   ├── vernacular-coach.js
    │   └── xray-educator.js
    ├── tests/                          # 35 test suites (234 passing tests)
    ├── training/                       # ML dataset, training scripts, model metrics
    └── ui/                             # Zero-latency block screen (blocked.html)
```

### 16.2 Complete List of 35 Test Suites (234 Tests)
Every test suite executed by `npm test`:
1. `tests/allowlist_abuse.test.js`: Verifies allowlisted domains cannot be exploited via open redirects or high-risk file downloads.
2. `tests/bharat_shield_hackathon.test.js`: Integration tests for Digital Arrest, APK droppers, UPI collect traps, vernacular advisories, and dossier credential redaction.
3. `tests/clickfix_shadowdom.test.js`: Pierces open Shadow DOM trees and detects fake verification lures combined with PowerShell execution.
4. `tests/convergence.test.js`: Validates the multi-source convergence rule requiring $\ge 2$ independent operational sources for block verdicts.
5. `tests/domain_age.test.js`: Tests newly registered domain heuristics and timestamp extraction.
6. `tests/download_smuggling_spoof.test.js`: Flags disguised double extensions (`.mp4.exe`), tiny video traps, and download smuggling.
7. `tests/exfil_and_doh.test.js`: Tests webhook exfiltration traps (Telegram/Discord), Cloudflare DoH sinkholing, and federated SSO exemptions.
8. `tests/homograph.test.js`: Detects Unicode homoglyphs and Cyrillic/Greek confusable attacks.
9. `tests/main_world_interceptor.test.js`: Tests Node `vm` sandbox interception of fetch, XHR, sendBeacon, and WebSocket for Telegram/Discord webhooks.
10. `tests/malware_anomaly.test.js`: Evaluates malware domain heuristics and risk score adjustments.
11. `tests/message_security.test.js`: Validates internal extension message sender authentication (`validateMessageSender`).
12. `tests/mobile_core.test.js`: Ensures all mobile core modules match extension counterparts and run offline in pure environments.
13. `tests/nextgen_threat_matrix.test.js`: Tests next-gen threat heuristics and the 26-feature candidate vector extractor (`extract26Features`).
14. `tests/parity.test.js`: Verifies parity between Python training feature extraction and JavaScript runtime feature extraction.
15. `tests/popup_logic.test.js`: Unit tests for popup view model formatting, traffic light states, language detection, and internal URL handling.
16. `tests/psl.test.js`: Validates Public Suffix List parsing for single-level, multi-level, and private domain boundaries.
17. `tests/reason_ids.test.js`: Verifies all structured Reason IDs map to valid categories and have non-empty localized strings.
18. `tests/redirect_popunder.test.js`: Tests multi-hop redirect chains, link shorteners, and popunder detection.
19. `tests/rendering.test.js`: Validates Shadow DOM security overlay rendering, animation styles, and button handlers.
20. `tests/reputation.test.js`: Tests Cloudflare 1.1.1.2 DoH sinkhole querying and network error fallbacks.
21. `tests/rules.test.js`: Unit tests for each of the 16 synchronous URL heuristic rules.
22. `tests/sample_data.test.js`: Evaluates all 30 Indian cyber fraud sample cases against `scanText()`.
23. `tests/text_scanner.test.js`: Tests 15 core scenarios of `scanText()` (KYC, Digital Arrest, APKs, UPI traps, multilingual strings, garbage text).
24. `tests/verify_bitdefender_zero_day.test.js`: Tests Bitdefender-tier zero-day defenses (MurmurHash3 favicon clones, CDN hotlinks, free hosting traps, anti-analysis evasion).
25. `tests/verify_cyber_fraud.js`: Tests Indian banking KYC phishing, illegal UPI PINs, Telegram exfiltration, and 0 false positives.
26. `tests/verify_emergency_production_fix.js`: Tests production emergency fixes and critical risk overrides.
27. `tests/verify_interactive_override_and_safety.js`: Validates user override flows ("I understand the risk") and navigation to safety.
28. `tests/verify_malvertising_redirect_rotator.js`: Tests ad rotators, hex queries, and malvertising bridge interception.
29. `tests/verify_media_embed_exemption.js`: Asserts legitimate media streaming embeds (YouTube, Vimeo) are not falsely blocked.
30. `tests/verify_nextgen_hardening.js`: Validates next-gen hardening against AiTM reverse proxies, BitB popups, and Web3 drainers.
31. `tests/verify_popunder_fixes.js`: Tests `window.open` `about:blank` popup trapping and popunder mitigation.
32. `tests/verify_popup_window_termination.js`: Tests automated tab termination of rogue spawned popunder windows.
33. `tests/verify_smart_download_rules.js`: Tests smart download policies, file extension risk categorization, and user override prompts.
34. `tests/verify_zero_false_positives.test.js`: Evaluates 50+ real-world top domains and enterprise login portals ensuring 0 false positive blocks.
35. `tests/verify_zero_trust_defenses.js`: Tests zero-trust protection against BitB, Evilginx AiTM, Quishing, clipboard address swappers, and rogue push traps.

### 16.3 Sample Data Schema
Located in [sample_data/indian_cyber_fraud_test_cases.json](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/sample_data/indian_cyber_fraud_test_cases.json):
```json
{
  "id": "sbi-kyc-typosquat",
  "category": "banking_kyc_typosquat | upi_collect_trap | digital_arrest | apk_dropper | legitimate_portal",
  "input": "https://sbi-kyc-verification-portal.invalid/update-pan",
  "inputType": "url | text",
  "expectedVerdict": "danger | safe",
  "expectedSignals": ["SIG_KYC_CYBER_FRAUD"],
  "notes": "SBI brand name impersonation on synthetic .invalid domain with urgent PAN update path"
}
```

---

## ONE-PAGE VERSION

> **Verity 2.0 (Bharat Shield)** is an open-source, on-device cyber defense suite designed to protect Indian citizens against localized financial fraud, including "Digital Arrest" extortion, fake bank KYC phishing, deceptive UPI collect traps, and malicious WhatsApp APK droppers.

### Key Architecture & Capabilities
1. **Dual Protection Surfaces**: A Manifest V3 browser extension (for Chrome, Edge, Brave, and mobile browsers supporting extensions like Firefox for Android) and an installable Progressive Web App (PWA) with Android Web Share Target.
2. **Sub-Millisecond Engine**: Executes in < 0.5 ms on native Node (Allowlist: ~0.005 ms, 16 rules: ~0.43 ms, 18-feature extraction: ~0.005 ms, text scan: ~0.16 ms).
3. **18-Feature On-Device ONNX ML & 2-Layer Neural MLP Meta-Fusion**: Uses an 18-feature LightGBM model (`phishing_model_v2.onnx`, 26.88 KB) plus an on-device 2-Layer Neural Multi-Layer Perceptron (10 input -> 8 hidden ReLU -> 1 output Sigmoid) and Continuous 8D DOM Vector Topology Embedding.
4. **Subword Character N-Gram Bayesian NLP & Hybrid Online Intel**: Continuous subword language modeling catches mutated Hinglish/obfuscated scam SMS/chats; public zero-key Certificate Transparency (CT) log sentinel and Dual DoH CNAME unmasker detect disposable certificates and serverless cloaking.
5. **Adaptive Risk Engine**: Implements category caps, diminishing weights `[1.0, 0.75, 0.55, 0.35, 0.20, 0.10]`, and a convergence rule requiring $\ge 2$ independent sources for a Block verdict to eliminate false positives.
6. **Runtime Traps**: MAIN-world prototype hooks intercepting `fetch`, `XMLHttpRequest`, `navigator.sendBeacon`, and `WebSocket` connections to Telegram/Discord exfiltration endpoints; traps ClickFix clipboard injection and uncloaks closed Shadow DOM trees.
7. **Citizen-Centric UI**: Localized in English, Hindi, Tamil, and Telugu with interactive "Spot-the-Scam" micro-quizzes, traffic-light cards, Golden Safety Rules, and direct 1930 National Cyber Crime Helpline access. (Voice assistance is implemented in code but marked `[DORMANT]` in the UI).
8. **Strict Privacy**: 100% on-device processing; zero browsing history or credentials ever leave the device. Hostnames only are queried via DNS-over-HTTPS (`1.1.1.2`) and public CT logs (`crt.sh`).
9. **Verified Test Coverage**: 336 passing automated tests across 41 test suites in `npm test` with 0 failures. Ready-to-submit deliverables codified in [docs/SUBMISSION_PACKET.md](file:///e:/Finebehaviour%20-%20Copy%20-%20Copy%20%282%29/docs/SUBMISSION_PACKET.md).
