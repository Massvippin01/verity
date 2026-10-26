# VERITY 3.0 | Platform Capability Matrix

**Document Version:** 3.0.0  
**Status:** Codebase Audit & Empirical Verification  
**Evaluation Standard:** Zero-Fabrication Operating Rules  

---

## 1. Capability Classification Taxonomy

Every architectural capability is categorized under one of five strict statuses:
- **`IMPLEMENTED AND VERIFIED`**: Code exists, call sites are wired to active UI/engines, and verified with automated test suites or subagent browser execution.
- **`IMPLEMENTED BUT UNVERIFIED`**: Code exists in codebase but lacks automated test coverage or verified interactive validation.
- **`PARTIAL`**: Core engine logic exists, but platform integration is constrained by sandbox boundaries or partial UI wiring.
- **`PLANNED`**: Architecture and interface specifications designed; implementation targeted for subsequent milestones.
- **`UNSUPPORTED`**: Explicitly excluded due to OS security sandboxes, regulatory constraints, or anti-surveillance privacy boundaries.

---

## 2. Comprehensive Capability Matrix

| Capability Domain | Specific Feature / Sub-Capability | Verification Status | Implementation File & Functions | Supporting Automated Tests | Permissions & Platform Requirements |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Browser Extension** | Real-time DOM Phishing & Homoglyph Inspection | **IMPLEMENTED AND VERIFIED** | `content/content-script.js`, `background/rules.js`, `background/brand-detector.js` | `universal_behavior.test.js`, `content_script.test.js` | Manifest V3 `activeTab`, CSP: `script-src 'self'` |
| **Browser Extension** | Masquerading Download Interception (.mp4.exe) | **IMPLEMENTED AND VERIFIED** | `shared/file-magic-inspector.js`, `background/service_worker.js` | `universal_behavior.test.js` | Chrome `downloads` permission |
| **Browser Extension** | Popunder Ad-Rotator Defusal | **IMPLEMENTED AND VERIFIED** | `content/crack-site-shield.js`, `content/content-script.js` | `universal_behavior.test.js` | Chrome `tabs` / content script injection |
| **Mobile PWA** | Standalone Offline PWA Installation | **IMPLEMENTED AND VERIFIED** | `mobile-scanner/index.html`, `mobile-scanner/manifest.webmanifest`, `mobile-scanner/sw.js` | Verified via Chrome DevTools Subagent | Service Worker caching, standalone display |
| **Mobile PWA** | Web Share Target (Receive Shared SMS/Links) | **IMPLEMENTED AND VERIFIED** | `mobile-scanner/manifest.webmanifest` (`share_target`), `mobile-scanner/scanner.js` | `citizen_journeys_e2e.test.js` | Web Share Target API (GET action) |
| **Mobile PWA** | Live Camera QR Viewfinder & Fallback | **IMPLEMENTED AND VERIFIED** | `mobile-scanner/scanner.js` (`startCameraScanner()`), ZXing library | Interactive Subagent test & error handling | `navigator.mediaDevices.getUserMedia` |
| **Android-Native Feasibility**| User-Initiated Share Intent Receiver | **PARTIAL** | `android-app/` stub; full design in `docs/VERITY_NATIVE_PLATFORM_FEASIBILITY.md` | Documented architecture | `android.intent.action.SEND` |
| **Android-Native Feasibility**| Silent Background SMS Inbox Scraping | **UNSUPPORTED** | N/A — Excluded by Design | N/A | **Prohibited by Google Play SMS/Call Log Policy** & Privacy Invariant |
| **Android-Native Feasibility**| Accessibility Service Screen Scraping | **UNSUPPORTED** | N/A — Excluded by Design | N/A | Excluded due to battery/security risks & Play Store restrictions |
| **Local Detection** | 16 Deterministic URL Heuristic Rules | **IMPLEMENTED AND VERIFIED** | `background/rules.js`, `background/risk-engine.js` | `benchmark.test.js`, `rules.test.js` | Zero permissions; pure synchronous JavaScript |
| **Local Detection** | Subword NLP Conversational Extortion Detector | **IMPLEMENTED AND VERIFIED** | `shared/ai-nlp-classifier.js`, `shared/text-scanner.js` | `citizen_journeys_e2e.test.js` | Local dictionary hash lookup; < 0.5ms |
| **Local Detection** | Deep NPCI UPI Protocol Forensics | **IMPLEMENTED AND VERIFIED** | `shared/upi-forensics.js` (`analyzeUpiIntentForensics`) | `citizen_journeys_e2e.test.js`, `network_egress.test.js` | Zero permissions; RFC/NPCI intent specification parser |
| **Local Detection** | Offline Tabular ONNX Machine Learning Model | **PARTIAL (Ablated)** | `background/risk-engine.js`, `training/fraud_detector.onnx` | Verified in unit test (`ML_WEIGHT = 0.0`) | Disclosed ~42% standalone accuracy; ablated in favor of heuristics |
| **External Reputation** | DNS-over-HTTPS (DoH) Hostname Resolution | **IMPLEMENTED AND VERIFIED** | `shared/online-scam-verifier.js` (`checkDnsOverHttpsAndCloak`) | `online_verifier.test.js` | User opt-in; strips URL paths, queries, credentials |
| **External Reputation** | ICANN RDAP Domain Registration Age Audit | **IMPLEMENTED AND VERIFIED** | `shared/online-scam-verifier.js` (`checkIcannRdapDomainAge`) | `online_verifier.test.js` | Apex domain only (`rdap.org`); zero PII |
| **Threat Intelligence** | Authenticated Ed25519 Threat Pack Verifier | **IMPLEMENTED AND VERIFIED** | `shared/threat-pack-verifier.js` (`verifyThreatPack`) | `threat_pack_verifier.test.js` (10 passing tests) | Standard `node:crypto` / Web Crypto RFC 8032 |
| **Threat Intelligence** | Anti-Rollback & Sequence Monotonicity Guard | **IMPLEMENTED AND VERIFIED** | `shared/threat-pack-verifier.js` | `threat_pack_verifier.test.js` | Sequence integer validation against active state |
| **Recovery Guidance** | 10-Branch Situation-Specific Decision Tree | **IMPLEMENTED AND VERIFIED** | `shared/recovery-advisor.js` (`RECOVERY_GUIDES`) | `recovery_advisor.test.js`, `citizen_journeys_e2e.test.js` | Zero external network sockets |
| **Recovery Guidance** | Official Indian Helpline Registry (1930) | **IMPLEMENTED AND VERIFIED** | `shared/recovery-advisor.js` (`OFFICIAL_RECOVERY_REGISTRY`) | `recovery_advisor.test.js` | Tel URI (`tel:1930`) & direct portal URLs |
| **Evidence Receipt** | Plaintext Secret Stripper (`sanitizeSecrets`) | **IMPLEMENTED AND VERIFIED** | `shared/recovery-advisor.js`, `shared/flight-recorder.js` | `recovery_advisor.test.js`, `flight_recorder.test.js` | Masks Aadhaar, PAN, Card PAN, OTP, CVV, Passwords |
| **Evidence Receipt** | Markdown & JSON Receipt Export | **IMPLEMENTED AND VERIFIED** | `shared/recovery-advisor.js` (`generateEvidenceReceipt`) | `recovery_advisor.test.js` | Client-side blob generation |
| **Autonomous Actions** | Bounded Reversible Safe Action Policy Engine | **IMPLEMENTED AND VERIFIED** | `shared/safe-action-policy.js` (`evaluateSafeActionPolicy`) | `safe_action_policy.test.js` (7 passing tests) | Deterministic pure functions |
| **Autonomous Actions** | Prohibited Irreversible Autonomous Actions | **IMPLEMENTED AND VERIFIED** | `shared/safe-action-policy.js` (`PROHIBITED_AUTOMATIC_ACTIONS`) | `safe_action_policy.test.js` | Enforced at code level: blocks financial/account disruption |
| **Autonomous Actions** | Automated Bank Account Freezing | **UNSUPPORTED** | N/A — Excluded by Regulatory Design | N/A | Requires Core Banking System (CBS) integration; routes to 1930 |
| **Incident Timeline** | Local Incident Flight Recorder (Ring Buffer) | **IMPLEMENTED AND VERIFIED** | `shared/flight-recorder.js` (`FlightRecorder`) | `flight_recorder.test.js` (6 passing tests) | In-memory / local storage; max 50 records |
| **Incident Timeline** | Non-Judicial Disclaimer on Exports | **IMPLEMENTED AND VERIFIED** | `shared/flight-recorder.js` (`LEGAL_DISCLAIMER`) | `flight_recorder.test.js` | Mandatory export banner |
