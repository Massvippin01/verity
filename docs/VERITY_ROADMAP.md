# VERITY 2.0 | Engineering & Product Architecture Roadmap

**Document Version:** 2.0.0  
**Authors:** Principal Engineering & Product Strategy Team  
**Date:** October 2026  
**Product Vision:** A citizen-first cyber-fraud prevention and recovery assistant that empowers every Indian citizen to detect, understand, prevent, and recover from digital deception.

---

## 1. Roadmap Architecture: Grounded in Verified Milestones

The VERITY roadmap avoids aspirational vaporware. Every future phase is gated by technical feasibility, platform sandbox realities, ethical constraints, and empirical test requirements.

```
+-----------------------------------------------------------------------------------+
| MILESTONE 1: Verified Baseline & Citizen Recovery Core (COMPLETED - OCT 2026)      |
| • Versioned Verdict Contract (2.0.0) with explicit abstentions                    |
| • Citizen Recovery Engine (10 Post-Compromise Paths, 1930 Helpline, Bank Directory)|
| • Remediated Reddit Privacy Egress Defect (SEC-LEAK-01)                           |
| • Mobile-First PWA & Chrome MV3 Extension with Evidence Receipt Export             |
| • 417 Automated Tests Passing (100%), 2.8ms Scan Latency                          |
+-----------------------------------------------------------------------------------+
                                          │
                                          ▼
+-----------------------------------------------------------------------------------+
| MILESTONE 2: Controlled Pilot & Signed Threat Packs (Q1 2027)                     |
| • 60-Citizen Usability & Cognitive Research Pilot (Phase J Protocol)              |
| • Ed25519 Cryptographically Signed Offline Threat Indicator Packs                 |
| • Web Share Target v2 (Screenshot & Image Intent Ingestion)                       |
| • Expansion to 8 Indic Languages (Adding Bengali, Marathi, Kannada, Malayalam)    |
+-----------------------------------------------------------------------------------+
                                          │
                                          ▼
+-----------------------------------------------------------------------------------+
| MILESTONE 3: Vernacular Voice Coach & Quantized Indic SLM (Q2 - Q3 2027)          |
| • Vernacular Audio Prompts (Web Speech API) for Low-Literacy Rural Citizens       |
| • On-Device 8-bit Quantized Small Language Model (<15MB, WebGPU/WASM)             |
| • Formal Read-Only Threat Feed Sync with State Cyber Cells                        |
| • Optical Character Recognition (OCR) for Local WhatsApp Screenshot Analysis      |
+-----------------------------------------------------------------------------------+
                                          │
                                          ▼
+-----------------------------------------------------------------------------------+
| MILESTONE 4: Longitudinal Field Impact & Institutional Scale (2028)                |
| • Randomized Controlled Trial measuring actual citizen financial loss reduction   |
| • Open Community Threat Federation with Differential Privacy Guarantees           |
| • Zero-Knowledge Telemetry for Emerging Scam Pattern Aggregation                  |
+-----------------------------------------------------------------------------------+
```

---

## 2. Granular Milestone Breakdown

### Milestone 1: Verified Baseline & Citizen Recovery Core (DELIVERED)
- [x] **Audit & Ground Truth Verification:** Complete inspection of existing codebase; documented in `docs/VERITY_BASELINE_AUDIT.md`.
- [x] **20-Category Indian Scam Taxonomy:** Mapped threat objectives, observables, unavailable evidence, and detection rules in `docs/VERITY_SCENARIO_COVERAGE.md`.
- [x] **Versioned Verdict Contract (Schema 2.0.0):** Created `verity-extension/shared/verdict-contract.js` with structured risk ratings, human explanations, and 5 explicit abstention codes.
- [x] **Post-Incident Citizen Recovery Advisor:** Created `verity-extension/shared/recovery-advisor.js` with 10 situation-specific recovery branches, emergency 1930 integration, bank helpline directory, and secret redaction.
- [x] **Privacy Leak Remediation:** Eliminated user message transmission to Reddit API in `online-scam-verifier.js:680`.
- [x] **Mobile-First PWA Experience:** Implemented upfront Privacy Disclosure, responsive Action Card, Recovery Mode panel, and sanitized Evidence Receipt generation in `mobile-scanner/`.
- [x] **Multilingual Support (EN, TA, HI, TE):** Expanded UI strings in `citizen-messages.js` for seamless native language switching.
- [x] **Automated Testing & Benchmarks:** Expanded test suite to 417 passing tests; recorded 2.8ms mean latency across 1,000 iterations.

---

### Milestone 2: Controlled Pilot & Signed Threat Packs (Target: Q1 2027)

#### Objective 2.1: Controlled Human Pilot Execution
- Execute Phase J usability protocol across the 4 cohorts (Students, Seniors, Rural/First-Time Users, Cyber Volunteers).
- Measure Action Comprehension Rate (target $>95\%$) and Recovery Time-to-Complete (target $<60\text{s}$).

#### Objective 2.2: Cryptographically Signed Rule Updates
- Implement Ed25519 public-key signature verification for dynamic threat rule updates.
- Ensure community threat packs cannot be tampered with via Man-in-the-Middle (MitM) attacks or compromised mirrors.
- Format:
  ```json
  {
    "pack_version": "2027.01.15",
    "signature": "base64_ed25519_signature...",
    "indicators": [ ... ]
  }
  ```

#### Objective 2.3: Expanded Regional Language Corpus
- Author and test localized Indic threat vocabularies for Bengali (`bn`), Marathi (`mr`), Kannada (`kn`), and Malayalam (`ml`).
- Engage native cybersecurity educators to validate transliterated SMS lures (e.g., Romanized Hindi/Tamil/Kannada).

---

### Milestone 3: Vernacular Voice Coach & Quantized Indic SLM (Target: Q2–Q3 2027)

#### Objective 3.1: Vernacular Voice Coach for Accessibility
- Implement client-side text-to-speech using standard browser `window.speechSynthesis`.
- Automatically speak the Recommended Safe Action (e.g., *"இது மோசடி செய்தி, எந்த லிங்க்கையும் கிளிக் செய்யாதீர்கள்"*) when an elder or visually impaired citizen scans an interaction.

#### Objective 3.2: Edge-Quantized Scam Language Model (SLM)
- Replace the legacy 18-feature tabular ONNX model with a compact (8-bit quantized, <15MB) transformer-based model capable of contextual Indic semantic understanding.
- Run via WebGPU / ONNX Runtime Web WebAssembly without server offloading.
- Maintain fallback to deterministic heuristics if WebAssembly or WebGPU is unsupported.

#### Objective 3.3: Client-Side OCR for Scam Screenshots
- Integrate Tesseract.js / WebAssembly OCR to allow citizens to upload or share screenshots of deceptive WhatsApp conversations, fake court arrest notices, or UPI payment screens without typing.
- All OCR processing strictly on-device.

---

### Milestone 4: Longitudinal Field Impact & Institutional Scale (Target: 2028)

#### Objective 4.1: Longitudinal Field Loss Reduction Study
- Partner with academic researchers and legal aid societies to track a cohort of 5,000 citizens over a 12-month period.
- Empirically quantify the reduction in successful financial fraud incidents compared to an unassisted control group.

#### Objective 4.2: Privacy-Preserving Threat Federation
- Implement differential privacy (Local Differential Privacy / RAPPOR) enabling citizens to anonymously contribute anonymized threat hashes to the community pool without revealing IP, phone numbers, or browsing history.

---

## 3. Engineering Commitments & Quality Gates

Every milestone release must satisfy the following non-negotiable gates:
1. **100% Pass on Automated Test Suite:** No regressions permitted.
2. **Deterministic Build Reproducibility:** Zero proprietary or unpinned dependencies.
3. **Zero Secret Leakage:** Invariant sanitization tests must execute on every build.
4. **Sub-15ms Latency Budget:** Client-side heuristics must maintain real-time responsiveness.
5. **No Fake Capabilities:** UI must never claim or imply powers that the software cannot deliver.
