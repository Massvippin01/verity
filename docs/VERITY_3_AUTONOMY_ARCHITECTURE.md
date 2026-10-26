# VERITY 3.0 | Bounded Autonomy & Ecosystem Architecture

**Document Version:** 3.0.0  
**Status:** Engineering Baseline Verified (448 Tests Passing, 0 Failures)  
**Architect:** Principal Engineer & Cybersecurity Architect  
**Target Codebase:** VERITY 3.0 / Bharat Shield  
**License:** Open Source (MIT)

---

## 1. Architectural Mission & Paradigm

VERITY 3.0 evolves the citizen-first cybersecurity baseline of VERITY 2.0 into an autonomous, accountable, and ecosystem-integrated cyber-safety platform. Where legacy defenses rely either on invasive cloud surveillance (proxying all citizen traffic to centralized servers) or completely passive warning dialogs, VERITY 3.0 enforces a **Bounded Autonomy** paradigm:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                       VERITY 3.0 CITIZEN LIFECYCLE PIPELINE                     │
│                                                                                 │
│   [DETECTION]             [POLICY]            [AUTONOMY]          [RECOVERY]    │
│  Deterministic    ───►  Safe Action    ───►  Bounded &      ───►  10-Branch     │
│  Heuristics (1ms)       Policy Engine        Reversible           Advisor &     │
│  + Signed Packs         (Zero-Surprise)      Interventions        Flight Log    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 1.1 Core Principles of Bounded Autonomy
1. **Zero Unilateral Consequential Disruption:** Autonomous actions are strictly limited to *reversible, safety-preserving protective pauses* (e.g. pausing an unverified executable download or defusing an ad-rotator popunder). Consequential or irreversible operations (e.g. blocking a bank account, closing sessions, or filing police reports) strictly require verified user confirmation and authorized institutional integration.
2. **Explicit Abstention Invariant:** When technical evidence is ambiguous, incomplete, or degraded, the system emits an explicit `ABSTAIN` state (`INSUFFICIENT_EVIDENCE`). Missing evidence is **never converted into an assertion of safety**, and uncertain verdicts **never authorize automatic disruption**.
3. **Uncalibrated Model Prohibition:** Machine learning classifiers without empirical confidence calibration are prohibited from independently authorizing protective actions. Autonomous interventions require deterministic signature matches or calibrated confidence thresholds ($\ge 0.85$).
4. **Client-Side Data Minimization:** Primary message scanning, UPI forensic unmasking, credential redacting, and timeline storage execute 100% on the local device without central telemetry collection.

---

## 2. Component Topology & Data Flow

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             CLIENT RUNTIME BOUNDARY                              │
│                                                                                  │
│  ┌──────────────────────┐    ┌──────────────────────┐    ┌────────────────────┐  │
│  │   Text / URL / UPI   │    │ Authenticated Threat │    │  Heuristic Rules   │  │
│  │   Input Modalities   │    │ Packs (Ed25519)      │    │  (16 Synchronous)  │  │
│  └──────────┬───────────┘    └──────────┬───────────┘    └─────────┬──────────┘  │
│             │                           │                          │             │
│             ▼                           ▼                          ▼             │
│  ┌────────────────────────────────────────────────────────────────────────────┐  │
│  │                       VERDICT CONTRACT (SCHEMA 2.0.0)                      │  │
│  │   • scanId, threatCategory, riskClassification, riskScore                  │  │
│  │   • Separated empirical evidence vs inferences                             │  │
│  │   • Explicit abstentionReason & uncertainty metadata                       │  │
│  └──────────────────────────────────────┬─────────────────────────────────────┘  │
│                                         │                                        │
│                                         ▼                                        │
│  ┌────────────────────────────────────────────────────────────────────────────┐  │
│  │                     SAFE ACTION POLICY ENGINE (v1.0.0)                     │  │
│  │   • recommendedAction (Citizen-facing safe guidance)                       │  │
│  │   • allowedAutomaticAction (Reversible, platform-supported pause only)    │  │
│  │   • requiredUserConfirmation (Explicit dialog for overrides/mitigation)    │  │
│  │   • auditEvent (Deterministic event metadata)                              │  │
│  └──────────────────┬───────────────────────────────────┬─────────────────────┘  │
│                     │                                   │                        │
│                     ▼                                   ▼                        │
│  ┌────────────────────────────────────┐   ┌───────────────────────────────────┐  │
│  │   PROTECTIVE ACTIONS EXECUTOR      │   │     INCIDENT FLIGHT RECORDER      │  │
│  │   • downloads.pause (Browser API)  │   │   • Local 50-event ring buffer    │  │
│  │   • popup.close (Tab defusal)      │   │   • Facts vs Assertions split     │  │
│  │   • User-confirmed override hook   │   │   • Aadhaar/PAN/OTP secret scrub  │  │
│  └────────────────────────────────────┘   │   • SHA-256 integrity checksum    │  │
│                                           │   • Non-judicial disclaimer export│  │
│                                           └───────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Policy Execution Lifecycle

1. **Intake & Normalization:** Citizen pastes SMS, captures QR code, or extension intercepts page navigation.
2. **Forensic Analysis:** Subword NLP, regex coercion detectors, homoglyph calculators, and NPCI URI analyzers execute synchronously (< 2ms).
3. **Verdict Generation:** Emits versioned `VerdictContract` (SAFE, CAUTION, HIGH_RISK, or ABSTAIN).
4. **Policy Evaluation:** Consumes Verdict Contract and platform capability flags:
   - If `ABSTAIN`: Disables automatic actions; outputs `MANUAL_VERIFY_OFFLINE`.
   - If `HIGH_RISK` + verified executable dropper + download pause supported: Emits `PAUSE_AND_PROMPT_DOWNLOAD` with `RESUME_DOWNLOAD` reversal hook.
   - If `HIGH_RISK` + digital arrest / fake KYC: Emits `RECOMMEND_EMERGENCY_RECOVERY` directing user to 1930.
5. **Flight Recording:** Logs incident with separated observed facts vs unverified citizen assertions; scrubbed of all PII and hashed with SHA-256.

---

## 4. Verification Evidence

- Baseline test suite: **448 passing tests**, 0 failures across 25 suites.
- Latency benchmarks: **1.17 ms** mean heuristic pipeline latency.
- Distribution integrity: Verified self-contained in standalone scratch environments.
