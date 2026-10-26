# VERITY 2.0 | Controlled Citizen Usability Pilot Protocol

**Document Version:** 1.0.0  
**Research Lead:** Lead Accessibility Specialist & Principal Engineer  
**Date:** October 2026  
**Status:** Protocol Approved for Field Execution (Pre-Pilot Readiness)  
**Ethical Review:** Zero Real Malware / Strictly Synthetic Scenarios  
**Anti-Fabrication Notice:** In accordance with Mission Rules, no participant observations or field results are claimed until empirical pilot trials have been conducted.

---

## 1. Research Questions & Hypotheses

### 1.1 Primary Research Questions
- **RQ1 (Comprehension & Safe Action):** Does the Explainable Scam Action Card enable citizens to correctly identify deceptive interactions and choose safe actions compared to generic browser warning pages?
- **RQ2 (Post-Compromise Mitigation):** Does the 10-branch Recovery Mode reduce the latency to initiate emergency financial mitigation (dialing 1930, card blocking) for users who have already interacted with a scam?
- **RQ3 (Vernacular Accessibility):** Does localized translation (Tamil, Hindi, Telugu) reduce cognitive friction and increase comprehension for non-English fluent smartphone users?
- **RQ4 (Evidence Receipt Utility):** Does the sanitized Evidence Receipt generator allow users to export technical incident artifacts for official reporting (`cybercrime.gov.in`) without leaking personal passwords, OTPs, or Aadhaar numbers?

### 1.2 Formal Hypotheses
- **H1:** At least **90%** of participants presented with high-risk scenarios (Digital Arrest, UPI collect trap, Fake KYC) will correctly select the non-compliance action ("Do not click / Do not pay").
- **H2:** At least **85%** of participants assigned a compromised scenario will successfully locate the **1930** emergency helpline and access situation-specific recovery steps within **60 seconds**.
- **H3:** Over **80%** of vernacular-preferring participants will report higher confidence in understanding warning rationale when using native language modes (Tamil/Hindi) compared to English.
- **H4 (Zero Leakage Invariant):** In **100%** of generated Evidence Receipts, synthetic personal secrets (Aadhaar, PAN, card numbers, OTPs) will be automatically redacted.

---

## 2. Participant Recruitment & Ethical Informed Consent

### 2.1 Target Participant Cohorts (Total Target: $N = 60$)
To ensure representative coverage across the Indian digital demographic, participants will be recruited across four distinct cohorts:

| Cohort | Target Size | Demographic Characteristics | Vulnerability Profile |
| :--- | :--- | :--- | :--- |
| **Cohort A: Young Digital Adopters** | $N = 15$ | College students, gig-economy workers (Age 18–25), daily UPI users | High exposure to Telegram task scams, fake job offers, investment lures |
| **Cohort B: Senior Citizens / Pensioners** | $N = 15$ | Retired individuals, pensioners (Age 60+), netbanking users | High fear of disconnection; frequent targets of digital arrest & fake KYC SMS |
| **Cohort C: First-Time / Vernacular Users** | $N = 15$ | Small-business owners, domestic workers, rural citizens; Tamil or Hindi preferred | Low English fluency, high susceptibility to phone and QR payment deception |
| **Cohort D: Community Digital Volunteers** | $N = 15$ | Cyber cell volunteers, common service center (CSC) operators, legal aid workers | Frontline responders who assist victims in filing police and bank complaints |

### 2.2 Ethical Safeguards & Informed Consent Process
1. **Voluntary Participation:** Participants may withdraw at any time without penalty or loss of benefits.
2. **Strictly Synthetic Test Materials:**
   - No participant will ever be shown a live malicious URL, active phishing page, or real malware APK.
   - All domains are restricted to the RFC 2606 reserved `.invalid` TLD (e.g. `sbi-kyc-verify.invalid`).
   - All phone numbers, UPI handles, and officer names are synthetic and fictional.
3. **No Real Credential Policy:**
   - Participants are explicitly instructed **never** to enter real banking passwords, UPI PINs, Aadhaar numbers, or OTPs into the test environment.
   - Standardized synthetic test tokens are provided (e.g., Aadhaar: `2345 6789 0123`, Card: `4111 1111 1111 1111`).
4. **Institutional Consent Form:**
   - Each participant must sign a plain-language consent form (available in English, Tamil, and Hindi) detailing the study's objective, observation methods, and privacy rights.

---

## 3. Synthetic Scenarios & Safe Test Fixtures

The pilot utilizes six controlled synthetic scenarios reflecting high-risk Indian cybercrime categories and benign controls:

| Scenario Code | Threat Category | Input Modality | Synthetic Content / Payload | Expected Safe Action |
| :--- | :--- | :--- | :--- | :--- |
| **SCEN-01** | Digital Arrest Extortion | Message / SMS | `"FINAL NOTICE: CBI Officer Rajesh Kumar. A non-bailable arrest warrant has been issued under PMLA. Contact Cyber Cell on WhatsApp +91-9988776655 immediately to verify Aadhaar or face detention."` | Disconnect, do not call, do not transfer money. |
| **SCEN-02** | Fake KYC Account Block | SMS with Link | `"Dear Customer, your SBI account will be suspended today. Update PAN & Aadhaar KYC immediately at: https://sbi-kyc-verify.invalid/login"` | Do not click, verify via official bank branch. |
| **SCEN-03** | Deceptive UPI Collect Trap | UPI Intent / QR | `upi://pay?pa=refund-desk@ybl&pn=QuickRefund&am=5000&tn=Electricity+Bill+Refund` | Do not approve payment, do not enter PIN. |
| **SCEN-04** | Malicious APK Dropper | Text / Download | `"India Post: Your parcel is on hold. Download the delivery tracking update app: https://indiapost-parcel.invalid/TrackOrder.apk"` | Do not download APK; delete message. |
| **SCEN-05** | Benign Merchant Payment (Control) | UPI QR | `upi://pay?pa=merchant@icici&pn=CoffeeShop&am=250` | Safe to approve payment. |
| **SCEN-06** | Ambiguous Input (Abstention) | Text Message | `"hello please call me urgently"` | Exercise caution, verify identity directly before acting. |

---

## 4. Evaluated User Tasks

Participants will complete five sequential tasks using the Mobile Scanner PWA (`http://localhost:8080/mobile-scanner/index.html`):

### Task 1: Threat Scan & Initial Assessment (Detection)
- *Instruction:* "You received this SMS message (SCEN-01 or SCEN-02) on your phone. Use VERITY to check whether it is safe or dangerous."
- *Measure:* Participant navigates to the scanner, pastes or selects the scenario, and observes the verdict card.

### Task 2: Warning Comprehension (Explain)
- *Instruction:* "Look at the result card. In your own words, what is the danger, and what does the card recommend you do next?"
- *Measure:* Accuracy of the participant's explanation compared to the displayed warning and Recommended Safe Next Step.

### Task 3: Vernacular Language Switching (Accessibility)
- *Instruction:* "Switch the language to Tamil (or Hindi). Read the Golden Safety Rule and the warning reasons. Does the text make sense to you?"
- *Measure:* Ease of language toggle, self-reported clarity, and identification of any awkward phrasing or transliteration issues.

### Task 4: Post-Compromise Recovery Journey (Recovery)
- *Instruction:* "Imagine you were panicked and already clicked the link and entered your NetBanking password. What steps does VERITY give you to protect yourself?"
- *Measure:* Latency to open Recovery Mode, select "Entered Account Password", identify the need to change passwords and call **1930**, and locate bank emergency helplines.

### Task 5: Evidence Receipt Generation & Export (Receipt)
- *Instruction:* "You want to file a complaint on cybercrime.gov.in. Generate an Evidence Receipt from VERITY and check what information it contains."
- *Measure:* Success in clicking "Generate Evidence Receipt", checking if confidential numbers were masked, and copying or downloading the markdown receipt.

---

## 5. Measured Usability & Cognitive Metrics

| Metric Name | Measurement Tool | Target Threshold | Rationale |
| :--- | :--- | :--- | :--- |
| **Correct Safe-Action Rate** | Binary (1 = Safe action chosen, 0 = Complied with scam) | $\ge 90\%$ | Ensures the interface prevents dangerous citizen behaviors. |
| **Warning Comprehension Score** | 5-point Likert Scale (1 = Completely confused, 5 = Clear rationale) | Mean $\ge 4.0 / 5.0$ | Validates that explanations avoid confusing technical jargon. |
| **Time to Decision** | Stopwatch (Seconds from viewing verdict to stating action) | $\le 10\text{ seconds}$ | Evaluates if the Action Card communicates urgency without cognitive overload. |
| **Recovery Latency** | Stopwatch (Seconds to locate 1930 and relevant checklist) | $\le 60\text{ seconds}$ | Critical for the "Golden Hour" inter-bank freeze window. |
| **Task Completion Rate** | Percentage of participants completing all 5 tasks | $\ge 90\%$ | Overall functional usability of the PWA. |
| **Accessibility Observations** | Qualitative error log (contrast, touch targets, screen-reader) | 0 critical blockers | Ensures seniors and low-vision users can navigate effectively. |
| **Privacy Comprehension** | Binary question: "Did your private message leave your phone?" | $\ge 85\%$ correct | Verifies that citizens understand local-only processing. |

---

## 6. Data Minimization & Retention Plan

- **Zero PII Collection:** No participant names, government IDs, phone numbers, or email addresses will be logged in study records. Participants are assigned anonymous identifiers (`P01` to `P60`).
- **Local Tabular Storage:** Study observations (timestamps, scores, qualitative feedback) are stored in encrypted, local tabular format (`pilot_observations.csv`).
- **Zero Cloud Egress:** Pilot evaluation machines run offline or strictly on local loopback (`http://localhost:8080`).
- **Data Retention & Disposal:** Raw evaluation notes are retained for 30 days post-study for audit reconciliation and destroyed thereafter.

---

## 7. Analysis Methodology & Pilot Reporting Template

Once real observations are gathered from human participants, results must be compiled using this standardized format:

```markdown
# VERITY 2.0 Usability Pilot Findings Report
- Pilot Dates: [YYYY-MM-DD to YYYY-MM-DD]
- Enrolled Participants: N = [Count] across [Cohorts]
- Overall Safe-Action Rate: [XX.X]%
- Mean Warning Comprehension: [X.X] / 5.0
- Mean Recovery Time to 1930: [XX] seconds
- Language Preference Breakdown: [XX]% EN, [XX]% TA, [XX]% HI, [XX]% TE
- Identified UX Friction Points: [List]
- Required Code Mitigations: [List]
```
