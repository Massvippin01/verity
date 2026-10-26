# VERITY 3.0 | Incident Flight Recorder Specification

**Document Version:** 1.0.0  
**Status:** Flight Recorder Engine Implemented & Unit-Tested  
**Target Codebase:** `verity-extension/shared/flight-recorder.js`  
**Test Suite:** `verity-extension/tests/flight_recorder.test.js` (**6 PASS / 0 FAIL**)  
**Storage Architecture:** Local In-Memory / LocalStorage Circular Ring Buffer (Max 50 Records)  

---

## 1. Flight Recorder Architecture & Data Minimization

The Incident Flight Recorder maintains an on-device chronological timeline of detected security events, forensic evidence, citizen responses, and completed recovery steps.

### 1.1 Data Minimization & Privacy Invariants
1. **Fact vs. Assertion Separation:** Observed technical findings (e.g. domain age, entropy, NPCI URI parameters) are strictly segregated from unverified citizen claims (e.g. "caller claimed to be from CBI").
2. **No Raw Message Storage By Default:** To prevent storing sensitive extortion or private chats on the device, raw messages are dropped immediately after forensic parsing. Storing a context snippet requires explicit user consent, and is capped at 200 characters with full secret scrubbing.
3. **Automated Secret Scrubbing:** Cleartext passwords, Aadhaar numbers (`XXXX-XXXX-0123`), PAN numbers (`ABCDE****F`), Credit/Debit Card PANs (`****-****-****-1111`), CVVs (`[REDACTED_CVV]`), OTPs (`[REDACTED_PIN]`), and phone numbers (`+91-XXXXX-XX210`) are stripped before storage.
4. **Bounded Capacity Ring Buffer:** Enforces a default 50-event limit. When capacity is exceeded, the oldest incident is automatically purged.
5. **Tamper-Detection Checksums:** Each record calculates a SHA-256 integrity digest over canonical JSON. Checksums recalculate whenever the citizen logs a recovery step.
6. **Non-Judicial Disclaimer:** All exports include a mandatory legal disclaimer: *"This document is a client-side diagnostic incident timeline generated on-device by Verity. It does NOT constitute legally certified judicial forensic evidence."*

---

## 2. Flight Record Schema

```json
{
  "recordId": "rec_m8a1b2_x9",
  "timestamp": "2026-10-25T12:00:00.000Z",
  "scanId": "scn_k9a2bc_x4",
  "modality": "message",
  "threatCategory": "digital_arrest_extortion",
  "riskClassification": "HIGH_RISK",
  "riskScore": 90,
  "policyVersion": "1.0.0",
  "recommendedActionId": "RECOMMEND_EMERGENCY_RECOVERY",
  "automatedActionTaken": null,
  
  "observedFacts": [
    "Origin protocol: WhatsApp VoIP",
    "Regex match: PMLA Section 45 non-bailable warrant coercion",
    "Lexical match: Video interrogation demand"
  ],

  "userAssertions": {
    "reportedSender": "Caller claimed to be CBI Officer Rajesh Kumar",
    "claimedDemand": "Demanded transfer to RBI verification account"
  },

  "sanitizedSnippet": "FINAL NOTICE: CBI Officer Rajesh Kumar. A non-bailable arrest warrant has been issued...",

  "userInteractions": [
    {
      "timestamp": "2026-10-25T12:01:15.000Z",
      "action": "EMERGENCY_CALL_INITIATED",
      "stepId": "CALL_1930",
      "note": "Citizen dialed 1930 Helpline"
    },
    {
      "timestamp": "2026-10-25T12:02:30.000Z",
      "action": "RECOVERY_STEP_DONE",
      "stepId": "DISCONNECT_CALL",
      "note": "WhatsApp call disconnected"
    }
  ],

  "recoveryProgress": [
    "CALL_1930",
    "DISCONNECT_CALL"
  ],

  "checksum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

---

## 3. Public API Methods

- `recordIncident(params)`: Inserts a new incident into the ring buffer, applying secret sanitization and computing the initial SHA-256 checksum.
- `logUserInteraction(recordId, interaction)`: Appends user actions or recovery progress steps and re-computes the checksum.
- `deleteRecord(recordId)`: Removes an individual incident from storage upon user request.
- `purgeAll()`: Instantly clears all records from the timeline.
- `exportTimelineJson()`: Generates structured JSON export with disclaimer banner.
- `exportTimelineMarkdown()`: Generates human-readable Markdown export for attaching to `cybercrime.gov.in`.

---

## 4. Test Verification

Verified by [tests/flight_recorder.test.js](file:///c:/PROJECTS/verity_v2-main/verity_v2-main/verity-extension/tests/flight_recorder.test.js) (6 passing tests):
- Fact vs Assertion separation & Default no-raw-message storage.
- Secret Sanitizer masks Aadhaar, PAN, Card, OTP, CVV, Phone, and Password.
- Ring Buffer capacity prunes oldest records.
- User interaction logging and recovery progress tracking.
- Single incident deletion and complete purge.
- Markdown and JSON exports include Legal Disclaimer.
