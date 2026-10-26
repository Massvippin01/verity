# VERITY 3.0 | Authenticated Threat-Pack Specification

**Document Version:** 1.0.0  
**Status:** Verification Interface Implemented & Unit-Tested  
**Target Codebase:** `verity-extension/shared/threat-pack-verifier.js`  
**Test Suite:** `verity-extension/tests/threat_pack_verifier.test.js` (**10 PASS / 0 FAIL**)  
**Cryptographic Primitive:** Ed25519 (RFC 8032) via standard `node:crypto` and Web Crypto API  

---

## 1. Threat Pack Schema Specification

Authenticated Threat Packs allow offline-capable, cryptographically verified indicator updates without requiring direct cloud surveillance of citizen devices.

### 1.1 Complete JSON Schema (Schema Version: `1.0.0`)

```json
{
  "schemaVersion": "1.0.0",
  "packId": "bharat-threat-pack-2026-10-alpha",
  "sequence": 105,
  "issuer": "verity-threat-intel-authority",
  "keyId": "key-ed25519-v1",
  "createdAt": "2026-10-25T12:00:00.000Z",
  "expiresAt": "2026-10-26T12:00:00.000Z",
  "indicators": [
    {
      "type": "domain",
      "value": "sbi-kyc-verify-portal.invalid",
      "threatCategory": "fake_kyc_account_blocking",
      "severity": "HIGH_RISK",
      "confidence": 0.99,
      "provenance": "I4C-advisory-2026-10",
      "action": "block"
    },
    {
      "type": "vpa",
      "value": "refund-desk@ybl",
      "threatCategory": "upi_collect_payment_deception",
      "severity": "HIGH_RISK",
      "confidence": 0.95,
      "provenance": "NPCI-alert-2026",
      "action": "block"
    }
  ],
  "revocations": [
    {
      "packId": "bharat-threat-pack-2026-09-deprecated",
      "reason": "Superseded by sequence 105"
    }
  ],
  "signature": "3a9f8e... (128-hex character Ed25519 signature)"
}
```

### 1.2 Schema Field Definitions

| Field Name | Type | Description | Invariant & Validation Rules |
| :--- | :--- | :--- | :--- |
| `schemaVersion` | String | Format version | Must equal `"1.0.0"`. |
| `packId` | String | Unique bundle identifier | Non-empty alphanumeric string. |
| `sequence` | Integer | Monotonically increasing sequence number | **Anti-Rollback Guard:** Incoming sequence must be strictly greater than active sequence ($seq_{in} > seq_{current}$). |
| `issuer` | String | Organization publishing the bundle | Must match registered issuer in trusted keystore. |
| `keyId` | String | Identifier of the public key | Must exist in local trusted keystore. |
| `createdAt` | ISO-8601 String | Timestamp of bundle creation | Clock-skew guard: $T_{created} \le T_{now} + 120\text{s}$. |
| `expiresAt` | ISO-8601 String | Bundle validity deadline | **Expiry Guard:** $T_{now} < T_{expires}$. Expired packs are rejected. |
| `indicators` | Array | Threat indicator list | Allowed types: `domain`, `vpa`, `phone`, `url_pattern`, `apk_sha256`. Normalization enforced. |
| `revocations` | Array | Revoked pack or indicator IDs | List of superseded identifiers. |
| `signature` | Hex String | Ed25519 cryptographic signature | Computed over canonical JSON representation of payload (excluding signature field). |

---

## 2. Cryptographic Verification Interface

The verification interface is implemented in `verity-extension/shared/threat-pack-verifier.js`:

```javascript
import { verifyThreatPack } from './shared/threat-pack-verifier.js';

const result = verifyThreatPack(incomingPack, {
  trustedKeys: localKeystoreMap,
  currentSequence: activeInstalledSequence,
  currentTimestamp: Date.now()
});

if (result.verified) {
  // Install sanitized, verified indicators
  installIndicators(result.verifiedPack.indicators);
} else {
  // Reject update and log security event
  console.warn(`[ThreatPack] Rejected: ${result.errorCode} - ${result.reason}`);
}
```

### 2.1 Threat Pack Security Invariants
1. **Zero Custom Cryptography:** Relies exclusively on RFC 8032 Ed25519 digital signatures.
2. **Replay & Rollback Protection:** Sequence numbers must be strictly increasing. If an attacker replays an older signed bundle (e.g. from 2 weeks ago), the sequence check fails with `SEQUENCE_ROLLBACK_DETECTED`.
3. **Key Revocation & Rotation:** If an authority key is compromised, its status is updated to `status: 'revoked'` in the keystore. Any bundle signed with a revoked key fails with `SIGNING_KEY_REVOKED`.
4. **Canonical Serialization:** Payload keys are sorted recursively (`canonicalJsonStringify`) prior to signing and verification, preventing hash mismatches due to object key ordering.
5. **No Crowdsourced Blind Trust:** A threat indicator is never verified solely because multiple untrusted users submitted it. Only indicators originating from verified provenance (e.g. CERT-In, I4C, NPCI) and signed by an authorized key are accepted.

---

## 3. Current Implementation Status & Test Verification

- **Code:** Implemented in [threat-pack-verifier.js](file:///c:/PROJECTS/verity_v2-main/verity_v2-main/verity-extension/shared/threat-pack-verifier.js).
- **Automated Tests:** 10 test cases passing in [tests/threat_pack_verifier.test.js](file:///c:/PROJECTS/verity_v2-main/verity_v2-main/verity-extension/tests/threat_pack_verifier.test.js):
  - Valid Ed25519 signature verification and indicator normalization.
  - Tampered indicator payload rejection (`INVALID_SIGNATURE`).
  - Corrupted signature rejection (`INVALID_SIGNATURE`).
  - Sequence rollback rejection (`SEQUENCE_ROLLBACK_DETECTED`).
  - Expired pack rejection (`PACK_EXPIRED`).
  - Future timestamp beyond clock skew rejection (`FUTURE_TIMESTAMP_DETECTED`).
  - Revoked key rejection (`SIGNING_KEY_REVOKED`).
  - Untrusted key ID rejection (`UNTRUSTED_KEY_ID`).
  - Issuer mismatch rejection (`ISSUER_MISMATCH`).
  - Malformed schema rejection (`MALFORMED_SCHEMA`).
- **Production Status:** Local test keys and verification interface are fully operational. Distribution network infrastructure (CDN/key server) is documented as **PLANNED** for Milestone 2.
