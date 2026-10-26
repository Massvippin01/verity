# VERITY 3.0 | Safe Action Policy Specification

**Document Version:** 1.0.0  
**Status:** Policy Engine Implemented & Unit-Tested  
**Target Codebase:** `verity-extension/shared/safe-action-policy.js`  
**Test Suite:** `verity-extension/tests/safe_action_policy.test.js` (**7 PASS / 0 FAIL**)  
**Design Paradigm:** Deterministic Bounded Autonomy  

---

## 1. Safe Action Policy Engine Overview

The Safe Action Policy Engine translates versioned Verdict Contract objects (`verdict-contract.js`) into actionable, accountable citizen guidance and strictly bounded autonomous protective actions.

### 1.1 Policy Invariants
1. **Explicit ABSTAIN Preservation:** When the Verdict Contract is `ABSTAIN`, the policy outputs `MANUAL_VERIFY_OFFLINE` with **strictly `allowedAutomaticAction: null`**. Missing evidence is never interpreted as SAFE, and uncertain verdicts never trigger automatic disruption.
2. **Uncalibrated Model Guard:** Classification models without empirical confidence calibration cannot independently authorize consequential or automatic actions. Automation requires deterministic signature matches or calibrated confidence $\ge 0.85$.
3. **Reversibility of Autonomous Actions:** Only reversible protective actions (such as pausing an unverified `.exe` download or defusing an ad-rotator popunder) are permitted automatically. Every automatic action must expose a reversal hook (e.g. `RESUME_DOWNLOAD`).
4. **Prohibition of Irreversible Autonomous Disruption:** Irreversible actions (`BLOCK_BANK_ACCOUNT`, `PERMANENT_DELETE_FILE`, `REVOKE_ALL_SESSIONS`) are strictly prohibited from automated execution (`PROHIBITED_AUTOMATIC_ACTIONS`).
5. **Separation of Evidence vs Guidance:** Policy references specific technical evidence items and generates structured audit events for local Flight Recorder logging.

---

## 2. Policy Output Schema

```typescript
interface SafeActionPolicyOutcome {
  policyVersion: '1.0.0';
  evaluationId: string; // e.g. "pol_k9a2bc_x4"
  timestamp: string;    // ISO-8601
  scanId: string;
  riskClassification: 'SAFE' | 'CAUTION' | 'HIGH_RISK' | 'ABSTAIN';
  threatCategory?: string;
  abstentionReason?: string | null;

  recommendedAction: {
    id: string; // e.g. "DISPLAY_SCAM_ACTION_CARD", "ALLOW_NORMAL", "MANUAL_VERIFY_OFFLINE"
    label: string;
    urgency: 'NORMAL' | 'ADVISORY' | 'HIGH' | 'CRITICAL';
    safeNextStep: string;
    reason?: string;
    emergencyHelpline?: string; // Default: "1930"
  };

  allowedAutomaticAction: null | {
    actionType: string; // e.g. "PAUSE_AND_PROMPT_DOWNLOAD", "DEFUSE_ROGUE_POPUNDER"
    isReversible: true;
    reversalAction: string; // e.g. "RESUME_DOWNLOAD"
    rationale: string;
    requiredPermission: string;
  };

  requiredUserConfirmation: null | {
    prompt: string;
    options: string[];
  };

  confidenceAndUncertainty: {
    riskScore: number;
    calibratedConfidence: number | null;
    isUncalibrated: boolean;
    uncertaintyState: string;
    knownLimitations: string[];
  };

  reassessment: {
    requiresReassessment: boolean;
    ttlSeconds: number;
    condition?: string;
  };

  auditEvent: {
    policyVersion: string;
    evaluationId: string;
    scanId: string;
    timestamp: string;
    decision: string;
    automaticActionPermitted: boolean;
    automaticActionType?: string | null;
    confirmationRequired: boolean;
  };
}
```

---

## 3. Decision Matrix

| Verdict Input | Calibrated Confidence | Hard Override Evidence | Platform Support Flag | Policy Decision | Automatic Action Permitted | User Confirmation Required |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `SAFE` (0–30) | $\ge 0.90$ | None | Any | `ALLOW_NORMAL` | `null` | `null` |
| `ABSTAIN` | Any / Null | None | Any | `MANUAL_VERIFY_OFFLINE` | `null` (Strict) | `null` |
| `CAUTION` (35–65) | Any | None | Any | `EXERCISE_CAUTION` | `null` | `null` |
| `HIGH_RISK` | Null (Uncalibrated) | None | Any | `DISPLAY_SCAM_ACTION_CARD` | `null` (Gated) | Optional prompt |
| `HIGH_RISK` | $\ge 0.85$ | `SIG_MALICIOUS_DOWNLOAD_EXE` | `supportsDownloadPause` | `PAUSE_AND_PROMPT_DOWNLOAD` | `PAUSE_AND_PROMPT_DOWNLOAD` | `['Cancel & Delete', 'Download Anyway']` |
| `HIGH_RISK` | $\ge 0.85$ | `SIG_AD_ROTATOR_POPUNDER` | `supportsPopupDefusal` | `DEFUSE_ROGUE_POPUNDER` | `DEFUSE_ROGUE_POPUNDER` | `null` (Reversal hook available) |
| `HIGH_RISK` | Any | `SIG_DIGITAL_ARREST_COERCION` | Any | `RECOMMEND_EMERGENCY_RECOVERY` | `null` | `['Open Recovery Guide', 'Dismiss']` |

---

## 4. Test Verification

Verified by [tests/safe_action_policy.test.js](file:///c:/PROJECTS/verity_v2-main/verity_v2-main/verity-extension/tests/safe_action_policy.test.js) (7 passing tests):
- Invariant 1: Explicit ABSTAIN never triggers automatic disruption.
- Invariant 2: Benign SAFE verdicts allow normal proceeding without side-effects.
- Invariant 3: Uncalibrated models cannot independently authorize automatic actions.
- Invariant 4: Bounded reversible protective actions authorized for verified threats.
- Invariant 5: Severe extortion routes to Emergency Recovery with confirmation.
- Invariant 6: Irreversible actions are PROHIBITED from automated execution.
- Invariant 7: Emits structured audit event for local flight recorder.
