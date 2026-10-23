# Indian Cyber Fraud Labeled Benchmark Dataset

This benchmark dataset (`sample_data/indian_cyber_fraud_test_cases.json`) contains **30 curated and labeled test cases** covering the most prevalent cyber fraud vectors targeting Indian citizens, alongside verified legitimate Indian and global portals.

---

## 1. Safety & Defanging Policy

> [!IMPORTANT]
> **All scam domains in this dataset are 100% synthetic and defanged using the IETF RFC 2606 reserved `.invalid` top-level domain.**
> - **Zero Real Victims**: No actual victims' personal details, Aadhaar numbers, or account credentials are included.
> - **Zero Live Infrastructure**: Scams use synthetic hosts (e.g., `sbi-kyc-verification-portal.invalid`) that can never resolve on the public Internet.
> - **Safe Execution**: All test cases can be safely parsed, inspected, and run in offline CI/CD test runners without risk of accidental outbound exploitation.

---

## 2. JSON Schema Specification

Each test case adheres to the following strict schema:

```json
{
  "id": "string (unique test case identifier)",
  "category": "banking_kyc_typosquat | upi_collect_trap | digital_arrest | apk_dropper | legitimate_portal",
  "input": "string (raw URL, SMS/WhatsApp text corpus, or upi://pay URI)",
  "inputType": "url | text | upi",
  "expectedVerdict": "danger | safe",
  "expectedSignals": ["array of Verity threat signal IDs expected to trigger"],
  "notes": "string (threat context, mechanism, and security implications)"
}
```

### Field Definitions

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Unique kebab-case identifier for test reporting and tracking. |
| `category` | `string` | Threat classification category. |
| `input` | `string` | The exact string passed to Verity's portable `scanText(input)` engine. |
| `inputType` | `string` | Format indicator: `url` (web link), `text` (SMS / WhatsApp message), or `upi` (direct UPI intent URI). |
| `expectedVerdict` | `string` | High-level risk verdict: `'danger'` (threat score $\ge 70$) or `'safe'` (threat score $< 35$). |
| `expectedSignals` | `string[]` | Array of signal IDs (e.g., `SIG_KYC_CYBER_FRAUD`, `SIG_UPI_QR_COLLECT_TRAP`, `SIG_DIGITAL_ARREST_EXTORTION`, `SIG_MALICIOUS_APK_DROPPER`). |
| `notes` | `string` | Detailed analysis of the attack vector and social engineering technique. |

---

## 3. Threat Categories

### Category 1: Banking & KYC Typosquats (6 Cases)
Simulates phishing links distributed via SMS ("Aadhaar/PAN KYC expired; update within 24 hours to prevent account block"):
- **SBI**: `sbi-kyc-verification-portal.invalid/update-pan`
- **HDFC Bank**: `hdfc-netbanking-kyc-alert.invalid/login`
- **ICICI Bank**: `icici-banking-kyc-reward.invalid/verify`
- **Axis Bank**: `axis-bank-kyc-update-alert.invalid/security`
- **India Post**: `indiapost-kyc-delivery-update.invalid/track`
- **DigiLocker**: `digilocker-aadhaar-kyc-verify.invalid/doc`

### Category 2: UPI Collect Traps (5 Cases)
Simulates reverse-charge UPI scams where scammers pose as buyers (e.g., OLX), lottery organizers, or customer support:
- `upi://pay` URIs embedding `am=<amount>` alongside receive/refund/claim lures (`tn=OLX+Payment+Accept`, `tn=Claim+Cashback+Reward`, `tn=Receive+Ticket+Refund`).
- When a victim approves the notification or enters their UPI PIN expecting to *receive* funds, their account is instantly debited.

### Category 3: Digital Arrest Extortion Scripts (7 Cases)
Simulates high-pressure extortion scripts impersonating law enforcement:
- **CBI / Cyber Crime Investigation** (English & Hindi)
- **Customs & Narcotics Seizure Warrants** (English & Hindi)
- **TRAI Mobile Disconnection & MHA Notices** (English)
- **State Police Crime Branch Money Laundering Notices** (English & Tamil)
- Includes vernacular scripts in **Hindi (हिन्दी)** and **Tamil (தமிழ்)** targeting regional citizens with threats of virtual arrest warrants and demanding video call appearances.

### Category 4: Malicious APK Droppers (4 Cases)
Simulates drive-by dropper links and SMS APK distributions:
- `RTO_Challan.apk`: Traffic challan payment lure delivering spyware.
- `PM_Kisan_Yojana.apk`: Farmer subsidy lure delivering a banking Trojan.
- `BESCOM_Bill.apk`: Electricity power cut lure.
- `Wedding_Card.apk`: Social engineering lure masquerading as wedding photo/invitation apps.

### Category 5: Legitimate Portals (8 Cases — False Positive Control)
Critical control set to ensure **0% false positive rate** on essential services:
- `onlinesbi.sbi` (State Bank of India)
- `irctc.co.in` (Indian Railways IRCTC)
- `digilocker.gov.in` (Government of India DigiLocker)
- `incometax.gov.in` (Income Tax Department)
- `hdfcbank.com` (HDFC Bank Limited)
- `icicibank.com` (ICICI Bank)
- `accounts.google.com` (Google Identity / OAuth)
- `login.microsoftonline.com` (Microsoft Identity / Entra ID)

---

## 4. Running the Evaluation Suite

Execute the dedicated test runner via:

```bash
npm test
```

Or run the sample data test suite specifically:

```bash
node --test tests/sample_data.test.js
```

The test runner asserts:
1. Every scam test case produces a `danger` verdict (Score $\ge 70$).
2. Every legitimate portal produces a `safe` verdict (Score $< 35$, target 0).
3. False positive rate on legitimate portals is **exactly 0%**.
