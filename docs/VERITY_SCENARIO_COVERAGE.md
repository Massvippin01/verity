# VERITY 2.0 (Bharat Shield) — True Detection & Scenario Coverage Matrix

**Evaluation Date**: October 2026  
**Auditor**: Principal Cybersecurity Architect & Fraud Prevention Researcher  
**Status Standard**:  
- `Implemented and tested`: Verified in active test suite with dedicated code and passing assertions.
- `Implemented but insufficiently tested`: Working detector exists, but edge cases or held-out tests are sparse.
- `Partially supported`: Certain facets detected (e.g. lexical or brand flags), but end-to-end intent relies on partial heuristics.
- `Not implemented`: No current code exists to identify this specific threat.
- `Blocked by platform or external dependency`: Outside browser/PWA sandbox capabilities.
- `Not safely inferable from available evidence`: Threat lacks sufficient client-side signals without invasive monitoring.

---

## 1. Scenario Taxonomy Matrix Overview

The following matrix documents the 20 core cyber-fraud categories prevalent in the Indian digital ecosystem.

| # | Threat Category | Implemented Detectors & Source Files | Supported Input Modalities | Implementation Status | Confidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | Phishing & Credential Harvesting | `rules.js`, `brand-detector.js`, `favicon-matcher.js`, `content-script.js` | URL, DOM HTML | **Implemented and tested** | High |
| **2** | Fake Refunds, Cashback & Reward Traps | `upi-forensics.js`, `text-scanner.js` | UPI Intent, Text Message, URL | **Implemented and tested** | High |
| **3** | UPI Collect Requests & Payment Deception | `upi-forensics.js`, `text-scanner.js` | `upi://pay` URI, QR Code Payload | **Implemented and tested** | High |
| **4** | QR-Code Payment & Malicious Link Lures (Quishing) | `mobile-scanner/scanner.js`, `upi-forensics.js` | Camera Stream, QR Image, Raw URI | **Implemented and tested** | High |
| **5** | Bank & Payment Provider Impersonation | `brand-detector.js`, `bharat-scam-detectors.js` | URL, Text Message, DOM Form | **Implemented and tested** | High |
| **6** | Fake KYC Updates & Account-Blocking Threats | `bharat-scam-detectors.js`, `text-scanner.js` | SMS, WhatsApp, URL | **Implemented and tested** | High |
| **7** | Courier, Parcel & Delivery Scams | `text-scanner.js`, `rules.js` | SMS, WhatsApp, URL | **Implemented and tested** | High |
| **8** | Job, Recruitment & Task Scams | `secv-intent-engine.js`, `text-scanner.js` | WhatsApp, Telegram text, URL | **Partially supported** | Medium |
| **9** | Investment, Trading & Guaranteed Returns | `secv-intent-engine.js`, `rules.js` | Messaging Text, URL | **Partially supported** | Medium |
| **10** | Loan, Credit & Fee-Advance Scams | `secv-intent-engine.js`, `text-scanner.js` | Text, URL | **Partially supported** | Medium |
| **11** | Government-Benefit & Public-Service Impersonation | `bharat-scam-detectors.js`, `rules.js` | URL, Text Message | **Implemented and tested** | High |
| **12** | Fake Shopping & Marketplace Fraud (OLX Traps) | `upi-forensics.js`, `brand-detector.js` | Text, UPI URI, URL | **Implemented and tested** | High |
| **13** | Tech-Support & Remote-Access RAT Lures | `file-magic-inspector.js`, `content-script.js` | URL, Downloaded File | **Partially supported** | Medium |
| **14** | Romance, Friendship & Social Engineering | `secv-intent-engine.js` | Plain text | **Not safely inferable** | Low |
| **15** | Digital Arrest Threats, Coercion & Extortion | `bharat-scam-detectors.js`, `text-scanner.js` | Text Message, URL, WebRTC/DOM | **Implemented and tested** | High |
| **16** | Malicious APKs & Suspicious Downloads | `bharat-scam-detectors.js`, `file-magic-inspector.js` | File Download, URL, APK name | **Implemented and tested** | High |
| **17** | Suspicious Phone Numbers & Sender IDs | None (No client-side SMS header inspection) | Sender Header | **Blocked by platform** | High (Limitation) |
| **18** | Account Takeover & Fake Recovery Scams | `rules.js`, `content-script.js` | URL, DOM form | **Partially supported** | Medium |
| **19** | Benign but Unusual / Legitimate Payments | `payment-gateway-allowlist.js`, `enterprise-whitelist.js` | URL, UPI URI, Checkout DOM | **Implemented and tested** | High |
| **20** | Unknown, Novel or Insufficiently Evidenced | `shared/verdict-contract.js` (Abstention Engine) | Any input | **Implemented and tested** | High |

---

## 2. In-Depth Category Forensic Analysis

### 1. Phishing & Credential Harvesting
* **Threat Objective & Attacker Behaviour**: Steal netbanking passwords, credit card numbers, ATM PINs, and corporate SSO credentials using deceptive clones of trusted institutions.
* **Intended Victim**: Citizens accessing banking, email, or e-commerce services on mobile or desktop browsers.
* **Observable Evidence Available to VERITY**: FQDN, subdomain count, Levenshtein distance against known brands, DOM password/card input fields on non-official origins, MurmurHash3 favicon matching, and MAIN-world exfiltration traps.
* **Evidence Unavailable to VERITY**: Backend database processing, DNS records resolved over private VPNs, or credentials transmitted over offline telephone calls.
* **Supported Input Modalities**: URL, Full Webpage DOM.
* **Existing Detector & Location**: `verity-extension/background/rules.js`, `verity-extension/background/brand-detector.js`, `verity-extension/content/content-script.js`.
* **Expected Result & Uncertainty Handling**: High Risk (`danger` / `score >= 85`) if credential form appears on an unverified domain; abstains if domain is an official allowlisted IdP.
* **False-Positive Risks**: Internal corporate login portals or multi-tenant staging subdomains. Mitigated via `enterprise-whitelist.js`.
* **Prevention & Recovery Actions**:
  * *Prevention*: Warn/block navigation; do not submit passwords or cards.
  * *Recovery*: If submitted, immediately change credentials from a trusted device and call bank helpline to freeze netbanking.
* **Test Fixtures**: `verity-extension/tests/bharat_shield_hackathon.test.js`, `sample_data/indian_cyber_fraud_test_cases.json` (`sbi-kyc-typosquat`).
* **Implementation Status**: **Implemented and tested**.

### 2. Fake Refunds, Cashback & Reward Traps
* **Threat Objective**: Trick victims into believing they are receiving money, while actually debiting their accounts via deceptive UPI collect links or forms.
* **Intended Victim**: Digital payment users, OLX sellers, rewards seekers.
* **Observable Evidence Available to VERITY**: `upi://pay` URI parameters (`am`, `pa`, `pn`, `tn`), surrounding text mentioning "cashback", "refund", "claim", or "prize".
* **Evidence Unavailable to VERITY**: Bank balance, payment app internal authentication screens.
* **Supported Input Modalities**: Text message, WhatsApp forward, QR code, Web link.
* **Existing Detector & Location**: `verity-extension/shared/upi-forensics.js`, `verity-extension/shared/text-scanner.js`.
* **Expected Result & Uncertainty Handling**: Flagged with `SIG_UPI_QR_COLLECT_TRAP` (`danger`, score 100).
* **False-Positive Risks**: Legitimate merchant checkouts with discounts. Mitigated by `isLegitimateCheckoutFlow` and verified merchant code (`mc`) whitelist.
* **Prevention & Recovery Actions**:
  * *Prevention*: Remind user that receiving money never requires entering a UPI PIN.
  * *Recovery*: If approved, report immediately to 1930 / bank to invoke CFCFRMS transaction halt during the Golden Hour.
* **Test Fixtures**: `sample_data/indian_cyber_fraud_test_cases.json` (`upi-paytm-cashback-trap`).
* **Implementation Status**: **Implemented and tested**.

### 3. UPI Collect Requests & Payment Deception
* **Threat Objective**: Send unrequested P2P collect mandates with deceptive remarks (e.g. "Payment Received", "Income Tax Refund") to debit the user.
* **Intended Victim**: Small business merchants, peer-to-peer marketplace users.
* **Observable Evidence Available to VERITY**: Raw `upi://pay` intent string, unverified payee handle (`@ybl`, `@okhdfcbank`), non-merchant category.
* **Evidence Unavailable to VERITY**: NPCI switch transaction status, bank SMS delivery.
* **Supported Input Modalities**: `upi://pay` URI, QR image scan.
* **Existing Detector & Location**: `verity-extension/shared/upi-forensics.js`.
* **Expected Result & Uncertainty Handling**: Hard override `danger` verdict if collect amount is paired with receive keywords.
* **False-Positive Risks**: Peer splitting bills. Mitigated by checking if explicit refund/cashback keywords are absent.
* **Prevention & Recovery Actions**:
  * *Prevention*: Decline the mandate in UPI app.
  * *Recovery*: Note transaction UTR number, call 1930 and bank branch.
* **Test Fixtures**: `verity-extension/tests/world_class_wow_features.test.js` (`NPCI Forensics 1-3`).
* **Implementation Status**: **Implemented and tested**.

### 4. QR-Code Payment & Malicious Link Lures (Quishing)
* **Threat Objective**: Embed deceptive UPI payment intents or phishing URLs into physical or digital QR codes to bypass email/SMS text filters.
* **Intended Victim**: Shoppers, restaurant diners, online buyers.
* **Observable Evidence Available to VERITY**: Decoded string from client-side BarcodeDetector, protocol scheme (`upi://` vs `https://`).
* **Evidence Unavailable to VERITY**: Physical stickers placed over legitimate store QR stands.
* **Supported Input Modalities**: Live camera video stream, uploaded screenshot / photo.
* **Existing Detector & Location**: `mobile-scanner/scanner.js` (`handleQrFile`, `toggleLiveCameraScanner`), `upi-forensics.js`.
* **Expected Result & Uncertainty Handling**: Safely decodes and inspects content in an offline sandbox before execution; flags collect traps or malicious URLs.
* **False-Positive Risks**: Benign static merchant QR codes. Verified merchant codes (`mc=5411` etc.) pass cleanly.
* **Prevention & Recovery Actions**:
  * *Prevention*: Inspect payee name on VERITY display before scanning inside UPI app.
  * *Recovery*: If paid, initiate UPI chargeback dispute through app and file on cybercrime.gov.in.
* **Test Fixtures**: `verity-extension/tests/verify_zero_trust_defenses.js` (`Zero-Trust Case 3: Quishing`).
* **Implementation Status**: **Implemented and tested**.

### 5. Bank & Payment Provider Impersonation
* **Threat Objective**: Clone visual identities of SBI, HDFC, ICICI, Paytm, PhonePe, or Google Pay to capture user credentials or trigger unauthorized fund transfers.
* **Intended Victim**: Banking and fintech customers.
* **Observable Evidence Available to VERITY**: Domain mismatch against official whitelist (`brands.json`), MurmurHash3 favicon matching, page titles.
* **Evidence Unavailable to VERITY**: Legitimate out-of-band communication sent by actual bank.
* **Supported Input Modalities**: URL, In-browser DOM.
* **Existing Detector & Location**: `verity-extension/background/brand-detector.js`, `verity-extension/background/favicon-matcher.js`.
* **Expected Result & Uncertainty Handling**: Flags `SIG_DOM_BRAND_IMPERSONATION` or `SIG_CROSS_ORIGIN_BRAND_ASSET_THEFT` (`score >= 85`).
* **False-Positive Risks**: Official regional bank portals or third-party payment partner domains. Mitigated by `legit-domains.js`.
* **Prevention & Recovery Actions**:
  * *Prevention*: Navigate only to bookmarked official URLs (e.g. `onlinesbi.sbi`).
  * *Recovery*: Call official bank customer care from back of debit card.
* **Test Fixtures**: `verity-extension/tests/bharat_shield_hackathon.test.js`.
* **Implementation Status**: **Implemented and tested**.

### 6. Fake KYC Updates & Account-Blocking Threats
* **Threat Objective**: Leverage psychological panic ("Your account will be suspended within 24 hours") to force victims onto phishing sites collecting PAN, Aadhaar, and OTPs.
* **Intended Victim**: Bank account holders, SIM card users (TRAI / BSNL KYC lures).
* **Observable Evidence Available to VERITY**: Keywords ("KYC", "pan update", "account suspended", "blocked", "immediate action"), synthetic domains (`.invalid`, `.top`, `.xyz`).
* **Evidence Unavailable to VERITY**: Actual KYC status with the bank or telecom operator.
* **Supported Input Modalities**: SMS text, WhatsApp message, URL.
* **Existing Detector & Location**: `verity-extension/content/bharat-scam-detectors.js`, `verity-extension/shared/text-scanner.js`.
* **Expected Result & Uncertainty Handling**: Flags `SIG_KYC_CYBER_FRAUD` (`danger`, score 90).
* **False-Positive Risks**: Official transactional SMS reminding customer of routine KYC renewal. Mitigated by verifying presence of suspicious external links.
* **Prevention & Recovery Actions**:
  * *Prevention*: Banks never request KYC updates via WhatsApp or third-party links. Visit official branch.
  * *Recovery*: If Aadhaar/PAN shared, lock Aadhaar biometrics on UIDAI portal (`myaadhaar.uidai.gov.in`).
* **Test Fixtures**: `sample_data/indian_cyber_fraud_test_cases.json` (`sbi-kyc-typosquat`).
* **Implementation Status**: **Implemented and tested**.

### 7. Courier, Parcel & Delivery Scams
* **Threat Objective**: Impersonate India Post, FedEx, BlueDart claiming a package is withheld for wrong address, demanding ₹25 fee to steal card credentials.
* **Intended Victim**: E-commerce shoppers.
* **Observable Evidence Available to VERITY**: Brand tokens ("India Post", "Speed Post"), address update lures, low-value fee traps, non-gov domains.
* **Evidence Unavailable to VERITY**: User's real package tracking numbers.
* **Supported Input Modalities**: SMS text, URL.
* **Existing Detector & Location**: `verity-extension/shared/text-scanner.js`, `verity-extension/background/rules.js`.
* **Expected Result & Uncertainty Handling**: Flags `SIG_FAKE_PARCEL_DELIVERY_LURE` (`danger`, score 85).
* **False-Positive Risks**: Official delivery notification with tracking link. Mitigated by allowlisting `indiapost.gov.in`.
* **Prevention & Recovery Actions**:
  * *Prevention*: Check tracking on official India Post website only.
  * *Recovery*: Block debit/credit card immediately if card details were entered.
* **Test Fixtures**: `sample_data/indian_cyber_fraud_test_cases.json` (`indiapost-kyc-delivery`).
* **Implementation Status**: **Implemented and tested**.

### 8. Job, Recruitment & Task Scams
* **Threat Objective**: Promise lucrative work-from-home earnings (e.g. YouTube video liking, Telegram rating tasks), requiring advance deposits before payouts.
* **Intended Victim**: Job seekers, students, homemakers.
* **Observable Evidence Available to VERITY**: Psycholinguistic urgency, high-return task keywords, Telegram channel invite links.
* **Evidence Unavailable to VERITY**: Private Telegram/WhatsApp chat history.
* **Supported Input Modalities**: Message text, URL.
* **Existing Detector & Location**: `verity-extension/shared/secv-intent-engine.js`.
* **Expected Result & Uncertainty Handling**: Emits `caution` advisory on suspicious employment lures; refrains from definitive block without verified malicious link.
* **False-Positive Risks**: Legitimate freelance job postings.
* **Prevention & Recovery Actions**:
  * *Prevention*: Legitimate employers never ask candidates to pay for tasks or training upfront.
  * *Recovery*: Stop sending money immediately; file complaint on cybercrime.gov.in.
* **Test Fixtures**: Synthetic task scam scenarios.
* **Implementation Status**: **Partially supported**.

### 9. Investment, Trading & Guaranteed Returns
* **Threat Objective**: Entice citizens into fraudulent "VIP trading apps" or crypto pools promising 200% weekly returns, then locking withdrawals.
* **Intended Victim**: Retail investors, retirees.
* **Observable Evidence Available to VERITY**: Unrealistic guaranteed return language, unregistered APK downloads, unregulated broker domains.
* **Evidence Unavailable to VERITY**: Off-platform bank transfers or crypto transaction ledgers.
* **Supported Input Modalities**: Text message, URL.
* **Existing Detector & Location**: `verity-extension/shared/secv-intent-engine.js`, `verity-extension/background/rules.js`.
* **Expected Result & Uncertainty Handling**: Flags financial risk keywords on untrusted domains.
* **False-Positive Risks**: Legitimate SEBI-registered broker promotions.
* **Prevention & Recovery Actions**:
  * *Prevention*: Check SEBI registration list (`sebi.gov.in`) before investing.
  * *Recovery*: File complaint with SEBI SCORES and local Cyber Crime Cell.
* **Test Fixtures**: Synthetic investment scam text fixtures.
* **Implementation Status**: **Partially supported**.

### 10. Loan, Credit & Fee-Advance Scams
* **Threat Objective**: Offer instant, collateral-free personal loans via deceptive apps, demanding "processing fee" or "GST deposit" upfront, then blackmailing victims using contact list exfiltration.
* **Intended Victim**: Financially distressed citizens.
* **Observable Evidence Available to VERITY**: Loan approval promises without credit check, direct `.apk` downloads, advance fee requests.
* **Evidence Unavailable to VERITY**: Mobile phone contact book access (PWA sandbox).
* **Supported Input Modalities**: SMS text, URL, APK download link.
* **Existing Detector & Location**: `verity-extension/shared/text-scanner.js`, `verity-extension/background/rules.js`.
* **Expected Result & Uncertainty Handling**: Flags predatory loan keywords and unverified APK droppers.
* **False-Positive Risks**: NBFC pre-approved loan advertisements.
* **Prevention & Recovery Actions**:
  * *Prevention*: Only download RBI-registered lending apps from Google Play Store; never pay processing fees upfront.
  * *Recovery*: Report illegal loan harassment to RBI Sachet portal (`sachet.rbi.org.in`) and 1930.
* **Test Fixtures**: Synthetic loan scam text fixtures.
* **Implementation Status**: **Partially supported**.

### 11. Government-Benefit & Public-Service Impersonation
* **Threat Objective**: Masquerade as PM Kisan, PM Awas Yojana, Ladli Behna, or Free Electricity subsidy portals to steal citizen details or distribute trojans.
* **Intended Victim**: Rural citizens, subsidy beneficiaries.
* **Observable Evidence Available to VERITY**: Government department acronyms on non-`.gov.in` / non-`.nic.in` domains, malicious APK filenames (`pm_kisan.apk`).
* **Evidence Unavailable to VERITY**: State department backend portals.
* **Supported Input Modalities**: URL, Text, APK link.
* **Existing Detector & Location**: `verity-extension/content/bharat-scam-detectors.js`, `verity-extension/background/rules.js`.
* **Expected Result & Uncertainty Handling**: Hard override `danger` verdict if government brand is claimed on non-governmental TLD.
* **False-Positive Risks**: None when checking official `.gov.in` domain hierarchy.
* **Prevention & Recovery Actions**:
  * *Prevention*: Official Indian government portals strictly end in `.gov.in` or `.nic.in`.
  * *Recovery*: File report on National Cyber Crime Reporting Portal.
* **Test Fixtures**: `sample_data/indian_cyber_fraud_test_cases.json`.
* **Implementation Status**: **Implemented and tested**.

### 12. Fake Shopping Sites & Marketplace Scams
* **Threat Objective**: Advertise expensive electronics/clothing at 90% discount, collect card or UPI payments, and never ship goods.
* **Intended Victim**: Online bargain shoppers.
* **Observable Evidence Available to VERITY**: Brand typosquatting (e.g. `amaz0n-sale.shop`), freshly registered domains (RDAP age < 30 days), absence of legitimate payment gateways.
* **Evidence Unavailable to VERITY**: Physical warehouse or inventory verification.
* **Supported Input Modalities**: URL, Page DOM.
* **Existing Detector & Location**: `verity-extension/background/brand-detector.js`, `verity-extension/background/rdap-sentinel.js`.
* **Expected Result & Uncertainty Handling**: High risk if brand variant on novel domain with checkout forms.
* **False-Positive Risks**: Newly launched legitimate boutique stores.
* **Prevention & Recovery Actions**:
  * *Prevention*: Verify company contact information and check official domain.
  * *Recovery*: File a chargeback dispute with credit card issuing bank.
* **Test Fixtures**: Synthetic e-commerce phish fixtures.
* **Implementation Status**: **Implemented and tested**.

### 13. Tech-Support Scams & Remote-Access RAT Lures
* **Threat Objective**: Display fake browser crash/virus alerts, directing victim to call a toll-free number or install remote-desktop software (AnyDesk, TeamViewer, RustDesk) to drain bank accounts.
* **Intended Victim**: Elderly users, non-technical citizens.
* **Observable Evidence Available to VERITY**: Full-screen lockup scripts, fake Windows Defender / Microsoft warnings, links to known remote access tool downloads.
* **Evidence Unavailable to VERITY**: Active phone conversation with the scam operator.
* **Supported Input Modalities**: Webpage DOM, URL.
* **Existing Detector & Location**: `verity-extension/content/content-script.js`, `verity-extension/shared/file-magic-inspector.js`.
* **Expected Result & Uncertainty Handling**: Flags tech-support alert dialogs and full-screen trapping scripts.
* **False-Positive Risks**: Legitimate enterprise remote IT support pages.
* **Prevention & Recovery Actions**:
  * *Prevention*: Disconnect internet, close browser tab, never give 9-digit AnyDesk code to callers.
  * *Recovery*: If code shared, immediately disconnect Wi-Fi/mobile data and uninstall the app.
* **Test Fixtures**: Synthetic fake alert fixtures.
* **Implementation Status**: **Partially supported**.

### 14. Romance, Friendship & Social Engineering Fraud
* **Threat Objective**: Establish long-term emotional rapport, then claim sudden customs detainment, hospital emergency, or foreign gift clearance requiring money transfers.
* **Intended Victim**: Vulnerable individuals, matrimonial site users.
* **Observable Evidence Available to VERITY**: Plain text messages containing emotional coercion and customs fee payment requests.
* **Evidence Unavailable to VERITY**: Genuine personal relationship context, offline interactions.
* **Supported Input Modalities**: Plain text.
* **Existing Detector & Location**: `verity-extension/shared/secv-intent-engine.js`.
* **Expected Result & Uncertainty Handling**: Does not issue automated blocks on personal communication; surfaces educational caution if financial transfer requests occur.
* **False-Positive Risks**: Extremely high if automated; must abstain from definitive scam verdicts.
* **Prevention & Recovery Actions**:
  * *Prevention*: Never send money or gifts to individuals met solely online.
  * *Recovery*: Cease all communication, preserve chat screenshots, file police complaint.
* **Test Fixtures**: Synthetic social engineering conversational text.
* **Implementation Status**: **Not safely inferable from available evidence** (Intentional abstention).

### 15. Digital Arrest Threats, Coercion & Extortion
* **Threat Objective**: Impersonate CBI, ED, Mumbai/Delhi Police via Skype/WhatsApp video call, claiming victim's Aadhaar was found on a narcotics package, forcing isolation and fund transfer to "RBI safe accounts".
* **Intended Victim**: Educated urban citizens, senior citizens, working professionals.
* **Observable Evidence Available to VERITY**: Law enforcement intimidation keywords, camera/mic surveillance requests on non-governmental web origins, demands to stay on continuous video calls.
* **Evidence Unavailable to VERITY**: Private WhatsApp/Skype video stream content (encrypted).
* **Supported Input Modalities**: Text message, WhatsApp forward, Webpage requesting camera/mic.
* **Existing Detector & Location**: `verity-extension/content/bharat-scam-detectors.js` (`detectDigitalArrestAndApkScams`, `detectDigitalArrestSurveillanceTrap`).
* **Expected Result & Uncertainty Handling**: Immediate `danger` block (`score >= 90`).
* **False-Positive Risks**: Zero false positives on official government portals (`.gov.in`).
* **Prevention & Recovery Actions**:
  * *Prevention*: Indian law enforcement NEVER conducts arrests or takes statements over Skype/WhatsApp video calls. Hang up immediately.
  * *Recovery*: Call National Cyber Crime Helpline `1930` immediately to log complaint.
* **Test Fixtures**: `verity-extension/tests/world_class_wow_features.test.js` (`Surveillance Trap 1-2`), `sample_data/indian_cyber_fraud_test_cases.json`.
* **Implementation Status**: **Implemented and tested**.

### 16. Malicious Applications & Suspicious Downloads
* **Threat Objective**: Distribute remote access trojans (RATs) and SMS-stealing malware disguised as utility apps (`RTO_Challan.apk`, `electricity_bill.apk`).
* **Intended Victim**: Smartphone users receiving SMS challan alerts.
* **Observable Evidence Available to VERITY**: Content-Disposition header, file extension masquerades (`.mp4.exe`, `.apk`), file magic byte inspection, unverified source domain.
* **Evidence Unavailable to VERITY**: Android OS package installer execution.
* **Supported Input Modalities**: File download stream, URL.
* **Existing Detector & Location**: `verity-extension/content/bharat-scam-detectors.js`, `verity-extension/shared/file-magic-inspector.js`.
* **Expected Result & Uncertainty Handling**: Chrome download interceptor pauses download and displays warning modal; mobile scanner flags APK links.
* **False-Positive Risks**: Legitimate open-source APK downloads (e.g. F-Droid). Mitigated by publisher reputation checks.
* **Prevention & Recovery Actions**:
  * *Prevention*: Never install `.apk` files received over WhatsApp or SMS.
  * *Recovery*: Boot phone into Safe Mode, uninstall suspicious app, revoke Accessibility permissions, inform bank.
* **Test Fixtures**: `verity-extension/tests/verify_smart_download_rules.js`.
* **Implementation Status**: **Implemented and tested**.

### 17. Suspicious Phone Numbers & Messaging Identities
* **Threat Objective**: Spoof sender IDs (e.g. `SBI-IN`, `AXISBK`) or use virtual international numbers (+92, +880, +1) to deceive victims.
* **Intended Victim**: Mobile phone users.
* **Observable Evidence Available to VERITY**: Plain text copied by user into the app.
* **Evidence Unavailable to VERITY**: Native Android SMS telephony header metadata, SS7 routing info (restricted by Android OS security sandbox).
* **Supported Input Modalities**: Copied text.
* **Existing Detector & Location**: None (Platform boundary).
* **Expected Result & Uncertainty Handling**: Explicitly abstains and advises user to verify sender via official channels.
* **False-Positive Risks**: N/A.
* **Prevention & Recovery Actions**:
  * *Prevention*: Check sender headers via DoT Sanchar Saathi / Chakshu portal (`sancharsaathi.gov.in`).
  * *Recovery*: Report fraudulent numbers on Chakshu.
* **Test Fixtures**: N/A.
* **Implementation Status**: **Blocked by platform or external dependency**.

### 18. Account Takeover & Recovery Scams
* **Threat Objective**: Trick victims into handing over two-factor recovery codes, password reset links, or SIM swap authorizations.
* **Intended Victim**: Social media and banking account owners.
* **Observable Evidence Available to VERITY**: Password reset and recovery paths on non-official domains, OAuth redirect manipulation.
* **Evidence Unavailable to VERITY**: Telecom SIM swap requests.
* **Supported Input Modalities**: URL, Webpage DOM.
* **Existing Detector & Location**: `verity-extension/background/rules.js`, `verity-extension/content/content-script.js`.
* **Expected Result & Uncertainty Handling**: Flags unauthorized credential recovery endpoints.
* **False-Positive Risks**: Official self-service recovery pages on legitimate domains.
* **Prevention & Recovery Actions**:
  * *Prevention*: Never share password reset links or OTPs with anyone claiming to help recover your account.
  * *Recovery*: Log into official service directly, invalidate all active sessions, enable authenticator app 2FA.
* **Test Fixtures**: Synthetic account recovery phishing URLs.
* **Implementation Status**: **Partially supported**.

### 19. Benign but Unusual URLs or Legitimate Payment Interactions
* **Threat Objective**: Ensure legitimate payment gateways (Stripe, Razorpay, BillDesk), corporate login portals, and novel benign URLs are not erroneously blocked (Zero False Positives).
* **Intended Victim**: Normal internet users and businesses.
* **Observable Evidence Available to VERITY**: Valid digital signatures (`sign=`), authorized merchant categories (`mc=5411`), legitimate enterprise IdP configurations, verified WHOIS/RDAP domain age.
* **Evidence Unavailable to VERITY**: Private corporate agreements.
* **Supported Input Modalities**: URL, Payment DOM, UPI URI.
* **Existing Detector & Location**: `verity-extension/shared/payment-gateway-allowlist.js`, `verity-extension/background/enterprise-whitelist.js`.
* **Expected Result & Uncertainty Handling**: Clean `allow` verdict (`score <= 20`, safe).
* **False-Positive Risks**: The primary failure mode of over-aggressive security tools. Rigorously guarded in VERITY.
* **Prevention & Recovery Actions**: User proceeds normally without disruption.
* **Test Fixtures**: `verity-extension/tests/real_payment_gateways_safety.test.js`, `verity-extension/tests/verify_zero_false_positives.test.js`.
* **Implementation Status**: **Implemented and tested**.

### 20. Unknown, Novel or Insufficiently Evidenced Interactions
* **Threat Objective**: Handle novel zero-day interactions where available client-side signals are inconclusive, avoiding false certainty.
* **Intended Victim**: Citizens encountering novel campaign infrastructure.
* **Observable Evidence Available to VERITY**: No high-confidence signals fired; no matching brand, allowlist, or threat feed entry.
* **Evidence Unavailable to VERITY**: Ground-truth reputation.
* **Supported Input Modalities**: Any input.
* **Existing Detector & Location**: `verity-extension/shared/verdict-contract.js` (`UNABLE_TO_DETERMINE`, `INSUFFICIENT_EVIDENCE`).
* **Expected Result & Uncertainty Handling**: Explicit abstention state. Returns `caution` with advisory text rather than an unsupported claim of safety.
* **False-Positive Risks**: Low.
* **Prevention & Recovery Actions**: Advise citizen to pause, verify with known contacts, or check through official helplines before proceeding.
* **Test Fixtures**: Synthesized novel edge cases.
* **Implementation Status**: **Implemented and tested**.
