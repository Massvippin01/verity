# VERITY 3.0 | Native Platform Feasibility Study: Android, iOS & Desktop

**Document Version:** 1.0.0  
**Status:** Architectural Feasibility & Platform Constraint Audit  
**Author:** Principal Systems Architect & Mobile Security Lead  
**Scope:** Android (Native / PWA), iOS (Webkit / PWA), Desktop (Chrome / Edge / Native)  

---

## 1. Executive Summary & Philosophy

When scaling cyber-safety protections from Web extensions and PWAs to native mobile ecosystems, systems frequently fall into the trap of promising "silent background surveillance" or "automatic SMS interception." Such promises violate operating system security sandboxes, Google Play / Apple App Store developer policies, and core citizen privacy guarantees.

VERITY enforces a **User-Centric Capability Boundary**:
- **Supported:** User-initiated integrations (Android Share Sheet, Web Share Target, notification forwarders, accessibility overlays with explicit opt-in).
- **Unsupported by Design:** Silent background SMS inbox scraping, kernel interception, and unauthorized background screen monitoring.

---

## 2. Android Platform Feasibility Matrix

### 2.1 Capability Analysis on Android 14+ (API Level 34+)

| Proposed Capability | Feasibility | Required Android API / Component | Required Permissions | Google Play Store Policy Constraints | Verdict / Recommendation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **User Share Target (SMS / Text / Link)** | **HIGH (Fully Feasible)** | `Intent.ACTION_SEND` with MIME types `text/plain` | None (User-initiated) | Compliant with all standard Google Play guidelines | **RECOMMENDED (Priority 1):** Native Android wrapper or PWA Web Share Target handles forwarded suspicious SMS/links seamlessly. |
| **Notification Listener (Scam Banner)** | **MEDIUM (Feasible with Consent)** | `NotificationListenerService` | `android.permission.BIND_NOTIFICATION_LISTENER_SERVICE` | Requires prominent disclosure in Google Play Console. Must demonstrate core safety utility. | **FEASIBLE:** Inspects notification text of incoming SMS/WhatsApp for digital arrest coercion without reading inbox directly. |
| **Silent Background SMS Inbox Scraping** | **ZERO (Prohibited)** | `Telephony.SMS_RECEIVED` or `SMS_READ` | `android.permission.READ_SMS`, `RECEIVE_SMS` | **STRICTLY RESTRICTED:** Google Play limits SMS permissions exclusively to Default SMS Handlers (e.g. Google Messages). Non-default apps face immediate app removal. | **EXCLUDED & REJECTED:** Violates store policies and citizen privacy guarantees. |
| **Accessibility Service Screen Scraping** | **LOW / RISKY** | `AccessibilityService` | `android.permission.BIND_ACCESSIBILITY_SERVICE` | Google Play strictly audits Accessibility APIs; permits only apps designed for people with disabilities or proven enterprise safety tools. | **EXCLUDED:** Extreme battery drain, fragile UI hooks, and high risk of Play Store suspension. |
| **VPN / Local Loopback DNS Filtering** | **HIGH (Feasible)** | `VpnService` with local `tun2socks` | `android.permission.BIND_VPN_SERVICE` | Permitted for local device firewalls if zero external proxying is conducted. | **FEASIBLE (Milestone 4):** Enables on-device DNS blocking of verified malicious domains without sending browsing traffic to cloud servers. |
| **Direct UPI App Launch & Deep-Linking** | **HIGH (Fully Feasible)** | `Intent.ACTION_VIEW` with `upi://pay` | `android.permission.INTERNET` (for merchant check) | Standard Android intent resolution | **RECOMMENDED:** Inspects parameters locally before handing off to user's installed UPI app (PhonePe, Google Pay, Paytm). |

---

## 3. iOS Platform Feasibility Matrix (iOS 17+)

| Proposed Capability | Feasibility | Required iOS Framework / API | App Store Review Guideline Constraints | Architecture Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| **Web Share Target (PWA)** | **HIGH** | Web Share Target API / Safari Share Sheet | Standard Webkit support | Add to Home Screen PWA supports direct share handling. |
| **SMS/MMS Message Filtering** | **MEDIUM** | `IdentityLookup` framework (`ILMessageFilterExtension`) | Permitted specifically for SMS spam filtering. The extension receives incoming SMS and returns `.allow`, `.filter`, or `.junk`. | **FEASIBLE (Milestone 3):** iOS natively supports local offline rule-based SMS spam filtering without exposing messages to the main app. |
| **Safari Web Extension** | **HIGH** | Safari Web Extensions (Manifest V3) | App Store review requires standard Safari extension packaging in Xcode. | **FEASIBLE:** Shared codebase in `verity-extension/` can be wrapped into Xcode macOS/iOS Safari Extension target. |
| **Background Network Packet Inspection** | **ZERO (Restricted)** | `NetworkExtension` (NEPacketTunnelProvider) | Requires special Apple entitlement (`com.apple.developer.networking.networkextension`). Highly restricted approval process. | **EXCLUDED:** Complex review and unsuited for lightweight citizen utility. |

---

## 4. Desktop Platform Feasibility Matrix (Windows, macOS, Linux)

| Platform Component | Architecture | Permissions & Installation | Security & Sandbox State |
| :--- | :--- | :--- | :--- |
| **Chrome / Edge Extension** | Manifest V3 (`verity-extension/`) | Chrome Web Store / Edge Addons | **FULLY OPERATIONAL:** `activeTab`, local storage, downloads inspection, zero remote eval. |
| **Desktop PWA** | Web App Manifest (`mobile-scanner/`) | Installed via Chrome/Edge ("Install Verity Shield") | **FULLY OPERATIONAL:** Runs in standalone window with local offline service worker caching. |
| **Native Daemon (Optional)** | Local Go / Rust proxy | Native system service | Not required; Web extension covers browser perimeter with zero system privileges. |

---

## 5. Architectural Roadmap for Native Expansion

1. **Step 1 (Immediate / Milestone 2):** Package Android PWA into Trusted Web Activity (TWA) via Google Bubblewrap. Enables Google Play Store listing with zero binary bloat and full Web Share Target integration.
2. **Step 2 (Milestone 3):** iOS Safari Web Extension using Xcode converter tool to run `verity-extension/` natively on iOS Safari.
3. **Step 3 (Milestone 4):** Android Native `NotificationListenerService` companion app providing proactive heads-up warnings on incoming WhatsApp digital arrest extortion calls.
