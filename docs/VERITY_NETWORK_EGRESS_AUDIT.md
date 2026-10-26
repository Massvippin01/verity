# VERITY 3.0 | Network Egress & Data Privacy Audit

**Document Version:** 3.0.0  
**Audit Date:** October 2026  
**Auditor:** Principal Engineer & Cybersecurity Architect  
**Evaluation Standard:** Zero-Knowledge Data Minimization  
**Regression Test Suite:** `verity-extension/tests/network_egress.test.js` (**PASS**)

---

## 1. Network Egress Trace & Destination Inventory

Every outbound network socket initiated by any component of the VERITY platform is documented below:

| Destination / Endpoint | Purpose | Trigger Condition | Data Transmitted | User Consent State | Failure / Timeout Behaviour | Can Credentials, Paths or User Text Escape? |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `https://cloudflare-dns.com/dns-query` | DNS-over-HTTPS (DoH) A/AAAA/TXT record lookup | User explicitly triggers "Verify URL / Online Scan" | Hostname only (e.g. `sbi.co.in`) | Explicit user action | Aborts after 800ms; falls back to offline heuristics with `isOfflineFallback: true` | **NO.** Full URL paths, query parameters, passwords, and fragments are stripped prior to socket dispatch. |
| `https://dns.google/resolve` | Fallback DoH resolver | If Cloudflare DoH request fails or times out | Hostname only | Inherited from primary DoH | Aborts after 800ms; falls back to offline mode | **NO.** Hostname only. |
| `https://rdap.org/domain/{domain}` | ICANN RDAP domain registration age check | Online scan of unfamiliar domain | Apex registered domain only (e.g. `example.com`) | Explicit user action | Gracefully skipped; step marked as skipped in audit receipt | **NO.** Subdomains, URL paths, and query parameters are stripped before RDAP URI construction. |
| `https://query.wikidata.org/sparql` | Official bank/brand entity domain verification | Domain claims official Indian bank brand | Verified brand entity name token (e.g. `"State Bank of India"`) | Explicit user action | Falls back to offline brand rules | **NO.** User messages are never injected; only normalized brand dictionary tokens queried. |
| `https://crt.sh/?q={domain}&output=json` | Certificate Transparency logs check | Online domain SSL audit | Apex domain or hostname | Explicit user action | Skipped if unreachable; no block decision made on crt.sh failure alone | **NO.** Hostname only. |
| `https://www.reddit.com/r/Scams/search.json` | Public threat & community corroboration | Online scam verification | **Remediated:** Confirmed brand entity or apex domain only. | Explicit user action | Skipped if query empty or network error | **NO (Remediated).** Raw message snippets are never sent to Reddit. |
| `http://localhost:8080/*` (Demo Server) | Serving static web assets | Browser loading PWA | Zero citizen data; HTTP GET for static files only | Local loopback | Server serves files locally; no cloud proxying | **NO.** Local demo server has zero POST/PUT ingestion endpoints and logs only static file GET paths. |

---

## 2. Privacy Defect Audit & Remediations

### 2.1 Remediation of SEC-LEAK-01: Reddit Unsanitized Snippet Fallback
- **Component:** `verity-extension/shared/online-scam-verifier.js` (former line 680)
- **Vulnerability:** When online verification was invoked on text without an identified brand, the code previously defaulted to: `query = candidateEntity || (hostname || input.slice(0, 40));`. If a user checked private banking text without a known brand, the first 40 characters were transmitted as a query parameter to Reddit.
- **Remediation Implemented:**
  ```javascript
  const queryStr = (candidateEntity && candidateEntity.length >= 3) ? candidateEntity : (hostname || null);
  if (queryStr) {
    onlinePromises.push(checkRedditScamCorroboration(queryStr, queryOptions));
  } else {
    onlinePromises.push(Promise.resolve(null));
  }
  ```
  If neither a validated public brand entity nor a public hostname exists, community searching is aborted. Private citizen messages never leave the device.
- **Verification:** Verified via `tests/network_egress.test.js`.

### 2.2 Remediation of SEC-LEAK-02: Conversational Text Domain Extraction Leak
- **Component:** `verity-extension/shared/online-scam-verifier.js` (`extractDomainFromUrl` and line 650)
- **Vulnerability:** When a multi-word private message without a URL was passed to `verifyUrlAndMessageOnline`, line 650 evaluated: `extractDomainFromUrl(targetUrl || input)`. Because `targetUrl` was empty, `input` (the entire private message) was passed to `extractDomainFromUrl`. The URL parser interpreted the spaces or words as a host, transmitting user message text to Cloudflare DoH (`https://cloudflare-dns.com/dns-query?name=private%20conversation...`).
- **Remediation Implemented:**
  1. `extractDomainFromUrl` now strictly validates: if the input contains whitespace and no URL matches, it returns `''` immediately.
  2. Input is only treated as a candidate domain if it does not contain whitespace and matches a valid domain pattern (`/^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/`).
- **Verification:** Verified via `tests/network_egress.test.js` (`Local text scanner triggers ZERO network egress` and `SEC-LEAK-01 Regression Guard`).

---

## 3. Privacy Claims Reconciliation

1. **"100% On-Device Processing":**  
   - *Status:* **QUALIFIED & ACCURATE.** True for all SMS scanning, text analysis, UPI collect unmasking, APK heuristics, and recovery guides. For unfamiliar external links, opt-in reputation checks query public DNS and RDAP registries; however, URL paths, query parameters, credentials, and message content are stripped before transmission.
2. **"Zero Telemetry":**  
   - *Status:* **VERIFIED TRUE.** VERITY operates zero telemetry beacons, zero analytics databases, zero tracking pixels, and zero proprietary collection endpoints.
3. **"Offline Resilience":**  
   - *Status:* **VERIFIED TRUE.** When disconnected (`navigator.onLine === false` or air-gapped), local heuristics, regex signatures, and the Recovery Advisor operate without interruption, setting `isOfflineFallback: true` in the Verdict Contract.
