# Verity Security: Architectural Limitations & Threat Surface Analysis

This document provides a transparent, engineering-level assessment of the architectural boundaries, threat model limitations, and trade-offs in Verity 2.0.

---

## 1. Web Worker Network Exfiltration Bypass

### Mechanism
`content/main-world-interceptor.js` executes within the webpage's **MAIN world** window context at `document_start`. It intercepts network communication by instrumenting `window.fetch`, `window.XMLHttpRequest`, `navigator.sendBeacon`, and `window.WebSocket`.

### Limitation
Web Workers (`Worker`, `SharedWorker`, and `ServiceWorker`) run in separate execution threads with their own global scope (`DedicatedWorkerGlobalScope`). They do not inherit the `window` prototype chain.
- If a malicious script spawns a Web Worker (for example, via an inline `Blob` or `data:` URI) and issues network requests from inside that worker thread, those calls bypass the MAIN-world JavaScript prototypes.
- While Declarative Net Request (DNR) rules and Chrome `webRequest` operate at the browser's C++ network layer and can intercept known malicious domains, dynamic exfiltration to unlisted generic endpoints via Web Workers will not trigger MAIN-world signal dispatching.

---

## 2. Dynamic Code Execution & Eval-Built Calls

### Mechanism
Verity hooks global network constructors and methods to inspect target URLs before requests are dispatched, using strict regular expressions and heuristic string matching.

### Limitation
Malicious scripts utilizing multi-stage dynamic code synthesis (such as indirect `eval`, `new Function(...)`, WebAssembly-based network stacks, or pristine prototype restoration from sandboxed iframes before extension injection) can assemble target endpoints byte-by-byte at runtime.
- Although prototype traps trigger when the final `fetch()`, `xhr.send()`, or `new WebSocket()` is invoked, endpoints constructed to evade standard URL patterns (e.g., custom WebRTC data channels, DNS tunneling, or non-standard webhook schemas) are not intercepted by standard HTTP/WebSocket prototype traps.

---

## 3. Canvas Forms Without DOM Event Listeners

### Mechanism
Verity's content script inspects DOM structures to identify credential harvesting forms, input fields, password lures, and fake human verification mechanisms (e.g. ClickFix) within standard DOM elements and pierced Shadow DOM boundaries.

### Limitation
Adversaries deploying canvas-based phishing kits can draw a pixel-perfect credential login form directly onto an HTML5 `<canvas>` element without creating real DOM input nodes.
- If the phishing kit captures input using raw canvas coordinate mathematics or custom virtual keyboards rather than standard DOM input elements or accessible text fields, DOM-level heuristic inspection cannot detect the form fields.
- Running continuous client-side Optical Character Recognition (OCR) or computer vision inference on every canvas render frame would introduce severe CPU/GPU battery overhead and latency unacceptable for a real-time browser extension.

---

## 4. Machine Learning Model Scope (18 Features)

### Mechanism
Verity features an on-device machine learning classifier (Random Forest / Decision Tree) designed to evaluate zero-day and unlisted URLs in less than 1 millisecond without cloud round-trips.

### Limitation
The model evaluates exactly **18 lexical and structural features** extracted from the URL:
1. `url_length`
2. `hostname_length`
3. `path_length`
4. `subdomain_count`
5. `is_ip_address`
6. `has_punycode`
7. `entropy`
8. `hyphen_count`
9. `numeric_ratio`
10. `suspicious_tld`
11. `query_length`
12. `vowel_consonant_ratio`
13. `brand_min_dist`
14. `has_mixed_script`
15. `sensitive_dir_depth`
16. `longest_token_length`
17. `special_char_density`
18. `is_port_in_url`

While effective for identifying lexical anomalies, brand typosquatting, and domain spoofing on zero-day URLs, lexical analysis alone cannot assess the visual layout or backend behavioral state of benign-looking URLs. Compromised legitimate websites or multi-tenant SaaS hosting platforms displaying deceptive content require heuristic rule layers and DOM-level inspection rather than standalone ML classification.

---

## 5. PWA / Standalone Mobile Scanner Navigation Interception

### Mechanism
The standalone Mobile Scanner / PWA implementation provides on-device scanning for suspicious SMS/WhatsApp messages, UPI collect lures, APK download links, and QR codes via text analysis and Web Share Target.

### Limitation
PWAs operate entirely within the standard browser security sandbox. Unlike Chrome Extensions, PWAs lack privileged browser platform APIs:
- No access to `chrome.webNavigation`, `chrome.webRequest`, or `chrome.declarativeNetRequest`.
- Cannot inject content scripts into other web pages or active browser tabs.
- Cannot perform live, background navigation interception or system-wide URL redirection across third-party browser apps.
Protection on mobile is restricted to explicit user sharing, text/URL pasting, and offline analysis.

---

## 6. DNS-over-HTTPS (DoH) Hostname-Only Resolution

### Mechanism
Verity queries Cloudflare Security DNS-over-HTTPS (`1.1.1.2`) to detect sinkholed malware, command-and-control (C2), and known phishing domains with zero local database bloat.

### Limitation
Standard DNS protocol semantics operate strictly at the **hostname / domain level**:
- DoH queries transmit only domain names (e.g., `malicious-domain.xyz`).
- DoH cannot verify full paths (e.g., `https://cloud-storage.com/user/phish/login.php`), query strings, hash fragments, or request payloads.
- If a threat is hosted on a high-reputation shared platform or CDN (e.g., `firebaseapp.com`, `github.io`, `workers.dev`), DoH will return a clean verdict because the parent domain is not globally sinkholed. Path-specific threats rely on Verity's lexical analysis, content script rules, and threat intelligence heuristics.
