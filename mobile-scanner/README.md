# Verity Shield — Mobile "Share-to-Verify" Scanner (PWA)

Zero-install Android Progressive Web App (PWA) designed to protect Indian citizens from cyber fraud directly from WhatsApp, SMS, and QR codes.

Built with **zero build tools** and **zero audio/speech dependencies**. Reuses the exact same on-device heuristics, Bharat fraud detectors, and risk engine as the browser extension.

---

## Features

- **Android Share-to-Verify**: Share any suspicious message, text, or link directly from WhatsApp or SMS to Verity without copying and pasting.
- **Multilingual Citizen Guidance**: Instant advisories in **English**, **தமிழ் (Tamil)**, **हिन्दी (Hindi)**, and **తెలుగు (Telugu)**.
- **UPI QR Collect-Trap Protection**: Decodes QR codes / `upi://pay` links and flags deceptive collect/deduct scams disguised as cashback, rewards, or OLX buyer advances.
- **Interactive "Spot The Scam" Micro-Quiz**: Dynamic educational cards and 1-question quizzes to build citizen cyber immunity.
- **100% Offline & Private**: Everything runs locally inside the browser. No messages, links, or telemetry are ever uploaded.

---

## Running Locally

Run a lightweight static HTTP server from the project directory:

```bash
# Serve the mobile-scanner directory
npx serve mobile-scanner
```

Or run via Python's built-in HTTP server:

```bash
cd mobile-scanner
python -m http.server 8080
```

Open `http://localhost:8080` in your desktop or mobile browser.

---

## Deploying to GitHub Pages

Because all asset paths, imports, and manifest scopes are relative (`./`), the PWA works seamlessly under any GitHub Pages subpath:

1. Push your repository to GitHub.
2. In your GitHub repository, navigate to **Settings > Pages**.
3. Under **Build and deployment > Source**, select **Deploy from a branch**.
4. Choose your branch (e.g., `main` or `gh-pages`) and select the `/` (root) or `/mobile-scanner` folder.
5. Once deployed, open the HTTPS URL (e.g. `https://<username>.github.io/<repo>/mobile-scanner/`).

---

## Installing on Android (Chrome / Brave / Edge)

1. Open your deployed HTTPS URL in **Chrome for Android**.
2. Tap the three dots (`⋮`) in the top right corner.
3. Tap **Add to Home screen** (or **Install app**).
4. An icon titled **Verity** will appear on your Android home screen and app drawer.

---

## Testing "Share from WhatsApp"

Once installed on Android over HTTPS:
1. Open WhatsApp, SMS, or Telegram.
2. Long-press any suspicious message or link and tap **Share**.
3. Select **Verity** from the Android system share sheet.
4. Verity opens automatically, pre-fills the message, scans it instantly, and displays the threat verdict.

---

## Architecture & Honest Limitations

- **Engine Architecture**: ML scoring runs in the browser extension; the PWA uses the rules engine + Bharat scam detectors + heuristic synergy scoring. This avoids multi-megabyte WASM/ONNX runtime overhead, ensuring instantaneous mobile loading (< 300ms) on 2G/3G connections.
- **Android Share Target**: Web Share Target requires the PWA to be **installed to the home screen** and served over **HTTPS** (or `localhost`). It will not appear in the native Android share drawer when opened as a normal tab in the browser.
- **QR Barcode Detection**: Automatic QR decoding relies on the browser's native `BarcodeDetector` API (available on Android Chrome/Edge). On browsers without native `BarcodeDetector` support (such as Firefox Android or desktop Safari), Verity gracefully asks citizens to paste the UPI link or URL without crashing.
