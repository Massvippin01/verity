# Verity Bharat Shield: Native Android APK Build & Deployment Guide

This guide details how to build and deploy the standalone native Android APK for **Verity Shield: Citizen Cyber Lab** with zero external dependencies.

---

## 🏗️ Architecture: Unified Shared Core

Both the **Chrome Extension** and the **Native Android APK** run on the exact same offline-first threat intelligence core:

```
                  ┌──────────────────────────────────────────┐
                  │          Verity Unified Core             │
                  │   (shared/ & background/ risk engine)    │
                  └────────────────────┬─────────────────────┘
                                       │
                 ┌─────────────────────┴─────────────────────┐
                 ▼                                           ▼
   ┌───────────────────────────┐               ┌───────────────────────────┐
   │  Chrome Desktop Extension │               │     Native Android APK    │
   │   - Active Tab DOM Guard  │               │   - WebView Bridge        │
   │   - Bitdefender Parity    │               │   - ACTION_SEND Share     │
   │   - Real-Time Overlay     │               │   - ACTION_VIEW Deep-Link │
   │   - Download Interceptor  │               │   - Notification Listener │
   └───────────────────────────┘               └───────────────────────────┘
```

---

## 🚀 Fast 3-Step APK Build & Run

### Step 1: Sync Web Forensics Lab into Android Assets
Run the build script to compile the shared engine and copy `mobile-scanner/` into the Android asset directory:

```bash
# From workspace root
node verity-extension/scripts/build-mobile-core.js
mkdir -p android-app/android/app/src/main/assets/public
cp -r mobile-scanner/* android-app/android/app/src/main/assets/public/
```

*(On Windows PowerShell):*
```powershell
node verity-extension/scripts/build-mobile-core.js
New-Item -ItemType Directory -Force -Path "android-app/android/app/src/main/assets/public"
Copy-Item -Recurse -Force "mobile-scanner/*" "android-app/android/app/src/main/assets/public/"
```

### Step 2: Build Debug APK via Gradle CLI
Compile the native Android application:

```bash
cd android-app/android
./gradlew assembleDebug
```

*(On Windows PowerShell):*
```powershell
cd android-app/android
.\gradlew.bat assembleDebug
```

The output APK will be generated at:
`android-app/android/app/build/outputs/apk/debug/app-debug.apk`

### Step 3: Install on Device or Emulator
Deploy the APK to your connected Android phone or emulator:

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

---

## 🧪 Testing Native Android Capabilities

### 1. Test Android Web Share Target (`ACTION_SEND`)
1. Open any messaging app (WhatsApp, Telegram, SMS) or Chrome.
2. Select suspicious message text or link.
3. Tap **Share** -> Choose **Verity Shield**.
4. Verity automatically opens, selects the appropriate Shield tab, and performs an instant security scan with proof steps!

You can also simulate this via ADB CLI:
```bash
adb shell am start -a android.intent.action.SEND \
  -t "text/plain" \
  -e android.intent.extra.TEXT "Urgent: CBI narcotics parcel under Aadhaar. Connect immediately." \
  in.bharatshield.verity/.MainActivity
```

### 2. Test Deep-Link UPI Intent Pre-Screening (`ACTION_VIEW`)
Simulate clicking a suspicious payment link or scanning a QR code:
```bash
adb shell am start -a android.intent.action.VIEW \
  -d "upi://pay?pa=scammer99@ybl&am=5000&tn=OLX_refund_claim" \
  in.bharatshield.verity/.MainActivity
```
Verity opens directly on **Shield 3: UPI & Payment Safety**, warning the citizen that this intent deducts ₹5,000!

### 3. Test Real-Time Phishing Notification Listener
1. Enable Verity Notification Access under Android **Settings -> Apps -> Special App Access -> Notification Access -> Verity Shield**.
2. When any incoming SMS or WhatsApp notification arrives containing extortion keywords ("digital arrest", "CBI", "electricity disconnect", "KYC blocked") or suspicious shorteners, `VerityNotificationService` intercepts the lure in real time and displays an alert warning the citizen before they tap or pay.

---

## 🔒 Security & Privacy Guarantees
- **No Third-Party Analytics or Trackers**: Zero telemetry or remote ad libraries.
- **Offline-First Resilience**: All core risk heuristics and UPI forensics execute 100% locally on the device without requiring internet connectivity.
- **Keyless Public Verification**: Real-time DoH, RDAP, and Wikidata checks use 100% free keyless public APIs with strict timeouts.
