/**
 * tests/redirects_crack_and_mobile_lab.test.js — Verification Suite for Multi-Hop Forensics, Crack-Site Shield & Mobile Cyber Lab
 *
 * Verifies:
 * 1. Multi-Hop Malvertising Redirect Chain & Tab-Under Analyzer (shared/redirect-forensics.js & background/risk-engine.js)
 * 2. Crack / Warez / Piracy Site Malware Shield Traps A-D (content/crack-site-shield.js)
 * 3. Mobile Binary File Magic-Byte Inspector (shared/file-magic-inspector.js)
 * 4. Redirect Chain Simulation Unroller (shared/text-scanner.js)
 * 5. Risk Engine Hard Overrides & Multilingual Citizen Advisories (en, ta, hi, te)
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeRedirectChainForensics } from '../shared/redirect-forensics.js';
import { detectCrackSiteMalwareTraps } from '../content/crack-site-shield.js';
import { inspectFileMagicBytes } from '../shared/file-magic-inspector.js';
import { unrollRedirectChainSimulation, scanText } from '../shared/text-scanner.js';
import { calculateRisk } from '../background/risk-engine.js';
import { getText, goldenRuleForSignal } from '../shared/citizen-messages.js';
import { t } from '../shared/messages.js';

// ════════════════════════════════════════════════════════════════════════════════
// 1. MULTI-HOP REDIRECT CHAIN & TAB-UNDER FORENSICS TESTS
// ════════════════════════════════════════════════════════════════════════════════

test('Redirect Forensics 1: Rapid multi-hop traversals with high-risk rotator TLDs trigger SIG_MALVERTISING_REDIRECT_CHAIN', () => {
  const chain = [
    { url: 'https://bit.ly/claim-prize', timestamp: 1000 },
    { url: 'https://rotator.icu/track', timestamp: 1300 },
    { url: 'https://ad-bridge.top/gate', timestamp: 1600 },
    { url: 'https://malware-drop.xyz/download', timestamp: 1900 }
  ];

  const result = analyzeRedirectChainForensics(chain);

  assert.equal(result.hasRapidMultiHop, true);
  assert.equal(result.hasTldTurbulence, true);
  assert.equal(result.uniqueRootDomains, 4);
  assert.ok(result.elapsedMs <= 2500);
  assert.ok(result.signals.includes('SIG_MALVERTISING_REDIRECT_CHAIN'));

  // Risk engine evaluation
  const riskVerdict = calculateRisk(
    'https://malware-drop.xyz/download',
    [{ id: 'SIG_MALVERTISING_REDIRECT_CHAIN', score: 80 }],
    null, null, null, null, null, null, 1.0, []
  );

  assert.equal(riskVerdict.action, 'block');
  assert.equal(riskVerdict.severity, 'danger');
  assert.ok(riskVerdict.score >= 80);
});

test('Redirect Forensics 2: Rotator query bridge parameters trigger ad-rotator detection', () => {
  const chain = [
    { url: 'https://news-blog.example/story', timestamp: 1000 },
    { url: 'https://ad-rotator.net/jump?subid=987654&clickid=aff123', timestamp: 1400 },
    { url: 'https://landing-gate.com/offer', timestamp: 1800 }
  ];

  const result = analyzeRedirectChainForensics(chain);

  assert.equal(result.hasRapidMultiHop, true);
  assert.equal(result.hasAdRotatorQuery, true);
  assert.ok(result.signals.includes('SIG_MALVERTISING_REDIRECT_CHAIN'));
});

test('Redirect Forensics 3: Tab-Under background tab swap triggers SIG_TAB_UNDER_HIJACK', () => {
  const chain = [
    { url: 'https://legit-reader.org/article', timestamp: 1000, isTabHidden: false },
    { url: 'https://deceptive-casino-affiliate.com/register', timestamp: 1500, isTabHidden: true }
  ];

  const result = analyzeRedirectChainForensics(chain);

  assert.equal(result.hasTabUnderSwap, true);
  assert.ok(result.signals.includes('SIG_TAB_UNDER_HIJACK'));

  // Risk engine evaluation
  const riskVerdict = calculateRisk(
    'https://deceptive-casino-affiliate.com/register',
    [{ id: 'SIG_TAB_UNDER_HIJACK', score: 85 }],
    null, null, null, null, null, null, 1.0, []
  );

  assert.equal(riskVerdict.action, 'block');
  assert.equal(riskVerdict.severity, 'danger');
  assert.ok(riskVerdict.score >= 85);
});

test('Redirect Forensics 4: Slow, benign same-origin redirect chain is not flagged', () => {
  const chain = [
    { url: 'https://example.com/login', timestamp: 1000 },
    { url: 'https://example.com/dashboard', timestamp: 4500 }
  ];

  const result = analyzeRedirectChainForensics(chain);

  assert.equal(result.hasRapidMultiHop, false);
  assert.equal(result.hasTldTurbulence, false);
  assert.equal(result.hasAdRotatorQuery, false);
  assert.equal(result.hasTabUnderSwap, false);
  assert.equal(result.detected, false);
  assert.equal(result.signals.length, 0);
});

// ════════════════════════════════════════════════════════════════════════════════
// 2. CRACK / WAREZ / PIRACY SITE MALWARE SHIELD TESTS
// ════════════════════════════════════════════════════════════════════════════════

test('Crack Shield 1: Trap A — Encrypted archive password stealer lure triggers SIG_ARCHIVE_PASSWORD_STEALER_LURE', () => {
  const snapshot = {
    text: 'Download Adobe Photoshop 2024 Pre-Activated Full Version. Archive password: 1234. Disable antivirus before extracting.',
    links: [
      { text: 'Download Setup.zip', href: 'https://cdn-storage.invalid/photoshop_full.zip' }
    ],
    location: { hostname: 'crack-download-hub.net' }
  };

  const traps = detectCrackSiteMalwareTraps(snapshot);

  assert.equal(traps.detected, true);
  assert.equal(traps.hasArchivePasswordStealerLure, true);
  assert.ok(traps.signals.includes('SIG_ARCHIVE_PASSWORD_STEALER_LURE'));

  // Risk engine evaluation
  const riskVerdict = calculateRisk(
    'https://crack-download-hub.net/photoshop',
    [{ id: 'SIG_ARCHIVE_PASSWORD_STEALER_LURE', score: 90 }],
    null, null, null, null, null, null, 1.0, []
  );

  assert.equal(riskVerdict.action, 'block');
  assert.equal(riskVerdict.severity, 'danger');
  assert.ok(riskVerdict.score >= 90);
});

test('Crack Shield 2: Trap A Negative — Benign mention of password without archive download is safe', () => {
  const snapshot = {
    text: 'To reset your account password, click Forgot Password on the login page.',
    links: [
      { text: 'Help Center', href: 'https://support.example.com/help' }
    ],
    location: { hostname: 'example.com' }
  };

  const traps = detectCrackSiteMalwareTraps(snapshot);

  assert.equal(traps.hasArchivePasswordStealerLure, false);
  assert.equal(traps.detected, false);
});

test('Crack Shield 3: Trap B — Invisible full-screen clickjack overlay triggers SIG_CLICKJACK_INVISIBLE_OVERLAY', () => {
  const snapshot = {
    text: 'Click here to stream latest movies online.',
    overlays: [
      {
        position: 'fixed',
        zIndex: 99999,
        opacity: 0.01,
        width: '100vw',
        height: '100vh',
        top: '0px',
        left: '0px'
      }
    ],
    location: { hostname: 'free-stream-hub.org' }
  };

  const traps = detectCrackSiteMalwareTraps(snapshot);

  assert.equal(traps.detected, true);
  assert.equal(traps.hasClickjackInvisibleOverlay, true);
  assert.ok(traps.signals.includes('SIG_CLICKJACK_INVISIBLE_OVERLAY'));

  // Risk engine evaluation
  const riskVerdict = calculateRisk(
    'https://free-stream-hub.org/watch',
    [{ id: 'SIG_CLICKJACK_INVISIBLE_OVERLAY', score: 80 }],
    null, null, null, null, null, null, 1.0, []
  );

  assert.equal(riskVerdict.action, 'block');
  assert.equal(riskVerdict.severity, 'danger');
  assert.ok(riskVerdict.score >= 80);
});

test('Crack Shield 4: Trap B Negative — Normal visible modal dialog is not flagged as clickjack overlay', () => {
  const snapshot = {
    text: 'Please accept our privacy policy to continue.',
    overlays: [
      {
        position: 'fixed',
        zIndex: 1000,
        opacity: 1.0,
        background: '#ffffff',
        width: '400px',
        height: '300px'
      }
    ],
    location: { hostname: 'example.org' }
  };

  const traps = detectCrackSiteMalwareTraps(snapshot);

  assert.equal(traps.hasClickjackInvisibleOverlay, false);
  assert.equal(traps.detected, false);
});

test('Crack Shield 5: Trap C — Fake High Speed Download button pointing to external executable triggers SIG_FAKE_DOWNLOAD_BUTTON_TRAP', () => {
  const snapshot = {
    text: 'Grand Theft Auto V PC Keygen Crack',
    buttons: [
      {
        text: 'Fast Download Now (High Speed)',
        href: 'https://ad-network-rotator.top/payload/setup.exe'
      }
    ],
    location: { hostname: 'gta-crack-site.net' }
  };

  const traps = detectCrackSiteMalwareTraps(snapshot);

  assert.equal(traps.detected, true);
  assert.equal(traps.hasFakeDownloadButtonTrap, true);
  assert.ok(traps.signals.includes('SIG_FAKE_DOWNLOAD_BUTTON_TRAP'));

  // Risk engine evaluation
  const riskVerdict = calculateRisk(
    'https://gta-crack-site.net/download',
    [{ id: 'SIG_FAKE_DOWNLOAD_BUTTON_TRAP', score: 85 }],
    null, null, null, null, null, null, 1.0, []
  );

  assert.equal(riskVerdict.action, 'block');
  assert.equal(riskVerdict.severity, 'danger');
  assert.ok(riskVerdict.score >= 85);
});

test('Crack Shield 6: Trap C Negative — Legitimate same-origin download button is not flagged', () => {
  const snapshot = {
    text: 'Download Open Source Editor',
    buttons: [
      {
        text: 'Download Now',
        href: 'https://vscodium.com/releases/latest.zip'
      }
    ],
    location: { hostname: 'vscodium.com' }
  };

  const traps = detectCrackSiteMalwareTraps(snapshot);

  assert.equal(traps.hasFakeDownloadButtonTrap, false);
  assert.equal(traps.detected, false);
});

test('Crack Shield 7: Trap D — Fake Notification / Captcha download gate triggers SIG_NOTIFICATION_PERMISSION_TRAP', () => {
  const snapshot = {
    text: 'Click Allow to Download your file. Press Allow to verify you are human.',
    location: { hostname: 'file-download-portal.info' }
  };

  const traps = detectCrackSiteMalwareTraps(snapshot);

  assert.equal(traps.detected, true);
  assert.equal(traps.hasNotificationPermissionTrap, true);
  assert.ok(traps.signals.includes('SIG_NOTIFICATION_PERMISSION_TRAP'));

  // Risk engine evaluation
  const riskVerdict = calculateRisk(
    'https://file-download-portal.info/gate',
    [{ id: 'SIG_NOTIFICATION_PERMISSION_TRAP', score: 80 }],
    null, null, null, null, null, null, 1.0, []
  );

  assert.equal(riskVerdict.action, 'block');
  assert.equal(riskVerdict.severity, 'danger');
  assert.ok(riskVerdict.score >= 80);
});

// ════════════════════════════════════════════════════════════════════════════════
// 3. MOBILE BINARY FILE MAGIC-BYTE INSPECTOR TESTS
// ════════════════════════════════════════════════════════════════════════════════

test('File Magic 1: Windows PE Executable (MZ) disguised as HDFC Statement.pdf triggers SIG_FILE_MAGIC_BYTE_SPOOF', () => {
  const headerBytes = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
  const result = inspectFileMagicBytes('HDFC_Credit_Card_Statement.pdf', 'application/pdf', headerBytes);

  assert.equal(result.detected, true);
  assert.equal(result.detectedType, 'executable');
  assert.equal(result.severity, 'danger');
  assert.equal(result.score, 95);
  assert.equal(result.signal, 'SIG_FILE_MAGIC_BYTE_SPOOF');
  assert.match(result.reason, /disguised as document/i);
});

test('File Magic 2: Double extension executable invoice.pdf.exe triggers SIG_FILE_MAGIC_BYTE_SPOOF', () => {
  const headerBytes = new Uint8Array([0x4d, 0x5a, 0x90, 0x00]);
  const result = inspectFileMagicBytes('SBI_Pending_Challan.pdf.exe', 'application/x-msdownload', headerBytes);

  assert.equal(result.detected, true);
  assert.equal(result.severity, 'danger');
  assert.equal(result.score, 95);
  assert.equal(result.signal, 'SIG_FILE_MAGIC_BYTE_SPOOF');
});

test('File Magic 3: APK dropper (PK) named RTO_Traffic_Challan.apk triggers SIG_MALICIOUS_APK_DROPPER', () => {
  const headerBytes = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]);
  const result = inspectFileMagicBytes('RTO_Traffic_Challan.apk', 'application/vnd.android.package-archive', headerBytes);

  assert.equal(result.detected, true);
  assert.equal(result.detectedType, 'zip_apk');
  assert.equal(result.severity, 'danger');
  assert.equal(result.score, 90);
  assert.equal(result.signal, 'SIG_MALICIOUS_APK_DROPPER');
  assert.match(result.reason, /Android APK/i);
});

test('File Magic 3b: ZIP/APK archive disguised as document (e.g. Bill_Update.pdf) triggers SIG_ARCHIVE_DISGUISED_AS_DOC', () => {
  const headerBytes = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]);
  const result = inspectFileMagicBytes('Bill_Update.pdf', 'application/pdf', headerBytes);

  assert.equal(result.detected, true);
  assert.equal(result.detectedType, 'zip_apk');
  assert.equal(result.severity, 'danger');
  assert.equal(result.score, 90);
  assert.equal(result.signal, 'SIG_ARCHIVE_DISGUISED_AS_DOC');
  assert.match(result.reason, /disguised as document/i);
});

test('File Magic 4: Benign PDF file (%PDF) returns safe verdict (0% false positive)', () => {
  const headerBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x35]);
  const result = inspectFileMagicBytes('syllabus.pdf', 'application/pdf', headerBytes);

  assert.equal(result.detected, false);
  assert.equal(result.detectedType, 'pdf');
  assert.equal(result.severity, 'safe');
  assert.equal(result.score, 0);
  assert.equal(result.signal, null);
});

test('File Magic 5: Benign JPEG image (FF D8 FF) returns safe verdict', () => {
  const headerBytes = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46]);
  const result = inspectFileMagicBytes('receipt.jpg', 'image/jpeg', headerBytes);

  assert.equal(result.detected, false);
  assert.equal(result.detectedType, 'jpeg');
  assert.equal(result.severity, 'safe');
  assert.equal(result.score, 0);
});

// ════════════════════════════════════════════════════════════════════════════════
// 4. REDIRECT CHAIN SIMULATION UNROLLER TESTS
// ════════════════════════════════════════════════════════════════════════════════

test('Simulation Unroller 1: Unrolls multi-hop rotator string and flags danger destination', () => {
  const rawInput = 'https://bit.ly/win-gift -> https://rotator.icu/jump?subid=44321 -> https://ad-gate.top/next -> https://stealer-drop.xyz/payload.exe';
  const unrolled = unrollRedirectChainSimulation(rawInput);

  assert.equal(unrolled.chainLength, 4);
  assert.equal(unrolled.finalUrl, 'https://stealer-drop.xyz/payload.exe');
  assert.equal(unrolled.forensics.hasRapidMultiHop, true);
  assert.equal(unrolled.forensics.hasTldTurbulence, true);
  assert.equal(unrolled.forensics.hasAdRotatorQuery, true);
  assert.equal(unrolled.verdict.severity, 'danger');
  assert.ok(unrolled.verdict.score >= 80);
  assert.ok(unrolled.hops[0].url.includes('bit.ly'));
  assert.ok(unrolled.hops[3].url.includes('stealer-drop.xyz'));
});

// ════════════════════════════════════════════════════════════════════════════════
// 5. MULTILINGUAL CITIZEN ADVISORY & REASON ID COVERAGE
// ════════════════════════════════════════════════════════════════════════════════

test('Multilingual Coverage: All 6 new signals have complete, valid translations across en, ta, hi, te', () => {
  const newSignals = [
    'SIG_MALVERTISING_REDIRECT_CHAIN',
    'SIG_TAB_UNDER_HIJACK',
    'SIG_ARCHIVE_PASSWORD_STEALER_LURE',
    'SIG_CLICKJACK_INVISIBLE_OVERLAY',
    'SIG_FAKE_DOWNLOAD_BUTTON_TRAP',
    'SIG_NOTIFICATION_PERMISSION_TRAP'
  ];

  const langs = ['en', 'ta', 'hi', 'te'];

  for (const sig of newSignals) {
    for (const lang of langs) {
      const text = getText(lang, `REASON_PLAIN.${sig}`);
      assert.ok(text && text.length > 5, `Missing translation for ${sig} in ${lang}`);
    }

    // Verify golden rule mapping
    const ruleKey = goldenRuleForSignal(sig);
    assert.ok(
      ['malvertising', 'apk', 'generic', 'otp_password'].includes(ruleKey),
      `Invalid or missing golden rule key ${ruleKey} for ${sig}`
    );

    // Verify English message lookup
    const enReason = t(sig);
    assert.ok(enReason && enReason.length > 5, `Missing English message for ${sig}`);
  }
});
