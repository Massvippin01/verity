import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

// Import portable engine from mobile-scanner/core/
import { scanText, parseUpiString } from '../../mobile-scanner/core/index.js';
import brands from '../../mobile-scanner/core/brands.json' with { type: 'json' };

test('Mobile Core: 1. Preset Fake SBI KYC scenario returns danger verdict', () => {
  const input = 'Dear customer, your SBI NetBanking account is blocked. Update your PAN/Aadhaar KYC immediately at: https://sbi-kyc-verify.invalid/login';
  const result = scanText(input, { brandsList: brands });

  assert.equal(result.verdict, 'danger');
  assert.ok(result.score >= 70, `Expected score >= 70, got ${result.score}`);
  assert.equal(result.goldenRuleKey, 'otp_password');
});

test('Mobile Core: 2. Preset CBI Digital Arrest scenario returns danger verdict', () => {
  const input = 'Urgent: CBI cyber crime cell notice. A narcotics parcel under your Aadhaar has been intercepted. You are under digital arrest. Connect to video call immediately.';
  const result = scanText(input, { brandsList: brands });

  assert.equal(result.verdict, 'danger');
  assert.ok(result.score >= 80, `Expected score >= 80, got ${result.score}`);
  assert.equal(result.goldenRuleKey, 'digital_arrest');
  assert.ok(result.signals.some(s => s.id === 'SIG_DIGITAL_ARREST_EXTORTION'));
});

test('Mobile Core: 3. Preset OLX UPI QR collect trap scenario returns danger verdict', () => {
  const input = 'upi://pay?pa=buyer99@ybl&am=25000&tn=OLX buyer advance refund claim';
  const result = scanText(input, { brandsList: brands });

  assert.equal(result.verdict, 'danger');
  assert.ok(result.score >= 70, `Expected score >= 70, got ${result.score}`);
  assert.equal(result.goldenRuleKey, 'upi');
  assert.ok(result.extracted.upi !== null);
  assert.equal(result.extracted.upi.isCollect, true);
  assert.equal(result.extracted.upi.am, '25000');
  assert.ok(result.signals.some(s => s.id === 'SIG_UPI_QR_COLLECT_TRAP'));
});

test('Mobile Core: 4. Preset RTO Challan.apk download scenario returns danger verdict', () => {
  const input = 'Pending traffic challan of Rs 1,000 for your vehicle. Download and pay fine: https://parivahan-challan.invalid/app/RTO_Challan.apk';
  const result = scanText(input, { brandsList: brands });

  assert.equal(result.verdict, 'danger');
  assert.ok(result.score >= 80, `Expected score >= 80, got ${result.score}`);
  assert.equal(result.goldenRuleKey, 'apk');
  assert.ok(result.extracted.apkNames.some(n => n.toLowerCase() === 'rto_challan.apk'));
  assert.ok(result.signals.some(s => s.id === 'SIG_MALICIOUS_APK_DROPPER'));
});

test('Mobile Core: 5. Three legitimate Indian portals return safe verdict (score 0)', () => {
  const legitSites = [
    'https://onlinesbi.sbi',
    'https://www.irctc.co.in/nget/',
    'https://digilocker.gov.in/'
  ];

  for (const url of legitSites) {
    const res = scanText(url, { brandsList: brands });
    assert.equal(res.verdict, 'safe', `Expected safe for ${url}, got ${res.verdict}`);
    assert.equal(res.score, 0, `Expected score 0 for ${url}, got ${res.score}`);
    assert.equal(res.signals.length, 0);
  }
});

test('Mobile Core: 6. manifest.webmanifest includes standalone display, icons, and share_target', () => {
  const manifestPath = path.resolve('../mobile-scanner/manifest.webmanifest');
  assert.ok(fs.existsSync(manifestPath), 'manifest.webmanifest must exist');

  const raw = fs.readFileSync(manifestPath, 'utf8');
  const manifest = JSON.parse(raw);

  assert.equal(manifest.display, 'standalone');
  assert.equal(manifest.start_url, './');
  assert.equal(manifest.scope, './');
  assert.ok(manifest.theme_color);

  // Check icons
  assert.ok(Array.isArray(manifest.icons) && manifest.icons.length >= 2);
  const icon192 = manifest.icons.find(i => i.sizes === '192x192');
  const icon512 = manifest.icons.find(i => i.sizes === '512x512');
  assert.ok(icon192, '192x192 icon missing');
  assert.ok(icon512, '512x512 icon missing');

  // Verify icon files on disk
  const icon192File = path.resolve('../mobile-scanner', icon192.src);
  const icon512File = path.resolve('../mobile-scanner', icon512.src);
  assert.ok(fs.existsSync(icon192File), 'icon-192.png file does not exist');
  assert.ok(fs.existsSync(icon512File), 'icon-512.png file does not exist');
  assert.ok(fs.statSync(icon192File).size > 100);
  assert.ok(fs.statSync(icon512File).size > 100);

  // Check share_target
  assert.ok(manifest.share_target, 'share_target must be defined');
  assert.equal(manifest.share_target.action, './');
  assert.equal(manifest.share_target.method.toUpperCase(), 'GET');
  assert.deepEqual(manifest.share_target.params, {
    title: 'title',
    text: 'text',
    url: 'url'
  });
});

test('Mobile Core: 7. No file in mobile-scanner/ references chrome.* extension APIs', () => {
  const mobileDir = path.resolve('../mobile-scanner');

  function checkDir(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        checkDir(fullPath);
      } else if (entry.isFile() && (entry.name.endsWith('.js') || entry.name.endsWith('.html') || entry.name.endsWith('.webmanifest'))) {
        const content = fs.readFileSync(fullPath, 'utf8');
        assert.equal(
          content.includes('chrome.'),
          false,
          `Forbidden chrome.* reference found in mobile file: ${path.relative(mobileDir, fullPath)}`
        );
      }
    }
  }

  checkDir(mobileDir);
});
