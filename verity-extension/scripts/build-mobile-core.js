#!/usr/bin/env node
/**
 * scripts/build-mobile-core.js — Builds mobile-scanner/core/ by copying engine files
 *
 * Copies pure engine modules from verity-extension/ without rewriting code.
 * Vendors tldts ESM from node_modules. Generates maskable PWA icons.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Determine extension root and repository root
const extensionRoot = path.resolve(__dirname, '..');
const repoRoot = path.resolve(extensionRoot, '..');

// Target locations: repo root mobile-scanner AND extension-internal mobile-scanner
const targets = [
  path.resolve(repoRoot, 'mobile-scanner'),
  path.resolve(extensionRoot, 'mobile-scanner')
];

console.log('Building Mobile PWA Core from:', extensionRoot);

// 1. Files to copy verbatim
const coreFiles = [
  { src: 'background/rules.js', dest: 'core/background/rules.js' },
  { src: 'background/risk-engine.js', dest: 'core/background/risk-engine.js' },
  { src: 'background/rich-feature-extractor.js', dest: 'core/background/rich-feature-extractor.js' },
  { src: 'background/homograph-detector.js', dest: 'core/background/homograph-detector.js' },
  { src: 'background/favicon-matcher.js', dest: 'core/background/favicon-matcher.js' },
  { src: 'background/enterprise-whitelist.js', dest: 'core/background/enterprise-whitelist.js' },
  { src: 'background/brand-detector.js', dest: 'core/background/brand-detector.js' },
  { src: 'content/bharat-scam-detectors.js', dest: 'core/content/bharat-scam-detectors.js' },
  { src: 'shared/legit-domains.js', dest: 'core/shared/legit-domains.js' },
  { src: 'shared/messages.en.js', dest: 'core/shared/messages.en.js' },
  { src: 'shared/messages.js', dest: 'core/shared/messages.js' },
  { src: 'shared/xray-educator.js', dest: 'core/shared/xray-educator.js' },
  { src: 'shared/citizen-messages.js', dest: 'core/shared/citizen-messages.js' },
  { src: 'shared/text-scanner.js', dest: 'core/shared/text-scanner.js' },
  { src: 'shared/upi-forensics.js', dest: 'core/shared/upi-forensics.js' },
  { src: 'shared/file-magic-inspector.js', dest: 'core/shared/file-magic-inspector.js' },
  { src: 'content/crack-site-shield.js', dest: 'core/content/crack-site-shield.js' },
  { src: 'shared/redirect-forensics.js', dest: 'core/shared/redirect-forensics.js' },
  { src: 'shared/psl.js', dest: 'core/shared/psl.js' },
  { src: 'brands.json', dest: 'core/brands.json' }
];

// Copy entire config/ directory
const configDir = path.resolve(extensionRoot, 'config');
const configFiles = fs.readdirSync(configDir);
for (const file of configFiles) {
  coreFiles.push({ src: `config/${file}`, dest: `core/config/${file}` });
}

// Vendored tldts
const tldtsSrc = path.resolve(extensionRoot, 'node_modules/tldts/dist/index.esm.min.js');

/**
 * Creates valid PNG buffer with RGBA pixel callback
 */
function createShieldPng(width, height) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  function makeChunk(type, data) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length, 0);
    const typeBuf = Buffer.from(type);
    const crcBuf = Buffer.alloc(4);
    const combined = Buffer.concat([typeBuf, data]);

    const crcTable = [];
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      crcTable[n] = c;
    }
    let crc = 0xffffffff;
    for (let i = 0; i < combined.length; i++) crc = crcTable[(crc ^ combined[i]) & 0xff] ^ (crc >>> 8);
    crcBuf.writeInt32BE((crc ^ 0xffffffff) | 0, 0);

    return Buffer.concat([len, typeBuf, data, crcBuf]);
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;

  const rawRows = [];
  const cx = width / 2;
  const cy = height / 2;
  const radius = width * 0.46;

  for (let y = 0; y < height; y++) {
    const row = Buffer.alloc(1 + width * 4);
    row[0] = 0;
    for (let x = 0; x < width; x++) {
      const dx = x - cx;
      const dy = y - cy;
      const dist = Math.sqrt(dx * dx + dy * dy);

      // Dark slate background circle
      let r = 11, g = 15, b = 25, a = 255;

      // Outer ring
      if (dist <= radius && dist >= radius - (width * 0.05)) {
        r = 16; g = 185; b = 129; a = 255; // Emerald border
      } else if (dist < radius - (width * 0.05)) {
        // Inner shield area
        const normY = (y - (height * 0.2)) / (height * 0.6);
        const normX = Math.abs(x - cx) / (width * 0.35);
        if (normY >= 0 && normY <= 1 && normX <= (1 - normY * 0.4)) {
          r = 5; g = 150; b = 105; a = 255;
          // Inner checkmark
          const inCheckX = (x - cx) / width;
          const inCheckY = (y - cy) / height;
          if ((inCheckY >= inCheckX * 0.9 - 0.05 && inCheckY <= inCheckX * 0.9 + 0.05 && inCheckX >= -0.15 && inCheckX <= 0.18) ||
              (inCheckY >= -inCheckX * 1.5 - 0.1 && inCheckY <= -inCheckX * 1.5 && inCheckX >= -0.22 && inCheckX <= -0.12)) {
            r = 255; g = 255; b = 255; a = 255;
          }
        }
      }

      const offset = 1 + x * 4;
      row[offset] = r; row[offset + 1] = g; row[offset + 2] = b; row[offset + 3] = a;
    }
    rawRows.push(row);
  }

  const compressed = zlib.deflateSync(Buffer.concat(rawRows));
  return Buffer.concat([
    signature,
    makeChunk('IHDR', ihdr),
    makeChunk('IDAT', compressed),
    makeChunk('IEND', Buffer.alloc(0))
  ]);
}

const icon192 = createShieldPng(192, 192);
const icon512 = createShieldPng(512, 512);

// Top-level core re-exports
const coreIndexCode = `export { scanText, parseUpiString, extractUrls } from './shared/text-scanner.js';
export {
  LANGS,
  STATUS,
  UI,
  GOLDEN_RULES,
  REASON_PLAIN,
  goldenRuleForSignal,
  getText,
  detectDefaultLang
} from './shared/citizen-messages.js';
export { generateXRayTeachingCards, parseUrlAnatomy } from './shared/xray-educator.js';
`;

const textScannerReExport = `export * from './shared/text-scanner.js';\nexport { default } from './shared/text-scanner.js';\n`;
const citizenMessagesReExport = `export * from './shared/citizen-messages.js';\nexport { default } from './shared/citizen-messages.js';\n`;
const xrayEducatorReExport = `export * from './shared/xray-educator.js';\nexport { default } from './shared/xray-educator.js';\n`;

// Process all targets
for (const targetBase of targets) {
  console.log(`Populating: ${targetBase}`);
  fs.mkdirSync(path.resolve(targetBase, 'icons'), { recursive: true });
  fs.mkdirSync(path.resolve(targetBase, 'core/vendor'), { recursive: true });
  fs.mkdirSync(path.resolve(targetBase, 'core/background'), { recursive: true });
  fs.mkdirSync(path.resolve(targetBase, 'core/shared'), { recursive: true });
  fs.mkdirSync(path.resolve(targetBase, 'core/content'), { recursive: true });
  fs.mkdirSync(path.resolve(targetBase, 'core/config'), { recursive: true });

  // 1. Copy core files verbatim
  for (const item of coreFiles) {
    const srcPath = path.resolve(extensionRoot, item.src);
    const destPath = path.resolve(targetBase, item.dest);
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    fs.copyFileSync(srcPath, destPath);
  }

  // 2. Vendor tldts
  if (fs.existsSync(tldtsSrc)) {
    fs.copyFileSync(tldtsSrc, path.resolve(targetBase, 'core/vendor/tldts.esm.js'));
  }

  // 3. Write core re-exports
  fs.writeFileSync(path.resolve(targetBase, 'core/index.js'), coreIndexCode);
  fs.writeFileSync(path.resolve(targetBase, 'core/text-scanner.js'), textScannerReExport);
  fs.writeFileSync(path.resolve(targetBase, 'core/citizen-messages.js'), citizenMessagesReExport);
  fs.writeFileSync(path.resolve(targetBase, 'core/xray-educator.js'), xrayEducatorReExport);

  // 4. Save PNG icons
  fs.writeFileSync(path.resolve(targetBase, 'icons/icon-192.png'), icon192);
  fs.writeFileSync(path.resolve(targetBase, 'icons/icon-512.png'), icon512);
}

console.log('Mobile core engine build complete! 16 files copied + icons generated.');
