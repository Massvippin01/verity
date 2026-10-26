import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const distDir = path.resolve(rootDir, 'dist');
const stageDir = path.resolve(distDir, 'stage_verity');
const zipFile = path.resolve(distDir, 'verity-v2.0-submission.zip');

console.log('=== VERITY 2.0 SUBMISSION PACKAGING ===');
console.log('Root Directory:', rootDir);

// 1. Clean dist staging
if (fs.existsSync(stageDir)) {
  fs.rmSync(stageDir, { recursive: true, force: true });
}
fs.mkdirSync(stageDir, { recursive: true });

// 2. Explicit Allowlist
const ALLOWLIST_FILES = [
  '.gitignore',
  'LICENSE',
  'package.json',
  'README.md',
  'test_server.js',
  'verity_demo_server.js'
];

const ALLOWLIST_DIRS = [
  'android-app',
  'demo',
  'docs',
  'mobile-scanner',
  'sample_data',
  'scripts',
  'verity-cloud',
  'verity-extension'
];

// Blocklist patterns that must NEVER enter the distribution ZIP
const BLOCKLIST_PATTERNS = [
  /node_modules/i,
  /(?:^|[\\\/])\.git(?:[\\\/]|$)/i,
  /\.gemini/i,
  /\.DS_Store/i,
  /\.env/i,
  /\.log$/i,
  /\.tmp$/i,
  /\.bak$/i,
  /thumbs\.db/i,
  /dist[\\\/]/i
];

function shouldInclude(relPath) {
  for (const pattern of BLOCKLIST_PATTERNS) {
    if (pattern.test(relPath)) return false;
  }
  return true;
}

function copyRecursive(src, dest, baseRel = '') {
  const stat = fs.statSync(src);
  if (stat.isDirectory()) {
    if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
    const entries = fs.readdirSync(src);
    for (const entry of entries) {
      const srcChild = path.join(src, entry);
      const destChild = path.join(dest, entry);
      const relChild = path.join(baseRel, entry);
      if (shouldInclude(relChild)) {
        copyRecursive(srcChild, destChild, relChild);
      }
    }
  } else {
    if (shouldInclude(baseRel)) {
      fs.copyFileSync(src, dest);
    }
  }
}

// Copy allowlisted root files
console.log('Copying allowlisted root files...');
for (const file of ALLOWLIST_FILES) {
  const src = path.join(rootDir, file);
  const dest = path.join(stageDir, file);
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, dest);
    console.log(`  + ${file}`);
  }
}

// Copy allowlisted directories
console.log('Copying allowlisted directories...');
for (const dir of ALLOWLIST_DIRS) {
  const src = path.join(rootDir, dir);
  const dest = path.join(stageDir, dir);
  if (fs.existsSync(src)) {
    console.log(`  + ${dir}/`);
    copyRecursive(src, dest, dir);
  }
}

// 3. Verify zero secrets or prohibited artifacts in stage
console.log('\nRunning safety and secrecy scan on staged files...');
let stagedFileCount = 0;
let totalSizeBytes = 0;

function auditStaged(dir) {
  const entries = fs.readdirSync(dir);
  for (const entry of entries) {
    const fullPath = path.join(dir, entry);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      auditStaged(fullPath);
    } else {
      stagedFileCount++;
      totalSizeBytes += stat.size;
      const rel = path.relative(stageDir, fullPath);
      // Check prohibited filename patterns
      for (const pattern of BLOCKLIST_PATTERNS) {
        if (pattern.test(rel)) {
          throw new Error(`SECURITY AUDIT FAILURE: Blocked file leaked into stage: ${rel}`);
        }
      }
    }
  }
}

auditStaged(stageDir);
console.log(`Safety audit PASSED: ${stagedFileCount} files verified (${(totalSizeBytes / (1024 * 1024)).toFixed(2)} MB uncompressed).`);

// 4. Create ZIP archive
if (fs.existsSync(zipFile)) {
  fs.unlinkSync(zipFile);
}

console.log('\nCompressing staged package to ZIP archive...');
const psCommand = `powershell -NoProfile -Command "Compress-Archive -Path '${stageDir}\\*' -DestinationPath '${zipFile}' -CompressionLevel Optimal"`;
execSync(psCommand, { stdio: 'inherit' });

const zipStat = fs.statSync(zipFile);
console.log(`\nSUCCESS: Distribution archive created at:\n  ${zipFile}\n  Size: ${(zipStat.size / (1024 * 1024)).toFixed(2)} MB`);

// Clean staging dir
fs.rmSync(stageDir, { recursive: true, force: true });
console.log('Staging cleanup complete.');
