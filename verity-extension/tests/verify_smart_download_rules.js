/**
 * tests/verify_smart_download_rules.js
 *
 * Verifies:
 * 1. Safe media files (.mp4 1.3 GB) on unverified CDN (fastly.fastbytes.xyz) score <= 30 (allow/SAFE), NOT paused/blocked.
 * 2. Masquerading executables (.mp4.exe) and APKs on unverified domains score >= 85 (block/PAUSED).
 * 3. Suspiciously small video traps (< 500 KB) flag advisory warning.
 * 4. Interactive "Download Anyway" (resume) and "Cancel & Delete" actions work correctly.
 * 5. Official publisher software downloads (.exe) remain safe (Score <= 20).
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeDownload } from '../background/download/downloadAnalyzer.js';
import { applyDownloadPolicy } from '../background/download/downloadPolicy.js';
import {
  proceedAnyway,
  cancelAndDelete,
  userApprovedDownloadIds,
  approveDownload,
  isDownloadApproved,
  initDownloadMonitor
} from '../background/download/downloadMonitor.js';
import { calculateRisk } from '../background/risk-engine.js';
import {
  isIpBasedUrl,
  hasMissingHttps,
  hasExcessiveSubdomains,
  hasBrandNameInWrongDomain,
  hasSuspiciousUrlPattern,
  hasPunycodeOrKeywords,
  hasBrandVariantMatch,
  hasMalvertisingPattern,
  hasRandomLookingHostname,
  hasAffiliateTrackerPattern,
  hasPiracyOrUnverifiedMediaPattern,
} from '../background/rules.js';

function buildTestRuleSignals(url) {
  return [
    isIpBasedUrl(url),
    hasMissingHttps(url),
    hasExcessiveSubdomains(url),
    hasBrandNameInWrongDomain(url, []),
    hasSuspiciousUrlPattern(url),
    hasPunycodeOrKeywords(url),
    hasBrandVariantMatch(url, []),
    hasMalvertisingPattern(url),
    hasRandomLookingHostname(url),
    hasAffiliateTrackerPattern(url),
    hasPiracyOrUnverifiedMediaPattern(url),
  ];
}

// Setup Chrome API Mocks
const resumedDownloads = new Set();
const pausedDownloads = new Set();
const cancelledDownloads = new Set();
const erasedDownloads = new Set();

globalThis.chrome = {
  downloads: {
    pause: async (id) => { pausedDownloads.add(id); },
    resume: async (id) => { resumedDownloads.add(id); pausedDownloads.delete(id); },
    cancel: async (id) => { cancelledDownloads.add(id); },
    erase: async (query) => { erasedDownloads.add(query.id); },
    search: async () => []
  },
  storage: {
    session: {
      get: async () => ({}),
      set: async () => ({})
    }
  },
  tabs: {
    create: async () => ({ id: 999 })
  }
};

test('Case 1: Legitimate 1.3 GB .mp4 on fastly.fastbytes.xyz must ALLOW (Score <= 30), NOT paused or blocked', async () => {
  const url = 'https://fastly.fastbytes.xyz/movie.mp4';
  const downloadItem = {
    downloadId: 101,
    filename: 'Moviesda.Mobi_-_Meesaya_Murukku_2_2026_HDRip_1080p_HD_(1.3_GB).mp4',
    url: url,
    finalUrl: url,
    referrer: 'https://moviesda.soy/',
    mimeType: 'video/mp4',
    fileSize: 1395864371, // 1.3 GB
    danger: 'safe',
    tabId: 1
  };

  const ruleSignals = buildTestRuleSignals(url);
  const { verdict, downloadSignals, trustIndicators, checklist } = await analyzeDownload(
    downloadItem,
    [],
    calculateRisk,
    ruleSignals
  );

  console.log('\n--- Case 1: Legitimate 1.3 GB Media on .xyz CDN ---');
  console.log('Filename:', downloadItem.filename);
  console.log('Score:', verdict.score, '| Action:', verdict.action, '| Severity:', verdict.severity);
  console.log('Trust Indicators:', trustIndicators);
  console.log('Checklist:', checklist);

  assert.ok(verdict.score <= 30, `Score must be <= 30, got ${verdict.score}`);
  assert.equal(verdict.action, 'allow', 'Action must be allow');
  assert.equal(verdict.severity, 'safe', 'Severity must be safe');
  assert.ok(trustIndicators.length >= 2, 'Must have at least 2 trust indicators');
  assert.ok(trustIndicators.some(t => t.includes('Verified passive media format')), 'Must identify passive media');

  // Policy check
  const policy = await applyDownloadPolicy(downloadItem.downloadId, verdict, downloadSignals);
  console.log('Applied Policy:', policy);
  assert.equal(policy.action, 'allow', 'Policy action must be allow');
  assert.equal(policy.paused, false, 'Download must NOT be paused');
  assert.equal(policy.cancelled, false, 'Download must NOT be cancelled');
});

test('Case 2: Fake disguised video (Meesaya_Murukku_2_HD.mp4.exe) on .xyz must BLOCK (Score >= 85) & PAUSE', async () => {
  const url = 'https://fastly.fastbytes.xyz/Meesaya_Murukku_2_HD.mp4.exe';
  const downloadItem = {
    downloadId: 102,
    filename: 'Meesaya_Murukku_2_HD.mp4.exe',
    url: url,
    finalUrl: url,
    referrer: 'https://moviesda.soy/',
    mimeType: 'application/x-msdownload',
    fileSize: 2500000,
    danger: 'unknown',
    tabId: 1
  };

  const ruleSignals = buildTestRuleSignals(url);
  const { verdict, downloadSignals, checklist } = await analyzeDownload(
    downloadItem,
    [],
    calculateRisk,
    ruleSignals
  );

  console.log('\n--- Case 2: Masquerading Executable (.mp4.exe) ---');
  console.log('Score:', verdict.score, '| Action:', verdict.action);
  console.log('Checklist:', checklist);

  assert.ok(verdict.score >= 85, `Score must be >= 85, got ${verdict.score}`);
  assert.equal(verdict.action, 'block', 'Action must be block');
  assert.equal(verdict.severity, 'danger', 'Severity must be danger');

  // Policy check: Must pause so user can choose to resume or delete
  pausedDownloads.clear();
  const policy = await applyDownloadPolicy(downloadItem.downloadId, verdict, downloadSignals);
  console.log('Applied Policy:', policy);
  assert.equal(policy.action, 'block');
  assert.equal(policy.paused, true, 'Download must be paused');
  assert.equal(policy.cancelled, false, 'Must NOT immediately delete so user can override');
  assert.ok(pausedDownloads.has(102), 'Chrome API pause must have been called for id 102');
});

test('Case 3: Fake Player Update APK (Movie_Player_Update.apk) on .xyz must BLOCK (Score >= 85) & PAUSE', async () => {
  const url = 'https://fastly.fastbytes.xyz/Movie_Player_Update.apk';
  const downloadItem = {
    downloadId: 103,
    filename: 'Movie_Player_Update.apk',
    url: url,
    finalUrl: url,
    referrer: 'https://moviesda.soy/',
    mimeType: 'application/vnd.android.package-archive',
    fileSize: 15000000,
    danger: 'unknown',
    tabId: 1
  };

  const ruleSignals = buildTestRuleSignals(url);
  const { verdict, downloadSignals, checklist } = await analyzeDownload(
    downloadItem,
    [],
    calculateRisk,
    ruleSignals
  );

  console.log('\n--- Case 3: Untrusted APK Download ---');
  console.log('Score:', verdict.score, '| Action:', verdict.action);

  assert.ok(verdict.score >= 85, `Score must be >= 85, got ${verdict.score}`);
  assert.equal(verdict.action, 'block');
  assert.equal(verdict.severity, 'danger');

  pausedDownloads.clear();
  const policy = await applyDownloadPolicy(downloadItem.downloadId, verdict, downloadSignals);
  assert.equal(policy.action, 'block');
  assert.equal(policy.paused, true, 'Download must be paused');
  assert.ok(pausedDownloads.has(103), 'Chrome API pause must have been called for id 103');
});

test('Case 4: Tiny Video Trap (< 500 KB video on unverified domain) triggers advisory caution', async () => {
  const url = 'https://fastly.fastbytes.xyz/fake_trailer.mp4';
  const downloadItem = {
    downloadId: 104,
    filename: 'fake_trailer.mp4',
    url: url,
    finalUrl: url,
    referrer: 'https://moviesda.soy/',
    mimeType: 'video/mp4',
    fileSize: 120 * 1024, // 120 KB
    danger: 'safe',
    tabId: 1
  };

  const ruleSignals = buildTestRuleSignals(url);
  const { verdict, checklist } = await analyzeDownload(
    downloadItem,
    [],
    calculateRisk,
    ruleSignals
  );

  console.log('\n--- Case 4: Tiny Video Trap ---');
  console.log('Score:', verdict.score, '| Action:', verdict.action);

  assert.ok(verdict.score >= 40, `Score must be >= 40 for tiny video trap, got ${verdict.score}`);
  assert.equal(verdict.action, 'warn', 'Action should be warn advisory');
  assert.ok(checklist.some(c => c.text.includes('Suspiciously small video file')));
});

test('Case 5: Interactive User Overrides ("Download Anyway" and "Cancel & Delete")', async () => {
  const downloadId = 555;
  userApprovedDownloadIds.clear();
  resumedDownloads.clear();
  cancelledDownloads.clear();
  erasedDownloads.clear();

  // Test "Download Anyway" (proceedAnyway)
  assert.equal(isDownloadApproved(downloadId), false);
  const proceedResult = await proceedAnyway(downloadId);
  assert.equal(proceedResult.ok, true);
  assert.equal(isDownloadApproved(downloadId), true);
  assert.ok(resumedDownloads.has(downloadId), 'chrome.downloads.resume must have been called');

  // Verify that an approved download is not blocked by applyDownloadPolicy
  const approvedPolicy = await applyDownloadPolicy(downloadId, { action: 'block', severity: 'danger' }, {}, isDownloadApproved(downloadId));
  assert.equal(approvedPolicy.action, 'allow', 'Approved download must allow');
  assert.equal(approvedPolicy.paused, false);

  // Test "Cancel & Delete" (cancelAndDelete)
  const delId = 777;
  const cancelResult = await cancelAndDelete(delId);
  assert.equal(cancelResult.ok, true);
  assert.ok(cancelledDownloads.has(delId), 'chrome.downloads.cancel must have been called');
  assert.ok(erasedDownloads.has(delId), 'chrome.downloads.erase must have been called');
});

test('Case 6: Official Software Publisher Domain (.exe) remains safe (Score <= 20)', async () => {
  const url = 'https://github.com/videolan/vlc/releases/download/vlc-3.0.18-win64.exe';
  const downloadItem = {
    downloadId: 888,
    filename: 'vlc-3.0.18-win64.exe',
    url: url,
    finalUrl: url,
    referrer: 'https://github.com/',
    mimeType: 'application/x-msdownload',
    fileSize: 45000000,
    danger: 'safe',
    tabId: 1
  };

  const { verdict } = await analyzeDownload(downloadItem, [], calculateRisk, []);
  console.log('\n--- Case 6: Official Publisher .exe Download ---');
  console.log('Score:', verdict.score, '| Action:', verdict.action);
  assert.ok(verdict.score <= 20, `Official software score must be <= 20, got ${verdict.score}`);
  assert.equal(verdict.action, 'allow', 'Action must be allow');
});
