/**
 * downloadAnalyzer.js - Combines all download signals into normalized risk features.
 * Reuses existing Verity modules: reputation, brand detector, redirect signals, risk engine.
 * Does NOT create a second risk engine.
 */

import { classifyFile } from './fileTypeAnalyzer.js';
import { analyzeFilename } from './filenameAnalyzer.js';
import { checkReputation } from '../reputation.js';
import { getRedirectSignals } from '../redirect-analyzer.js';
import { isAllowlistedDomain } from '../../shared/legit-domains.js';
import { getDomain } from '../../shared/psl.js';

/**
 * Extract hostname safely.
 * @param {string} urlString
 */
function safeHostname(urlString) {
  try { return new URL(urlString).hostname.toLowerCase(); } catch { return ''; }
}

// ─── 4-Tier File Trust Matrix Definitions ───────────────────────────────────

// Tier 1: Safe Passive Media & Documents
export const TIER1_PASSIVE_EXTENSIONS = new Set([
  '.mp4', '.mkv', '.webm', '.avi', '.mov', '.wmv',
  '.mp3', '.flac', '.wav', '.aac', '.ogg', '.m4a',
  '.jpg', '.jpeg', '.png', '.webp', '.gif', '.svg', '.bmp',
  '.srt', '.vtt', '.sub',
  '.txt', '.pdf', '.epub'
]);

export const VIDEO_EXTENSIONS = new Set(['.mp4', '.mkv', '.avi', '.webm', '.mov', '.wmv']);

// Tier 2: Archives & Modern Containers
export const TIER2_ARCHIVE_EXTENSIONS = new Set([
  '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.cab'
]);

export const TIER2_DISK_IMAGES = new Set([
  '.iso', '.img', '.vhd', '.vhdx', '.dmg'
]);

// Tier 3: High-Risk Executables & Scripts
export const TIER3_EXECUTABLE_EXTENSIONS = new Set([
  '.exe', '.com', '.scr', '.cpl', '.dll',
  '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.sh',
  '.msi', '.msp', '.pkg', '.deb', '.rpm', '.apk', '.xapk', '.apkm', '.ipa',
  '.lnk', '.chm', '.one', '.reg'
]);

// Known high-abuse TLDs
export const HIGH_ABUSE_TLDS = new Set([
  '.xyz', '.top', '.pw', '.tk', '.ml', '.rest', '.click', '.monster', '.live', '.fun', '.site', '.online'
]);

// Authoritative official software & game publisher domains
export const OFFICIAL_SOFTWARE_DOMAINS = new Set([
  'github.com', 'microsoft.com', 'mozilla.org', 'google.com',
  'videolan.org', 'steampowered.com', 'apple.com', 'adobe.com',
  'oracle.com', 'canonical.com', 'ubuntu.com', 'debian.org',
  'python.org', 'nodejs.org', 'golang.org', 'rust-lang.org',
  'vlc.org', 'steamcommunity.com', 'docker.com', 'jetbrains.com',
  'anydesk.com', 'teamviewer.com', 'rustdesk.com', 'zoom.us',
  'discord.com', 'slack.com', 'telegram.org', 'whatsapp.com',
  'libreoffice.org', 'apache.org', 'gimp.org', 'blender.org',
  '7-zip.org', 'win-rar.com', 'rarlab.com', 'notepad-plus-plus.org'
]);

export function formatFileSize(bytes) {
  if (!bytes || typeof bytes !== 'number' || bytes <= 0) return '';
  if (bytes < 1024) return bytes + ' B';
  const kb = bytes / 1024;
  if (kb < 1024) return kb.toFixed(1) + ' KB';
  const mb = kb / 1024;
  if (mb < 1024) return mb.toFixed(1) + ' MB';
  const gb = mb / 1024;
  return gb.toFixed(2) + ' GB';
}

export function isVerifiedSoftwareOrigin(hostname) {
  if (!hostname) return false;
  const host = hostname.toLowerCase();
  const regDomain = getDomain(host) || host;
  return OFFICIAL_SOFTWARE_DOMAINS.has(host) ||
         OFFICIAL_SOFTWARE_DOMAINS.has(regDomain) ||
         isAllowlistedDomain(host);
}

/**
 * Checks for masquerading executables (double-extension or executable MIME with passive extension).
 */
export function checkMasqueradingExecutable(filename, mimeType) {
  const lower = (filename || '').toLowerCase().trim();
  const mimeLower = (mimeType || '').toLowerCase().trim();

  const executableMimes = [
    'application/x-msdownload',
    'application/x-msdos-program',
    'application/vnd.microsoft.portable-executable',
    'application/vnd.android.package-archive',
    'application/x-executable',
    'application/x-sh',
    'application/x-bat',
    'application/x-dosexec',
    'application/x-msi'
  ];

  // 1. Double extension check
  const parts = lower.split('.');
  if (parts.length >= 3) {
    const actualExt = '.' + parts[parts.length - 1];
    const apparentExt = '.' + parts[parts.length - 2];
    if (TIER1_PASSIVE_EXTENSIONS.has(apparentExt) && (TIER3_EXECUTABLE_EXTENSIONS.has(actualExt) || TIER2_DISK_IMAGES.has(actualExt))) {
      return {
        isMasquerade: true,
        actualExtension: actualExt,
        apparentExtension: apparentExt,
        reason: `Executable file disguised with deceptive double extension "${apparentExt}${actualExt}"`
      };
    }
  }

  // Regex check for masquerading extensions
  const masqueradeRegex = /\.(mp4|mkv|webm|avi|mov|wmv|mp3|flac|wav|jpg|jpeg|png|webp|gif|srt|txt|pdf|epub)\.(exe|scr|cpl|msi|bat|cmd|ps1|vbs|vbe|js|hta|lnk|apk|xapk|reg|chm|com|jar|iso|vhd)$/i;
  const match = lower.match(masqueradeRegex);
  if (match) {
    return {
      isMasquerade: true,
      actualExtension: '.' + match[2],
      apparentExtension: '.' + match[1],
      reason: `Masquerading executable file: disguised as ".${match[1]}" with executable payload ".${match[2]}"`
    };
  }

  // 2. MIME type masquerade
  const lastDot = lower.lastIndexOf('.');
  const ext = lastDot >= 0 ? lower.slice(lastDot) : '';
  if (TIER1_PASSIVE_EXTENSIONS.has(ext)) {
    if (executableMimes.some(m => mimeLower.startsWith(m))) {
      return {
        isMasquerade: true,
        actualExtension: ext,
        apparentExtension: ext,
        reason: `MIME type masquerade: file claims passive extension "${ext}" but Content-Type is executable binary (${mimeLower})`
      };
    }
  }

  return { isMasquerade: false, actualExtension: ext, apparentExtension: '', reason: null };
}

/**
 * Analyze a download and produce a normalized risk features object with 4-Tier File Trust Evaluation.
 *
 * @param {object} downloadItem - Normalized chrome.downloads.DownloadItem
 * @param {Array}  brandsList   - Loaded brands for impersonation detection
 * @param {Function} calculateRisk - The central Verity risk engine function
 * @param {Array}  ruleSignals  - Pre-computed URL rule signals for source URL
 * @returns {Promise<object>} verdict from the central risk engine + downloadSignals + trustIndicators
 */
export async function analyzeDownload(downloadItem, brandsList, calculateRisk, ruleSignals) {
  const {
    downloadId,
    filename,
    url,
    finalUrl,
    referrer,
    mimeType,
    fileSize,
    danger,
    tabId,
  } = downloadItem;

  // ── 1. File Type Analysis ──────────────────────────────────────────────────
  const fileType = classifyFile(filename, mimeType);

  // ── 2. Filename Analysis ───────────────────────────────────────────────────
  const filenameAnalysis = analyzeFilename(filename);

  // ── 3. Source URL Reputation ───────────────────────────────────────────────
  const sourceUrl = referrer || url || '';
  const finalUrlStr = finalUrl || url || '';
  const sourceHostname = safeHostname(sourceUrl);
  const finalHostname  = safeHostname(finalUrlStr);

  let threatIntel = null;
  if (sourceHostname) {
    try {
      threatIntel = await checkReputation(sourceUrl);
    } catch { /* fail safe */ }
  }

  // ── 4. Brand Impersonation via filename ────────────────────────────────────
  let brandImpersonation = false;
  let brandImpersonationName = null;
  if (brandsList && Array.isArray(brandsList)) {
    const lowerFilename = (filename || '').toLowerCase();
    for (const brand of brandsList) {
      const brandLower = (brand.name || '').toLowerCase();
      if (brandLower.length > 2 && lowerFilename.includes(brandLower)) {
        const isOfficialDomain = (brand.domains || []).some(d =>
          finalHostname === d || finalHostname.endsWith('.' + d)
        );
        if (!isOfficialDomain) {
          brandImpersonation = true;
          brandImpersonationName = brand.name;
          break;
        }
      }
    }
  }

  // ── 5. Redirect Signals ────────────────────────────────────────────────────
  let redirectSignals = null;
  if (tabId != null) {
    try {
      redirectSignals = getRedirectSignals(tabId);
    } catch { /* fail safe */ }
  }

  // ── 6. Chrome Danger State ─────────────────────────────────────────────────
  const chromeDangerState = danger || 'unknown';
  const chromeSaysDangerous = ['dangerous', 'dangerousHost', 'uncommon', 'dangerousUrl', 'dangerousContent'].includes(chromeDangerState);

  // ── 7. Source Domain Risk Context ─────────────────────────────────────────
  const sourceDomainMalicious = !!(threatIntel && threatIntel.malware);
  const isHighAbuseTld = Array.from(HIGH_ABUSE_TLDS).some(tld =>
    sourceHostname.endsWith(tld) || finalHostname.endsWith(tld)
  );
  const sourceDomainSuspicious = sourceDomainMalicious || isHighAbuseTld;

  // ── 7b. HTML Smuggling Detection ──────────────────────────────────────────
  const urlLower = (url || '').toLowerCase();
  const finalUrlLower = (finalUrl || '').toLowerCase();
  const isBlobOrData = urlLower.startsWith('blob:') || urlLower.startsWith('data:') ||
                       finalUrlLower.startsWith('blob:') || finalUrlLower.startsWith('data:');

  const originatingUrl = downloadItem.originatingUrl || referrer || '';
  const originatingHost = downloadItem.originatingHostname || safeHostname(originatingUrl);
  const isAllowlistedOrigin = isAllowlistedDomain(originatingUrl) || isAllowlistedDomain(originatingHost);

  const htmlSmuggling = !!(downloadItem.htmlSmuggling ?? (isBlobOrData && !isAllowlistedOrigin));

  // ── 8. Build Normalized Download Risk Features ─────────────────────────────
  const dangerousExtensionList = [
    '.exe', '.com', '.scr', '.cpl', '.dll',
    '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.sh',
    '.msi', '.msp', '.pkg', '.deb', '.rpm', '.dmg', '.apk', '.xapk', '.apkm', '.ipa',
    '.iso', '.img', '.vhd', '.vhdx', '.lnk', '.chm', '.one', '.reg', '.cab'
  ];
  const ext = (fileType.extension || '').toLowerCase();
  const isDangerousExtension = dangerousExtensionList.includes(ext);

  // Remote Desktop Scam Tool Detection
  const remoteTools = ['anydesk', 'rustdesk', 'ultraviewer', 'teamviewer', 'screenconnect', 'supremo', 'ammyy', 'quickassist'];
  const officialRemoteDomains = ['anydesk.com', 'teamviewer.com', 'rustdesk.com', 'ultraviewer.net', 'screenconnect.com', 'supremo.net', 'ammyy.com', 'microsoft.com'];
  const lowerFilename = (filename || '').toLowerCase();
  const matchedRemoteTool = remoteTools.find(t => lowerFilename.includes(t));
  const isOfficialRemoteDomain = officialRemoteDomains.some(d =>
    finalHostname === d || finalHostname.endsWith('.' + d) ||
    sourceHostname === d || sourceHostname.endsWith('.' + d)
  );
  const remoteAccessScam = !!(matchedRemoteTool && !isOfficialRemoteDomain);

  // Masquerade and Double Extension Analysis (Rule A)
  const masquerade = checkMasqueradingExecutable(filename, mimeType);

  const downloadSignals = {
    analysisContext: 'download',
    remoteAccessScam,
    remoteAccessTool: matchedRemoteTool || null,
    // File type
    executableDownload: fileType.isExecutable || masquerade.isMasquerade,
    scriptDownload:     fileType.isScript,
    installerDownload:  fileType.isInstaller,
    archiveDownload:    fileType.isArchive,
    fileCategory:       fileType.category,
    extension:          fileType.extension,
    isDangerousExtension: isDangerousExtension || masquerade.isMasquerade,
    // HTML Smuggling & Spoofing
    htmlSmuggling,
    originatingHostname: originatingHost,
    contentDispositionSpoofed: !!downloadItem.contentDispositionSpoofed,
    // Filename analysis
    doubleExtension:    filenameAnalysis.doubleExtension || masquerade.isMasquerade,
    misleadingFilename: filenameAnalysis.misleadingFilename,
    suspiciousKeyword:  filenameAnalysis.suspiciousKeyword,
    hasUnicode:         filenameAnalysis.hasUnicode,
    apparentExtension:  masquerade.apparentExtension || filenameAnalysis.apparentExtension,
    // Source analysis
    sourceDomainSuspicious,
    sourceDomainMalicious,
    // Brand
    brandImpersonation,
    brandImpersonationName,
    // Redirect
    shortenerDetected: !!(redirectSignals && redirectSignals.shortenerDetected),
    redirectCount:     redirectSignals ? redirectSignals.redirectCount : 0,
    crossDomainRedirectCount: redirectSignals ? redirectSignals.crossDomainRedirectCount : 0,
    // Chrome danger
    chromeDangerState,
    chromeSaysDangerous,
    // Raw data for display
    filename,
    sourceHostname: sourceHostname || finalHostname,
    fileSize,
  };

  // ── 9. Feed into Central Risk Engine ──────────────────────────────────────
  const downloadDomSignals = {
    isTrustedDomain: false,
    hasPasswordInput: false,
    loginFormCount: 0,
    formActions: [],
    scam: false,
    pup: false,
    financialMatches: [],
    hasCredentialCollection: false,
    paymentFields: {},
    hasPaymentForm: false,
    claimedProviders: [],
    pageText: '',
    pageTitle: filename || '',
  };

  const verdict = (typeof calculateRisk === 'function') ? calculateRisk(
    sourceUrl || finalUrlStr,
    ruleSignals || [],
    null,             // mlScore — not applicable for downloads
    downloadDomSignals,
    threatIntel,
    redirectSignals,
    null,             // paymentAnalysis — not applicable here
    downloadSignals
  ) : {
    score: 0,
    riskScore: 0,
    severity: 'safe',
    action: 'allow',
    signals: [],
    reasons: []
  };

  // ── 10. 4-Tier File Trust Matrix Evaluation & Normalization ────────────────
  const isVerifiedDomain = isVerifiedSoftwareOrigin(sourceHostname) || isVerifiedSoftwareOrigin(finalHostname);
  const effectiveSize = (typeof fileSize === 'number' && fileSize > 0) ? fileSize : 0;
  const formattedSize = formatFileSize(effectiveSize);

  let trustIndicators = [];
  const checklist = [];

  // TIER 1: Safe Passive Media & Documents
  if (TIER1_PASSIVE_EXTENSIONS.has(ext)) {
    if (masquerade.isMasquerade) {
      // Rule A: Masquerading executable
      verdict.score = 95;
      verdict.riskScore = 95;
      verdict.action = 'block';
      verdict.severity = 'danger';
      verdict.state = 'danger';
      verdict.reasons = [masquerade.reason];
      checklist.push({ type: 'fail', text: masquerade.reason });
      checklist.push({ type: 'fail', text: 'Executable payload disguised as media or document' });
      checklist.push({ type: 'fail', text: 'Blocked for system execution safety' });
    } else {
      // Check Rule B: Tiny Video Trap (< 500 KB on unverified domain)
      const isTinyVideo = VIDEO_EXTENSIONS.has(ext) && !isVerifiedDomain && (effectiveSize > 0 && effectiveSize < 500 * 1024);
      if (isTinyVideo) {
        verdict.score = Math.max(verdict.score, 45);
        verdict.riskScore = verdict.score;
        verdict.action = 'warn';
        verdict.severity = 'caution';
        verdict.state = 'caution';
        verdict.reasons = [`Suspiciously small video file (${formattedSize}) from unverified domain (possible fake download payload)`];
        checklist.push({ type: 'warn', text: `Suspiciously small video file (${formattedSize}) (possible fake download payload)` });
        checklist.push({ type: 'warn', text: `Hosted on unverified third-party origin (${sourceHostname || finalHostname})` });
        checklist.push({ type: 'pass', text: 'No executable code or double-extension detected' });
      } else {
        // Rule C: Genuine passive media file
        // CAP risk score at 25 (SAFE / allow) or at most 40 (CAUTION advisory — NEVER pause or block!)
        verdict.score = Math.min(verdict.score, 25);
        verdict.riskScore = verdict.score;
        verdict.action = 'allow';
        verdict.severity = 'safe';
        verdict.state = 'safe';
        verdict.reasons = [];

        trustIndicators = [
          `Verified passive media format (${ext})`,
          'No executable code or double-extension detected'
        ];
        if (effectiveSize > 0) {
          trustIndicators.push(`Standard media file size (${formattedSize})`);
        }

        checklist.push({ type: 'pass', text: `Verified passive media format (${ext})` });
        checklist.push({ type: 'pass', text: 'No executable code or double-extension detected' });
        if (effectiveSize > 0) {
          checklist.push({ type: 'pass', text: `Standard media file size (${formattedSize})` });
        }
        if (sourceDomainSuspicious) {
          checklist.push({ type: 'warn', text: `Hosted on unverified third-party CDN (${sourceHostname || finalHostname})` });
        }
      }
    }
  }

  // TIER 2: Archives & Disk Containers
  else if (TIER2_ARCHIVE_EXTENSIONS.has(ext) || TIER2_DISK_IMAGES.has(ext)) {
    if (isVerifiedDomain) {
      verdict.score = 0;
      verdict.riskScore = 0;
      verdict.action = 'allow';
      verdict.severity = 'safe';
      verdict.state = 'safe';
      verdict.reasons = [];
      trustIndicators = [`Downloaded from verified official publisher (${sourceHostname || finalHostname})`];
      checklist.push({ type: 'pass', text: `Downloaded from verified official publisher (${sourceHostname || finalHostname})` });
      checklist.push({ type: 'pass', text: 'No spoofed headers detected' });
    } else {
      if (TIER2_DISK_IMAGES.has(ext)) {
        // Disk images (.iso, .img, .vhd) from unverified domains score 75 (Pause & Ask)
        verdict.score = Math.max(verdict.score, 75);
        verdict.riskScore = verdict.score;
        verdict.action = 'block';
        verdict.severity = 'danger';
        verdict.state = 'danger';
        verdict.reasons = [`Disk image container (${ext}) downloaded from unverified origin requires confirmation`];
        checklist.push({ type: 'fail', text: `Disk image container (${ext}) can mount executable filesystem` });
        checklist.push({ type: 'warn', text: `Unverified source domain (${sourceHostname || finalHostname})` });
        checklist.push({ type: 'fail', text: 'Not digitally signed by a known publisher domain' });
      } else {
        // Standard archive (.zip, .rar, .7z)
        if (isHighAbuseTld) {
          // High-abuse TLD -> Score: 70 (Pause & Ask)
          verdict.score = Math.max(verdict.score, 70);
          verdict.riskScore = verdict.score;
          verdict.action = 'block';
          verdict.severity = 'danger';
          verdict.state = 'danger';
          verdict.reasons = [`Archive file (${ext}) hosted on high-abuse TLD domain`];
          checklist.push({ type: 'fail', text: `Archive container (${ext}) hosted on high-abuse TLD` });
          checklist.push({ type: 'warn', text: `Unverified source domain (${sourceHostname || finalHostname})` });
        } else {
          // Unverified domain -> Score 45–60 (CAUTION)
          verdict.score = Math.max(Math.min(verdict.score, 60), 45);
          verdict.riskScore = verdict.score;
          verdict.action = 'warn';
          verdict.severity = 'caution';
          verdict.state = 'caution';
          checklist.push({ type: 'warn', text: `Archive container from unverified origin (${sourceHostname || finalHostname})` });
        }
      }
    }
  }

  // TIER 3: High-Risk Executables & Scripts
  else if (TIER3_EXECUTABLE_EXTENSIONS.has(ext) || downloadSignals.isDangerousExtension) {
    if (isVerifiedDomain && !remoteAccessScam) {
      verdict.score = Math.min(verdict.score, 20);
      verdict.riskScore = verdict.score;
      verdict.action = 'allow';
      verdict.severity = 'safe';
      verdict.state = 'safe';
      verdict.reasons = [];
      trustIndicators = [`Official verified software publisher (${sourceHostname || finalHostname})`];
      checklist.push({ type: 'pass', text: `Official verified software publisher (${sourceHostname || finalHostname})` });
      checklist.push({ type: 'pass', text: 'Verified download identity' });
    } else {
      verdict.score = Math.max(verdict.score, 85);
      verdict.riskScore = verdict.score;
      verdict.action = 'block';
      verdict.severity = 'danger';
      verdict.state = 'danger';
      checklist.push({ type: 'fail', text: `Executable file (${ext}) can run arbitrary system commands` });
      if (sourceDomainSuspicious) {
        checklist.push({ type: 'warn', text: `Unverified source domain uses high-abuse TLD (${sourceHostname || finalHostname})` });
      } else {
        checklist.push({ type: 'warn', text: `Unverified source domain (${sourceHostname || finalHostname})` });
      }
      checklist.push({ type: 'fail', text: 'Not digitally signed by a known publisher domain' });
    }
  }

  // Critical Overrides: Remote Access Scam, HTML Smuggling, Spoofing, Chrome Dangerous
  if (remoteAccessScam) {
    verdict.score = 90;
    verdict.riskScore = 90;
    verdict.action = 'block';
    verdict.severity = 'danger';
    verdict.state = 'danger';
    checklist.unshift({ type: 'fail', text: `Remote desktop access tool (${matchedRemoteTool}) downloaded from unverified origin` });
  }

  if (chromeSaysDangerous) {
    verdict.score = 95;
    verdict.riskScore = 95;
    verdict.action = 'block';
    verdict.severity = 'danger';
    verdict.state = 'danger';
    checklist.unshift({ type: 'fail', text: 'Google Chrome identified this download as dangerous' });
  }

  if (downloadSignals.htmlSmuggling && (downloadSignals.isDangerousExtension || downloadSignals.archiveDownload)) {
    verdict.score = Math.max(verdict.score, 85);
    verdict.riskScore = verdict.score;
    verdict.action = 'block';
    verdict.severity = 'danger';
    verdict.state = 'danger';
    checklist.unshift({ type: 'fail', text: 'HTML smuggling: blob/data payload generated from unverified origin' });
  }

  if (downloadSignals.contentDispositionSpoofed) {
    verdict.score = Math.max(verdict.score, 85);
    verdict.riskScore = verdict.score;
    verdict.action = 'block';
    verdict.severity = 'danger';
    verdict.state = 'danger';
    checklist.unshift({ type: 'fail', text: 'Content-Disposition header spoofed document URL to executable/container' });
  }

  downloadSignals.trustIndicators = trustIndicators;
  downloadSignals.checklist = checklist;
  verdict.trustIndicators = trustIndicators;
  verdict.checklist = checklist;

  return { verdict, downloadSignals, trustIndicators, checklist };
}

