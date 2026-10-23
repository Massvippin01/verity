/**
 * mobile-scanner/scanner.js — 4-Tool Citizen Cyber Forensics Lab Logic
 *
 * 1. Message, Link & Multi-Hop Redirect Chain Scanner
 * 2. QR Image / UPI Screenshot Inspector (BarcodeDetector + Simulation)
 * 3. WhatsApp File & APK Magic-Byte Inspector (100% Offline via File.slice)
 * 4. Multilingual Plain-Language Advisories & Educational Micro-Quiz
 */

import { scanText, parseUpiString, unrollRedirectChainSimulation } from './core/shared/text-scanner.js';
import { inspectFileMagicBytes } from './core/shared/file-magic-inspector.js';
import {
  LANGS,
  STATUS,
  UI,
  GOLDEN_RULES,
  REASON_PLAIN,
  goldenRuleForSignal,
  detectDefaultLang
} from './core/shared/citizen-messages.js';
import { generateXRayTeachingCards } from './core/shared/xray-educator.js';

// Application State
let currentLang = 'en';
let cachedBrands = [];
let lastScanResult = null;
let quizAnswered = false;

// DOM Elements
const $ = (id) => document.getElementById(id);
const langBtns = document.querySelectorAll('.lang-btn');
const toolTabs = document.querySelectorAll('.tool-tab-btn');
const demoChips = document.querySelectorAll('.chip-btn');

const panelScanner = $('panel-scanner');
const panelQr = $('panel-qr');
const panelFile = $('panel-file');

const scannerTextarea = $('scanner-textarea');
const btnCheck = $('btn-check');
const btnUnroll = $('btn-unroll');
const redirectTraceBox = $('redirect-trace-box');
const traceHopCount = $('trace-hop-count');
const hopsList = $('hops-list');

const qrDropzone = $('qr-dropzone');
const qrFileInput = $('qr-file-input');
const qrNotice = $('qr-notice');

const fileDropzone = $('file-dropzone');
const magicFileInput = $('magic-file-input');
const fileResultBox = $('file-result-box');
const fileMetaName = $('file-meta-name');
const fileMetaSize = $('file-meta-size');
const fileMetaHex = $('file-meta-hex');

const verdictCard = $('verdict-card');
const verdictIcon = $('verdict-icon');
const verdictTitle = $('verdict-title');
const verdictScoreBadge = $('verdict-score-badge');
const upiTrapBanner = $('upi-trap-banner');
const reasonsList = $('reasons-list');

const whyAccordion = $('why-accordion');
const whySummary = $('why-summary');
const whyBullets = $('why-bullets');
const quizHeading = $('quiz-heading');
const quizPrompt = $('quiz-prompt');
const quizOptionsGroup = $('quiz-options-group');
const quizFeedbackBox = $('quiz-feedback-box');

const goldenTitle = $('golden-title');
const goldenText = $('golden-text');
const privacyLine = $('privacy-line');

// Demo Pre-Sets
export const DEMO_PRESETS = {
  sbi_kyc: 'Dear customer, your SBI NetBanking account is blocked. Update your PAN/Aadhaar KYC immediately at: https://sbi-kyc-verify.invalid/login',
  digital_arrest: 'Urgent: CBI cyber crime cell notice. A narcotics parcel under your Aadhaar has been intercepted. You are under digital arrest. Connect to video call immediately.',
  olx_upi: 'upi://pay?pa=buyer99@ybl&am=25000&tn=OLX buyer advance refund claim',
  rto_apk: 'Pending traffic challan of Rs 1,000 for your vehicle. Download and pay fine: https://parivahan-challan.invalid/app/RTO_Challan.apk',
  multihop_rotator: 'https://bit.ly/claim-prize -> https://rotator.icu/track?subid=987654 -> https://ad-bridge.top/gate -> https://malware-drop.xyz/download'
};

export const QR_SIMULATIONS = {
  olx_qr: 'upi://pay?pa=buyer99@ybl&am=25000&tn=OLX buyer advance refund claim',
  unsigned_p2p: 'upi://pay?pa=unknown_p2p@upi&am=5000&tn=Instant approval fee',
  safe_merchant: 'upi://pay?pa=swiggy@icici&pn=Swiggy&am=450&mc=5411&sign=VALID_MOCK_SIGNATURE'
};

export const MAGIC_SIMULATIONS = {
  spoofed_pdf: {
    name: 'HDFC_Credit_Card_Statement.pdf',
    type: 'application/pdf',
    bytes: new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00])
  },
  rto_apk: {
    name: 'RTO_Traffic_Challan.apk',
    type: 'application/vnd.android.package-archive',
    bytes: new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00])
  },
  safe_pdf: {
    name: 'syllabus.pdf',
    type: 'application/pdf',
    bytes: new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37])
  }
};

/**
 * Loads the brands dataset once.
 */
async function loadBrands() {
  if (cachedBrands.length > 0) return cachedBrands;
  try {
    const res = await fetch('./core/brands.json');
    if (res.ok) cachedBrands = await res.json();
  } catch (err) {
    cachedBrands = [];
  }
  return cachedBrands;
}

/**
 * Updates all translated labels on screen.
 */
export function updateLanguageUI() {
  document.documentElement.lang = currentLang;

  langBtns.forEach(btn => {
    const isSel = btn.dataset.lang === currentLang;
    btn.classList.toggle('active', isSel);
    btn.setAttribute('aria-selected', isSel ? 'true' : 'false');
  });

  const setT = (el, txt) => {
    if (el && txt) {
      el.textContent = txt;
      el.setAttribute('lang', currentLang);
    }
  };

  setT(btnCheck, UI[currentLang]?.checkButton || UI.en.checkButton);
  if (scannerTextarea) {
    scannerTextarea.placeholder = UI[currentLang]?.pastePlaceholder || UI.en.pastePlaceholder;
    scannerTextarea.setAttribute('lang', currentLang);
  }
  setT(goldenTitle, UI[currentLang]?.goldenRuleTitle || UI.en.goldenRuleTitle);
  setT(whySummary, UI[currentLang]?.whyTitle || UI.en.whyTitle);
  setT(privacyLine, UI[currentLang]?.privacyLine || UI.en.privacyLine);

  if (lastScanResult) {
    renderVerdict(lastScanResult);
  }
}

/**
 * Switches the active UI language.
 */
export function setLanguage(langCode) {
  if (['en', 'ta', 'hi', 'te'].includes(langCode)) {
    currentLang = langCode;
    try {
      localStorage.setItem('verity_lang', langCode);
    } catch (_) {}
    updateLanguageUI();
  }
}

/**
 * Switches tool tabs between Scanner, QR, and File Magic Inspector.
 */
export function switchToolTab(toolKey) {
  toolTabs.forEach(btn => {
    const isSel = btn.dataset.tool === toolKey;
    btn.classList.toggle('active', isSel);
    btn.setAttribute('aria-selected', isSel ? 'true' : 'false');
  });

  if (panelScanner) panelScanner.classList.toggle('hidden', toolKey !== 'scanner');
  if (panelQr) panelQr.classList.toggle('hidden', toolKey !== 'qr');
  if (panelFile) panelFile.classList.toggle('hidden', toolKey !== 'file');
}

/**
 * Resolves localized reason descriptions.
 */
function getPlainReasons(signals = [], max = 3) {
  const out = [];
  for (const s of signals) {
    const id = s.id || s;
    const localized = REASON_PLAIN[id]?.[currentLang] || REASON_PLAIN[id]?.en;
    if (localized && !out.includes(localized)) {
      out.push(localized);
    }
    if (out.length >= max) break;
  }
  if (out.length === 0 && signals.length > 0) {
    signals.slice(0, max).forEach(s => {
      const id = s.id || s;
      out.push(id.replace(/^(SIG_|RULE_)/, '').replace(/_/g, ' '));
    });
  }
  return out;
}

/**
 * Renders the verdict traffic light card.
 */
function renderVerdict(res) {
  if (!res || !verdictCard) return;

  const status = res.verdict?.severity || res.verdict?.state || res.severity || res.state || 'safe';
  verdictCard.className = 'verdict-card card-' + status;
  verdictCard.classList.remove('hidden');

  if (verdictIcon) {
    verdictIcon.textContent = status === 'safe' ? '🟢' : status === 'caution' ? '🟡' : '🔴';
  }
  if (verdictTitle) {
    verdictTitle.textContent = STATUS[currentLang]?.[status] || STATUS.en[status];
    verdictTitle.setAttribute('lang', currentLang);
  }
  if (verdictScoreBadge) {
    verdictScoreBadge.textContent = `${res.score || 0}/100`;
  }

  // UPI debit trap banner
  if (upiTrapBanner) {
    if (res.extracted?.upi?.isCollect || res.isCollect) {
      upiTrapBanner.classList.remove('hidden');
      upiTrapBanner.textContent = '⚠️ Scanning this will take money OUT of your account.';
    } else {
      upiTrapBanner.classList.add('hidden');
    }
  }

  // Reasons list
  if (reasonsList) {
    while (reasonsList.firstChild) reasonsList.removeChild(reasonsList.firstChild);
    const signalIds = (res.signals || []).map(s => (typeof s === 'string' ? s : s.id));
    const plainReasons = getPlainReasons(signalIds, status === 'danger' ? 4 : 2);
    if (plainReasons.length > 0) {
      reasonsList.classList.remove('hidden');
      plainReasons.forEach(r => {
        const li = document.createElement('li');
        li.textContent = `❌ ${r}`;
        li.setAttribute('lang', currentLang);
        reasonsList.appendChild(li);
      });
    } else {
      reasonsList.classList.add('hidden');
    }
  }

  // Educational X-Ray & Micro-Quiz
  if (whyAccordion) {
    whyAccordion.classList.remove('hidden');
    const firstUrl = res.extracted?.urls?.[0] || res.finalUrl || 'https://suspicious-site.invalid';
    const analysisObj = {
      score: res.score,
      signals: res.signals || [],
      reasons: (res.signals || []).map(s => (typeof s === 'string' ? s : s.id))
    };
    const teaching = generateXRayTeachingCards(analysisObj, firstUrl);

    if (whyBullets) {
      while (whyBullets.firstChild) whyBullets.removeChild(whyBullets.firstChild);
      const signalIds = (res.signals || []).map(s => (typeof s === 'string' ? s : s.id));
      const plainExplanations = getPlainReasons(signalIds, 3);
      if (plainExplanations.length > 0) {
        plainExplanations.forEach(txt => {
          const p = document.createElement('p');
          p.textContent = `• ${txt}`;
          p.setAttribute('lang', currentLang);
          whyBullets.appendChild(p);
        });
      } else {
        const p = document.createElement('p');
        p.textContent = UI[currentLang]?.noThreatFound || UI.en.noThreatFound;
        whyBullets.appendChild(p);
      }
    }

    const quiz = teaching.cards.find(c => c.cardType === 'MICRO_QUIZ');
    if (quiz && quizPrompt && quizOptionsGroup) {
      if (quizHeading) quizHeading.textContent = '🎯 Spot The Scam Challenge';
      quizPrompt.textContent = quiz.question;
      while (quizOptionsGroup.firstChild) quizOptionsGroup.removeChild(quizOptionsGroup.firstChild);
      if (quizFeedbackBox) {
        quizFeedbackBox.className = 'quiz-feedback-box hidden';
        while (quizFeedbackBox.firstChild) quizFeedbackBox.removeChild(quizFeedbackBox.firstChild);
      }
      quizAnswered = false;

      quiz.options.forEach((optText, idx) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'quiz-opt-btn';
        btn.dataset.idx = String(idx);
        btn.textContent = optText;

        btn.addEventListener('click', () => {
          if (quizAnswered) return;
          quizAnswered = true;
          const isCorrect = idx === quiz.correctIndex;

          quizOptionsGroup.querySelectorAll('.quiz-opt-btn').forEach((b, bIdx) => {
            b.disabled = true;
            if (bIdx === quiz.correctIndex) {
              b.classList.add('correct');
              b.textContent = `✅ ${quiz.options[bIdx]}`;
            } else if (bIdx === idx && !isCorrect) {
              b.classList.add('wrong');
              b.textContent = `❌ ${quiz.options[bIdx]}`;
            }
          });

          if (quizFeedbackBox) {
            quizFeedbackBox.classList.remove('hidden');
            quizFeedbackBox.classList.add(isCorrect ? 'fb-correct' : 'fb-wrong');
            quizFeedbackBox.textContent = isCorrect ? `🎉 Correct! ${quiz.explanation}` : `⚠️ ${quiz.explanation}`;
          }
        });

        quizOptionsGroup.appendChild(btn);
      });
    }
  }

  // Update Golden Safety Rule
  const ruleKey = res.goldenRuleKey || (res.signals && res.signals.length > 0 ? goldenRuleForSignal(res.signals[0].id || res.signals[0]) : 'generic');
  if (goldenText) {
    goldenText.textContent = GOLDEN_RULES[ruleKey]?.[currentLang] || GOLDEN_RULES[ruleKey]?.en || GOLDEN_RULES.generic.en;
    goldenText.setAttribute('lang', currentLang);
  }
}

/**
 * Executes a scan of arbitrary input text / message.
 */
export async function executeScan(overrideText = null) {
  const text = (overrideText !== null ? overrideText : (scannerTextarea?.value || '')).trim();
  if (!text) return;

  const brands = await loadBrands();

  // If input contains multiple hops or arrow indicators, run redirect unroller simulation
  if (text.includes('->') || text.includes('=>') || text.includes('\nhttp')) {
    return unrollRedirectTrace(text);
  }

  const res = scanText(text, brands);
  lastScanResult = res;
  renderVerdict(res);
  return res;
}

/**
 * Unrolls and visually traces a multi-hop redirect chain.
 */
export function unrollRedirectTrace(inputChainOrUrl) {
  const unrolled = unrollRedirectChainSimulation(inputChainOrUrl);
  lastScanResult = unrolled;

  if (redirectTraceBox && hopsList) {
    redirectTraceBox.classList.remove('hidden');
    while (hopsList.firstChild) hopsList.removeChild(hopsList.firstChild);

    if (traceHopCount) {
      traceHopCount.textContent = `${unrolled.hops.length} Hops`;
    }

    unrolled.hops.forEach((h, idx) => {
      const card = document.createElement('div');
      card.className = 'hop-card' + (h.isSuspicious ? ' hop-suspicious' : ' hop-safe');

      const left = document.createElement('div');
      left.className = 'hop-left';

      const badge = document.createElement('span');
      badge.className = 'hop-badge';
      badge.textContent = `Hop ${h.hop}`;

      const urlSpan = document.createElement('span');
      urlSpan.className = 'hop-url';
      urlSpan.textContent = h.url;
      urlSpan.title = h.url;

      left.appendChild(badge);
      left.appendChild(urlSpan);

      const statusSpan = document.createElement('span');
      statusSpan.className = 'hop-status';
      statusSpan.textContent = h.status;

      card.appendChild(left);
      card.appendChild(statusSpan);
      hopsList.appendChild(card);
    });
  }

  renderVerdict(unrolled);
  return unrolled;
}

/**
 * Inspects a binary file locally without executing or uploading.
 */
export async function inspectFile(file) {
  if (!file) return;

  try {
    // Read first 8 bytes offline via File.slice
    const slice = file.slice(0, 8);
    const buf = await slice.arrayBuffer();
    const uint8 = new Uint8Array(buf);

    const hexParts = [];
    for (let i = 0; i < uint8.length; i++) {
      hexParts.push(uint8[i].toString(16).padStart(2, '0').toUpperCase());
    }
    const hexStr = hexParts.join(' ') || '00 00 00 00';

    if (fileResultBox) {
      fileResultBox.classList.remove('hidden');
      if (fileMetaName) fileMetaName.textContent = `Filename: ${file.name}`;
      if (fileMetaSize) fileMetaSize.textContent = `${file.size || 0} bytes`;
      if (fileMetaHex) fileMetaHex.textContent = hexStr;
    }

    const res = inspectFileMagicBytes(file.name, file.type, uint8);
    lastScanResult = res;
    renderVerdict(res);
    return res;
  } catch (err) {
    console.error('File magic inspection error:', err);
  }
}

/**
 * Handles barcode and QR image inspection.
 */
export async function handleQrFile(file) {
  if (!file) return;

  const showNotice = (msg, isErr = false) => {
    if (!qrNotice) return;
    qrNotice.textContent = msg;
    qrNotice.className = 'qr-notice' + (isErr ? ' qr-error' : '');
    qrNotice.classList.remove('hidden');
  };

  showNotice('Inspecting QR code image...');

  if ('BarcodeDetector' in window) {
    try {
      const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
      const img = new Image();
      const url = URL.createObjectURL(file);

      img.onload = async () => {
        try {
          const codes = await detector.detect(img);
          URL.revokeObjectURL(url);
          if (codes && codes.length > 0) {
            const raw = codes[0].rawValue;
            showNotice(`QR payload extracted: ${raw.slice(0, 50)}...`);
            if (scannerTextarea) scannerTextarea.value = raw;
            switchToolTab('scanner');
            executeScan(raw);
          } else {
            showNotice('No readable QR code found in image.', true);
          }
        } catch (err) {
          URL.revokeObjectURL(url);
          showNotice('Could not scan image: ' + err.message, true);
        }
      };
      img.onerror = () => {
        URL.revokeObjectURL(url);
        showNotice('Failed to load image file.', true);
      };
      img.src = url;
    } catch (e) {
      showNotice('Barcode detector failed: ' + e.message, true);
    }
  } else {
    showNotice('BarcodeDetector API unavailable on this browser. Use preset QR simulations.', true);
  }
}

/**
 * Initializes the Citizen Cyber Lab.
 */
export function initApp() {
  // 1. Language preference hydration
  let stored = null;
  try {
    stored = localStorage.getItem('verity_lang');
  } catch (_) {}

  currentLang = (stored && ['en', 'ta', 'hi', 'te'].includes(stored))
    ? stored
    : detectDefaultLang(navigator?.language);

  updateLanguageUI();

  // 2. Language switch buttons
  langBtns.forEach(btn => {
    btn.addEventListener('click', () => setLanguage(btn.dataset.lang));
  });

  // 3. Tool tabs
  toolTabs.forEach(tab => {
    tab.addEventListener('click', () => switchToolTab(tab.dataset.tool));
  });

  // 4. Scanner demo chips
  demoChips.forEach(chip => {
    chip.addEventListener('click', () => {
      const demoKey = chip.dataset.demo;
      const demoQr = chip.dataset.demoQr;
      const demoMagic = chip.dataset.demoMagic;

      if (demoKey && DEMO_PRESETS[demoKey]) {
        const sample = DEMO_PRESETS[demoKey];
        if (scannerTextarea) scannerTextarea.value = sample;
        switchToolTab('scanner');
        executeScan(sample);
      } else if (demoQr && QR_SIMULATIONS[demoQr]) {
        const upiUri = QR_SIMULATIONS[demoQr];
        if (scannerTextarea) scannerTextarea.value = upiUri;
        switchToolTab('scanner');
        executeScan(upiUri);
      } else if (demoMagic && MAGIC_SIMULATIONS[demoMagic]) {
        const spec = MAGIC_SIMULATIONS[demoMagic];
        switchToolTab('file');
        const mockFile = {
          name: spec.name,
          type: spec.type,
          size: spec.bytes.length,
          slice: (s, e) => ({
            arrayBuffer: async () => spec.bytes.buffer.slice(s, e)
          })
        };
        inspectFile(mockFile);
      }
    });
  });

  // 5. Manual action buttons
  if (btnCheck) {
    btnCheck.addEventListener('click', () => executeScan());
  }

  if (btnUnroll) {
    btnUnroll.addEventListener('click', () => {
      const text = scannerTextarea?.value || '';
      unrollRedirectTrace(text);
    });
  }

  // 6. QR Dropzone
  if (qrDropzone && qrFileInput) {
    qrDropzone.addEventListener('click', () => qrFileInput.click());
    qrFileInput.addEventListener('change', (e) => {
      const file = e.target.files?.[0];
      if (file) handleQrFile(file);
    });
  }

  // 7. File Magic Dropzone
  if (fileDropzone && magicFileInput) {
    fileDropzone.addEventListener('click', () => magicFileInput.click());
    magicFileInput.addEventListener('change', (e) => {
      const file = e.target.files?.[0];
      if (file) inspectFile(file);
    });
  }

  // 8. Preload brands
  loadBrands();

  // 9. Android Share Target Handler
  if (typeof window !== 'undefined' && window.location?.search) {
    const params = new URLSearchParams(window.location.search);
    const sharedParts = [
      params.get('text'),
      params.get('url'),
      params.get('title')
    ].filter(Boolean);

    if (sharedParts.length > 0) {
      const combinedText = sharedParts.join(' ').trim();
      if (scannerTextarea) scannerTextarea.value = combinedText;
      executeScan(combinedText);
      try {
        window.history.replaceState({}, document.title, window.location.pathname);
      } catch (_) {}
    }
  }

  // 10. Service Worker
  if ('serviceWorker' in navigator && (window.location.protocol === 'https:' || window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')) {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  }
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
  } else {
    initApp();
  }
}

export default {
  executeScan,
  unrollRedirectTrace,
  inspectFile,
  handleQrFile,
  setLanguage,
  switchToolTab,
  initApp
};
