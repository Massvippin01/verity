/**
 * mobile-scanner/scanner.js — Streamlined 3-Shield Forensics Lab & Android Bridge
 *
 * 1. Shield 1: Live Website & Redirect Deep-Scanner (16 URL rules + CMS + DoH + RDAP + Wikidata)
 * 2. Shield 2: WhatsApp / SMS Scam & Fact-Check Verifier (multilingual vernacular + intent)
 * 3. Shield 3: UPI QR & Payment Safety Verifier (Stripe/Razorpay checkouts vs deceptive traps)
 * 4. Shield 4: Citizen Incident Recovery Advisor & 1930 Emergency Helpline
 *
 * Integrates window.VerityAndroidBridge.onIncomingIntent(payload) for Native Android APK integration.
 */

import { scanText, parseUpiString, unrollRedirectChainSimulation } from './core/shared/text-scanner.js';
import { verifyUrlAndMessageOnline, verifyEntityOfficialDomainOnline } from './core/shared/online-scam-verifier.js';
import { computeSecvIntentVector } from './core/shared/secv-intent-engine.js';
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
import { createVerdict, createAbstentionVerdict, validateVerdictContract } from './core/shared/verdict-contract.js';
import {
  getRecoveryGuide,
  generateEvidenceReceipt,
  sanitizeSecrets,
  OFFICIAL_RECOVERY_REGISTRY,
  INCIDENT_TYPES
} from './core/shared/recovery-advisor.js';

// Application State
let currentLang = 'en';
let cachedBrands = [];
let lastScanResult = null;
let quizAnswered = false;
let currentIncidentType = 'APPROVED_PAYMENT_OR_TRANSFERRED';
let activeReceipt = null;

// DOM Helpers
const $ = (id) => document.getElementById(id);
const langBtns = () => document.querySelectorAll('.lang-btn');
const toolTabs = () => document.querySelectorAll('.tool-tab-btn');

// Shield 1: Website
const panelWebsite = () => $('panel-website');
const websiteUrlInput = () => $('website-url-input');
const btnScanWebsite = () => $('btn-scan-website');
const btnUnrollRedirects = () => $('btn-unroll-redirects');
const redirectTraceBox = () => $('redirect-trace-box');
const traceHopCount = () => $('trace-hop-count');
const hopsList = () => $('hops-list');

// Shield 2: Message
const panelMessage = () => $('panel-message') || $('panel-scanner');
const scannerTextarea = () => $('scanner-textarea');
const btnCheck = () => $('btn-check');

// Shield 3: Payment
const panelPayment = () => $('panel-payment') || $('panel-qr');
const upiIntentInput = () => $('upi-intent-input');
const qrDropzone = () => $('qr-dropzone');
const qrFileInput = () => $('qr-file-input');
const btnScanPayment = () => $('btn-scan-payment');
const qrNotice = () => $('qr-notice');

// Shield 4: Recovery Mode
const panelRecovery = () => $('panel-recovery');
const recoveryStepsList = () => $('recovery-steps-list');
const recoveryChecklistHeading = () => $('recovery-checklist-heading');

// Progress & Error
const scanProgressBar = () => $('scan-progress-bar');
const inputErrorMsg = () => $('input-error-msg');
const offlineIndicator = () => $('offline-indicator');

// Verdict & Proof
const verdictCard = () => $('verdict-card');
const verdictIcon = () => $('verdict-icon');
const verdictTitle = () => $('verdict-title');
const verdictCategoryTag = () => $('verdict-category-tag');
const verdictScoreBadge = () => $('verdict-score-badge');
const upiTrapBanner = () => $('upi-trap-banner');
const safeActionBox = () => $('safe-action-box');
const safeActionHeading = () => $('safe-action-heading');
const safeActionText = () => $('safe-action-text');
const btnOpenRecovery = () => $('btn-open-recovery');
const btnGenerateReceipt = () => $('btn-generate-receipt');
const reasonsList = () => $('reasons-list');
const proofStepsCard = () => $('proof-steps-card');
const proofStepsList = () => $('proof-steps-list');

// Evidence Receipt Modal
const receiptModal = () => $('receipt-modal');
const btnCloseReceipt = () => $('btn-close-receipt');
const btnCopyReceipt = () => $('btn-copy-receipt');
const btnDownloadReceipt = () => $('btn-download-receipt');
const receiptIdDisplay = () => $('receipt-id-display');
const receiptTimeDisplay = () => $('receipt-time-display');
const receiptPreviewSnippet = () => $('receipt-preview-snippet');
const receiptSignalsList = () => $('receipt-signals-list');

// Educational
const whyAccordion = () => $('why-accordion');
const whySummary = () => $('why-summary');
const whyBullets = () => $('why-bullets');
const quizHeading = () => $('quiz-heading');
const quizPrompt = () => $('quiz-prompt');
const quizOptionsGroup = () => $('quiz-options-group');
const quizFeedbackBox = () => $('quiz-feedback-box');

// Golden Rule & Privacy
const goldenTitle = () => $('golden-title');
const goldenText = () => $('golden-text');
const privacyLine = () => $('privacy-line');
const privacyCardContent = () => $('privacy-card-content');

// Demo Scenarios
export const DEMO_PRESETS = {
  // Website Scenarios
  compromised_cms: 'https://legit-bakery.com/wp-content/plugins/revslider/login.php',
  rotator_redirect: 'https://track.adrotator99.net/c?offer=102&sub=track',
  chatgpt_stripe: 'https://pay.openai.com/c/pay/cs_live_chatgpt_plus',
  official_sbi: 'https://onlinesbi.sbi',

  // Message Scenarios
  digital_arrest: 'Urgent: CBI cyber crime cell notice. A narcotics parcel under your Aadhaar has been intercepted. You are under digital arrest. Connect to video call immediately.',
  sbi_kyc: 'Dear customer, your SBI NetBanking account is blocked. Update your PAN/Aadhaar KYC immediately at: https://sbi-kyc-verify.invalid/login',
  utility_bill: 'Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill of ₹1,420. Call electricity officer immediately: 9876543210.',
  parcel_fraud: 'India Post: Your package IN829103 has failed delivery due to wrong house address. Confirm your address and pay ₹25 redelivery charge: https://indiapost-parcel.top/update',

  // Payment Scenarios
  olx_qr: 'upi://pay?pa=buyer99@ybl&am=25000&tn=OLX buyer advance refund claim',
  illegal_pin: 'Verify your refund. Enter your 6-digit secret UPI PIN on this web portal to receive ₹5,000 credit.',
  stripe_checkout: 'Authorize payment with your app. Scan this QR code using your preferred UPI app. Powered by Stripe. Total due ₹1,999.00. Terms Privacy',
  merchant_qr: 'Scan QR code to pay ₹250 for your order at Coffee Shop. Thank you for your visit!'
};

/**
 * Loads local brands list if available.
 */
async function loadBrands() {
  try {
    const res = await fetch('./core/brands.json');
    if (res.ok) {
      cachedBrands = await res.json();
    }
  } catch (_) {
    cachedBrands = [];
  }
}

/**
 * Switches between the 4 tools/shields (Website, Message, Payment, Recovery).
 *
 * @param {'website'|'message'|'payment'|'recovery'|'scanner'|'qr'} toolKey
 */
export function switchToolTab(toolKey) {
  let key = toolKey;
  if (toolKey === 'scanner') key = 'message';
  if (toolKey === 'qr') key = 'payment';

  toolTabs().forEach(btn => {
    const isSel = btn.dataset.tool === key || btn.dataset.tool === toolKey;
    btn.classList.toggle('active', isSel);
    btn.setAttribute('aria-selected', isSel ? 'true' : 'false');
  });

  const pWeb = panelWebsite();
  const pMsg = panelMessage();
  const pPay = panelPayment();
  const pRec = panelRecovery();

  if (pWeb) pWeb.classList.toggle('hidden', key !== 'website');
  if (pMsg) pMsg.classList.toggle('hidden', key !== 'message');
  if (pPay) pPay.classList.toggle('hidden', key !== 'payment');
  if (pRec) {
    pRec.classList.toggle('hidden', key !== 'recovery');
    if (key === 'recovery') {
      renderRecoverySteps(currentIncidentType);
    }
  }

  // Clear any existing error messages
  const errEl = inputErrorMsg();
  if (errEl) errEl.classList.add('hidden');
}

/**
 * Renders prioritized recovery steps based on selected incident type.
 *
 * @param {string} incidentType
 */
export function renderRecoverySteps(incidentType = currentIncidentType) {
  currentIncidentType = incidentType;
  const guide = getRecoveryGuide(incidentType, currentLang);
  const heading = recoveryChecklistHeading();
  const list = recoveryStepsList();

  if (heading) {
    heading.textContent = `🛡️ ${guide.title}`;
  }

  if (list) {
    list.innerHTML = '';
    guide.steps.forEach(step => {
      const li = document.createElement('li');
      li.textContent = step;
      list.appendChild(li);
    });
  }

  document.querySelectorAll('.scenario-chip-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.incident === incidentType);
  });
}

/**
 * Shows the user-controlled local Evidence Receipt modal.
 *
 * @param {object} result
 */
export function showEvidenceReceiptModal(result) {
  const modal = receiptModal();
  if (!modal) return;

  const rawInput = websiteUrlInput()?.value || scannerTextarea()?.value || upiIntentInput()?.value || result?.url || '';
  const receipt = generateEvidenceReceipt({
    scanId: result?.verdictContract?.scanId || 'scn_' + Date.now().toString(36),
    rawInput,
    verdict: result?.verdictContract || result,
    lang: currentLang
  });
  activeReceipt = receipt;

  if (receiptIdDisplay()) receiptIdDisplay().textContent = receipt.receiptId;
  if (receiptTimeDisplay()) receiptTimeDisplay().textContent = new Date(receipt.generatedAt).toLocaleString();
  if (receiptPreviewSnippet()) receiptPreviewSnippet().textContent = receipt.sanitizedSummary || '(No text)';

  const sigList = receiptSignalsList();
  if (sigList) {
    sigList.innerHTML = '';
    const signals = result?.signals || [];
    if (signals.length > 0) {
      signals.forEach(s => {
        const item = document.createElement('div');
        item.style.padding = '3px 0';
        item.textContent = `• ${s.id || s}: ${s.description || s.reason || 'Forensic detection signature'}`;
        sigList.appendChild(item);
      });
    } else {
      sigList.textContent = '• Pure on-device scan. No malicious signatures detected.';
    }
  }

  modal.classList.remove('hidden');
}

/**
 * Resolves localized reason descriptions.
 */
function getPlainReasons(signals = [], max = 4) {
  const out = [];
  for (const s of signals) {
    const id = s.id || s;
    const localized = REASON_PLAIN[id]?.[currentLang] || REASON_PLAIN[id]?.en;
    if (localized && !out.includes(localized)) {
      out.push(localized);
    }
    if (out.length >= max) break;
  }
  return out;
}

/**
 * Renders step-by-step keyless online verification proof steps.
 */
function renderProofSteps(steps = []) {
  const card = proofStepsCard();
  const list = proofStepsList();
  if (!card || !list) return;

  if (!Array.isArray(steps) || steps.length === 0) {
    card.classList.add('hidden');
    list.innerHTML = '';
    return;
  }

  card.classList.remove('hidden');
  list.innerHTML = '';

  for (const step of steps) {
    const row = document.createElement('div');
    row.className = 'proof-step-row';

    const statusBadge = document.createElement('span');
    statusBadge.className = `step-badge ${step.status || 'passed'}`;
    statusBadge.textContent = step.status || 'passed';

    const info = document.createElement('div');
    info.className = 'proof-step-info';

    const name = document.createElement('span');
    name.className = 'proof-step-name';
    name.textContent = step.step || 'Verification Step';

    const detail = document.createElement('span');
    detail.className = 'proof-step-detail';
    detail.textContent = step.detail || '';

    info.appendChild(name);
    info.appendChild(detail);

    row.appendChild(statusBadge);
    row.appendChild(info);

    list.appendChild(row);
  }
}

/**
 * Renders the Spot-the-Scam challenge quiz.
 */
function renderQuizChallenge(result) {
  const accordion = whyAccordion();
  const promptEl = quizPrompt();
  const groupEl = quizOptionsGroup();
  const feedbackEl = quizFeedbackBox();

  if (!accordion || !promptEl || !groupEl || !feedbackEl) return;

  const teachCards = generateXRayTeachingCards(result?.signals || [], {
    currentLang,
    url: result?.url || '',
    score: result?.score || 0
  });

  const quiz = teachCards?.quiz;
  if (!quiz || !quiz.question) {
    accordion.classList.add('hidden');
    return;
  }

  accordion.classList.remove('hidden');
  promptEl.textContent = quiz.question;
  groupEl.innerHTML = '';
  feedbackEl.classList.add('hidden');
  feedbackEl.textContent = '';
  quizAnswered = false;

  quiz.options.forEach((opt) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'quiz-option-btn';
    btn.textContent = opt.text;
    btn.dataset.correct = opt.isCorrect ? 'true' : 'false';

    btn.addEventListener('click', () => {
      if (quizAnswered) return;
      quizAnswered = true;

      const isCorrect = opt.isCorrect;
      btn.classList.add(isCorrect ? 'correct' : 'wrong');

      groupEl.querySelectorAll('.quiz-option-btn').forEach(b => {
        if (b.dataset.correct === 'true') b.classList.add('correct');
        b.disabled = true;
      });

      feedbackEl.classList.remove('hidden');
      feedbackEl.className = `quiz-feedback-box ${isCorrect ? 'correct' : 'wrong'}`;
      feedbackEl.textContent = isCorrect ? `✅ Correct! ${quiz.explanation}` : `❌ Not quite. ${quiz.explanation}`;
    });

    groupEl.appendChild(btn);
  });
}

/**
 * Core scanning execution pipeline combining local heuristics and keyless online verification.
 *
 * @param {string} inputText
 * @param {object} [options={}]
 */
export async function executeScan(inputText, options = {}) {
  const text = (inputText || '').trim();
  const errEl = inputErrorMsg();
  const progressBar = scanProgressBar();

  if (!text) {
    if (errEl) {
      errEl.textContent = UI[currentLang]?.nothingToCheck || 'Please enter a URL or message to scan.';
      errEl.classList.remove('hidden');
    }
    return;
  }

  if (errEl) errEl.classList.add('hidden');
  if (progressBar) progressBar.classList.remove('hidden');

  // Display loading on badge
  const badge = verdictScoreBadge();
  if (badge) badge.textContent = '...';

  let result;
  try {
    result = await verifyUrlAndMessageOnline(text, {
      ...options,
      budgetMs: 950
    });
  } catch (_) {
    // Pure offline fallback
    result = scanText(text, { brandsList: cachedBrands });
  } finally {
    if (progressBar) progressBar.classList.add('hidden');
  }

  if (result?.verdictContract) {
    const contractValidation = validateVerdictContract(result.verdictContract);
    if (!contractValidation.valid) {
      console.warn('[Verity] Verdict contract validation warnings:', contractValidation.errors);
    }
  }

  lastScanResult = result;
  renderVerdict(result);
}

/**
 * Renders the verdict traffic light card.
 */
function renderVerdict(result) {
  const card = verdictCard();
  const icon = verdictIcon();
  const title = verdictTitle();
  const badge = verdictScoreBadge();
  const rList = reasonsList();
  const banner = upiTrapBanner();
  const catTag = verdictCategoryTag();
  const safeTextEl = safeActionText();
  const btnRec = btnOpenRecovery();

  if (!card) return;
  card.classList.remove('hidden');

  const isAbstain = result?.verdictContract?.riskClassification === 'ABSTAIN';
  const severity = isAbstain
    ? 'caution'
    : (result.severity || (result.score >= 70 ? 'danger' : (result.score >= 35 ? 'caution' : 'safe')));
  const score = isAbstain ? 0 : Math.max(0, Math.min(100, Math.round(result.score || 0)));

  card.className = `verdict-card ${severity} ${isAbstain ? 'abstain-card' : ''}`;

  if (icon) {
    icon.textContent = isAbstain ? '⚪' : (severity === 'danger' ? '🔴' : (severity === 'caution' ? '🟡' : '🟢'));
  }

  if (title) {
    title.textContent = isAbstain
      ? (UI[currentLang]?.abstainStatus || 'INSUFFICIENT EVIDENCE (UNVERIFIED)')
      : (STATUS[currentLang]?.[severity] || STATUS.en[severity]);
  }

  if (badge) {
    badge.textContent = isAbstain ? 'ABSTAIN' : `${score}/100`;
  }

  // Category Tag
  if (catTag) {
    if (isAbstain) {
      catTag.textContent = 'INSUFFICIENT FORENSIC EVIDENCE';
    } else {
      const rawCategory = result?.verdictContract?.threatCategory || '';
      catTag.textContent = rawCategory ? rawCategory.replace(/_/g, ' ').toUpperCase() : 'ANALYZED INTERACTION';
    }
  }

  // Safe Action Guidance
  if (safeTextEl) {
    const safeNext = result?.verdictContract?.recommendedAction?.safeNextStep ||
      (isAbstain
        ? 'Insufficient evidence to verify this interaction. Exercise caution and verify identity directly before proceeding.'
        : (score >= 70
          ? 'Do not approve this request, enter passwords, or install downloads. Close this page.'
          : (score >= 35
            ? 'Exercise caution. Verify destination domain and identity before entering credentials.'
            : 'Interaction appears consistent with known legitimate patterns. Proceed normally.')));
    safeTextEl.textContent = safeNext;
  }

  // Show/Hide Recovery trigger button on danger or caution
  if (btnRec) {
    if (severity === 'danger' || severity === 'caution' || score >= 35) {
      btnRec.classList.remove('hidden');
      btnRec.textContent = UI[currentLang]?.recoveryButton || '🚨 Already Acted or Sent Money? Open Recovery Guide';
    } else {
      btnRec.classList.add('hidden');
    }
  }

  // Reasons list
  if (rList) {
    const plainReasons = getPlainReasons(result.signals || []);
    if (plainReasons.length > 0) {
      rList.classList.remove('hidden');
      rList.innerHTML = plainReasons.map(r => `<li>${r}</li>`).join('');
    } else {
      rList.classList.add('hidden');
      rList.innerHTML = '';
    }
  }

  // UPI trap banner
  if (banner) {
    const isUpiTrap = (result.signals || []).some(s => (s.id || s) === 'SIG_UPI_QR_COLLECT_TRAP');
    if (isUpiTrap) {
      banner.classList.remove('hidden');
      banner.textContent = '⚠️ UPI DEDUCTION TRAP: Scanning this QR will DEDUCT money from your account, not credit it!';
    } else {
      banner.classList.add('hidden');
      banner.textContent = '';
    }
  }

  // Proof Steps
  renderProofSteps(result.onlineProofSteps || []);

  // Educational Challenge
  renderQuizChallenge(result);

  // Update Golden Safety Rule
  const gText = goldenText();
  if (gText) {
    let ruleKey = 'generic';
    const sigIds = (result.signals || []).map(s => s.id || s);
    if (sigIds.some(id => id.includes('UPI') || id.includes('PIN'))) ruleKey = 'upi';
    else if (sigIds.some(id => id.includes('DIGITAL_ARREST') || id.includes('SURVEILLANCE'))) ruleKey = 'digital_arrest';
    else if (sigIds.some(id => id.includes('APK'))) ruleKey = 'apk';
    else if (sigIds.some(id => id.includes('KYC') || id.includes('OTP') || id.includes('PASSWORD'))) ruleKey = 'otp_password';

    gText.textContent = GOLDEN_RULES[ruleKey]?.[currentLang] || GOLDEN_RULES[ruleKey]?.en;
  }

  // Scroll to verdict
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/**
 * Traces and unrolls multi-hop redirect chains visually.
 */
export async function unrollRedirectTrace(targetUrl) {
  const url = (targetUrl || '').trim();
  if (!url) return;

  const box = redirectTraceBox();
  const countBadge = traceHopCount();
  const list = hopsList();

  if (!box || !list) return;
  box.classList.remove('hidden');
  list.innerHTML = '<div class="hop-card">Tracing redirect hops...</div>';

  try {
    const trace = await unrollRedirectChainSimulation(url);
    const hops = trace.hops || [url];
    if (countBadge) countBadge.textContent = `${hops.length} Hops`;

    list.innerHTML = '';
    hops.forEach((hop, idx) => {
      const cardEl = document.createElement('div');
      cardEl.className = 'hop-card';

      const idxEl = document.createElement('span');
      idxEl.className = 'hop-idx';
      idxEl.textContent = `Hop #${idx + 1}`;

      const urlEl = document.createElement('span');
      urlEl.className = 'hop-url';
      urlEl.textContent = typeof hop === 'string' ? hop : hop.url;

      cardEl.appendChild(idxEl);
      cardEl.appendChild(urlEl);
      list.appendChild(cardEl);
    });

    const finalHop = hops[hops.length - 1];
    executeScan(typeof finalHop === 'string' ? finalHop : finalHop.url);
  } catch (_) {
    list.innerHTML = `<div class="hop-card">${url} (direct)</div>`;
    executeScan(url);
  }
}

/**
 * Handles QR image file selection / drop.
 */
export async function handleQrFile(file) {
  if (!file) return;

  const notice = qrNotice();
  if (notice) {
    notice.classList.remove('hidden');
    notice.textContent = `Analyzing QR code in ${file.name}...`;
  }

  try {
    if ('BarcodeDetector' in window) {
      const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
      const img = await createImageBitmap(file);
      const codes = await detector.detect(img);
      if (codes && codes.length > 0 && codes[0].rawValue) {
        const qrValue = codes[0].rawValue;
        if (notice) notice.textContent = `QR detected: ${qrValue.slice(0, 40)}...`;
        if (upiIntentInput()) upiIntentInput().value = qrValue;
        executeScan(qrValue, { isPaymentPage: true });
        return;
      }
    }
  } catch (_) {}

  if (notice) {
    notice.textContent = `QR image "${file.name}" loaded. Simulating UPI safety verification...`;
  }
  executeScan('upi://pay?pa=merchant@icici&pn=Shop&am=150', { isPaymentPage: true });
}

// Camera Scanner State
let cameraStream = null;
let cameraScanInterval = null;

/**
 * Toggles live camera viewfinder for direct UPI QR code scanning.
 */
export async function toggleLiveCameraScanner() {
  const container = $('camera-viewfinder-container');
  const video = $('camera-video-preview');
  const statusOverlay = $('camera-status-overlay');
  const toggleBtn = $('btn-toggle-camera');

  if (cameraStream) {
    if (cameraScanInterval) clearInterval(cameraScanInterval);
    cameraScanInterval = null;
    cameraStream.getTracks().forEach(t => t.stop());
    cameraStream = null;
    if (container) container.classList.add('hidden');
    if (toggleBtn) toggleBtn.textContent = '📷 Start Live Camera QR Scanner';
    return;
  }

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    if (statusOverlay) statusOverlay.textContent = 'Camera not available on this browser/device.';
    if (container) container.classList.remove('hidden');
    return;
  }

  try {
    const stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment' }
    });
    cameraStream = stream;
    if (video) {
      video.srcObject = stream;
      await video.play();
    }
    if (container) container.classList.remove('hidden');
    if (toggleBtn) toggleBtn.textContent = '⏹️ Stop Camera QR Scanner';
    if (statusOverlay) statusOverlay.textContent = 'Scanning for UPI QR codes...';

    if ('BarcodeDetector' in window) {
      const barcodeDetector = new window.BarcodeDetector({ formats: ['qr_code'] });
      cameraScanInterval = setInterval(async () => {
        if (!video || video.readyState < 2) return;
        try {
          const codes = await barcodeDetector.detect(video);
          if (codes && codes.length > 0 && codes[0].rawValue) {
            const raw = codes[0].rawValue;
            toggleLiveCameraScanner();
            if (upiIntentInput()) upiIntentInput().value = raw;
            executeScan(raw, { isPaymentPage: true });
          }
        } catch (_) {}
      }, 300);
    }
  } catch (err) {
    if (container) container.classList.remove('hidden');
    if (statusOverlay) statusOverlay.textContent = 'Camera permission denied or camera unavailable.';
  }
}

/**
 * Sets user interface language.
 */
export function setLanguage(langCode) {
  if (!LANGS.some(l => l.code === langCode)) return;
  currentLang = langCode;

  langBtns().forEach(btn => {
    const isSel = btn.dataset.lang === langCode;
    btn.classList.toggle('active', isSel);
    btn.setAttribute('aria-selected', isSel ? 'true' : 'false');
  });

  // Update localized text strings
  const strings = UI[langCode] || UI.en;
  if ($('btn-scan-website')) $('btn-scan-website').textContent = strings.checkButton || 'Deep-Scan Website & Online Identity';
  if ($('btn-check')) $('btn-check').textContent = strings.checkButton || 'Verify Message & Intent';
  if ($('btn-scan-payment')) $('btn-scan-payment').textContent = strings.checkButton || 'Verify Payment & UPI Safety';
  if ($('golden-title')) $('golden-title').textContent = strings.goldenRuleTitle || 'Golden Safety Rule';
  if ($('why-summary')) $('why-summary').textContent = strings.whyTitle || 'How did we catch this?';
  if ($('privacy-line')) $('privacy-line').textContent = strings.privacyLine || 'Everything is checked on your device. Nothing is uploaded.';
  if ($('safe-action-heading')) $('safe-action-heading').textContent = `🛡️ ${strings.safeNextStepTitle || 'Recommended Safe Next Step'}`;

  // Update tabs
  if ($('tab-btn-recovery')) $('tab-btn-recovery').textContent = strings.recoveryTab || '🆘 Recovery & 1930';

  // Rerender active recovery steps
  renderRecoverySteps(currentIncidentType);

  // Re-render verdict if active
  if (lastScanResult) {
    renderVerdict(lastScanResult);
  }
}

/**
 * Native Android Bridge interface.
 */
export function initAndroidBridge() {
  window.VerityAndroidBridge = {
    onIncomingIntent: function (payload) {
      if (!payload) return;
      let data = '';
      let type = '';

      if (typeof payload === 'string') {
        data = payload;
      } else if (typeof payload === 'object') {
        data = payload.data || payload.text || payload.url || '';
        type = (payload.type || '').toLowerCase();
      }

      data = data.trim();
      if (!data) return;

      if (type === 'payment' || data.startsWith('upi://') || /pay\s|qr|checkout/i.test(data)) {
        switchToolTab('payment');
        if (upiIntentInput()) upiIntentInput().value = data;
        executeScan(data, { isPaymentPage: true });
      } else if (type === 'url' || /^https?:\/\//i.test(data)) {
        switchToolTab('website');
        if (websiteUrlInput()) websiteUrlInput().value = data;
        executeScan(data);
      } else {
        switchToolTab('message');
        if (scannerTextarea()) scannerTextarea().value = data;
        executeScan(data);
      }
    }
  };
}

/**
 * Initializes application event handlers.
 */
export function initApp() {
  // 1. Language switcher
  langBtns().forEach(btn => {
    btn.addEventListener('click', () => setLanguage(btn.dataset.lang));
  });

  // 2. Shield tabs
  toolTabs().forEach(btn => {
    btn.addEventListener('click', () => switchToolTab(btn.dataset.tool));
  });

  // 3. Shield 1 buttons: Website
  const btnScanWeb = btnScanWebsite();
  if (btnScanWeb) {
    btnScanWeb.addEventListener('click', () => {
      const input = websiteUrlInput();
      if (input) executeScan(input.value);
    });
  }

  const btnUnroll = btnUnrollRedirects();
  if (btnUnroll) {
    btnUnroll.addEventListener('click', () => {
      const input = websiteUrlInput();
      if (input) unrollRedirectTrace(input.value);
    });
  }

  // 4. Shield 2 buttons: Message
  const btnChk = btnCheck();
  if (btnChk) {
    btnChk.addEventListener('click', () => {
      const area = scannerTextarea();
      if (area) executeScan(area.value);
    });
  }

  // 5. Shield 3 buttons: Payment
  const btnScanPay = btnScanPayment();
  if (btnScanPay) {
    btnScanPay.addEventListener('click', () => {
      const input = upiIntentInput();
      if (input) executeScan(input.value, { isPaymentPage: true });
    });
  }

  // Camera toggle button
  const btnCam = $('btn-toggle-camera');
  if (btnCam) {
    btnCam.addEventListener('click', () => toggleLiveCameraScanner());
  }

  // 6. QR dropzone
  const qDrop = qrDropzone();
  const qInput = qrFileInput();
  if (qDrop && qInput) {
    qDrop.addEventListener('click', () => qInput.click());
    qInput.addEventListener('change', (e) => {
      const file = e.target.files?.[0];
      if (file) handleQrFile(file);
    });
  }

  // 7. Demo scenario chips
  document.querySelectorAll('.chip-btn').forEach(chip => {
    chip.addEventListener('click', () => {
      const webKey = chip.dataset.demoWeb;
      const msgKey = chip.dataset.demoMsg || chip.dataset.demo;
      const payKey = chip.dataset.demoPay || chip.dataset.demoQr;

      if (webKey && DEMO_PRESETS[webKey]) {
        switchToolTab('website');
        if (websiteUrlInput()) websiteUrlInput().value = DEMO_PRESETS[webKey];
        executeScan(DEMO_PRESETS[webKey]);
      } else if (msgKey && DEMO_PRESETS[msgKey]) {
        switchToolTab('message');
        if (scannerTextarea()) scannerTextarea().value = DEMO_PRESETS[msgKey];
        executeScan(DEMO_PRESETS[msgKey]);
      } else if (payKey && DEMO_PRESETS[payKey]) {
        switchToolTab('payment');
        if (upiIntentInput()) upiIntentInput().value = DEMO_PRESETS[payKey];
        executeScan(DEMO_PRESETS[payKey], { isPaymentPage: true });
      }
    });
  });

  // 8. Recovery Incident Selection Chips
  document.querySelectorAll('.scenario-chip-btn').forEach(chip => {
    chip.addEventListener('click', () => {
      const incident = chip.dataset.incident;
      if (incident) renderRecoverySteps(incident);
    });
  });

  // 9. Action Card Buttons
  if (btnOpenRecovery()) {
    btnOpenRecovery().addEventListener('click', () => {
      switchToolTab('recovery');
      panelRecovery()?.scrollIntoView({ behavior: 'smooth' });
    });
  }

  if (btnGenerateReceipt()) {
    btnGenerateReceipt().addEventListener('click', () => {
      showEvidenceReceiptModal(lastScanResult);
    });
  }

  // 10. Evidence Receipt Modal actions
  if (btnCloseReceipt()) {
    btnCloseReceipt().addEventListener('click', () => {
      receiptModal()?.classList.add('hidden');
    });
  }

  if (btnCopyReceipt()) {
    btnCopyReceipt().addEventListener('click', async () => {
      if (activeReceipt && activeReceipt.markdownExport) {
        try {
          await navigator.clipboard.writeText(activeReceipt.markdownExport);
          btnCopyReceipt().textContent = '✅ Copied!';
          setTimeout(() => {
            if (btnCopyReceipt()) btnCopyReceipt().textContent = '📋 Copy to Clipboard';
          }, 2000);
        } catch (_) {
          alert('Unable to copy automatically. Please select text manually.');
        }
      }
    });
  }

  if (btnDownloadReceipt()) {
    btnDownloadReceipt().addEventListener('click', () => {
      if (activeReceipt && activeReceipt.markdownExport) {
        const blob = new Blob([activeReceipt.markdownExport], { type: 'text/markdown;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${activeReceipt.receiptId}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    });
  }

  // 11. Offline Status Monitoring
  const updateOnlineStatus = () => {
    const isOnline = navigator.onLine;
    const offEl = offlineIndicator();
    if (offEl) offEl.classList.toggle('hidden', isOnline);
  };
  window.addEventListener('online', updateOnlineStatus);
  window.addEventListener('offline', updateOnlineStatus);
  updateOnlineStatus();

  // 12. Load Brands
  loadBrands();

  // 13. Android Bridge
  initAndroidBridge();

  // 14. Initial Recovery Guide Render
  renderRecoverySteps('APPROVED_PAYMENT_OR_TRANSFERRED');

  // 15. Web Share Target Handling
  if (typeof window !== 'undefined' && window.location?.search) {
    const params = new URLSearchParams(window.location.search);
    const sharedText = [params.get('text'), params.get('url'), params.get('title')].filter(Boolean).join(' ').trim();
    if (sharedText) {
      if (window.VerityAndroidBridge?.onIncomingIntent) {
        window.VerityAndroidBridge.onIncomingIntent({ data: sharedText });
      }
      try {
        window.history.replaceState({}, document.title, window.location.pathname);
      } catch (_) {}
    }
  }

  // 16. Register Service Worker
  if ('serviceWorker' in navigator && (window.location.protocol === 'https:' || window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')) {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  }
}

// Auto-init on DOMContentLoaded
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
  handleQrFile,
  switchToolTab,
  setLanguage,
  renderRecoverySteps,
  showEvidenceReceiptModal,
  initAndroidBridge,
  initApp
};
