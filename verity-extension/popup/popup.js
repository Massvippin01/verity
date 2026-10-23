import {
  formatTabViewModel,
  formatScanResult,
  detectEffectiveLang,
  isInternalUrl,
  SUPPORTED_LANGS
} from './popup-logic.js';
import { UI } from '../shared/citizen-messages.js';
import { scanText } from '../shared/text-scanner.js';
import { createSafeElement } from '../shared/safe-dom.js';

let currentLang = 'en', activeTab = null, activeVerdict = null, cachedBrands = [], lastScanResult = null;
const $ = (id) => document.getElementById(id);
const headerStatusDot = $('header-status-dot');
const langPills = document.querySelectorAll('.lang-pill');
const labelCurrentSite = $('label-current-site');
const currentSiteCard = $('current-site-card');
const currentSiteIndicator = $('current-site-indicator');
const currentSiteStatus = $('current-site-status');
const currentSiteDomain = $('current-site-domain');
const currentSiteScore = $('current-site-score');
const currentSiteReasons = $('current-site-reasons');
const labelQuickChecker = $('label-quick-checker');
const checkerInput = $('checker-input');
const charCount = $('char-count');
const btnCheck = $('btn-check');
const scanResultCard = $('scan-result-card');
const scanIndicator = $('scan-indicator');
const scanStatus = $('scan-status');
const scanScoreSub = $('scan-score-sub');
const scanReasons = $('scan-reasons');
const scanWhyDetails = $('scan-why-details');
const scanWhySummary = $('scan-why-summary');
const scanWhyBody = $('scan-why-body');
const goldenTitle = $('golden-title');
const goldenText = $('golden-text');
const privacyNote = $('privacy-note');
const btnToggleAdvanced = $('btn-toggle-advanced');
const advancedPre = $('advanced-pre');

async function loadBrandsDataset() {
  if (cachedBrands.length > 0) return cachedBrands;
  try {
    const url = typeof chrome !== 'undefined' && chrome.runtime?.getURL ? chrome.runtime.getURL('brands.json') : '../brands.json';
    const r = await fetch(url);
    if (r.ok) cachedBrands = await r.json();
  } catch (_) {}
  return cachedBrands;
}

function updateStaticTranslations() {
  document.documentElement.lang = currentLang;
  langPills.forEach(p => {
    const s = p.dataset.lang === currentLang;
    p.classList.toggle('active', s);
    p.setAttribute('aria-selected', s ? 'true' : 'false');
  });

  const setT = (el, txt) => {
    if (el && txt) { el.textContent = txt; el.setAttribute('lang', currentLang); }
  };
  setT(labelCurrentSite, UI[currentLang]?.currentSite || UI.en.currentSite);
  setT(labelQuickChecker, UI[currentLang]?.quickChecker || UI.en.quickChecker);
  if (checkerInput) {
    checkerInput.placeholder = UI[currentLang]?.pastePlaceholder || UI.en.pastePlaceholder;
    checkerInput.setAttribute('lang', currentLang);
  }
  setT(btnCheck, UI[currentLang]?.checkButton || UI.en.checkButton);
  setT(privacyNote, UI[currentLang]?.privacyLine || UI.en.privacyLine);
  setT(btnToggleAdvanced, UI[currentLang]?.advancedDetails || UI.en.advancedDetails);
  setT(scanWhySummary, UI[currentLang]?.whyTitle || UI.en.whyTitle);
}

function renderCurrentSiteCard() {
  const vm = formatTabViewModel(activeTab, activeVerdict, currentLang);
  if (headerStatusDot) headerStatusDot.className = 'status-dot dot-' + vm.status;
  if (currentSiteCard) currentSiteCard.className = 'traffic-card card-' + vm.status;
  if (currentSiteIndicator) {
    currentSiteIndicator.textContent = vm.status === 'safe' ? '🟢' : vm.status === 'caution' ? '🟡' : vm.status === 'danger' ? '🔴' : '⚪';
  }
  if (currentSiteStatus) {
    currentSiteStatus.textContent = vm.statusText;
    currentSiteStatus.setAttribute('lang', currentLang);
  }
  if (currentSiteDomain) currentSiteDomain.textContent = vm.domain || 'Unknown';
  if (currentSiteScore) currentSiteScore.textContent = `${vm.score}/100`;

  if (currentSiteReasons) {
    while (currentSiteReasons.firstChild) currentSiteReasons.removeChild(currentSiteReasons.firstChild);
    if (vm.plainReasons.length > 0) {
      currentSiteReasons.classList.remove('hidden');
      vm.plainReasons.forEach(txt => {
        const li = createSafeElement('li', `❌ ${txt}`);
        li.setAttribute('lang', currentLang);
        currentSiteReasons.appendChild(li);
      });
    } else {
      currentSiteReasons.classList.add('hidden');
    }
  }

  if (goldenTitle) { goldenTitle.textContent = vm.goldenRuleTitle; goldenTitle.setAttribute('lang', currentLang); }
  if (goldenText) { goldenText.textContent = vm.goldenRuleText; goldenText.setAttribute('lang', currentLang); }
  if (advancedPre) advancedPre.textContent = vm.advancedDetails;
}

function renderScanResult(scanResult) {
  if (!scanResult) { scanResultCard?.classList.add('hidden'); return; }
  const vm = formatScanResult(scanResult, currentLang);
  scanResultCard.className = 'traffic-card card-' + vm.status;
  scanResultCard.classList.remove('hidden');

  scanIndicator.textContent = vm.status === 'safe' ? '🟢' : vm.status === 'caution' ? '🟡' : '🔴';
  scanStatus.textContent = vm.statusText;
  scanStatus.setAttribute('lang', currentLang);
  scanScoreSub.textContent = `Score: ${vm.score}/100`;

  while (scanReasons.firstChild) scanReasons.removeChild(scanReasons.firstChild);
  if (vm.plainReasons.length > 0) {
    scanReasons.classList.remove('hidden');
    vm.plainReasons.forEach(txt => {
      const li = createSafeElement('li', `❌ ${txt}`);
      li.setAttribute('lang', currentLang);
      scanReasons.appendChild(li);
    });
  } else {
    scanReasons.classList.add('hidden');
  }

  scanWhyDetails.classList.remove('hidden');
  while (scanWhyBody.firstChild) scanWhyBody.removeChild(scanWhyBody.firstChild);
  const p = createSafeElement('p', vm.plainReasons.length > 0 ? vm.plainReasons.join(' ') : (UI[currentLang]?.noThreatFound || UI.en.noThreatFound));
  p.setAttribute('lang', currentLang);
  scanWhyBody.appendChild(p);

  if (vm.status !== 'safe') {
    goldenTitle.textContent = vm.goldenRuleTitle;
    goldenTitle.setAttribute('lang', currentLang);
    goldenText.textContent = vm.goldenRuleText;
    goldenText.setAttribute('lang', currentLang);
  }

  if (advancedPre) {
    advancedPre.textContent = `${advancedPre.textContent}\n\n[Quick Scanner Result]\n${vm.advancedDetails}`;
  }
}

async function handleCheckClick() {
  const val = (checkerInput?.value || '').trim();
  if (!val) { checkerInput?.focus(); return; }
  const brands = await loadBrandsDataset();
  lastScanResult = scanText(val.slice(0, 5000), { brandsList: brands });
  renderScanResult(lastScanResult);
}

function setLanguage(newLang) {
  if (!SUPPORTED_LANGS.includes(newLang)) return;
  currentLang = newLang;
  if (typeof chrome !== 'undefined' && chrome.storage?.local) {
    chrome.storage.local.set({ verity_lang: newLang });
  }
  updateStaticTranslations();
  renderCurrentSiteCard();
  if (lastScanResult) renderScanResult(lastScanResult);
}

async function init() {
  let storedLang = null;
  if (typeof chrome !== 'undefined' && chrome.storage?.local) {
    try {
      const r = await chrome.storage.local.get(['verity_lang']);
      storedLang = r?.verity_lang || null;
    } catch (_) {}
  }
  currentLang = detectEffectiveLang(storedLang, navigator?.language);
  updateStaticTranslations();

  langPills.forEach(p => p.addEventListener('click', () => setLanguage(p.dataset.lang)));

  if (checkerInput) {
    checkerInput.addEventListener('input', () => {
      if (charCount) charCount.textContent = `${checkerInput.value.length}/5000`;
    });
    checkerInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); handleCheckClick(); }
    });
  }

  if (btnCheck) btnCheck.addEventListener('click', handleCheckClick);

  if (btnToggleAdvanced && advancedPre) {
    btnToggleAdvanced.addEventListener('click', () => {
      const exp = btnToggleAdvanced.getAttribute('aria-expanded') === 'true';
      btnToggleAdvanced.setAttribute('aria-expanded', !exp ? 'true' : 'false');
      advancedPre.classList.toggle('hidden', exp);
    });
  }

  if (typeof chrome !== 'undefined' && chrome.tabs?.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0]) {
        activeTab = tabs[0];
        if (isInternalUrl(activeTab.url)) {
          renderCurrentSiteCard();
        } else {
          chrome.runtime.sendMessage(
            { action: 'GET_TAB_VERDICT', tabId: activeTab.id },
            (resp) => {
              if (resp?.verdict) activeVerdict = resp.verdict;
              renderCurrentSiteCard();
            }
          );
        }
      } else {
        renderCurrentSiteCard();
      }
    });
  } else {
    renderCurrentSiteCard();
  }

  loadBrandsDataset();
}

document.addEventListener('DOMContentLoaded', init);
