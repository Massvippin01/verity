import { getVernacularAdvisory, speakVernacularAdvisory } from '../shared/vernacular-coach.js';
import { parseUrlAnatomy } from '../shared/xray-educator.js';

const LEGIT = {
  sbi: ['State Bank of India', 'onlinesbi.sbi'],
  hdfc: ['HDFC Bank', 'hdfcbank.com'],
  icici: ['ICICI Bank', 'icicibank.com'],
  paytm: ['Paytm', 'paytm.com'],
  incometax: ['Income Tax Dept', 'incometax.gov.in'],
  cbi: ['CBI', 'cbi.gov.in'],
  police: ['Cyber Crime Cell', 'cybercrime.gov.in'],
  challan: ['Transport Dept', 'echallan.parivahan.gov.in']
};

const STRINGS = {
  'en-IN': ['🚨 DANGEROUS FRAUD SITE BLOCKED', '🔊 Listen in English', '⏹️ Stop Voice', '🤔 How did we catch this fraud?', '🛡️ Take Me to Safety', 'I understand the risk (Advanced)', 'National Cyber Crime Helpline: Dial <strong>1930</strong> (Toll-Free)'],
  'hi-IN': ['🚨 खतरनाक फर्जी वेबसाइट ब्लॉक की गई', '🔊 सुनें हिन्दी में', '⏹️ आवाज़ रोकें', '🤔 हमने इस धोखाधड़ी को कैसे पकड़ा?', '🛡️ मुझे सुरक्षित स्थान पर ले जाएं', 'मैं जोखिम समझता हूँ (आगे बढ़ें)', 'राष्ट्रीय साइबर अपराध हेल्पलाइन: डायल करें <strong>1930</strong> (मुफ्त)'],
  'ta-IN': ['🚨 ஆபத்தான போலி தளம் தடுக்கப்பட்டது', '🔊 தமிழில் கேட்கவும்', '⏹️ ஆடியோவை நிறுத்து', '🤔 இந்த மோசடியை நாங்கள் எவ்வாறு கண்டுபிடித்தோம்?', '🛡️ என்னை பாதுகாப்பான இடத்திற்கு அழைத்துச் செல்லவும்', 'அபாயத்தை நான் புரிந்துகொள்கிறேன் (மேம்பட்டது)', 'தேசிய சைபர் குற்ற உதவி எண்: அழைக்கவும் <strong>1930</strong> (இலவசம்)'],
  'te-IN': ['🚨 ప్రమాదకరమైన నకిలీ వెబ్‌సైట్ నిరోధించబడింది', '🔊 తెలుగులో వినండి', '⏹️ ఆడియో ఆపండి', '🤔 మేము ఈ మోసాన్ని ఎలా పట్టుకున్నాము?', '🛡️ నన్ను సురక్షిత ప్రదేశానికి తీసుకెళ్లండి', 'నేను ప్రమాదాన్ని అర్థం చేసుకున్నాను (ముందుకు సాగండి)', 'జాతీయ సైబర్ క్రైమ్ హెల్ప్‌లైన్: కాల్ చేయండి <strong>1930</strong> (ఉచితం)']
};

const THREAT_BULLETS = {
  SIG_ILLEGAL_WEB_PIN_COLLECTION: '❌ Asks for confidential bank/UPI PIN on an unverified web page.',
  SIG_DIGITAL_ARREST_EXTORTION: '❌ Fake police threats scaring you into video calls and fund transfers.',
  SIG_MALICIOUS_APK_DROPPER: '❌ Tries to download an unverified Android app (.apk) to steal SMS OTPs.',
  SIG_UPI_QR_COLLECT_TRAP: '❌ Fake cashback lure to scan a QR code that deducts money.'
};

let currentLang = 'en-IN';
let activeSignal = 'SIG_PHISHING_KIT_WEBHOOK_EXFIL';
let suspectHost = 'suspicious-website.xyz';
let suspectUrl = '';
let isSpeaking = false;

function detectThreatCategory(host, reason) {
  const c = ((host || '') + ' ' + (reason || '')).toLowerCase();
  if (c.includes('arrest') || c.includes('cbi') || c.includes('police') || c.includes('narcotics')) return 'SIG_DIGITAL_ARREST_EXTORTION';
  if (c.includes('apk') || c.includes('download') || c.includes('app')) return 'SIG_MALICIOUS_APK_DROPPER';
  if (c.includes('pin') || c.includes('bank') || c.includes('kyc') || c.includes('sbi')) return 'SIG_ILLEGAL_WEB_PIN_COLLECTION';
  if (c.includes('qr') || c.includes('cashback') || c.includes('refund') || c.includes('olx')) return 'SIG_UPI_QR_COLLECT_TRAP';
  if (c.includes('clipboard') || c.includes('clickfix')) return 'SIG_CLICKFIX_CLIPBOARD_ATTACK';
  return 'SIG_PHISHING_KIT_WEBHOOK_EXFIL';
}

function updateUI() {
  const [badge, voiceBtn, voiceStop, whyTitle, btnSafe, linkOverride, helpline] = STRINGS[currentLang] || STRINGS['en-IN'];
  const adv = getVernacularAdvisory(activeSignal, currentLang);

  document.querySelectorAll('.lang-btn').forEach(b => b.classList.toggle('active', b.dataset.lang === currentLang));

  const setTxt = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
  setTxt('warning-badge', badge);
  setTxt('main-title', adv.title);
  setTxt('subtitle', adv.explanation);
  setTxt('golden-rule-text', adv.goldenRule);
  setTxt('why-title', whyTitle);
  setTxt('btn-safe', btnSafe);
  setTxt('link-override', linkOverride);

  const voiceBtnEl = document.getElementById('voice-audio-btn');
  if (voiceBtnEl) {
    voiceBtnEl.textContent = isSpeaking ? voiceStop : voiceBtn;
    voiceBtnEl.classList.toggle('speaking', isSpeaking);
  }

  const helpEl = document.getElementById('helpline-desc');
  if (helpEl) helpEl.innerHTML = helpline;

  renderXRayBullets();
}

function renderXRayBullets() {
  const listEl = document.getElementById('xray-list');
  if (!listEl) return;

  const anatomy = parseUrlAnatomy(suspectUrl || suspectHost);
  const hostLow = suspectHost.toLowerCase();
  let matched = null;
  for (const [k, v] of Object.entries(LEGIT)) {
    if (hostLow.includes(k)) { matched = v; break; }
  }

  const bullets = [
    matched ? `❌ Real: <code>${matched[1]}</code>. Fake site: <code>${anatomy.registeredDomain}</code>.` : `❌ Web address (<code>${anatomy.registeredDomain}</code>) is unverified and not official.`,
    THREAT_BULLETS[activeSignal] || '❌ Secretly transmits typed passwords to a scammer bot or server.',
    '❌ Fake urgency trying to rush you before consulting family.'
  ];

  listEl.innerHTML = bullets.map(b => `<li class="xray-item"><span class="icon">•</span><div>${b}</div></li>`).join('');
}

function init() {
  const params = new URLSearchParams(window.location.search);
  suspectHost = params.get('host') || window.location.hostname || 'suspicious-website.xyz';
  suspectUrl = params.get('url') || ('https://' + suspectHost);
  activeSignal = detectThreatCategory(suspectHost, params.get('reason') || params.get('signal') || '');

  const navLang = (navigator.language || '').toLowerCase();
  if (navLang.startsWith('hi')) currentLang = 'hi-IN';
  else if (navLang.startsWith('ta')) currentLang = 'ta-IN';
  else if (navLang.startsWith('te')) currentLang = 'te-IN';
  else currentLang = 'en-IN';

  document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      currentLang = btn.dataset.lang;
      if (isSpeaking) { window.speechSynthesis?.cancel(); isSpeaking = false; }
      updateUI();
    });
  });

  const voiceBtn = document.getElementById('voice-audio-btn');
  if (voiceBtn) {
    voiceBtn.addEventListener('click', () => {
      if (isSpeaking) {
        window.speechSynthesis?.cancel();
        isSpeaking = false;
        updateUI();
        return;
      }
      isSpeaking = true;
      updateUI();
      const res = speakVernacularAdvisory(activeSignal, currentLang);
      if (!res.spoken) { isSpeaking = false; updateUI(); return; }

      if (typeof window !== 'undefined' && window.speechSynthesis) {
        const timer = setInterval(() => {
          if (!window.speechSynthesis.speaking) {
            clearInterval(timer);
            isSpeaking = false;
            updateUI();
          }
        }, 400);
      }
    });
  }

  const btnSafe = document.getElementById('btn-safe');
  if (btnSafe) {
    btnSafe.addEventListener('click', () => {
      if (window.history.length > 1) window.history.back();
      else window.location.href = 'https://www.google.com';
    });
  }

  const linkOverride = document.getElementById('link-override');
  if (linkOverride) {
    linkOverride.addEventListener('click', () => {
      if (window.confirm('⚠️ HIGH RISK WARNING:\n\nThis site was blocked for cyber fraud. Proceeding may compromise your bank balance or passwords.\n\nAre you sure you want to proceed?')) {
        window.location.href = suspectUrl;
      }
    });
  }

  updateUI();
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}

export { STRINGS, LEGIT, detectThreatCategory, updateUI, init };
