import { getVernacularAdvisory } from '../shared/vernacular-coach.js';
import { generateXRayTeachingCards, parseUrlAnatomy } from '../shared/xray-educator.js';

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
  'en-IN': ['🚨 DANGEROUS FRAUD SITE BLOCKED', '', '', '🤔 How did we catch this?', '🛡️ Take Me to Safety', 'I understand the risk (Advanced)', 'National Cyber Crime Helpline: Dial 1930 (Toll-Free)'],
  'hi-IN': ['🚨 खतरनाक फर्जी वेबसाइट ब्लॉक की गई', '', '', '🤔 हमने इस धोखाधड़ी को कैसे पकड़ा?', '🛡️ मुझे सुरक्षित स्थान पर ले जाएं', 'मैं जोखिम समझता हूँ (तकनीकी जानकारी)', 'राष्ट्रीय साइबर अपराध हेल्पलाइन: डायल करें 1930 (मुफ्त)'],
  'ta-IN': ['🚨 ஆபத்தான போலி தளம் தடுக்கப்பட்டது', '', '', '🤔 இதை நாங்கள் எவ்வாறு கண்டுபிடித்தோம்?', '🛡️ என்னை பாதுகாப்பான இடத்திற்கு அழைத்துச் செல்லவும்', 'அபாயத்தை நான் புரிந்துகொள்கிறேன் (மேம்பட்டது)', 'தேசிய சைபர் குற்ற உதவி எண்: அழைக்கவும் 1930 (இலவசம்)'],
  'te-IN': ['🚨 ప్రమాదకరమైన నకిలీ వెబ్‌సైట్ నిరోధించబడింది', '', '', '🤔 మేము ఈ మోసాన్ని ఎలా పట్టుకున్నాము?', '🛡️ నన్ను సురక్షిత ప్రదేశానికి తీసుకెళ్లండి', 'నేను ప్రమాదాన్ని అర్థం చేసుకున్నాను (ముందుకు సాగండి)', 'జాతీయ సైబర్ క్రైమ్ హెల్ప్‌లైన్: కాల్ చేయండి 1930 (ఉచితం)']
};

const THREAT_BULLETS = {
  SIG_ILLEGAL_WEB_PIN_COLLECTION: 'Asks for confidential bank/UPI PIN on an unverified web page.',
  SIG_DIGITAL_ARREST_EXTORTION: 'Fake police threats scaring you into video calls and fund transfers.',
  SIG_MALICIOUS_APK_DROPPER: 'Tries to download an unverified Android app (.apk) to steal SMS OTPs.',
  SIG_UPI_QR_COLLECT_TRAP: 'Fake cashback lure to scan a QR code that deducts money.'
};

let currentLang = 'en-IN';
let suspectHost = 'suspicious-website.xyz';
let suspectUrl = 'https://suspicious-website.xyz';
let activeSignal = 'SIG_PHISHING_KIT_WEBHOOK_EXFIL';
let quizAnswered = false;

function detectThreatCategory(host, reason) {
  const c = ((host || '') + ' ' + (reason || '')).toLowerCase();
  if (c.includes('arrest') || c.includes('cbi') || c.includes('police') || c.includes('narcotics')) return 'SIG_DIGITAL_ARREST_EXTORTION';
  if (c.includes('apk') || c.includes('download') || c.includes('app')) return 'SIG_MALICIOUS_APK_DROPPER';
  if (c.includes('pin') || c.includes('bank') || c.includes('kyc') || c.includes('sbi')) return 'SIG_ILLEGAL_WEB_PIN_COLLECTION';
  if (c.includes('qr') || c.includes('cashback') || c.includes('refund') || c.includes('olx')) return 'SIG_UPI_QR_COLLECT_TRAP';
  if (c.includes('clipboard') || c.includes('clickfix')) return 'SIG_CLICKFIX_CLIPBOARD_ATTACK';
  return 'SIG_PHISHING_KIT_WEBHOOK_EXFIL';
}

function buildAnalysisFromParams(searchParamsOrUrl) {
  let p;
  if (!searchParamsOrUrl) p = new URLSearchParams('');
  else if (typeof searchParamsOrUrl === 'string') {
    const q = searchParamsOrUrl.indexOf('?');
    p = new URLSearchParams(q !== -1 ? searchParamsOrUrl.slice(q) : searchParamsOrUrl);
  } else if (searchParamsOrUrl instanceof URLSearchParams) p = searchParamsOrUrl;
  else if (typeof searchParamsOrUrl === 'object') {
    const h = searchParamsOrUrl.host || 'suspicious-website.xyz';
    const sig = searchParamsOrUrl.signal || detectThreatCategory(h, searchParamsOrUrl.reason || '');
    return {
      host: h,
      url: searchParamsOrUrl.url || (`https://${h}`),
      score: searchParamsOrUrl.score || 90,
      severity: searchParamsOrUrl.severity || 'CRITICAL',
      action: 'BLOCK',
      signals: [{ id: sig }],
      reasons: [{ id: sig, reason: searchParamsOrUrl.reason || '' }]
    };
  } else p = new URLSearchParams('');

  const rHost = p.get('host') || '', rUrl = p.get('url') || '', rReason = p.get('reason') || '', rSig = p.get('signal') || '';
  let host = rHost;
  if (!host && rUrl) {
    try { host = new URL(rUrl.includes('://') ? rUrl : `https://${rUrl}`).hostname || rUrl; } catch (_) { host = rUrl; }
  }
  if (!host) host = 'suspicious-website.xyz';
  const url = rUrl || (`https://${host}`);
  const sig = rSig || detectThreatCategory(host, rReason);

  return {
    host,
    url,
    score: 90,
    severity: 'CRITICAL',
    action: 'BLOCK',
    signals: [{ id: sig }],
    reasons: [{ id: sig, reason: rReason }]
  };
}

function updateUI() {
  const [badge, , , whyTitle, btnSafe, linkOverride, helpline] = STRINGS[currentLang] || STRINGS['en-IN'];
  const adv = getVernacularAdvisory(activeSignal, currentLang);

  document.querySelectorAll('.lang-btn').forEach(b => b.classList.toggle('active', b.dataset.lang === currentLang));

  const setTxt = (id, txt) => {
    const el = document.getElementById(id);
    if (el) el.textContent = txt;
  };
  setTxt('warning-badge', badge);
  setTxt('main-title', adv.title);
  setTxt('subtitle', adv.explanation);
  setTxt('golden-rule-text', adv.goldenRule);
  setTxt('why-title', whyTitle);
  setTxt('btn-safe', btnSafe);
  setTxt('link-override', linkOverride);
  setTxt('helpline-desc', helpline);

  const techPre = document.getElementById('technical-pre');
  if (techPre) {
    techPre.textContent = `[Threat Advisory]\nHost: ${suspectHost}\nURL: ${suspectUrl}\nSignal: ${activeSignal}\nAction: BLOCK (Score: 90/100)`;
  }

  renderXRayCurriculum();
}

function renderXRayCurriculum() {
  const analysis = {
    host: suspectHost,
    url: suspectUrl,
    signals: [{ id: activeSignal }],
    reasons: [THREAT_BULLETS[activeSignal] || 'Suspected cyber fraud']
  };

  const teaching = generateXRayTeachingCards(analysis, suspectUrl);
  const listEl = document.getElementById('xray-list');
  if (listEl) {
    while (listEl.firstChild) listEl.removeChild(listEl.firstChild);
    const anatomy = parseUrlAnatomy(suspectUrl || suspectHost);
    const hostLow = suspectHost.toLowerCase();
    let matched = null;
    for (const [k, v] of Object.entries(LEGIT)) {
      if (hostLow.includes(k)) { matched = v; break; }
    }

    const bullets = [
      matched ? `Real official website: ${matched[1]}. Fake site: ${anatomy.registeredDomain}.` : `Web address (${anatomy.registeredDomain}) is unverified and not official.`,
      THREAT_BULLETS[activeSignal] || 'Secretly transmits entered credentials or OTPs to scammers.',
      'Employs artificial panic or fake urgency to rush you before consulting family.'
    ];

    bullets.forEach(b => {
      const li = document.createElement('li');
      li.className = 'xray-item';
      const icon = document.createElement('span');
      icon.className = 'icon';
      icon.textContent = '❌';
      const div = document.createElement('div');
      div.textContent = b;
      li.appendChild(icon);
      li.appendChild(div);
      listEl.appendChild(li);
    });
  }

  const quizCard = teaching.cards.find(c => c.cardType === 'MICRO_QUIZ');
  const qTitleEl = document.getElementById('quiz-title');
  const qTextEl = document.getElementById('quiz-question');
  const qOptionsEl = document.getElementById('quiz-options');
  const qFeedbackEl = document.getElementById('quiz-feedback');

  if (quizCard && qTextEl && qOptionsEl) {
    if (qTitleEl) qTitleEl.textContent = '🎯 Spot The Scam Challenge';
    qTextEl.textContent = quizCard.question;
    while (qOptionsEl.firstChild) qOptionsEl.removeChild(qOptionsEl.firstChild);
    if (qFeedbackEl) {
      qFeedbackEl.className = 'quiz-feedback hidden';
      while (qFeedbackEl.firstChild) qFeedbackEl.removeChild(qFeedbackEl.firstChild);
    }
    quizAnswered = false;

    quizCard.options.forEach((optText, idx) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'quiz-btn';
      btn.dataset.idx = String(idx);
      btn.textContent = optText;

      btn.addEventListener('click', () => {
        if (quizAnswered) return;
        quizAnswered = true;
        const isCorrect = idx === quizCard.correctIndex;
        qOptionsEl.querySelectorAll('.quiz-btn').forEach((b, bIdx) => {
          b.disabled = true;
          if (bIdx === quizCard.correctIndex) {
            b.classList.add('correct');
            b.textContent = `✅ ${quizCard.options[bIdx]}`;
          } else if (bIdx === idx && !isCorrect) {
            b.classList.add('wrong');
            b.textContent = `❌ ${quizCard.options[bIdx]}`;
          }
        });

        if (qFeedbackEl) {
          qFeedbackEl.className = `quiz-feedback ${isCorrect ? 'correct' : 'wrong'}`;
          qFeedbackEl.textContent = isCorrect ? `✅ Correct! ${quizCard.explanation}` : `❌ Incorrect. ${quizCard.explanation}`;
        }
      });
      qOptionsEl.appendChild(btn);
    });
  }
}

function init() {
  const p = typeof window !== 'undefined' ? new URLSearchParams(window.location.search) : new URLSearchParams('');
  const a = buildAnalysisFromParams(p);
  suspectHost = a.host;
  suspectUrl = a.url;
  activeSignal = a.signals[0]?.id || 'SIG_PHISHING_KIT_WEBHOOK_EXFIL';

  const nav = (typeof navigator !== 'undefined' && navigator.language ? navigator.language : '').toLowerCase();
  if (nav.startsWith('hi')) currentLang = 'hi-IN';
  else if (nav.startsWith('ta')) currentLang = 'ta-IN';
  else if (nav.startsWith('te')) currentLang = 'te-IN';
  else currentLang = 'en-IN';

  document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.addEventListener('click', () => { currentLang = btn.dataset.lang; updateUI(); });
  });

  const btnSafe = document.getElementById('btn-safe');
  if (btnSafe) {
    btnSafe.addEventListener('click', () => {
      if (typeof chrome !== 'undefined' && chrome.tabs?.update) {
        chrome.tabs.update({ url: 'chrome://newtab' }).catch(() => {
          if (window.history.length > 1) window.history.back();
          else window.location.href = 'https://www.google.com';
        });
      } else if (typeof window !== 'undefined' && window.history.length > 1) {
        window.history.back();
      } else if (typeof window !== 'undefined') {
        window.location.href = 'https://www.google.com';
      }
    });
  }

  const linkOverride = document.getElementById('link-override');
  const techPre = document.getElementById('technical-pre');
  if (linkOverride && techPre) {
    linkOverride.addEventListener('click', () => techPre.classList.toggle('hidden'));
  }

  updateUI();
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}

export {
  STRINGS,
  LEGIT,
  detectThreatCategory,
  buildAnalysisFromParams,
  updateUI,
  init
};

export default {
  STRINGS,
  LEGIT,
  detectThreatCategory,
  buildAnalysisFromParams,
  updateUI,
  init
};
