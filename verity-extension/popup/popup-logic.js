import {
  STATUS,
  UI,
  GOLDEN_RULES,
  REASON_PLAIN,
  goldenRuleForSignal,
  detectDefaultLang
} from '../shared/citizen-messages.js';

export const SUPPORTED_LANGS = ['en', 'ta', 'hi', 'te'];

export const INTERNAL_PAGE_MSG = {
  en: 'Nothing to check here',
  ta: 'இங்கே சரிபார்க்க எதுவும் இல்லை',
  hi: 'यहाँ जांचने के लिए कुछ नहीं है',
  te: 'ఇక్కడ తనిఖీ చేయడానికి ఏమీ లేదు'
};

export function isInternalUrl(url) {
  if (!url || typeof url !== 'string') return true;
  const l = url.trim().toLowerCase();
  return (
    !l || l === 'about:blank' ||
    l.startsWith('chrome://') || l.startsWith('about:') ||
    l.startsWith('chrome-extension://') || l.startsWith('edge://') ||
    l.startsWith('brave://') || l.startsWith('devtools://') ||
    l.startsWith('view-source:') || l.startsWith('chrome-search://') ||
    l.startsWith('data:') || l.startsWith('blob:') ||
    l.startsWith('javascript:')
  );
}

export function extractDomain(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return '';
  try {
    return new URL(rawUrl).hostname || rawUrl;
  } catch (_) {
    return rawUrl;
  }
}

export function detectEffectiveLang(storedLang, navigatorLang) {
  return (storedLang && SUPPORTED_LANGS.includes(storedLang))
    ? storedLang
    : detectDefaultLang(navigatorLang);
}

export function getRotatingGenericRule(date = new Date()) {
  const rules = ['upi', 'digital_arrest', 'apk', 'otp_password', 'generic'];
  const day = Math.floor(date.getTime() / 86400000);
  return rules[Math.abs(day) % rules.length];
}

export function resolvePlainReasons(signals = [], lang = 'en', maxCount = 3) {
  const eff = SUPPORTED_LANGS.includes(lang) ? lang : 'en';
  const out = [];
  const seen = new Set();
  for (const s of signals) {
    const id = typeof s === 'string' ? s : (s?.id || s?.signal || '');
    if (!id || seen.has(id)) continue;
    seen.add(id);
    const txt = REASON_PLAIN[id]?.[eff] || REASON_PLAIN[id]?.en;
    if (txt) {
      out.push(txt);
    } else {
      const u = id.toUpperCase();
      if (u.includes('MALWARE')) {
        out.push(eff === 'ta' ? 'அறியப்பட்ட ஆபத்தான தளம்.' : eff === 'hi' ? 'खतरनाक वेबसाइट।' : eff === 'te' ? 'ప్రమాదకరమైన సైట్.' : 'Dangerous malicious website.');
      } else if (u.includes('TYPO') || u.includes('IMPERSON')) {
        out.push(eff === 'ta' ? 'அங்கீகரிக்கப்பட்ட நிறுவனம் போன்ற போலி தளம்.' : eff === 'hi' ? 'फर्जी नकली वेबसाइट।' : eff === 'te' ? 'నకిలీ వెబ్‌సైట్.' : 'Deceptive fake website.');
      } else {
        out.push(eff === 'ta' ? 'ரகசிய விவரங்களைத் திருடும் தளம்.' : eff === 'hi' ? 'पासवर्ड चुराने वाला पेज।' : eff === 'te' ? 'పాస్‌వర్డ్‌లు దొంగిలించే పేజీ.' : 'Attempts to steal passwords.');
      }
    }
    if (out.length >= maxCount) break;
  }
  return out;
}

export function formatTabViewModel(tab, verdict, lang = 'en', date = new Date()) {
  const eff = SUPPORTED_LANGS.includes(lang) ? lang : 'en';
  const url = tab?.url || verdict?.url || '';

  if (isInternalUrl(url)) {
    const r = getRotatingGenericRule(date);
    return {
      isInternal: true,
      status: 'neutral',
      statusText: INTERNAL_PAGE_MSG[eff] || INTERNAL_PAGE_MSG.en,
      domain: extractDomain(url) || 'browser',
      url,
      score: 0,
      plainReasons: [],
      goldenRuleKey: r,
      goldenRuleTitle: UI[eff]?.goldenRuleTitle || UI.en.goldenRuleTitle,
      goldenRuleText: GOLDEN_RULES[r]?.[eff] || GOLDEN_RULES[r]?.en,
      advancedDetails: 'Internal browser page. Sandboxed and protected by your browser.',
      rawSignals: []
    };
  }

  const rawScore = (typeof verdict?.score === 'number')
    ? verdict.score
    : ((typeof verdict?.riskScore === 'number')
      ? verdict.riskScore
      : (typeof verdict?.verdict?.score === 'number' ? verdict.verdict.score : 0));
  const score = Math.min(Math.max(rawScore, 0), 100);

  const rawSignals = Array.isArray(verdict?.signals)
    ? verdict.signals.map(s => typeof s === 'string' ? s : s?.id).filter(Boolean)
    : (Array.isArray(verdict?.verdict?.signals) ? verdict.verdict.signals.map(s => typeof s === 'string' ? s : s?.id).filter(Boolean) : []);

  const action = String(verdict?.action || verdict?.verdict?.action || '').toUpperCase();
  const severity = String(verdict?.severity || verdict?.state || verdict?.verdict?.severity || verdict?.verdict?.state || '').toUpperCase();

  let status = 'safe';
  if (score >= 70 || action === 'BLOCK' || severity === 'DANGER' || severity === 'CRITICAL' || severity === 'HIGH') {
    status = 'danger';
  } else if (score >= 35 || action === 'WARN' || severity === 'CAUTION' || severity === 'MEDIUM' || severity === 'LOW') {
    status = 'caution';
  }

  const plainReasons = status === 'safe'
    ? []
    : resolvePlainReasons(verdict?.signals || verdict?.reasons || verdict?.verdict?.reasons, eff, status === 'danger' ? 3 : 2);

  let goldenRuleKey = (status !== 'safe' && rawSignals.length > 0)
    ? goldenRuleForSignal(rawSignals[0])
    : getRotatingGenericRule(date);

  return {
    isInternal: false,
    status,
    statusText: STATUS[eff]?.[status] || STATUS.en[status],
    domain: extractDomain(url),
    url,
    score,
    plainReasons,
    goldenRuleKey,
    goldenRuleTitle: UI[eff]?.goldenRuleTitle || UI.en.goldenRuleTitle,
    goldenRuleText: GOLDEN_RULES[goldenRuleKey]?.[eff] || GOLDEN_RULES[goldenRuleKey]?.en || GOLDEN_RULES.generic.en,
    advancedDetails: `Domain: ${extractDomain(url)}\nScore: ${score}/100 (${status.toUpperCase()})\nSignals: ${rawSignals.join(', ') || 'None'}`,
    rawSignals
  };
}

export function formatScanResult(scanResult, lang = 'en') {
  const eff = SUPPORTED_LANGS.includes(lang) ? lang : 'en';
  if (!scanResult) {
    return {
      status: 'safe',
      statusText: STATUS[eff]?.safe || STATUS.en.safe,
      score: 0,
      plainReasons: [],
      goldenRuleKey: 'generic',
      goldenRuleTitle: UI[eff]?.goldenRuleTitle || UI.en.goldenRuleTitle,
      goldenRuleText: GOLDEN_RULES.generic[eff] || GOLDEN_RULES.generic.en,
      extracted: { urls: [], upi: null, apkNames: [] },
      advancedDetails: 'No input provided.',
      rawSignals: []
    };
  }

  const rawScore = (typeof scanResult.score === 'number')
    ? scanResult.score
    : ((typeof scanResult.riskScore === 'number')
      ? scanResult.riskScore
      : (typeof scanResult.verdict?.score === 'number' ? scanResult.verdict.score : 0));
  const score = Math.min(Math.max(rawScore, 0), 100);

  let rawStatus = typeof scanResult.verdict === 'string'
    ? scanResult.verdict
    : (scanResult.verdict?.state || scanResult.verdict?.severity || scanResult.status || 'safe');
  const statusStr = String(rawStatus).toLowerCase();

  let status = 'safe';
  if (score >= 70 || statusStr === 'danger' || statusStr === 'block') {
    status = 'danger';
  } else if (score >= 35 || statusStr === 'caution' || statusStr === 'warn') {
    status = 'caution';
  }

  const plainReasons = status === 'safe'
    ? []
    : resolvePlainReasons(scanResult.signals || scanResult.verdict?.reasons, eff, status === 'danger' ? 3 : 2);
  const goldenRuleKey = scanResult.goldenRuleKey || 'generic';
  const rawSignals = Array.isArray(scanResult.signals) ? scanResult.signals.map(s => s.id || s) : [];

  return {
    status,
    statusText: STATUS[eff]?.[status] || STATUS.en[status],
    score,
    plainReasons,
    goldenRuleKey,
    goldenRuleTitle: UI[eff]?.goldenRuleTitle || UI.en.goldenRuleTitle,
    goldenRuleText: GOLDEN_RULES[goldenRuleKey]?.[eff] || GOLDEN_RULES[goldenRuleKey]?.en || GOLDEN_RULES.generic.en,
    extracted: scanResult.extracted || { urls: [], upi: null, apkNames: [] },
    advancedDetails: `Verdict: ${status.toUpperCase()} (${score}/100)\nURLs: ${scanResult.extracted?.urls?.join(', ') || 'None'}\nAPKs: ${scanResult.extracted?.apkNames?.join(', ') || 'None'}\nUPI: ${scanResult.extracted?.upi ? (scanResult.extracted.upi.isCollect ? 'Trap' : 'Normal') : 'None'}\nSignals: ${rawSignals.join(', ') || 'None'}`,
    rawSignals
  };
}

export default {
  SUPPORTED_LANGS,
  INTERNAL_PAGE_MSG,
  isInternalUrl,
  extractDomain,
  detectEffectiveLang,
  getRotatingGenericRule,
  resolvePlainReasons,
  formatTabViewModel,
  formatScanResult
};
