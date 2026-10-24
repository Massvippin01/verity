export { scanText, parseUpiString, extractUrls } from './shared/text-scanner.js';
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
export { verifyUrlAndMessageOnline, verifyEntityOfficialDomainOnline } from './shared/online-scam-verifier.js';
export { computeSecvIntentVector, normalizeVernacularPhonetics } from './shared/secv-intent-engine.js';
export { verifyAutonomousBrandIdentity, auditDomainDmarcPosture, extractAssertedDomIdentity } from './shared/autonomous-brand-discovery.js';
