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
export { SCHEMA_VERSION, RULE_PACK_VERSION, createVerdict, createAbstentionVerdict, validateVerdictContract } from './shared/verdict-contract.js';
export { OFFICIAL_RECOVERY_REGISTRY, INCIDENT_TYPES, RECOVERY_GUIDES, sanitizeSecrets, generateEvidenceReceipt, getRecoveryGuide } from './shared/recovery-advisor.js';
export { POLICY_VERSION, ACTION_TYPES, PROHIBITED_AUTOMATIC_ACTIONS, evaluateSafeActionPolicy } from './shared/safe-action-policy.js';
export { THREAT_PACK_SCHEMA_VERSION, ALLOWED_INDICATOR_TYPES, verifyThreatPack } from './shared/threat-pack-verifier.js';
export { ThreatUpdateManager } from './shared/threat-update-manager.js';
export { FLIGHT_RECORDER_VERSION, LEGAL_DISCLAIMER, FlightRecorder, sanitizeFlightRecorderSecrets } from './shared/flight-recorder.js';
