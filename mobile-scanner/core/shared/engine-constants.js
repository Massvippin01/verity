/**
 * shared/engine-constants.js — Centralized, Immutable Engine Constants & Score Floors
 *
 * Provides frozen configuration for thresholds, category caps, multi-vector diminishing weights,
 * and the independent, order-invariant Maximum Severity Floor Resolver (applyScoreFloors).
 */

'use strict';

// ── Verdict Classification Thresholds ────────────────────────────────────────
export const THRESHOLDS = Object.freeze({
  BLOCK: 70,
  CAUTION: 35,
  SAFE: 0,
  CONVERGENCE_DEMOTION: 65,
  MAX_SCORE: 100
});

// ── Extended Diminishing Return Weights (10 Elements) ────────────────────────
// Smoothly scales multi-vector attacks triggering 6+ categories.
export const DIMINISHING_WEIGHTS = Object.freeze([
  1.0, 0.55, 0.35, 0.25, 0.18, 0.15, 0.12, 0.10, 0.08, 0.06
]);

// ── Score Floor Constants ───────────────────────────────────────────────────
export const SCORE_FLOORS = Object.freeze({
  // P0 / Critical Threat Vectors (Score >= 95)
  CROSS_ORIGIN_PASSWORD_REUSE: 95,
  ILLEGAL_WEB_PIN_COLLECTION: 95,
  BRAND_CREDENTIAL_PORTAL_TRAP: 95,
  PHISHING_KIT_WEBHOOK_EXFIL: 95,
  BITB_ATTACK: 95,
  WEB3_DRAINER_RAW_SIGN: 95,
  WEB3_UNLIMITED_APPROVAL: 95,
  CROSS_ORIGIN_CREDENTIAL_POST: 95,
  AITM_REVERSE_PROXY: 95,
  CLIPBOARD_ADDRESS_SWAP: 95,
  FAVICON_SPOOF_WITH_PAYMENT_OR_CREDENTIAL: 95,
  UPI_COLLECT_TRAP: 95,

  // P1 High Severity Threats (Score 88 - 90)
  PHISHSTATS_HIT: 90,
  KEYLOGGER_HONEYTOKEN_TRIPPED: 90,
  SURVEILLANCE_EXTORTION_TRAP: 90,
  NPCI_FORENSIC_COLLECT: 90,
  ARCHIVE_PASSWORD_STEALER_LURE: 90,
  MALICIOUS_APK_DROPPER: 90,
  FREE_HOSTING_CREDENTIAL_TRAP: 90,
  BRAND_ASSET_HOTLINK_SPOOF: 90,
  REMOTE_ACCESS_SCAM_DOWNLOAD: 90,
  CREDENTIAL_EXFIL: 90,
  BRAND_MISMATCH_WITH_CREDENTIALS: 90,
  CHROME_DANGEROUS_DOWNLOAD: 90,
  CT_EPHEMERAL_CERT_PHISH: 88,
  COMPROMISED_CMS_PHISH: 88,

  // P2 Advanced Phishing & Coercion Threats (Score 82 - 85)
  NEURAL_META_FUSION_PHISH: 85,
  AUTONOMOUS_BRAND_MISMATCH: 85,
  MISSING_DMARC_CREDENTIAL_TRAP: 85,
  SECV_CONVERGENCE: 85,
  UNIVERSAL_DOM_CLONE_PHISH: 85,
  UNIVERSAL_NRD_CREDENTIAL_TRAP: 85,
  UNIVERSAL_CLIPBOARD_MISMATCH: 85,
  BRAND_ASSET_THEFT: 85,
  BITB_POPUP_SPOOF: 85,
  DIGITAL_ARREST_EXTORTION: 85,
  UPI_QR_COLLECT_TRAP: 85,
  TAB_UNDER_HIJACK: 85,
  FAKE_DOWNLOAD_BUTTON_TRAP: 85,
  FAVICON_SPOOF: 85,
  DOM_BRAND_SPOOF: 85,
  KYC_CYBER_FRAUD: 85,
  MALICIOUS_QR_PAYLOAD: 85,
  TECH_SUPPORT_REMOTE_SCAM: 85,
  UNTRUSTED_SCREEN_SHARE: 85,
  CLICKFIX: 85,
  MALWARE_INTEL: 85,
  MALVERTISING_CRITICAL_OVERRIDE: 85,
  AI_NLP_SCAM_INTENT: 82,

  // Suspicious Infrastructure & Cloaking (Score 75 - 80)
  DNS_CNAME_CLOAKING: 80,
  MALVERTISING_REDIRECT_CHAIN: 80,
  CLICKJACK_INVISIBLE_OVERLAY: 80,
  NOTIFICATION_PERMISSION_TRAP: 80,
  ROGUE_PUSH_OR_SW_TRAP: 80,
  FREE_HOST_CREDENTIAL_PHISH: 75,
  SMUGGLING_OR_SPOOF_DANGER: 75
});

/**
 * Maximum Severity Floor Resolver (Order-Invariant).
 * Evaluates all triggered threat flags independently and resolves to the highest
 * applicable score floor. Guarantees that lower-floor signals (e.g. AI NLP @ 82)
 * can NEVER mask higher-floor critical signals (e.g. BitB @ 95, Clipboard Swap @ 95).
 *
 * @param {number} initialRiskScore - Current accumulated risk score
 * @param {Record<string, boolean|number>} threatFlags - Map of active threat flags
 * @returns {number} Resolved risk score respecting the maximum floor
 */
export function applyScoreFloors(initialRiskScore, threatFlags = {}) {
  let score = Number(initialRiskScore) || 0;

  // 1. Critical Threats (Floor 95)
  if (threatFlags.hasCrossOriginPasswordReuse) score = Math.max(score, SCORE_FLOORS.CROSS_ORIGIN_PASSWORD_REUSE);
  if (threatFlags.hasIllegalWebPinCollection) score = Math.max(score, SCORE_FLOORS.ILLEGAL_WEB_PIN_COLLECTION);
  if (threatFlags.hasBrandCredentialPortalTrap) score = Math.max(score, SCORE_FLOORS.BRAND_CREDENTIAL_PORTAL_TRAP);
  if (threatFlags.hasPhishingKitWebhookExfil) score = Math.max(score, SCORE_FLOORS.PHISHING_KIT_WEBHOOK_EXFIL);
  if (threatFlags.hasBitbAttack) score = Math.max(score, SCORE_FLOORS.BITB_ATTACK);
  if (threatFlags.hasWeb3DrainerRawSign) score = Math.max(score, SCORE_FLOORS.WEB3_DRAINER_RAW_SIGN);
  if (threatFlags.hasWeb3UnlimitedApproval) score = Math.max(score, SCORE_FLOORS.WEB3_UNLIMITED_APPROVAL);
  if (threatFlags.hasCrossOriginCredentialPost) score = Math.max(score, SCORE_FLOORS.CROSS_ORIGIN_CREDENTIAL_POST);
  if (threatFlags.hasAitmReverseProxy) score = Math.max(score, SCORE_FLOORS.AITM_REVERSE_PROXY);
  if (threatFlags.hasClipboardAddressSwap) score = Math.max(score, SCORE_FLOORS.CLIPBOARD_ADDRESS_SWAP);
  if (threatFlags.hasUpiCollectTrap) score = Math.max(score, SCORE_FLOORS.UPI_COLLECT_TRAP);
  if (threatFlags.hasFaviconSpoof && threatFlags.hasPaymentOrCredentialDemand) {
    score = Math.max(score, SCORE_FLOORS.FAVICON_SPOOF_WITH_PAYMENT_OR_CREDENTIAL);
  }

  // 2. High Severity Threats (Floor 88 - 90)
  if (threatFlags.hasPhishStatsHit) score = Math.max(score, SCORE_FLOORS.PHISHSTATS_HIT);
  if (threatFlags.hasKeyloggerHoneytokenTripped) score = Math.max(score, SCORE_FLOORS.KEYLOGGER_HONEYTOKEN_TRIPPED);
  if (threatFlags.hasSurveillanceExtortionTrap) score = Math.max(score, SCORE_FLOORS.SURVEILLANCE_EXTORTION_TRAP);
  if (threatFlags.hasNpciForensicCollect) score = Math.max(score, SCORE_FLOORS.NPCI_FORENSIC_COLLECT);
  if (threatFlags.hasArchivePasswordStealerLure) score = Math.max(score, SCORE_FLOORS.ARCHIVE_PASSWORD_STEALER_LURE);
  if (threatFlags.hasMaliciousApkDropper) score = Math.max(score, SCORE_FLOORS.MALICIOUS_APK_DROPPER);
  if (threatFlags.hasFreeHostingTrap && (
    threatFlags.hasBrandImpersonationSignal ||
    threatFlags.hasPasswordInput ||
    threatFlags.hasPaymentOrCredentialDemand ||
    threatFlags.hasCredentialCollection
  )) {
    score = Math.max(score, SCORE_FLOORS.FREE_HOSTING_CREDENTIAL_TRAP);
  }
  if (threatFlags.hasBrandAssetHotlinkSpoof) score = Math.max(score, SCORE_FLOORS.BRAND_ASSET_HOTLINK_SPOOF);
  if (threatFlags.hasRemoteAccessScamDownload) score = Math.max(score, SCORE_FLOORS.REMOTE_ACCESS_SCAM_DOWNLOAD);
  if (threatFlags.hasCredentialExfil) score = Math.max(score, SCORE_FLOORS.CREDENTIAL_EXFIL);
  if (threatFlags.hasBrandMismatchWithCredentials) score = Math.max(score, SCORE_FLOORS.BRAND_MISMATCH_WITH_CREDENTIALS);
  if (threatFlags.chromeSaysDangerous) score = Math.max(score, SCORE_FLOORS.CHROME_DANGEROUS_DOWNLOAD);
  if (threatFlags.hasCtEphemeralCertPhish) score = Math.max(score, SCORE_FLOORS.CT_EPHEMERAL_CERT_PHISH);
  if (threatFlags.hasCompromisedCmsPhish) score = Math.max(score, SCORE_FLOORS.COMPROMISED_CMS_PHISH);

  // 3. Advanced Phishing & Coercion (Floor 82 - 85)
  if (threatFlags.hasNeuralMetaFusionPhish) {
    const neuralScore = typeof threatFlags.neuralScore === 'number' ? threatFlags.neuralScore : SCORE_FLOORS.NEURAL_META_FUSION_PHISH;
    score = Math.max(score, neuralScore);
  }
  if (threatFlags.hasAutonomousBrandMismatch) score = Math.max(score, SCORE_FLOORS.AUTONOMOUS_BRAND_MISMATCH);
  if (threatFlags.hasMissingDmarcCredentialTrap) score = Math.max(score, SCORE_FLOORS.MISSING_DMARC_CREDENTIAL_TRAP);
  if (threatFlags.hasSecvConvergence) score = Math.max(score, SCORE_FLOORS.SECV_CONVERGENCE);
  if (threatFlags.hasUniversalDomClonePhish) score = Math.max(score, SCORE_FLOORS.UNIVERSAL_DOM_CLONE_PHISH);
  if (threatFlags.hasUniversalNrdCredentialTrap) score = Math.max(score, SCORE_FLOORS.UNIVERSAL_NRD_CREDENTIAL_TRAP);
  if (threatFlags.hasUniversalClipboardMismatch) score = Math.max(score, SCORE_FLOORS.UNIVERSAL_CLIPBOARD_MISMATCH);
  if (threatFlags.hasBrandAssetTheft) score = Math.max(score, SCORE_FLOORS.BRAND_ASSET_THEFT);
  if (threatFlags.hasBitbPopupSpoof) score = Math.max(score, SCORE_FLOORS.BITB_POPUP_SPOOF);
  if (threatFlags.hasDigitalArrestExtortion) score = Math.max(score, SCORE_FLOORS.DIGITAL_ARREST_EXTORTION);
  if (threatFlags.hasUpiQrCollectTrap) score = Math.max(score, SCORE_FLOORS.UPI_QR_COLLECT_TRAP);
  if (threatFlags.hasTabUnderHijack) score = Math.max(score, SCORE_FLOORS.TAB_UNDER_HIJACK);
  if (threatFlags.hasFakeDownloadButtonTrap) score = Math.max(score, SCORE_FLOORS.FAKE_DOWNLOAD_BUTTON_TRAP);
  if (threatFlags.hasFaviconSpoof) score = Math.max(score, SCORE_FLOORS.FAVICON_SPOOF);
  if (threatFlags.hasDomBrandSpoof) score = Math.max(score, SCORE_FLOORS.DOM_BRAND_SPOOF);
  if (threatFlags.hasKycCyberFraud) score = Math.max(score, SCORE_FLOORS.KYC_CYBER_FRAUD);
  if (threatFlags.hasMaliciousQrPayload) score = Math.max(score, SCORE_FLOORS.MALICIOUS_QR_PAYLOAD);
  if (threatFlags.hasTechSupportRemoteScam) score = Math.max(score, SCORE_FLOORS.TECH_SUPPORT_REMOTE_SCAM);
  if (threatFlags.hasUntrustedScreenShare) score = Math.max(score, SCORE_FLOORS.UNTRUSTED_SCREEN_SHARE);
  if (threatFlags.hasClickFix) score = Math.max(score, SCORE_FLOORS.CLICKFIX);
  if (threatFlags.hasMalwareIntel) score = Math.max(score, SCORE_FLOORS.MALWARE_INTEL);
  if (threatFlags.hasMalvertisingCriticalOverride) score = Math.max(score, SCORE_FLOORS.MALVERTISING_CRITICAL_OVERRIDE);
  if (threatFlags.hasAiNlpScamIntent) score = Math.max(score, SCORE_FLOORS.AI_NLP_SCAM_INTENT);

  // 4. Cloaking, Overlays & Redirect Infrastructure (Floor 75 - 80)
  if (threatFlags.hasDnsCnameCloaking) score = Math.max(score, SCORE_FLOORS.DNS_CNAME_CLOAKING);
  if (threatFlags.hasMalvertisingRedirectChain) score = Math.max(score, SCORE_FLOORS.MALVERTISING_REDIRECT_CHAIN);
  if (threatFlags.hasClickjackInvisibleOverlay) score = Math.max(score, SCORE_FLOORS.CLICKJACK_INVISIBLE_OVERLAY);
  if (threatFlags.hasNotificationPermissionTrap) score = Math.max(score, SCORE_FLOORS.NOTIFICATION_PERMISSION_TRAP);
  if (threatFlags.hasRoguePushOrSwTrap) score = Math.max(score, SCORE_FLOORS.ROGUE_PUSH_OR_SW_TRAP);
  if (threatFlags.hasFreeHostCredentialPhish) score = Math.max(score, SCORE_FLOORS.FREE_HOST_CREDENTIAL_PHISH);
  if (threatFlags.isSmugglingDanger || threatFlags.isSpoofDanger) score = Math.max(score, SCORE_FLOORS.SMUGGLING_OR_SPOOF_DANGER);

  return Math.min(THRESHOLDS.MAX_SCORE, Math.max(0, score));
}

export default {
  THRESHOLDS,
  DIMINISHING_WEIGHTS,
  SCORE_FLOORS,
  applyScoreFloors
};
