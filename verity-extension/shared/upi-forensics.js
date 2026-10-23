/**
 * shared/upi-forensics.js — Deep NPCI UPI Protocol Forensic Unmasker
 *
 * Audits upi://pay intent URIs against the official NPCI UPI Linking Specification.
 * Deterministically flags unsigned P2P collect traps with hardcoded debit amounts,
 * deceptive refund/cashback transaction notes, and impersonated consumer VPA handles.
 *
 * Zero external dependencies — portable across browser extensions, Node.js, and PWA.
 */

'use strict';

/**
 * High-value institutional keywords that fraudsters impersonate in consumer VPA local-parts.
 */
export const SUSPICIOUS_VPA_LOCAL_PATTERNS = [
  'refund',
  'cashback',
  'rewards',
  'reward',
  'sbihome',
  'sbi',
  'hdfc',
  'icici',
  'axis',
  'kotak',
  'pnb',
  'rbi',
  'cybercell',
  'police',
  'support',
  'care',
  'customercare',
  'customerhelp',
  'helpdesk',
  'helpline',
  'bescom',
  'tneb',
  'electricity',
  'indiapost',
  'speedpost',
  'kyc',
  'panupdate',
  'challan'
];

/**
 * Standard Indian consumer PSP handles (individual accounts, not verified corporate merchants).
 */
export const CONSUMER_PSP_HANDLES = [
  'ybl',
  'ibl',
  'axl',
  'okaxis',
  'oksbi',
  'okhdfcbank',
  'okicici',
  'paytm',
  'upi',
  'postbank',
  'kotak',
  'barodampay',
  'airtel',
  'fbl',
  'idfcbank',
  'waaxis',
  'wahdfc',
  'waicici',
  'wasbi'
];

/**
 * Deceptive keywords claiming that funds will be received, credited, or won.
 */
export const DECEPTIVE_CONTEXT_KEYWORDS = [
  'cashback', 'refund', 'receive', 'olx', 'buyer', 'advance',
  'claim', 'bonus', 'prize', 'lottery', 'reward', 'accept',
  'credit', 'credited', 'crediting', 'won', 'congratulations', 'gift',
  'verify', 'kyc', 'reactivate', 'unlock',
  'रिफंड', 'कैशबैक', 'इनाम', 'पैसे प्राप्त', 'क्रेडिट', 'लॉटरी',
  'கேஷ்பேக்', 'பணம் பெற', 'பரிசு',
  'క్యాష్‌బ్యాక్', 'డబ్బు పొందండి', 'బహుమతి'
];

/**
 * Extracts and audits query parameters from a upi://pay URI according to the NPCI specification.
 *
 * @param {string} upiUriString - Complete upi://pay URI string
 * @param {string} [surroundingText=''] - Optional text context in which the URI was found
 * @returns {{
 *   detected: boolean,
 *   signal: string|null,
 *   score: number,
 *   verdict: 'safe' | 'caution' | 'danger',
 *   payeeVpa: string,
 *   payeeName: string,
 *   debitAmount: number,
 *   isSignedMerchant: boolean,
 *   isUnsignedP2P: boolean,
 *   hasHardcodedDebitAmount: boolean,
 *   hasDeceptiveNoteOrContext: boolean,
 *   hasSuspiciousVpaHandle: boolean,
 *   redFlags: string[],
 *   forensicBreakdown: {
 *     payeeVpa: string,
 *     payeeName: string,
 *     debitAmount: string,
 *     merchantCode: string,
 *     isSignedMerchant: boolean,
 *     redFlags: string[]
 *   }
 * }}
 */
export function analyzeUpiIntentForensics(upiUriString, surroundingText = '') {
  const defaultResult = {
    detected: false,
    signal: null,
    score: 0,
    verdict: 'safe',
    payeeVpa: '',
    payeeName: '',
    debitAmount: 0,
    isSignedMerchant: false,
    isUnsignedP2P: false,
    hasHardcodedDebitAmount: false,
    hasDeceptiveNoteOrContext: false,
    hasSuspiciousVpaHandle: false,
    redFlags: [],
    forensicBreakdown: {
      payeeVpa: '',
      payeeName: '',
      debitAmount: '0',
      merchantCode: '',
      isSignedMerchant: false,
      redFlags: []
    }
  };

  if (!upiUriString || typeof upiUriString !== 'string') {
    return defaultResult;
  }

  // 1. Isolate the upi://pay raw URI
  let rawUri = upiUriString.trim();
  const upiMatch = rawUri.match(/upi:\/\/pay\?[^\s"'<>]+/i);
  if (upiMatch) {
    rawUri = upiMatch[0];
  } else if (!/^upi:\/\/pay\?/i.test(rawUri)) {
    return defaultResult;
  }

  try {
    const qIndex = rawUri.indexOf('?');
    const queryString = rawUri.slice(qIndex + 1);
    const params = new URLSearchParams(queryString);

    const pa = (params.get('pa') || '').trim();
    const pn = (params.get('pn') || '').trim();
    const am = (params.get('am') || '').trim();
    const tn = (params.get('tn') || '').trim();
    const mc = (params.get('mc') || '').trim();
    const sign = (params.get('sign') || '').trim();
    const mode = (params.get('mode') || '').trim();
    const orgid = (params.get('orgid') || '').trim();

    const redFlags = [];

    // 2. Deterministic Forensic Checks
    // Check A: Unsigned P2P
    const isUnsignedP2P = !sign && (!mc || mc === '0000' || mc === '0' || mc.toLowerCase() === 'null');
    if (isUnsignedP2P) {
      redFlags.push('NPCI_UNSIGNED_P2P: URI lacks PSP cryptographic signature (sign) and merchant category code (mc)');
    }

    // Check B: Hardcoded Debit Amount
    const parsedAmount = parseFloat(am);
    const hasHardcodedDebitAmount = !isNaN(parsedAmount) && parsedAmount > 0;
    if (hasHardcodedDebitAmount) {
      redFlags.push(`HARDCODED_DEBIT_AMOUNT: Unsigned URI forces an immediate debit of ₹${am} from the payer`);
    }

    // Check C: Deceptive Note / Context
    const combinedContext = `${surroundingText} ${tn} ${pn}`.toLowerCase();
    const hasDeceptiveNoteOrContext = DECEPTIVE_CONTEXT_KEYWORDS.some(k => combinedContext.includes(k));
    if (hasDeceptiveNoteOrContext) {
      redFlags.push('DECEPTIVE_LURE_MISMATCH: Payer is promised incoming credit/refund, but protocol enforces account deduction');
    }

    // Check D: Suspicious VPA Handle
    let hasSuspiciousVpaHandle = false;
    if (pa && pa.includes('@')) {
      const [localPart, handle] = pa.toLowerCase().split('@');
      const isConsumerPsp = CONSUMER_PSP_HANDLES.includes(handle);
      const isInstitutionalLocal = SUSPICIOUS_VPA_LOCAL_PATTERNS.some(p => localPart.includes(p));

      if (isConsumerPsp && isInstitutionalLocal) {
        hasSuspiciousVpaHandle = true;
        redFlags.push(`IMPERSONATED_VPA_HANDLE: Payee "${pa}" uses an official brand/care keyword on a personal consumer handle (@${handle})`);
      }
    }

    // 3. Verdict Synthesis
    const isSignedMerchant = !isUnsignedP2P && !!sign;
    const isFraudulent = (isUnsignedP2P && hasHardcodedDebitAmount && (hasDeceptiveNoteOrContext || hasSuspiciousVpaHandle)) ||
                         (hasSuspiciousVpaHandle && hasHardcodedDebitAmount);

    return {
      detected: isFraudulent,
      signal: isFraudulent ? 'SIG_NPCI_UNSIGNED_COLLECT_FORENSIC' : null,
      score: isFraudulent ? 90 : 0,
      verdict: isFraudulent ? 'danger' : 'safe',
      payeeVpa: pa,
      payeeName: pn,
      debitAmount: isNaN(parsedAmount) ? 0 : parsedAmount,
      isSignedMerchant,
      isUnsignedP2P,
      hasHardcodedDebitAmount,
      hasDeceptiveNoteOrContext,
      hasSuspiciousVpaHandle,
      redFlags,
      forensicBreakdown: {
        payeeVpa: pa,
        payeeName: pn,
        debitAmount: am || '0',
        merchantCode: mc,
        isSignedMerchant,
        redFlags
      }
    };
  } catch (_) {
    return defaultResult;
  }
}

export default {
  analyzeUpiIntentForensics,
  SUSPICIOUS_VPA_LOCAL_PATTERNS,
  CONSUMER_PSP_HANDLES,
  DECEPTIVE_CONTEXT_KEYWORDS
};
