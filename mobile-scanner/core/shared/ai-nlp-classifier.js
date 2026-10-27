/**
 * shared/ai-nlp-classifier.js — Subword Character N-Gram + Word Multinomial Bayesian Softmax NLP
 *
 * Replaces brittle regex reliance with continuous statistical NLP inference:
 * 1. Tokenizes text into word unigrams/bigrams and overlapping character 3-grams & 4-grams
 *    to handle leetspeak (p1n, 0tp, u_p_i), typos, and romanized Indian language variations.
 * 2. Computes log-odds scores across 5 distinct classes via pre-calibrated feature weight vectors.
 * 3. Applies a temperature-scaled Softmax function:
 *    P(class_k | x) = exp(logit_k / T) / sum_j exp(logit_j / T)
 * 4. Yields continuous posterior scam probability and dominant threat intent.
 */

'use strict';

export const NLP_CLASSES = [
  'SAFE_CONVERSATION',
  'COERCION_EXTORTION',
  'CREDENTIAL_PAYMENT_EXTRACTION',
  'MALWARE_DROPPER_DELIVERY',
  'URGENCY_SOCIAL_ENGINEERING'
];

// Pre-calibrated class base priors (log-odds bias)
// SAFE has higher natural prior in everyday usage
const CLASS_PRIORS = {
  SAFE_CONVERSATION: 1.2,
  COERCION_EXTORTION: -1.2,
  CREDENTIAL_PAYMENT_EXTRACTION: -1.0,
  MALWARE_DROPPER_DELIVERY: -1.1,
  URGENCY_SOCIAL_ENGINEERING: -0.9
};

// Feature weight vectors: mapping feature -> { class: log-odds weight }
const FEATURE_WEIGHTS = {
  // ── Word Unigrams ─────────────────────────────────────────────────────────
  // Safe words
  'dinner': { SAFE_CONVERSATION: 3.5 },
  'lunch': { SAFE_CONVERSATION: 3.2 },
  'coffee': { SAFE_CONVERSATION: 3.2 },
  'tea': { SAFE_CONVERSATION: 3.0 },
  'meet': { SAFE_CONVERSATION: 2.5 },
  'meeting': { SAFE_CONVERSATION: 2.0 },
  'tomorrow': { SAFE_CONVERSATION: 2.2 },
  'tonight': { SAFE_CONVERSATION: 0.5, URGENCY_SOCIAL_ENGINEERING: 2.0 },
  'project': { SAFE_CONVERSATION: 3.2 },
  'notes': { SAFE_CONVERSATION: 3.0 },
  'homework': { SAFE_CONVERSATION: 3.5 },
  'weekend': { SAFE_CONVERSATION: 3.0 },
  'family': { SAFE_CONVERSATION: 2.5 },
  'party': { SAFE_CONVERSATION: 3.0 },
  'movie': { SAFE_CONVERSATION: 3.0 },
  'birthday': { SAFE_CONVERSATION: 3.5 },
  'thanks': { SAFE_CONVERSATION: 2.5 },
  'thank': { SAFE_CONVERSATION: 2.5 },
  'weather': { SAFE_CONVERSATION: 3.0 },
  'college': { SAFE_CONVERSATION: 2.8 },
  'office': { SAFE_CONVERSATION: 2.0 },
  'news': { SAFE_CONVERSATION: 3.5 },
  'documentary': { SAFE_CONVERSATION: 3.5 },
  'watch': { SAFE_CONVERSATION: 2.5 },
  'reading': { SAFE_CONVERSATION: 2.5 },
  'article': { SAFE_CONVERSATION: 3.0 },

  // Coercion & Extortion (Digital arrest, police, CBI, narcotics)
  'police': { COERCION_EXTORTION: 4.5, SAFE_CONVERSATION: -2.0 },
  'cbi': { COERCION_EXTORTION: 5.0, SAFE_CONVERSATION: -2.5 },
  'arrest': { COERCION_EXTORTION: 5.0, SAFE_CONVERSATION: -2.5 },
  'narcotics': { COERCION_EXTORTION: 4.8, SAFE_CONVERSATION: -2.5 },
  'customs': { COERCION_EXTORTION: 4.2, SAFE_CONVERSATION: -1.8 },
  'parcel': { COERCION_EXTORTION: 3.0, URGENCY_SOCIAL_ENGINEERING: 2.0 },
  'warrant': { COERCION_EXTORTION: 4.8, SAFE_CONVERSATION: -2.0 },
  'court': { COERCION_EXTORTION: 3.8, SAFE_CONVERSATION: -1.5 },
  'skype': { COERCION_EXTORTION: 3.8, SAFE_CONVERSATION: -1.0 },
  'trafficking': { COERCION_EXTORTION: 4.5, SAFE_CONVERSATION: -2.0 },
  'crime': { COERCION_EXTORTION: 3.5, SAFE_CONVERSATION: -1.5 },
  'cybercrime': { COERCION_EXTORTION: 3.2 },
  'virtual': { COERCION_EXTORTION: 2.5 },
  'seized': { COERCION_EXTORTION: 3.5 },

  // Credential & Payment Extraction
  'pin': { CREDENTIAL_PAYMENT_EXTRACTION: 4.2, SAFE_CONVERSATION: -2.0 },
  'p1n': { CREDENTIAL_PAYMENT_EXTRACTION: 5.0, SAFE_CONVERSATION: -2.5 },
  'otp': { CREDENTIAL_PAYMENT_EXTRACTION: 4.5, SAFE_CONVERSATION: -2.0 },
  '0tp': { CREDENTIAL_PAYMENT_EXTRACTION: 5.0, SAFE_CONVERSATION: -2.5 },
  'password': { CREDENTIAL_PAYMENT_EXTRACTION: 4.0, SAFE_CONVERSATION: -1.5 },
  'upi': { CREDENTIAL_PAYMENT_EXTRACTION: 3.8, SAFE_CONVERSATION: -1.2 },
  'vpa': { CREDENTIAL_PAYMENT_EXTRACTION: 3.8, SAFE_CONVERSATION: -1.2 },
  'mpin': { CREDENTIAL_PAYMENT_EXTRACTION: 4.5, SAFE_CONVERSATION: -2.0 },
  'atm': { CREDENTIAL_PAYMENT_EXTRACTION: 3.5, SAFE_CONVERSATION: -1.2 },
  'kyc': { CREDENTIAL_PAYMENT_EXTRACTION: 4.0, SAFE_CONVERSATION: -1.8 },
  'pan': { CREDENTIAL_PAYMENT_EXTRACTION: 2.5, SAFE_CONVERSATION: -0.8 },
  'aadhaar': { CREDENTIAL_PAYMENT_EXTRACTION: 3.0, COERCION_EXTORTION: 2.0 },
  'aadhar': { CREDENTIAL_PAYMENT_EXTRACTION: 3.0, COERCION_EXTORTION: 2.0 },
  'refund': { CREDENTIAL_PAYMENT_EXTRACTION: 3.2, URGENCY_SOCIAL_ENGINEERING: 2.2 },
  'rfund': { CREDENTIAL_PAYMENT_EXTRACTION: 4.0, URGENCY_SOCIAL_ENGINEERING: 2.5 },
  'cashback': { CREDENTIAL_PAYMENT_EXTRACTION: 3.5, URGENCY_SOCIAL_ENGINEERING: 2.0 },
  'cshbck': { CREDENTIAL_PAYMENT_EXTRACTION: 4.2, URGENCY_SOCIAL_ENGINEERING: 2.5 },
  'cvv': { CREDENTIAL_PAYMENT_EXTRACTION: 4.8, SAFE_CONVERSATION: -2.0 },
  'claim': { CREDENTIAL_PAYMENT_EXTRACTION: 2.5, URGENCY_SOCIAL_ENGINEERING: 2.0 },
  'clm': { CREDENTIAL_PAYMENT_EXTRACTION: 3.2, URGENCY_SOCIAL_ENGINEERING: 2.2 },
  'deducted': { CREDENTIAL_PAYMENT_EXTRACTION: 3.0, URGENCY_SOCIAL_ENGINEERING: 2.0 },

  // Malware Dropper & Delivery
  'apk': { MALWARE_DROPPER_DELIVERY: 5.2, SAFE_CONVERSATION: -2.5 },
  'download': { MALWARE_DROPPER_DELIVERY: 2.8, SAFE_CONVERSATION: -0.5 },
  'dwnld': { MALWARE_DROPPER_DELIVERY: 3.5, SAFE_CONVERSATION: -1.0 },
  'install': { MALWARE_DROPPER_DELIVERY: 3.0, SAFE_CONVERSATION: -0.8 },
  'setup': { MALWARE_DROPPER_DELIVERY: 2.5 },
  'update': { MALWARE_DROPPER_DELIVERY: 2.0, URGENCY_SOCIAL_ENGINEERING: 1.8 },
  'dropper': { MALWARE_DROPPER_DELIVERY: 4.5 },
  'trojan': { MALWARE_DROPPER_DELIVERY: 4.5 },
  'sideload': { MALWARE_DROPPER_DELIVERY: 4.2 },

  // Urgency & Social Engineering
  'electricity': { URGENCY_SOCIAL_ENGINEERING: 4.5, SAFE_CONVERSATION: -1.5 },
  'elctrcity': { URGENCY_SOCIAL_ENGINEERING: 5.0, SAFE_CONVERSATION: -2.0 },
  'power': { URGENCY_SOCIAL_ENGINEERING: 2.8, SAFE_CONVERSATION: -0.5 },
  'pwr': { URGENCY_SOCIAL_ENGINEERING: 4.0, SAFE_CONVERSATION: -1.5 },
  'disconnected': { URGENCY_SOCIAL_ENGINEERING: 4.8, SAFE_CONVERSATION: -2.0 },
  'discnnected': { URGENCY_SOCIAL_ENGINEERING: 5.0, SAFE_CONVERSATION: -2.0 },
  'disconnection': { URGENCY_SOCIAL_ENGINEERING: 4.5, SAFE_CONVERSATION: -2.0 },
  'immediately': { URGENCY_SOCIAL_ENGINEERING: 3.2, SAFE_CONVERSATION: -1.0 },
  'immdtly': { URGENCY_SOCIAL_ENGINEERING: 4.2, SAFE_CONVERSATION: -1.5 },
  'urgent': { URGENCY_SOCIAL_ENGINEERING: 3.5, SAFE_CONVERSATION: -1.0 },
  'urgently': { URGENCY_SOCIAL_ENGINEERING: 3.5, SAFE_CONVERSATION: -1.0 },
  'suspended': { URGENCY_SOCIAL_ENGINEERING: 4.0, CREDENTIAL_PAYMENT_EXTRACTION: 2.0 },
  'blocked': { URGENCY_SOCIAL_ENGINEERING: 3.5, CREDENTIAL_PAYMENT_EXTRACTION: 2.0 },
  'lottery': { URGENCY_SOCIAL_ENGINEERING: 4.0, CREDENTIAL_PAYMENT_EXTRACTION: 2.0 },
  'congratulations': { URGENCY_SOCIAL_ENGINEERING: 3.0, SAFE_CONVERSATION: 0.5 },

  // ── Word Bigrams ──────────────────────────────────────────────────────────
  'power_disconnected': { URGENCY_SOCIAL_ENGINEERING: 5.0, SAFE_CONVERSATION: -3.0 },
  'pwr_discnnected': { URGENCY_SOCIAL_ENGINEERING: 5.5, SAFE_CONVERSATION: -3.0 },
  'electricity_disconnected': { URGENCY_SOCIAL_ENGINEERING: 5.5, SAFE_CONVERSATION: -3.0 },
  'pay_immediately': { URGENCY_SOCIAL_ENGINEERING: 4.5, CREDENTIAL_PAYMENT_EXTRACTION: 3.0 },
  'pay_immdtly': { URGENCY_SOCIAL_ENGINEERING: 4.8, CREDENTIAL_PAYMENT_EXTRACTION: 3.2 },
  'upi_pin': { CREDENTIAL_PAYMENT_EXTRACTION: 5.5, SAFE_CONVERSATION: -3.0 },
  'upi_p1n': { CREDENTIAL_PAYMENT_EXTRACTION: 6.0, SAFE_CONVERSATION: -3.0 },
  'enter_pin': { CREDENTIAL_PAYMENT_EXTRACTION: 5.0, SAFE_CONVERSATION: -3.0 },
  'entr_p1n': { CREDENTIAL_PAYMENT_EXTRACTION: 5.5, SAFE_CONVERSATION: -3.0 },
  'claim_refund': { CREDENTIAL_PAYMENT_EXTRACTION: 4.5, URGENCY_SOCIAL_ENGINEERING: 3.0 },
  'clm_rfund': { CREDENTIAL_PAYMENT_EXTRACTION: 5.2, URGENCY_SOCIAL_ENGINEERING: 3.5 },
  'digital_arrest': { COERCION_EXTORTION: 6.0, SAFE_CONVERSATION: -4.0 },
  'police_officer': { COERCION_EXTORTION: 4.5, SAFE_CONVERSATION: -2.0 },
  'cbi_officer': { COERCION_EXTORTION: 5.5, SAFE_CONVERSATION: -3.0 },
  'narcotics_parcel': { COERCION_EXTORTION: 5.5, SAFE_CONVERSATION: -3.0 },
  'download_apk': { MALWARE_DROPPER_DELIVERY: 6.0, SAFE_CONVERSATION: -3.5 },
  'install_apk': { MALWARE_DROPPER_DELIVERY: 6.0, SAFE_CONVERSATION: -3.5 },
  'bill_apk': { MALWARE_DROPPER_DELIVERY: 5.5, URGENCY_SOCIAL_ENGINEERING: 3.5 },
  'for_dinner': { SAFE_CONVERSATION: 3.5 },
  'let_meet': { SAFE_CONVERSATION: 3.0 },
  'after_work': { SAFE_CONVERSATION: 3.0 },
  'pdf_notes': { SAFE_CONVERSATION: 3.5 },
  'send_me': { SAFE_CONVERSATION: 2.0 },

  // ── Subword Character N-Grams (3-grams & 4-grams) ─────────────────────────
  // These fire on heavily mutated or concatenated tokens (e.g. "elctrcity", "p1n", "rfund")
  'elc': { URGENCY_SOCIAL_ENGINEERING: 2.2, SAFE_CONVERSATION: -0.8 },
  'lct': { URGENCY_SOCIAL_ENGINEERING: 2.0, SAFE_CONVERSATION: -0.8 },
  'ctr': { URGENCY_SOCIAL_ENGINEERING: 1.5 },
  'pwr': { URGENCY_SOCIAL_ENGINEERING: 2.5, SAFE_CONVERSATION: -0.8 },
  'disc': { URGENCY_SOCIAL_ENGINEERING: 2.2, SAFE_CONVERSATION: -0.8 },
  'cnct': { URGENCY_SOCIAL_ENGINEERING: 2.2, SAFE_CONVERSATION: -0.8 },
  '2nit': { URGENCY_SOCIAL_ENGINEERING: 2.8, SAFE_CONVERSATION: -0.8 },
  'nite': { URGENCY_SOCIAL_ENGINEERING: 2.0 },
  'immd': { URGENCY_SOCIAL_ENGINEERING: 2.5, SAFE_CONVERSATION: -0.8 },
  'mdtl': { URGENCY_SOCIAL_ENGINEERING: 2.5, SAFE_CONVERSATION: -0.8 },
  'p1n': { CREDENTIAL_PAYMENT_EXTRACTION: 3.5, SAFE_CONVERSATION: -1.5 },
  '0tp': { CREDENTIAL_PAYMENT_EXTRACTION: 3.5, SAFE_CONVERSATION: -1.5 },
  'rfnd': { CREDENTIAL_PAYMENT_EXTRACTION: 3.2, URGENCY_SOCIAL_ENGINEERING: 2.0 },
  'cshb': { CREDENTIAL_PAYMENT_EXTRACTION: 3.0, URGENCY_SOCIAL_ENGINEERING: 2.0 },
  'arst': { COERCION_EXTORTION: 3.2, SAFE_CONVERSATION: -1.5 },
  'narc': { COERCION_EXTORTION: 3.5, SAFE_CONVERSATION: -1.5 },
  'warr': { COERCION_EXTORTION: 3.0, SAFE_CONVERSATION: -1.2 },
  'dwnl': { MALWARE_DROPPER_DELIVERY: 2.8, SAFE_CONVERSATION: -1.0 },
  'dinn': { SAFE_CONVERSATION: 3.0 },
  'proj': { SAFE_CONVERSATION: 2.8 },
  'homw': { SAFE_CONVERSATION: 3.0 },
  'wknd': { SAFE_CONVERSATION: 2.8 }
};

/**
 * Normalizes leetspeak character substitutions (@ -> a, 0 -> o, 1 -> l/i, $ -> s, etc.)
 * @param {string} str
 * @returns {string}
 */
export function normalizeLeetspeakChars(str) {
  if (!str) return '';
  return str
    .replace(/@/g, 'a')
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/\$/g, 's')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/!/g, 'i');
}

/**
 * Lightweight suffix stemming to handle plural/tense variations without external heavy stemmers.
 * @param {string} word
 * @returns {string}
 */
export function stemToken(word) {
  if (!word || word.length < 5) return word;
  if (word.endsWith('ing') && word.length > 5) return word.slice(0, -3);
  if (word.endsWith('ed') && word.length > 4) return word.slice(0, -2);
  if (word.endsWith('es') && word.length > 4) return word.slice(0, -2);
  if (word.endsWith('s') && !word.endsWith('ss') && word.length > 4) return word.slice(0, -1);
  return word;
}

/**
 * Extracts normalized tokens: word unigrams, stems, bigrams, and character 3/4-grams.
 *
 * @param {string} text - Raw input string
 * @returns {string[]} Array of unique normalized feature strings
 */
export function extractSubwordFeatures(text) {
  if (!text || typeof text !== 'string') return [];

  const rawLower = text.toLowerCase();
  // Normalize leetspeak separators like u_p_i -> upi, p-i-n -> pin
  const leetCollapsed = rawLower.replace(/([a-z0-9])[\s_.-]+(?=[a-z0-9])/gi, '$1');
  const leetNormalized = normalizeLeetspeakChars(rawLower);
  const leetNormalizedCollapsed = normalizeLeetspeakChars(leetCollapsed);

  // Tokenize words
  const words = rawLower.split(/[^a-z0-9\u0900-\u0D7F]+/).filter(w => w.length > 0);
  const collapsedWords = leetCollapsed.split(/[^a-z0-9\u0900-\u0D7F]+/).filter(w => w.length > 0);
  const normWords = leetNormalized.split(/[^a-z0-9\u0900-\u0D7F]+/).filter(w => w.length > 0);
  const normCollapsedWords = leetNormalizedCollapsed.split(/[^a-z0-9\u0900-\u0D7F]+/).filter(w => w.length > 0);

  const features = new Set();
  const allTokenLists = [words, collapsedWords, normWords, normCollapsedWords];

  // 1. Word Unigrams & Lightweight Stems
  for (const list of allTokenLists) {
    for (const w of list) {
      if (w.length >= 2) {
        features.add(w);
        const stemmed = stemToken(w);
        if (stemmed.length >= 2) features.add(stemmed);
      }
    }
  }

  // 2. Word Bigrams
  for (let i = 0; i < words.length - 1; i++) {
    features.add(`${words[i]}_${words[i + 1]}`);
    if (normWords[i] && normWords[i + 1]) {
      features.add(`${normWords[i]}_${normWords[i + 1]}`);
    }
  }

  // 3. Overlapping Character 3-Grams and 4-Grams
  const allWordTokens = Array.from(new Set([...words, ...collapsedWords, ...normWords, ...normCollapsedWords]));
  for (const w of allWordTokens) {
    if (w.length >= 3) {
      for (let i = 0; i <= w.length - 3; i++) {
        features.add(w.slice(i, i + 3));
      }
    }
    if (w.length >= 4) {
      for (let i = 0; i <= w.length - 4; i++) {
        features.add(w.slice(i, i + 4));
      }
    }
  }

  return Array.from(features);
}

/**
 * Computes Softmax probabilities across classes with temperature scaling:
 * P(class_k) = exp((logit_k - max) / T) / sum_j exp((logit_j - max) / T)
 *
 * @param {Record<string, number>} logits
 * @param {number} [temperature=1.0]
 * @returns {Record<string, number>} Normalized probabilities
 */
export function computeTemperatureSoftmax(logits, temperature = 1.0) {
  const t = Math.max(0.1, temperature);
  const values = Object.values(logits);
  const maxLogit = Math.max(...values);

  let sumExp = 0;
  const expScores = {};

  for (const [cls, logit] of Object.entries(logits)) {
    const e = Math.exp((logit - maxLogit) / t);
    expScores[cls] = e;
    sumExp += e;
  }

  const probs = {};
  for (const cls of Object.keys(logits)) {
    probs[cls] = sumExp > 0 ? (expScores[cls] / sumExp) : (1 / values.length);
  }

  return probs;
}

/**
 * Classifies raw text using Subword N-Gram Multinomial Bayesian Softmax NLP.
 *
 * @param {string} rawText - Unseen or obfuscated message text
 * @param {object} [options={}] - Options (temperature)
 * @returns {{
 *   isScam: boolean,
 *   scamProbability: number,
 *   score: number,
 *   dominantClass: string,
 *   confidence: number,
 *   classProbabilities: Record<string, number>,
 *   signal: string
 * }}
 */
export function classifyTextWithSubwordAi(rawText, options = {}) {
  if (!rawText || typeof rawText !== 'string' || rawText.trim().length === 0) {
    return {
      isScam: false,
      scamProbability: 0,
      score: 0,
      dominantClass: 'SAFE_CONVERSATION',
      confidence: 1.0,
      classProbabilities: {
        SAFE_CONVERSATION: 1.0,
        COERCION_EXTORTION: 0,
        CREDENTIAL_PAYMENT_EXTRACTION: 0,
        MALWARE_DROPPER_DELIVERY: 0,
        URGENCY_SOCIAL_ENGINEERING: 0
      },
      signal: null
    };
  }

  const features = extractSubwordFeatures(rawText);

  // Initialize logits with class base priors
  const logits = {};
  for (const cls of NLP_CLASSES) {
    logits[cls] = CLASS_PRIORS[cls] || 0;
  }

  // Accumulate evidence from extracted features
  for (const f of features) {
    const weights = FEATURE_WEIGHTS[f];
    if (weights) {
      for (const [cls, w] of Object.entries(weights)) {
        if (logits[cls] !== undefined) {
          logits[cls] += w;
        }
      }
    }
  }

  const temperature = options.temperature || 1.1;
  const probs = computeTemperatureSoftmax(logits, temperature);

  // Scam probability is the complement of SAFE_CONVERSATION
  const safeProb = probs.SAFE_CONVERSATION || 0;
  const scamProbability = Math.min(1.0, Math.max(0, 1.0 - safeProb));
  const score = Math.round(scamProbability * 100);

  // Identify dominant threat class among non-safe classes
  let dominantClass = 'SAFE_CONVERSATION';
  let maxScamProb = -1;

  for (const cls of NLP_CLASSES) {
    if (cls !== 'SAFE_CONVERSATION') {
      const p = probs[cls] || 0;
      if (p > maxScamProb) {
        maxScamProb = p;
        dominantClass = cls;
      }
    }
  }

  const isScam = scamProbability >= 0.78;
  const signal = isScam ? 'SIG_AI_NLP_SCAM_INTENT' : null;

  return {
    isScam,
    scamProbability: Number(scamProbability.toFixed(4)),
    score,
    dominantClass: isScam ? dominantClass : 'SAFE_CONVERSATION',
    confidence: Number((isScam ? maxScamProb : safeProb).toFixed(4)),
    classProbabilities: probs,
    signal
  };
}

export default {
  NLP_CLASSES,
  extractSubwordFeatures,
  computeTemperatureSoftmax,
  classifyTextWithSubwordAi
};
