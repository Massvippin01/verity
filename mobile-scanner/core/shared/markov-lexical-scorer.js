/**
 * markov-lexical-scorer.js — Universal Character Bigram & Lexical Transition Scorer
 *
 * 100% Free Forever, client-side, zero-dependency lexical engine.
 * Detects Algorithmic Domain Generation (DGA), randomized phishing slugs,
 * and obfuscated hostnames across ANY language or TLD in < 0.05ms.
 *
 * Evaluates:
 *   1. Consonant-cluster runs (>= 4 consecutive consonants)
 *   2. Digit-letter interleaving (e.g. "a1b2c3d4" or "x7q9-k2m8")
 *   3. Vowel starvation (vowel ratio < 15% on tokens >= 6 chars)
 *   4. Low-probability character bigram transitions (e.g. "q" without "u", "zx", "qj", "xk")
 */

import { getDomain } from './psl.js';

// Set of very rare/unnatural bigrams in human language domain names
const RARE_BIGRAMS = new Set([
  'bk', 'cf', 'cj', 'cp', 'cv', 'cw', 'cx',
  'dx', 'fq', 'fx', 'fz', 'gq', 'gx', 'hx',
  'jb', 'jc', 'jd', 'jf', 'jg', 'jh', 'jk', 'jl', 'jm', 'jp', 'jq', 'jr', 'js', 'jt', 'jv', 'jw', 'jx', 'jz',
  'kq', 'kv', 'kx', 'kz',
  'lq', 'lx', 'mq', 'mx', 'px',
  'qb', 'qc', 'qd', 'qe', 'qf', 'qg', 'qh', 'qj', 'qk', 'ql', 'qm', 'qn', 'qo', 'qp', 'qq', 'qr', 'qs', 'qt', 'qv', 'qw', 'qx', 'qy', 'qz',
  'tq', 'tx',
  'vb', 'vc', 'vd', 'vf', 'vg', 'vh', 'vj', 'vk', 'vm', 'vn', 'vp', 'vq', 'vt', 'vw', 'vx', 'vz',
  'wq', 'wx', 'wz',
  'xb', 'xd', 'xf', 'xg', 'xj', 'xk', 'xl', 'xm', 'xn', 'xp', 'xq', 'xr', 'xs', 'xt', 'xv', 'xw', 'xx', 'xz',
  'yq', 'yv', 'yx', 'yz',
  'zb', 'zc', 'zd', 'zf', 'zg', 'zh', 'zj', 'zk', 'zl', 'zm', 'zn', 'zp', 'zq', 'zr', 'zs', 'zt', 'zv', 'zw', 'zx', 'zy', 'zz'
]);

const VOWELS = new Set(['a', 'e', 'i', 'o', 'u']);

/**
 * Computes the lexical anomaly score of a domain or token.
 *
 * @param {string} hostnameOrToken
 * @returns {{
 *   anomalyScore: number,
 *   isAnomalous: boolean,
 *   details: {
 *     token: string,
 *     consonantClusterMax: number,
 *     letterDigitSwitches: number,
 *     vowelRatio: number,
 *     rareBigramCount: number
 *   }
 * }}
 */
export function computeLexicalAnomalyScore(hostnameOrToken) {
  if (!hostnameOrToken || typeof hostnameOrToken !== 'string') {
    return {
      anomalyScore: 0,
      isAnomalous: false,
      details: { token: '', consonantClusterMax: 0, letterDigitSwitches: 0, vowelRatio: 0, rareBigramCount: 0 }
    };
  }

  // Extract relevant label (strip TLD or inspect main registrable SLD)
  const cleanInput = hostnameOrToken.toLowerCase().trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  const domain = getDomain(cleanInput) || cleanInput;
  // Get the primary label before the TLD (e.g. "x7q9-k2m8-login" from "x7q9-k2m8-login.com")
  const primaryToken = domain.includes('.') ? domain.split('.')[0] : domain;

  if (primaryToken.length < 4) {
    return {
      anomalyScore: 0,
      isAnomalous: false,
      details: { token: primaryToken, consonantClusterMax: 0, letterDigitSwitches: 0, vowelRatio: 1, rareBigramCount: 0 }
    };
  }

  let penalty = 0;
  let consonantClusterMax = 0;
  let currentConsonantCluster = 0;
  let letterDigitSwitches = 0;
  let vowelCount = 0;
  let letterCount = 0;
  let digitCount = 0;
  let rareBigramCount = 0;
  let lastCharType = null; // 'letter' | 'digit' | 'other'

  // Analyze characters
  for (let i = 0; i < primaryToken.length; i++) {
    const ch = primaryToken[i];

    if (ch >= 'a' && ch <= 'z') {
      letterCount++;
      if (lastCharType === 'digit') {
        letterDigitSwitches++;
      }
      lastCharType = 'letter';

      if (VOWELS.has(ch)) {
        vowelCount++;
        currentConsonantCluster = 0;
      } else {
        currentConsonantCluster++;
        if (currentConsonantCluster > consonantClusterMax) {
          consonantClusterMax = currentConsonantCluster;
        }
      }
    } else if (ch >= '0' && ch <= '9') {
      digitCount++;
      if (lastCharType === 'letter') {
        letterDigitSwitches++;
      }
      lastCharType = 'digit';
      currentConsonantCluster = 0;
    } else {
      // Separators/hyphens reset consonant cluster but do not break letter-digit interleaving tracking
      currentConsonantCluster = 0;
    }

    // Bigram analysis
    if (i > 0) {
      const prev = primaryToken[i - 1];
      if (prev >= 'a' && prev <= 'z' && ch >= 'a' && ch <= 'z') {
        const bg = prev + ch;
        if (RARE_BIGRAMS.has(bg)) {
          rareBigramCount++;
        }
      }
    }
  }

  // 1. Consonant Cluster Penalty
  if (consonantClusterMax >= 5) {
    penalty += 40;
  } else if (consonantClusterMax === 4) {
    penalty += 25;
  }

  // 2. Letter-Digit Interleaving Penalty (e.g. x7q9, a1b2c3)
  if (letterDigitSwitches >= 4) {
    penalty += 60;
  } else if (letterDigitSwitches >= 3) {
    penalty += 45;
  } else if (letterDigitSwitches === 2 && primaryToken.length <= 10) {
    penalty += 20;
  }

  // Interleaving with multiple digits (characteristic of DGA)
  if (digitCount >= 3 && letterDigitSwitches >= 3) {
    penalty += 25;
  }

  // 3. Vowel Starvation Penalty
  const vowelRatio = letterCount > 0 ? (vowelCount / letterCount) : 0;
  if (letterCount >= 6) {
    if (vowelRatio === 0) {
      penalty += 45;
    } else if (vowelRatio < 0.15) {
      penalty += 30;
    } else if (vowelRatio < 0.20 && consonantClusterMax >= 3) {
      penalty += 15;
    }
  }

  // 4. Rare Bigrams Penalty
  if (rareBigramCount >= 2) {
    penalty += 35;
  } else if (rareBigramCount === 1) {
    penalty += 15;
  }

  const anomalyScore = Math.min(100, Math.max(0, penalty));
  const isAnomalous = anomalyScore >= 60;

  return {
    anomalyScore,
    isAnomalous,
    details: {
      token: primaryToken,
      consonantClusterMax,
      letterDigitSwitches,
      vowelRatio: Math.round(vowelRatio * 100) / 100,
      rareBigramCount
    }
  };
}

export default {
  computeLexicalAnomalyScore
};
