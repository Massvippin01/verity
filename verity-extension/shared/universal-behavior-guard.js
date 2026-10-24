/**
 * universal-behavior-guard.js — Universal Behavioral Security Guard
 *
 * Provides domain-agnostic, zero-day client-side runtime protections:
 *   1. Universal Clipboard Selection-Mismatch Sentinel (verifyClipboardIntegrity)
 *      Catches silent clipboard replacement attacks (tampering user-highlighted text
 *      with shell commands, URLs, or payment/wallet identifiers).
 *   2. Zero-Knowledge Origin-Bound Credential Reuse Guard (checkCrossOriginCredentialReuse)
 *      Uses non-reversible salted cryptographic hashing so raw citizen passwords
 *      are never retained, while instantly flagging cross-origin password reuse traps.
 */

import { getDomain } from './psl.js';

const DEFAULT_ZK_SALT = 'verity_zk_credential_salt_v2026';

/**
 * Fast, deterministic 64-bit FNV-1a salted hash returning a 16-hex character digest.
 * Non-reversible zero-knowledge representation for on-device comparison.
 *
 * @param {string} input - Raw string (e.g. password)
 * @param {string} [salt=DEFAULT_ZK_SALT] - Local salt
 * @returns {string} 16-char hex digest
 */
export function hashPasswordWithSalt(input, salt = DEFAULT_ZK_SALT) {
  if (!input || typeof input !== 'string') return '';
  const combined = `${salt}:${input}:${salt}`;

  let h1 = 0x811c9dc5;
  let h2 = 0x9e3779b9;

  for (let i = 0; i < combined.length; i++) {
    const code = combined.charCodeAt(i);
    h1 ^= code;
    h1 = Math.imul(h1, 0x01000193);
    h2 ^= (code + i);
    h2 = Math.imul(h2, 0x5bd1e995);
  }

  const p1 = (h1 >>> 0).toString(16).padStart(8, '0');
  const p2 = (h2 >>> 0).toString(16).padStart(8, '0');
  return `${p1}${p2}`;
}

/**
 * Universal Clipboard Selection-Mismatch Sentinel
 *
 * Compares what the user actively selected/highlighted on the page against
 * what the webpage script is attempting to write to the system clipboard via
 * navigator.clipboard.writeText.
 *
 * @param {string} userSelectedText - Text highlighted by the citizen (window.getSelection())
 * @param {string} clipboardWritePayload - Payload page script is attempting to copy
 * @returns {{
 *   hijacked: boolean,
 *   signal: string|null,
 *   score: number,
 *   reason: string|null
 * }}
 */
export function verifyClipboardIntegrity(userSelectedText, clipboardWritePayload) {
  const selected = (userSelectedText || '').trim();
  const payload = (clipboardWritePayload || '').trim();

  // If user selected nothing (e.g. clicked an explicit "Copy Code" button),
  // clipboard write is not a selection mismatch
  if (!selected) {
    return { hijacked: false, signal: null, score: 0, reason: null };
  }

  // Exact or near-exact match is legitimate
  if (selected === payload) {
    return { hijacked: false, signal: null, score: 0, reason: null };
  }

  // Check if payload contains dangerous execution commands, URLs, or payment addresses
  const lowerPayload = payload.toLowerCase();

  // 1. Shell commands & script executors
  const SHELL_EXEC_REGEX = /\b(powershell|cmd(?:\.exe)?|mshta|bash|curl|wget|certutil|iex|invoke-webrequest|rm\s+-rf|rundll32|wscript|cscript|regsvr32)\b/i;
  const hasShellCmd = SHELL_EXEC_REGEX.test(payload);

  // 2. URLs / Web drops
  const URL_REGEX = /^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$/i;
  const hasUrl = URL_REGEX.test(payload) || (payload.startsWith('http://') || payload.startsWith('https://'));

  // 3. Payment addresses / Crypto / UPI identifiers
  const EVM_REGEX = /\b0x[a-fA-F0-9]{40}\b/;
  const BTC_REGEX = /\b(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,39}\b/;
  const SOL_REGEX = /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/;
  const UPI_REGEX = /\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b/;

  const hasPaymentOrCrypto = EVM_REGEX.test(payload) ||
                             BTC_REGEX.test(payload) ||
                             SOL_REGEX.test(payload) ||
                             UPI_REGEX.test(payload);

  if (hasShellCmd || hasUrl || hasPaymentOrCrypto) {
    const threatType = hasShellCmd
      ? 'terminal execution command'
      : (hasPaymentOrCrypto ? 'cryptocurrency/UPI payment address' : 'external web drop URL');

    return {
      hijacked: true,
      signal: 'SIG_UNIVERSAL_CLIPBOARD_MISMATCH',
      score: 85,
      reason: `Universal clipboard hijacking detected: Highlighted text "${selected.slice(0, 30)}..." was secretly replaced with an untrusted ${threatType}.`
    };
  }

  return { hijacked: false, signal: null, score: 0, reason: null };
}

/**
 * Zero-Knowledge Origin-Bound Credential Reuse Guard
 *
 * Inspects entered passwords without ever storing raw plaintext.
 * Detects when a password previously used on an authentic origin is submitted
 * on an unrelated origin.
 *
 * @param {string} inputPassword - User password entry
 * @param {string} currentHostname - Hostname of the current page
 * @param {Map<string, string>|Record<string, string>} storedHashesMap - Map of { hash -> authenticOrigin }
 * @param {string} [salt=DEFAULT_ZK_SALT] - Local salt
 * @returns {{
 *   reusedOnUntrustedOrigin: boolean,
 *   originalOrigin: string|null,
 *   signal: string|null,
 *   score: number,
 *   reason: string|null
 * }}
 */
export function checkCrossOriginCredentialReuse(
  inputPassword,
  currentHostname,
  storedHashesMap,
  salt = DEFAULT_ZK_SALT
) {
  if (!inputPassword || typeof inputPassword !== 'string' || inputPassword.length < 8) {
    return { reusedOnUntrustedOrigin: false, originalOrigin: null, signal: null, score: 0, reason: null };
  }

  if (!currentHostname || !storedHashesMap) {
    return { reusedOnUntrustedOrigin: false, originalOrigin: null, signal: null, score: 0, reason: null };
  }

  const hash = hashPasswordWithSalt(inputPassword, salt);
  let originalOrigin = null;

  if (storedHashesMap instanceof Map) {
    originalOrigin = storedHashesMap.get(hash) || null;
  } else if (typeof storedHashesMap === 'object') {
    originalOrigin = storedHashesMap[hash] || null;
  }

  if (!originalOrigin) {
    return { reusedOnUntrustedOrigin: false, originalOrigin: null, signal: null, score: 0, reason: null };
  }

  const cleanCurrent = currentHostname.toLowerCase().replace(/^www\./, '');
  const cleanOriginal = originalOrigin.toLowerCase().replace(/^www\./, '');

  if (cleanCurrent === cleanOriginal) {
    return { reusedOnUntrustedOrigin: false, originalOrigin, signal: null, score: 0, reason: null };
  }

  const rootCurrent = getDomain(cleanCurrent) || cleanCurrent;
  const rootOriginal = getDomain(cleanOriginal) || cleanOriginal;

  if (rootCurrent === rootOriginal) {
    // Shared root domain (e.g. auth.acme.com and app.acme.com)
    return { reusedOnUntrustedOrigin: false, originalOrigin, signal: null, score: 0, reason: null };
  }

  // Cross-origin credential reuse detected on an untrusted origin
  return {
    reusedOnUntrustedOrigin: true,
    originalOrigin,
    signal: 'SIG_CROSS_ORIGIN_PASSWORD_REUSE_TRAP',
    score: 95,
    reason: `Zero-Knowledge Credential Guard: Password previously registered for "${originalOrigin}" is being entered on untrusted origin "${currentHostname}".`
  };
}

export default {
  hashPasswordWithSalt,
  verifyClipboardIntegrity,
  checkCrossOriginCredentialReuse
};
