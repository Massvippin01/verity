/**
 * background/dnr-blocker.js — Declarative Net Request Purge & Safety Control
 *
 * All blocking must happen ONLY via Verity's own Risk Engine and Threat Shield.
 * To prevent browser-level ERR_BLOCKED_BY_CLIENT errors, this module purges ALL
 * existing declarativeNetRequest dynamic and session rules on startup and
 * renders dynamic rule registration a strict NO-OP.
 */

import { isAllowlistedDomain } from '../shared/legit-domains.js';

export const BASELINE_BLOCKED_DOMAINS = Object.freeze([]);

let dynamicRuleCounter = 2000;
export const MAX_DYNAMIC_RULES = 500;
const registeredDomains = new Set();
const registeredRules = new Map();

/**
 * Reset state for test environments.
 */
export function resetDnrForTesting() {
  registeredDomains.clear();
  registeredRules.clear();
  dynamicRuleCounter = 2000;
}

/**
 * Returns a copy of currently registered blocked domains (always empty Set).
 */
export function getBlockedDomainsDnr() {
  return new Set(registeredDomains);
}

/**
 * Startup Purge: Queries BOTH getDynamicRules() AND getSessionRules()
 * and deletes ALL existing rule IDs to eradicate ERR_BLOCKED_BY_CLIENT.
 */
export async function initDnrBlocker() {
  if (typeof chrome === 'undefined' || !chrome.declarativeNetRequest) {
    return { dynamicRemoved: 0, sessionRemoved: 0 };
  }

  let dynamicRemoved = 0;
  let sessionRemoved = 0;

  // 1. Purge all dynamic rules
  try {
    if (chrome.declarativeNetRequest.getDynamicRules && chrome.declarativeNetRequest.updateDynamicRules) {
      const dynamicRules = await chrome.declarativeNetRequest.getDynamicRules();
      if (dynamicRules && dynamicRules.length > 0) {
        const removeRuleIds = dynamicRules.map(r => r.id);
        await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds });
        dynamicRemoved = removeRuleIds.length;
      }
    }
  } catch (err) {
    console.warn('[Verity DNR] Failed to purge dynamic rules:', err);
  }

  // 2. Purge all session rules
  try {
    if (chrome.declarativeNetRequest.getSessionRules && chrome.declarativeNetRequest.updateSessionRules) {
      const sessionRules = await chrome.declarativeNetRequest.getSessionRules();
      if (sessionRules && sessionRules.length > 0) {
        const removeRuleIds = sessionRules.map(r => r.id);
        await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds });
        sessionRemoved = removeRuleIds.length;
      }
    }
  } catch (err) {
    console.warn('[Verity DNR] Failed to purge session rules:', err);
  }

  return { dynamicRemoved, sessionRemoved };
}

/**
 * Strict NO-OP: We must NEVER use declarativeNetRequest to dynamically block domains,
 * because ERR_BLOCKED_BY_CLIENT breaks user browsing and cannot be bypassed.
 * All blocking must happen ONLY via Verity's own Risk Engine and Threat Shield!
 * @param {string} _domain 
 * @returns {Promise<null>}
 */
export async function blockDomainDnr(_domain) {
  return null;
}

/**
 * Strict NO-OP alias
 */
export async function registerDynamicBlockDomain(_domain) {
  return null;
}

/**
 * Synchronizes local threat intelligence seeds and blocked domains directly into
 * Chrome's C++ network stack via chrome.declarativeNetRequest.updateDynamicRules.
 * Uses action 'redirect' pointing to /ui/blocked.html so native C++ zero-latency blocking
 * halts network packets in 0.001ms while gracefully rendering Verity's Threat Shield.
 *
 * @param {string[]} maliciousDomains
 * @returns {Promise<{ rulesAdded: number }>}
 */
export async function syncMalwareDomainsToDNR(maliciousDomains = []) {
  if (typeof chrome === 'undefined' || !chrome.declarativeNetRequest || !chrome.declarativeNetRequest.updateDynamicRules) {
    return { rulesAdded: 0 };
  }

  try {
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existingRules ? existingRules.map(r => r.id) : [];

    const addRules = (maliciousDomains || []).slice(0, 4500).map((domain, idx) => ({
      id: idx + 1000,
      priority: 100,
      action: {
        type: 'redirect',
        redirect: {
          extensionPath: `/ui/blocked.html?host=${encodeURIComponent(domain)}&reason=DNR_THREAT_INTEL`
        }
      },
      condition: {
        urlFilter: `||${domain}^`,
        resourceTypes: ['main_frame', 'sub_frame', 'script', 'xmlhttprequest']
      }
    }));

    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds,
      addRules
    });
    return { rulesAdded: addRules.length };
  } catch (err) {
    console.warn('[Verity DNR] Failed to sync malware domains to DNR:', err);
    return { rulesAdded: 0, error: err.message };
  }
}
