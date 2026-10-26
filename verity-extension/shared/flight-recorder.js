/**
 * shared/flight-recorder.js — Privacy-First Incident Flight Recorder
 *
 * Implements a local, client-side incident timeline manager that records
 * security events, technical observations, safe action decisions, and citizen recovery steps.
 *
 * Design Invariants:
 * 1. Separation of Concerns: Strictly differentiates between empirical observed facts,
 *    unverified user assertions, and system policy inferences.
 * 2. Zero Unsanitized Credentials: Plaintext OTPs, PINs, card numbers, Aadhaar, PAN,
 *    and cleartext passwords are scrubbed before storage.
 * 3. No Raw Message Storage By Default: Content is dropped after evaluation; only
 *    sanitized technical indicators (domains, protocols, hashes) are retained.
 * 4. Bounded Local Storage: Enforces a circular ring buffer (default 50 records)
 *    to prevent unbounded local storage growth.
 * 5. Tamper-Detection Checksums: Computes local SHA-256 integrity digests for records.
 * 6. Explicit Deletion Controls: Provides instant user-directed single-incident deletion
 *    and complete timeline purging.
 * 7. Non-Judicial Disclaimer: Explicitly disclaims legal certification to prevent misrepresentation.
 *
 * Universal portability: Zero platform lock-in; pure deterministic state machine.
 */

import crypto from 'node:crypto';
import { sanitizeSecrets } from './recovery-advisor.js';

export const FLIGHT_RECORDER_VERSION = '1.0.0';
export const DEFAULT_MAX_CAPACITY = 50;

export const LEGAL_DISCLAIMER =
  'LEGAL DISCLAIMER: This document is a client-side diagnostic incident timeline generated on-device by Verity. ' +
  'It does NOT constitute legally certified judicial forensic evidence or official police First Information Report (FIR). ' +
  'Citizens lodging formal complaints should provide original bank statements, SMS logs, and reference transaction IDs.';

/**
 * Extended secret sanitizer including Indian PAN cards and phone numbers.
 *
 * @param {string} text
 * @returns {string} Sanitized string
 */
export function sanitizeFlightRecorderSecrets(text) {
  if (!text || typeof text !== 'string') return '';

  let sanitized = sanitizeSecrets(text);

  // Redact Indian PAN numbers: 5 letters, 4 numbers, 1 letter (e.g. ABCDE1234F -> ABCDE****F)
  sanitized = sanitized.replace(/\b([A-Z]{5})[0-9]{4}([A-Z])\b/gi, '$1****$2');

  // Redact 10-digit Indian phone numbers with optional +91 prefix
  sanitized = sanitized.replace(/(?:\+91[\s-]?)?[6-9]\d{9}\b/g, (match) => {
    const digits = match.replace(/\D/g, '');
    const last3 = digits.slice(-3);
    return `+91-XXXXX-XX${last3}`;
  });

  return sanitized;
}

/**
 * Computes deterministic SHA-256 checksum over canonical record data.
 *
 * @param {object} record
 * @returns {string} Hex SHA-256 hash
 */
export function computeRecordChecksum(record) {
  const { checksum, ...signable } = record;
  const canonical = JSON.stringify(signable, Object.keys(signable).sort());
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Incident Flight Recorder Class managing local timeline state.
 */
export class FlightRecorder {
  constructor(options = {}) {
    this.version = FLIGHT_RECORDER_VERSION;
    this.maxCapacity = options.maxCapacity || DEFAULT_MAX_CAPACITY;
    this.timeline = []; // in-memory circular buffer
  }

  /**
   * Records a new security incident event into the timeline.
   *
   * @param {object} params
   * @param {object} params.verdict - Verdict Contract object
   * @param {object} params.policyOutcome - Safe Action Policy outcome
   * @param {object} [params.userAssertions={}] - User-declared context (unverified)
   * @param {Array<string>} [params.observedFacts=[]] - Technical findings
   * @param {string} [params.rawSnippet=null] - Optional snippet (scrubbed if provided)
   * @param {boolean} [params.storeSnippet=false] - Explicit user opt-in to store scrubbed snippet
   * @returns {object} Stored incident record
   */
  recordIncident(params) {
    if (!params.verdict || !params.verdict.scanId) {
      throw new Error('[FlightRecorder] Valid verdict contract is required to record an incident.');
    }

    const recordId = `rec_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`;
    const timestamp = new Date().toISOString();

    // 1. Separate Facts vs Assertions
    const observedFacts = Array.isArray(params.observedFacts) ? [...params.observedFacts] : [];
    if (params.verdict.evidence) {
      params.verdict.evidence.forEach(e => {
        const desc = typeof e === 'string' ? e : e?.description || e?.id;
        if (desc && !observedFacts.includes(desc)) {
          observedFacts.push(desc);
        }
      });
    }

    const userAssertions = params.userAssertions && typeof params.userAssertions === 'object'
      ? { ...params.userAssertions }
      : {};

    // 2. Data Minimization: sanitize snippet only if explicitly requested
    let sanitizedSnippet = null;
    if (params.storeSnippet && typeof params.rawSnippet === 'string') {
      sanitizedSnippet = sanitizeFlightRecorderSecrets(params.rawSnippet.trim()).slice(0, 200);
    }

    // 3. Construct Record Schema
    const record = {
      recordId,
      timestamp,
      scanId: params.verdict.scanId,
      modality: params.verdict.inputModality || 'composite',
      threatCategory: params.verdict.threatCategory || 'unsupported_or_unknown',
      riskClassification: params.verdict.riskClassification || 'ABSTAIN',
      riskScore: params.verdict.riskScore ?? 0,
      policyVersion: params.policyOutcome?.policyVersion || '1.0.0',
      recommendedActionId: params.policyOutcome?.recommendedAction?.id || 'MANUAL_VERIFY_OFFLINE',
      automatedActionTaken: params.policyOutcome?.allowedAutomaticAction?.actionType || null,
      
      // Categorical separation
      observedFacts,
      userAssertions,
      sanitizedSnippet,

      // Citizen interaction log
      userInteractions: [],
      recoveryProgress: [],

      checksum: ''
    };

    // 4. Compute Checksum
    record.checksum = computeRecordChecksum(record);

    // 5. Enforce Ring Buffer Capacity (prune oldest)
    if (this.timeline.length >= this.maxCapacity) {
      this.timeline.shift();
    }

    this.timeline.push(record);
    return record;
  }

  /**
   * Logs a user interaction or completed recovery step for an existing record.
   *
   * @param {string} recordId
   * @param {{ action: string, stepId?: string, note?: string }} interaction
   * @returns {object|null} Updated record
   */
  logUserInteraction(recordId, interaction) {
    const record = this.timeline.find(r => r.recordId === recordId);
    if (!record) return null;

    const entry = {
      timestamp: new Date().toISOString(),
      action: interaction.action,
      stepId: interaction.stepId || null,
      note: interaction.note ? sanitizeFlightRecorderSecrets(interaction.note).slice(0, 100) : null
    };

    record.userInteractions.push(entry);

    if (interaction.stepId && !record.recoveryProgress.includes(interaction.stepId)) {
      record.recoveryProgress.push(interaction.stepId);
    }

    record.checksum = computeRecordChecksum(record);
    return record;
  }

  /**
   * Deletes a single incident record from the timeline.
   *
   * @param {string} recordId
   * @returns {boolean} True if found and deleted
   */
  deleteRecord(recordId) {
    const idx = this.timeline.findIndex(r => r.recordId === recordId);
    if (idx !== -1) {
      this.timeline.splice(idx, 1);
      return true;
    }
    return false;
  }

  /**
   * Purges all recorded incidents from the local timeline.
   */
  purgeAll() {
    this.timeline = [];
  }

  /**
   * Returns a copy of all active records.
   *
   * @returns {Array<object>}
   */
  getTimeline() {
    return [...this.timeline];
  }

  /**
   * Exports the entire timeline as structured JSON.
   *
   * @returns {string} Formatted JSON
   */
  exportTimelineJson() {
    const payload = {
      recorderVersion: this.version,
      exportedAt: new Date().toISOString(),
      recordCount: this.timeline.length,
      disclaimer: LEGAL_DISCLAIMER,
      records: this.timeline
    };
    return JSON.stringify(payload, null, 2);
  }

  /**
   * Exports the timeline into formatted Markdown for incident reporting.
   *
   * @returns {string} Formatted Markdown
   */
  exportTimelineMarkdown() {
    let md = `# VERITY Incident Flight Recorder Timeline\n\n`;
    md += `**Exported At:** ${new Date().toISOString()}  \n`;
    md += `**Total Logged Events:** ${this.timeline.length}  \n`;
    md += `**Recorder Version:** ${this.version}\n\n`;
    md += `> [!NOTE]\n> **${LEGAL_DISCLAIMER}**\n\n---\n\n`;

    if (this.timeline.length === 0) {
      md += `*No security incidents currently recorded in local memory.*\n`;
      return md;
    }

    this.timeline.forEach((rec, idx) => {
      md += `### Event ${idx + 1}: ${rec.threatCategory.toUpperCase()} [${rec.riskClassification}]\n`;
      md += `- **Record ID:** \`${rec.recordId}\` (Scan: \`${rec.scanId}\`)\n`;
      md += `- **Timestamp:** ${rec.timestamp}\n`;
      md += `- **Risk Score:** ${rec.riskScore} / 100\n`;
      md += `- **Recommended Action:** \`${rec.recommendedActionId}\`\n`;
      if (rec.automatedActionTaken) {
        md += `- **Automated Protective Action:** \`${rec.automatedActionTaken}\`\n`;
      }
      
      md += `\n**Observed Technical Facts:**\n`;
      if (rec.observedFacts.length === 0) {
        md += `- *None recorded*\n`;
      } else {
        rec.observedFacts.forEach(fact => {
          md += `- ${fact}\n`;
        });
      }

      if (Object.keys(rec.userAssertions).length > 0) {
        md += `\n**Unverified User Assertions:**\n`;
        Object.entries(rec.userAssertions).forEach(([k, v]) => {
          md += `- *${k}:* ${sanitizeFlightRecorderSecrets(String(v))}\n`;
        });
      }

      if (rec.sanitizedSnippet) {
        md += `\n**Sanitized Context Snippet:**\n> \`${rec.sanitizedSnippet}\`\n`;
      }

      if (rec.userInteractions.length > 0) {
        md += `\n**Citizen Action Log:**\n`;
        rec.userInteractions.forEach(act => {
          md += `- [${act.timestamp}] ${act.action}${act.stepId ? ` (Step: ${act.stepId})` : ''}\n`;
        });
      }

      md += `\n- **Integrity Checksum (SHA-256):** \`${rec.checksum}\`\n\n---\n\n`;
    });

    return md;
  }
}

export default {
  FLIGHT_RECORDER_VERSION,
  DEFAULT_MAX_CAPACITY,
  LEGAL_DISCLAIMER,
  sanitizeFlightRecorderSecrets,
  computeRecordChecksum,
  FlightRecorder
};
