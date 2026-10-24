/**
 * shared/live-call-guardian.js — Live Scam Call Speakerphone AI Guardian
 *
 * Listens to speakerphone call audio in real-time via Web Speech API (SpeechRecognition)
 * and audits conversational transcripts for active cyber fraud extortion patterns:
 *   1. Remote Screen-Share Coaching (AnyDesk, TeamViewer, RustDesk, Play Store download)
 *   2. Digital Arrest Extortion (CBI, Police, Narcotics, Customs, Video Interrogation)
 *   3. Bank OTP & UPI PIN Coaching (Reading OTPs, entering UPI PIN to receive refund)
 *
 * 100% On-Device & Free Forever.
 */

'use strict';

export const REMOTE_ACCESS_CALL_PATTERNS = [
  /(?:download|install|open)\s+(?:anydesk|any\s*desk|teamviewer|rustdesk|quicksupport|airdroid)/i,
  /(?:share|sharing)\s+(?:your\s+)?screen/i,
  /(?:screen\s*share\s*karo|screen\s*share\s*pannunga|screen\s*share\s*cheyandi)/i,
  /(?:open|kholo|khole|ponga)\s+(?:google\s+)?play\s*store/i,
  /(?:play\s*store\s*open\s*karo|play\s*store\s*khole)/i,
  /(?:tell\s+me|read|give\s+me)\s+(?:the\s+)?(?:9|nine)[-\s]*digit\s*(?:code|number)/i,
  /(?:9|nine)[-\s]*digit\s*(?:code|number)\s*(?:batao|share\s*karo|bataiye)/i
];

export const DIGITAL_ARREST_CALL_PATTERNS = [
  /(?:mumbai|delhi|crime\s*branch|cyber\s*crime)\s*police/i,
  /(?:cbi|ed|nia|customs|interpol)\s*officer/i,
  /(?:customs|courier|fedex|dhl)\s*parcel/i,
  /(?:narcotics|drugs|contraband|mdma|passport)\s*(?:found\s*in|inside|seized)/i,
  /(?:aadhaar|identity)\s*(?:linked|used|found)\s*(?:in|to)\s*(?:money\s*laundering|fraud|crime)/i,
  /(?:stay\s+on|remain\s+on|do\s+not\s+disconnect)\s*(?:the\s+)?video\s*call/i,
  /(?:under\s+)?(?:digital|virtual)\s*arrest/i,
  /(?:transfer|deposit|send)\s+(?:to\s+)?(?:rbi|supreme\s*court|government|police)\s*(?:verification|escrow|safe)\s*account/i,
  /(?:clear\s+your\s+name|avoid\s+immediate\s+arrest)/i
];

export const OTP_UPI_CALL_PATTERNS = [
  /(?:tell|read|share|batao|bataiye)(?:\s+me|\s+out)?\s+(?:the\s+)?(?:(?:6|six|4|four)[-\s]*(?:digit)?)?\s*(?:code|otp|pin)/i,
  /(?:read|tell)\s+(?:me\s+)?(?:the\s+)?otp/i,
  /(?:otp\s*batao|otp\s*aayega|otp\s*share\s*karo)/i,
  /(?:enter|type|put)\s*(?:your\s+)?(?:upi|mpin|secret)?\s*pin\s*(?:to\s+receive|to\s+get|for\s+credit)/i,
  /(?:pin\s*dalo|pin\s*daal|pin\s*podu)\s*(?:paise\s*milega|cashback|refund)/i,
  /(?:scan|open)\s+(?:the\s+)?qr\s*code\s*(?:i\s*sent|received)/i,
  /(?:qr\s*scan\s*karo|qr\s*scan\s*karke\s*paise)/i,
  /(?:enter|send|pay)\s+(?:amount|money|rupees|paise)\s+(?:in|to|on)\s+(?:upi|gpay|phonepe|paytm)/i,
  /(?:approve|accept)\s*(?:the\s+)?(?:collect\s*request|payment\s*request)/i
];

/**
 * Evaluates real-time conversational speech transcript for active fraud patterns.
 *
 * @param {string} transcriptChunk - Latest spoken audio transcript chunk
 * @param {string} [cumulativeTranscript=''] - Full conversation transcript so far
 * @returns {{
 *   isThreat: boolean,
 *   severity: 'safe' | 'caution' | 'danger',
 *   score: number,
 *   signal: string|null,
 *   threatType: string|null,
 *   category: string|null,
 *   alertHeading: string,
 *   alertAdvice: string,
 *   summary: string,
 *   matchedPhrases: string[],
 *   matchedSignals: string[],
 *   transcriptPreview: string
 * }}
 */
export function evaluateLiveCallTranscriptChunk(transcriptChunk = '', cumulativeTranscript = '') {
  const combined = `${cumulativeTranscript} ${transcriptChunk}`.toLowerCase().trim();
  if (!combined) {
    return {
      isThreat: false,
      severity: 'safe',
      score: 0,
      signal: null,
      threatType: null,
      category: null,
      alertHeading: 'Call Conversation Normal',
      alertAdvice: 'No threat phrases detected on speakerphone.',
      summary: 'No threat phrases detected on speakerphone.',
      matchedPhrases: [],
      matchedSignals: [],
      transcriptPreview: ''
    };
  }

  const matchedPhrases = [];

  // 1. Live Remote Access / Screen-Share Trap
  for (const pattern of REMOTE_ACCESS_CALL_PATTERNS) {
    const match = combined.match(pattern);
    if (match) {
      matchedPhrases.push(match[0]);
    }
  }
  if (matchedPhrases.length > 0) {
    return {
      isThreat: true,
      severity: 'danger',
      score: 95,
      signal: 'SIG_LIVE_CALL_REMOTE_ACCESS_TRAP',
      threatType: 'remote_access_trap',
      category: 'scam_language',
      alertHeading: 'Remote Access Screen-Share Trap Detected',
      alertAdvice: 'HANG UP IMMEDIATELY! Never install AnyDesk or share your screen. Scammers will steal your bank accounts and money.',
      summary: 'Caller is demanding remote screen control or installation of AnyDesk/TeamViewer.',
      matchedPhrases,
      matchedSignals: ['SIG_LIVE_CALL_REMOTE_ACCESS_TRAP'],
      transcriptPreview: transcriptChunk.slice(0, 140)
    };
  }

  // 2. Live Digital Arrest Extortion Call
  for (const pattern of DIGITAL_ARREST_CALL_PATTERNS) {
    const match = combined.match(pattern);
    if (match) {
      matchedPhrases.push(match[0]);
    }
  }
  if (matchedPhrases.length > 0) {
    return {
      isThreat: true,
      severity: 'danger',
      score: 95,
      signal: 'SIG_LIVE_CALL_DIGITAL_ARREST',
      threatType: 'digital_arrest',
      category: 'scam_language',
      alertHeading: 'Digital Arrest Police Extortion Call',
      alertAdvice: 'HANG UP IMMEDIATELY! Law enforcement and CBI never conduct arrests on video calls or ask for funds transfers. Call 1930.',
      summary: 'Caller posing as CBI or police officer threatening digital arrest to extort money.',
      matchedPhrases,
      matchedSignals: ['SIG_LIVE_CALL_DIGITAL_ARREST'],
      transcriptPreview: transcriptChunk.slice(0, 140)
    };
  }

  // 3. Live Bank OTP & UPI PIN Coaching Trap
  for (const pattern of OTP_UPI_CALL_PATTERNS) {
    const match = combined.match(pattern);
    if (match) {
      matchedPhrases.push(match[0]);
    }
  }
  if (matchedPhrases.length > 0) {
    return {
      isThreat: true,
      severity: 'danger',
      score: 90,
      signal: 'SIG_LIVE_CALL_OTP_HARVEST',
      threatType: 'otp_harvest',
      category: 'dom_credentials',
      alertHeading: 'Bank OTP / UPI Debit Coaching Trap',
      alertAdvice: 'NEVER share your OTP or type your UPI PIN to receive money. UPI PIN is only needed to pay money.',
      summary: 'Caller is attempting to extract your confidential OTP or coerce UPI PIN entry.',
      matchedPhrases,
      matchedSignals: ['SIG_LIVE_CALL_OTP_HARVEST'],
      transcriptPreview: transcriptChunk.slice(0, 140)
    };
  }

  return {
    isThreat: false,
    severity: 'safe',
    score: 0,
    signal: null,
    threatType: null,
    category: null,
    alertHeading: 'Call Conversation Normal',
    alertAdvice: 'No extortion, remote-access, or OTP harvest phrases detected on speakerphone.',
    summary: 'No threat phrases detected on speakerphone.',
    matchedPhrases: [],
    matchedSignals: [],
    transcriptPreview: transcriptChunk.slice(0, 140)
  };
}

export default {
  REMOTE_ACCESS_CALL_PATTERNS,
  DIGITAL_ARREST_CALL_PATTERNS,
  OTP_UPI_CALL_PATTERNS,
  evaluateLiveCallTranscriptChunk
};
