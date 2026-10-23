/**
 * shared/file-magic-inspector.js — Pure, Offline Binary File Magic Header Inspector
 *
 * Inspects the initial header bytes of files selected via File Picker / WhatsApp share
 * to uncover disguised malware, double extensions, and malicious APK droppers 100% offline.
 *
 * Magic Byte Signatures:
 * - 0x4D, 0x5A ("MZ") -> Windows PE Executable (.exe, .dll, .scr)
 * - 0x50, 0x4B, 0x03, 0x04 ("PK\x03\x04") -> ZIP / APK Container (.zip, .apk, .jar)
 * - 0x25, 0x50, 0x44, 0x46 ("%PDF") -> Portable Document Format (.pdf)
 * - 0xFF, 0xD8, 0xFF -> JPEG Image (.jpg, .jpeg)
 * - 0x89, 0x50, 0x4E, 0x47 ("\x89PNG") -> PNG Image (.png)
 */

/**
 * Inspects a file's binary magic header bytes against its declared name and MIME type.
 *
 * @param {string} fileName - Declared filename (e.g. "SBI_Statement.pdf", "RTO_Traffic_Challan.apk")
 * @param {string} [mimeType=''] - Declared MIME type
 * @param {Uint8Array|ArrayBuffer|number[]} [headerBytesUint8Array] - First 4-16 bytes of the file
 * @returns {{
 *   fileName: string,
 *   mimeType: string,
 *   detectedType: string,
 *   score: number,
 *   severity: 'safe' | 'caution' | 'danger',
 *   state: 'safe' | 'caution' | 'danger',
 *   detected: boolean,
 *   signal: string | null,
 *   signals: string[],
 *   reason: string
 * }}
 */
export function inspectFileMagicBytes(fileName = '', mimeType = '', headerBytesUint8Array = null) {
  const name = String(fileName || '').trim();
  const lowerName = name.toLowerCase();

  let bytes = null;
  if (headerBytesUint8Array instanceof Uint8Array) {
    bytes = headerBytesUint8Array;
  } else if (headerBytesUint8Array instanceof ArrayBuffer) {
    bytes = new Uint8Array(headerBytesUint8Array);
  } else if (Array.isArray(headerBytesUint8Array)) {
    bytes = new Uint8Array(headerBytesUint8Array);
  } else {
    bytes = new Uint8Array(0);
  }

  const isClaimingDocOrMedia = /\.(pdf|jpg|jpeg|png|doc|docx|xls|xlsx|txt|mp4|csv)$/i.test(lowerName);
  const isDoubleExtension = /\.(pdf|jpg|jpeg|doc|docx|txt|xls|mp4)\.(exe|scr|bat|cmd|com|msi|vbs|js|apk)$/i.test(lowerName);

  // ── 1. Windows PE Executable (4D 5A -> "MZ") ──
  const isMZ = bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a;
  if (isMZ) {
    if (isClaimingDocOrMedia || isDoubleExtension) {
      return {
        fileName: name,
        mimeType,
        detectedType: 'executable',
        score: 95,
        severity: 'danger',
        state: 'danger',
        detected: true,
        signal: 'SIG_FILE_MAGIC_BYTE_SPOOF',
        signals: ['SIG_FILE_MAGIC_BYTE_SPOOF'],
        reason: `Critical threat: Executable program binary (MZ header) disguised as document "${name}".`
      };
    }

    return {
      fileName: name,
      mimeType,
      detectedType: 'executable',
      score: 85,
      severity: 'danger',
      state: 'danger',
      detected: true,
      signal: 'DOWNLOAD_EXECUTABLE',
      signals: ['DOWNLOAD_EXECUTABLE'],
      reason: `Executable program binary (MZ header) detected: "${name}".`
    };
  }

  // ── 2. ZIP / APK Archive (50 4B 03 04 -> "PK\x03\x04") ──
  const isPK = bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04;
  if (isPK) {
    if (lowerName.endsWith('.apk') || lowerName.includes('.apk')) {
      return {
        fileName: name,
        mimeType,
        detectedType: 'zip_apk',
        score: 90,
        severity: 'danger',
        state: 'danger',
        detected: true,
        signal: 'SIG_MALICIOUS_APK_DROPPER',
        signals: ['SIG_MALICIOUS_APK_DROPPER'],
        reason: `Critical threat: Android APK application package detected: "${name}".`
      };
    }

    if (isClaimingDocOrMedia) {
      return {
        fileName: name,
        mimeType,
        detectedType: 'zip_apk',
        score: 90,
        severity: 'danger',
        state: 'danger',
        detected: true,
        signal: 'SIG_ARCHIVE_DISGUISED_AS_DOC',
        signals: ['SIG_ARCHIVE_DISGUISED_AS_DOC'],
        reason: `Critical threat: Archive container (PK header) disguised as document "${name}".`
      };
    }

    return {
      fileName: name,
      mimeType,
      detectedType: 'zip_apk',
      score: 25,
      severity: 'caution',
      state: 'caution',
      detected: false,
      signal: 'DOWNLOAD_ARCHIVE',
      signals: ['DOWNLOAD_ARCHIVE'],
      reason: `Archive container file detected: "${name}".`
    };
  }

  // ── 3. Benign PDF Document (25 50 44 46 -> "%PDF") ──
  const isPDF = bytes.length >= 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46;
  if (isPDF) {
    return {
      fileName: name,
      mimeType,
      detectedType: 'pdf',
      score: 0,
      severity: 'safe',
      state: 'safe',
      detected: false,
      signal: null,
      signals: [],
      reason: 'Valid PDF document structure.'
    };
  }

  // ── 4. Benign Images (JPEG / PNG) ──
  const isJPEG = bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
  const isPNG = bytes.length >= 4 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47;
  if (isJPEG || isPNG) {
    return {
      fileName: name,
      mimeType,
      detectedType: isJPEG ? 'jpeg' : 'png',
      score: 0,
      severity: 'safe',
      state: 'safe',
      detected: false,
      signal: null,
      signals: [],
      reason: 'Valid image format.'
    };
  }

  // Default fallback for unknown or generic files
  return {
    fileName: name,
    mimeType,
    detectedType: 'unknown',
    score: 0,
    severity: 'safe',
    state: 'safe',
    detected: false,
    signal: null,
    signals: [],
    reason: 'Standard binary or text file.'
  };
}

if (typeof globalThis !== 'undefined') {
  globalThis.inspectFileMagicBytes = inspectFileMagicBytes;
}

export default {
  inspectFileMagicBytes
};
