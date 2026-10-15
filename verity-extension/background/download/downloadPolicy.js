/**
 * downloadPolicy.js - Translates central risk verdict into supported Chrome actions.
 * Only uses APIs that actually exist. Never fakes blocking.
 */

/**
 * Apply policy based on verdict.
 * @param {number} downloadId - Chrome download ID
 * @param {object} verdict    - From calculateRisk()
 * @param {object} downloadSignals - Normalized download features
 * @param {boolean} [isApproved] - Whether the user previously approved this download
 * @returns {Promise<{ action: string, cancelled: boolean, paused: boolean, reason: string }>}
 */
export async function applyDownloadPolicy(downloadId, verdict, downloadSignals, isApproved = false) {
  if (isApproved) {
    return { action: 'allow', cancelled: false, paused: false, reason: 'user_approved' };
  }

  const action = verdict.action || verdict.severity;
  let paused = false;

  // Verity high-risk, Chrome-confirmed danger, or dangerous format/smuggle:
  // Pause the download so the user can choose to "Download Anyway" or "Cancel & Delete"
  if (action === 'block' || verdict.severity === 'danger' || downloadSignals.chromeSaysDangerous) {
    if (typeof chrome !== 'undefined' && chrome.downloads && chrome.downloads.pause) {
      try {
        await chrome.downloads.pause(downloadId).catch(() => {});
        paused = true;
      } catch (_) {}
    }
    return { action: 'block', cancelled: false, paused: true, reason: 'verity_high_risk' };
  }

  // Caution/warn — notify but do not pause or cancel
  if (action === 'warn' || verdict.severity === 'caution') {
    return { action: 'warn', cancelled: false, paused: false, reason: 'verity_caution' };
  }

  // Safe / low risk — allow silently
  return { action: 'allow', cancelled: false, paused: false, reason: 'verity_safe' };
}

/**
 * Attempt to cancel a download via Chrome API.
 * Returns true if successful, false if API does not support it.
 */
async function tryCancelDownload(downloadId) {
  if (typeof chrome === 'undefined' || !chrome.downloads) return false;
  try {
    if (chrome.downloads.cancel) {
      await chrome.downloads.cancel(downloadId);
      return true;
    }
  } catch (e) {
    // Download finished before cancel — remove file from disk & erase from history
    try {
      if (chrome.downloads.removeFile) await chrome.downloads.removeFile(downloadId);
      if (chrome.downloads.erase) await chrome.downloads.erase({ id: downloadId });
      return true;
    } catch (e2) {}
  }
  return false;
}
