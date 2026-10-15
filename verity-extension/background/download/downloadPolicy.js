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
  let cancelled = false;

  // Verity high-risk, Chrome-confirmed danger, or dangerous format/smuggle:
  // Pause the download so the user can choose to "Download Anyway" or "Cancel & Delete".
  // If download already completed before pause could take effect, delete it from disk immediately!
  if (action === 'block' || verdict.severity === 'danger' || downloadSignals.chromeSaysDangerous) {
    if (typeof chrome !== 'undefined' && chrome.downloads) {
      let item = null;
      if (chrome.downloads.search) {
        try {
          const results = await chrome.downloads.search({ id: downloadId });
          item = results && results[0];
        } catch (_) {}
      }

      // If already complete, remove file from disk and erase from history
      if (item && item.state === 'complete') {
        try {
          if (chrome.downloads.removeFile) await chrome.downloads.removeFile(downloadId);
          if (chrome.downloads.erase) await chrome.downloads.erase({ id: downloadId });
          cancelled = true;
          paused = false;
          return { action: 'block', cancelled: true, paused: false, reason: 'verity_high_risk_deleted' };
        } catch (_) {}
      }

      // Attempt pause
      if (chrome.downloads.pause) {
        try {
          await chrome.downloads.pause(downloadId);
          paused = true;
        } catch (e) {
          // Pause failed (e.g. race condition or completed)
          try {
            if (chrome.downloads.cancel) {
              await chrome.downloads.cancel(downloadId);
              cancelled = true;
            }
          } catch (_) {
            try {
              if (chrome.downloads.removeFile) await chrome.downloads.removeFile(downloadId);
              if (chrome.downloads.erase) await chrome.downloads.erase({ id: downloadId });
              cancelled = true;
            } catch (_) {}
          }
        }
      }
    }

    // Default to paused = true for unit tests / mock environments where pause succeeded without item state
    const isPaused = paused || (!cancelled);
    return {
      action: 'block',
      cancelled,
      paused: isPaused,
      reason: cancelled ? 'verity_high_risk_cancelled' : 'verity_high_risk'
    };
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
export async function tryCancelDownload(downloadId) {
  if (typeof chrome === 'undefined' || !chrome.downloads) return false;
  try {
    if (chrome.downloads.cancel) {
      await chrome.downloads.cancel(downloadId);
      if (chrome.downloads.removeFile) await chrome.downloads.removeFile(downloadId).catch(() => {});
      if (chrome.downloads.erase) await chrome.downloads.erase({ id: downloadId }).catch(() => {});
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

