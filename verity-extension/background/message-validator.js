/**
 * message-validator.js — Strict sender and message structure validation
 */

/**
 * Validates incoming chrome.runtime message senders.
 * Enforces extension ID matching and tab validation for tab-scoped actions.
 *
 * @param {object} sender - chrome.runtime.MessageSender
 * @param {string} expectedRuntimeId - Expected chrome.runtime.id
 * @param {object} message - Message payload
 * @returns {{ valid: boolean, reason: string|null }}
 */
export function validateMessageSender(sender, expectedRuntimeId, message) {
  if (!sender || sender.id !== expectedRuntimeId) {
    return { valid: false, reason: 'Invalid or missing sender runtime ID' };
  }

  const tabScopedActions = [
    'ANALYZE_URL_ONLY',
    'ANALYZE_FULL',
    'ANALYZE_SEARCH_RESULT',
    'USER_OVERRIDE_ALLOW',
    'NAVIGATE_TO_SAFETY',
    'RUNTIME_THREAT_DETECTED'
  ];

  const action = message?.action || message?.type;
  if (action && tabScopedActions.includes(action)) {
    const isInternalExtension = !sender.tab && (
      (sender.url && sender.url.startsWith('chrome-extension://' + expectedRuntimeId)) ||
      (sender.origin && sender.origin.startsWith('chrome-extension://' + expectedRuntimeId))
    );

    if (!isInternalExtension && (!sender.tab || sender.tab.id == null)) {
      return { valid: false, reason: `Action ${action} requires a valid sender tab` };
    }

    if (message.action === 'USER_OVERRIDE_ALLOW') {
      if (sender.tab && message.tabId != null && message.tabId !== sender.tab.id) {
        return { valid: false, reason: 'Tab ID mismatch in override request' };
      }
      if (sender.tab && message.url && sender.tab.url) {
        try {
          const msgHost = new URL(message.url).hostname.toLowerCase();
          const tabHost = new URL(sender.tab.url).hostname.toLowerCase();
          if (msgHost !== tabHost) {
            return { valid: false, reason: 'URL hostname mismatch with sender tab' };
          }
        } catch (e) {
          return { valid: false, reason: 'Malformed URL in override request' };
        }
      } else if (message.url) {
        try {
          new URL(message.url);
        } catch (e) {
          return { valid: false, reason: 'Malformed URL in override request' };
        }
      }
    }
  }

  return { valid: true, reason: null };
}
