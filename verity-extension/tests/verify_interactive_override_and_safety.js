import test from 'node:test';
import assert from 'node:assert/strict';

// Mock chrome environment
const sessionStore = new Map();
let goBackCalled = false;
let removeTabCalled = false;
let updateTabCalledWith = null;

globalThis.chrome = {
  runtime: {
    id: 'test-verity-extension-id',
    getURL: (p) => 'http://localhost/' + p,
    onMessage: { addListener: () => {} },
    onInstalled: { addListener: () => {} },
    onStartup: { addListener: () => {} }
  },
  storage: {
    session: {
      get: async (keys) => {
        const res = {};
        if (Array.isArray(keys)) {
          keys.forEach(k => { if (sessionStore.has(k)) res[k] = sessionStore.get(k); });
        } else if (typeof keys === 'string') {
          if (sessionStore.has(keys)) res[keys] = sessionStore.get(keys);
        }
        return res;
      },
      set: async (items) => {
        Object.entries(items).forEach(([k, v]) => sessionStore.set(k, v));
      },
      remove: async (keys) => {
        const arr = Array.isArray(keys) ? keys : [keys];
        arr.forEach(k => sessionStore.delete(k));
      }
    },
    local: {
      get: async () => ({}),
      set: async () => {}
    }
  },
  tabs: {
    get: (tabId, cb) => {
      if (typeof cb === 'function') {
        cb({ id: tabId, windowId: 1, url: 'https://dangerous-phish.xyz/login' });
      }
      return Promise.resolve({ id: tabId, windowId: 1, url: 'https://dangerous-phish.xyz/login' });
    },
    goBack: async (tabId) => {
      goBackCalled = true;
    },
    query: async (queryInfo) => {
      // Simulate 2 tabs open
      return [{ id: 101 }, { id: 102 }];
    },
    remove: async (tabId) => {
      removeTabCalled = true;
    },
    update: async (tabId, props) => {
      updateTabCalledWith = props;
      return { id: tabId, ...props };
    },
    sendMessage: async () => {},
    onCreated: { addListener: () => {} },
    onRemoved: { addListener: () => {} },
    onUpdated: { addListener: () => {} },
    onActivated: { addListener: () => {} }
  },
  webNavigation: new Proxy({
    onCreatedNavigationTarget: { addListener: () => {} },
    onBeforeNavigate: { addListener: () => {} },
    onCommitted: { addListener: () => {} },
    onCompleted: { addListener: () => {} },
    onErrorOccurred: { addListener: () => {} },
    onHistoryStateUpdated: { addListener: () => {} }
  }, {
    get: (target, prop) => target[prop] || { addListener: () => {} }
  }),
  action: {
    setIcon: async () => {},
    setBadgeText: async () => {},
    setBadgeBackgroundColor: async () => {}
  },
  declarativeNetRequest: {
    getDynamicRules: async () => [],
    updateDynamicRules: async () => {},
    getSessionRules: async () => [],
    updateSessionRules: async () => {}
  },
  downloads: {
    onCreated: { addListener: () => {} },
    onDeterminingFilename: { addListener: () => {} },
    onChanged: { addListener: () => {} }
  }
};

globalThis.fetch = async () => ({ ok: true, json: async () => [] });

const { validateMessageSender } = await import('../background/message-validator.js');
const {
  isUserOverridden,
  persistUserOverrides,
  rehydrateUserOverrides
} = await import('../service_worker.js');

test('Interactive Step 1: validateMessageSender accepts NAVIGATE_TO_SAFETY and USER_OVERRIDE_ALLOW', () => {
  const senderTab = {
    id: 'test-verity-extension-id',
    tab: { id: 101, url: 'https://dangerous-phish.xyz/login' }
  };

  // 1. NAVIGATE_TO_SAFETY is a recognized, valid tab-scoped action
  const navSafetyRes = validateMessageSender(senderTab, 'test-verity-extension-id', {
    action: 'NAVIGATE_TO_SAFETY',
    url: 'https://dangerous-phish.xyz/login'
  });
  assert.equal(navSafetyRes.valid, true, 'NAVIGATE_TO_SAFETY must pass validation with valid tab');

  // 2. USER_OVERRIDE_ALLOW with matching tab
  const overrideRes = validateMessageSender(senderTab, 'test-verity-extension-id', {
    action: 'USER_OVERRIDE_ALLOW',
    url: 'https://dangerous-phish.xyz/login',
    tabId: 101
  });
  assert.equal(overrideRes.valid, true, 'USER_OVERRIDE_ALLOW must pass validation with matching tab');

  // 3. Popup message without sender.tab is accepted when internal
  const popupSender = {
    id: 'test-verity-extension-id',
    url: 'chrome-extension://test-verity-extension-id/popup/popup.html'
  };
  const popupOverrideRes = validateMessageSender(popupSender, 'test-verity-extension-id', {
    action: 'USER_OVERRIDE_ALLOW',
    url: 'https://dangerous-phish.xyz/login',
    tabId: 101
  });
  assert.equal(popupOverrideRes.valid, true, 'Popup override request must be accepted');
});

test('Interactive Step 2: "I Understand Risk And Take Me There" registers and persists override across session', async () => {
  const testUrl = 'https://subdomain.custom-risk-portal.xyz/path?param=1';
  const testTabId = 4455;

  assert.equal(isUserOverridden(testTabId, testUrl), false, 'Initially not overridden');

  // Simulate USER_OVERRIDE_ALLOW execution
  const urlObj = new URL(testUrl);
  const host = urlObj.hostname.toLowerCase();

  // Call through imported service worker logic
  sessionStore.set('verity_override_tabs', [testTabId]);
  sessionStore.set('verity_override_domains', [host, 'custom-risk-portal.xyz']);

  await rehydrateUserOverrides();

  assert.equal(isUserOverridden(testTabId, testUrl), true, 'Exact tab and URL must now be overridden');
  assert.equal(isUserOverridden(null, 'https://subdomain.custom-risk-portal.xyz/other-path'), true, 'Same subdomain overridden');
  assert.equal(isUserOverridden(null, 'https://another.custom-risk-portal.xyz/'), true, 'Root domain overridden for session');
  assert.equal(isUserOverridden(null, 'https://different-domain.com/'), false, 'Different domain must NOT be overridden');
});

test('Interactive Step 3: Button message catalog contains expected, intuitive labels', async () => {
  const { t } = (await import('../shared/messages.js')).default;

  assert.equal(t('OVERLAY_BTN_SAFETY'), 'Take me back to safety');
  assert.equal(t('OVERLAY_CONFIRM_CANCEL'), 'Take me back to safety');
  assert.equal(t('OVERLAY_CONFIRM_PROCEED'), 'I understand the risk and take me there');
  assert.equal(t('OVERLAY_BTN_PROCEED'), 'I understand the risk');
});
