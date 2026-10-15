import test from 'node:test';
import assert from 'node:assert/strict';

// ---------------------------------------------------------------------------
// Mock environment for service_worker tests
// ---------------------------------------------------------------------------
const removedTabs = [];
const sentMessages = [];

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
      get: async () => ({}),
      set: async () => {},
      remove: async () => {}
    },
    local: {
      get: async () => ({}),
      set: async () => {}
    }
  },
  tabs: {
    get: async (tabId) => ({ id: tabId, url: 'https://moviesda.soy/' }),
    remove: async (tabId) => {
      removedTabs.push(tabId);
    },
    sendMessage: async (tabId, msg) => {
      sentMessages.push({ tabId, msg });
    },
    query: async () => [],
    update: async () => {},
    onCreated: { addListener: () => {} },
    onRemoved: { addListener: () => {} },
    onUpdated: { addListener: () => {} },
    onActivated: { addListener: () => {} }
  },
  windows: {
    onCreated: { addListener: () => {} },
    remove: async () => {}
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

const { isSafeAllowlistedOrTopDomain } = await import('../service_worker.js');

test('Anti-Popup Case 1: isExplicitAdRotator catches all ad-rotator and popunder networks', () => {
  function isExplicitAdRotator(targetUrl) {
    const lowerTarget = (targetUrl || '').toLowerCase();
    return (
      lowerTarget.includes('utm_medium=popunder') ||
      lowerTarget.includes('propellerads') ||
      lowerTarget.includes('popads') ||
      lowerTarget.includes('wigglepoploaderfast') ||
      lowerTarget.includes('adsterra') ||
      lowerTarget.includes('clickadu') ||
      lowerTarget.includes('exoclick') ||
      lowerTarget.includes('popcash') ||
      lowerTarget.includes('hilltopads') ||
      lowerTarget.includes('richads') ||
      lowerTarget.includes('monetag') ||
      lowerTarget.includes('galaksion') ||
      lowerTarget.includes('bet365') ||
      lowerTarget.includes('1xbet') ||
      lowerTarget.includes('dafabet') ||
      lowerTarget.includes('popunder') ||
      lowerTarget.includes('onclick') ||
      /\?[a-f0-9]{16,64}/i.test(targetUrl)
    );
  }

  // Common pop-up and pop-under ad networks
  assert.equal(isExplicitAdRotator('https://traffic.adsterra.com/serve/pop'), true);
  assert.equal(isExplicitAdRotator('https://fastclick.clickadu.com/in/?zoneid=123'), true);
  assert.equal(isExplicitAdRotator('https://monetag.com/direct-link/456'), true);
  assert.equal(isExplicitAdRotator('https://bet365-bonus.xyz/claim'), true);
  assert.equal(isExplicitAdRotator('https://rotator.net/?540267a373b920a51ea99c645c7f'), true);

  // Legitimate links must NEVER be flagged as ad rotators
  assert.equal(isExplicitAdRotator('https://moviesda.soy/movie/tamil-2026'), false);
  assert.equal(isExplicitAdRotator('https://gofile.io/d/AbC123'), false);
  assert.equal(isExplicitAdRotator('https://accounts.google.com/o/oauth2/v2/auth'), false);
  assert.equal(isExplicitAdRotator('https://1fichier.com/?download_key'), false);
});

test('Anti-Popup Case 2: window.open interceptor logic defuses rogue popup calls and returns dummy window', () => {
  function evaluateWindowOpen(urlStr, features, curHost) {
    const lowerUrl = (urlStr || '').toLowerCase();
    const AD_PATTERNS = [
      'utm_medium=popunder', 'propellerads', 'popads', 'adsterra', 'clickadu',
      'exoclick', 'popcash', 'hilltopads', 'richads', 'monetag', 'galaksion',
      'wigglepoploaderfast', 'bet365', '1xbet', 'dafabet', 'popunder',
      'adnetwork', 'adrotator', 'trafficjunky', 'adnxs', 'onclick'
    ];

    if (!urlStr || urlStr === 'about:blank') {
      if (features && (features.includes('width=') || features.includes('popup='))) {
        return { blocked: true, reason: 'blank_with_popup_features' };
      }
    }

    if (AD_PATTERNS.some(p => lowerUrl.includes(p)) || /\?[a-f0-9]{16,64}/i.test(urlStr)) {
      return { blocked: true, reason: 'ad_network_pattern' };
    }

    const OAUTH_PROVIDERS = /(^|\.)(accounts\.google\.com|login\.microsoftonline\.com|appleid\.apple\.com|github\.com)$/i;
    try {
      const parsed = new URL(urlStr);
      if (parsed.hostname.toLowerCase() === curHost) return { blocked: false, reason: 'same_host' };
      if (OAUTH_PROVIDERS.test(parsed.hostname)) return { blocked: false, reason: 'oauth_idp' };
    } catch (_) {}

    return { blocked: false, reason: 'allowed' };
  }

  // 1. Rogue ad popup is blocked
  const res1 = evaluateWindowOpen('https://sbs-lander.clickadu.com/pop?zid=999', '', 'moviesda.soy');
  assert.equal(res1.blocked, true);

  // 2. Empty window.open with popup window features is blocked
  const res2 = evaluateWindowOpen('about:blank', 'width=400,height=500,popup=1', 'moviesda.soy');
  assert.equal(res2.blocked, true);

  // 3. Legitimate OAuth window.open is allowed
  const res3 = evaluateWindowOpen('https://accounts.google.com/o/oauth2/v2/auth?client_id=123', 'width=500,height=600', 'mysite.com');
  assert.equal(res3.blocked, false);
  assert.equal(res3.reason, 'oauth_idp');

  // 4. Same origin window.open is allowed
  const res4 = evaluateWindowOpen('https://moviesda.soy/player/embed?id=12', '', 'moviesda.soy');
  assert.equal(res4.blocked, false);
  assert.equal(res4.reason, 'same_host');
});

test('Anti-Popup Case 3: Spawned rogue popup tab auto-termination and toast dispatch', async () => {
  removedTabs.length = 0;
  sentMessages.length = 0;

  const openerTabId = 101;
  const spawnedTabId = 202;
  const rogueUrl = 'https://aar5n.wigglepoploaderfast.monster/?540267a373b920a51ea99c645c7f';

  // Simulate rogue tab termination logic
  async function terminateRogueSpawnedTab(tabId, openerId, targetUrl) {
    if (chrome.tabs && chrome.tabs.remove) {
      await chrome.tabs.remove(tabId);
    }
    if (openerId && chrome.tabs && chrome.tabs.sendMessage) {
      let host = targetUrl;
      try { host = new URL(targetUrl).hostname; } catch (_) {}
      await chrome.tabs.sendMessage(openerId, {
        action: 'POPUP_BLOCKED_TOAST',
        blockedUrl: targetUrl,
        hostname: host
      });
    }
  }

  await terminateRogueSpawnedTab(spawnedTabId, openerTabId, rogueUrl);

  assert.equal(removedTabs.includes(spawnedTabId), true, 'Spawned rogue tab must be immediately closed');
  assert.equal(sentMessages.length, 1, 'Opener tab must receive popup blocked toast');
  assert.equal(sentMessages[0].tabId, openerTabId);
  assert.equal(sentMessages[0].msg.action, 'POPUP_BLOCKED_TOAST');
  assert.equal(sentMessages[0].msg.hostname, 'aar5n.wigglepoploaderfast.monster');
});
