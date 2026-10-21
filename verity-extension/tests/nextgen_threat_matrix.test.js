import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateRisk } from '../background/risk-engine.js';
import { extract26Features } from '../background/rich-feature-extractor.js';
import { syncMalwareDomainsToDNR } from '../background/dnr-blocker.js';

test('BitB Defense: Browser-in-the-Browser fake address bar triggers critical block', () => {
  const url = 'https://malicious-portal.click/sso-login';
  const domSignals = {
    bitbPopupSpoof: true,
    bitbTarget: 'accounts.google.com',
    bitbReason: 'Browser-in-the-Browser fake address bar displaying "accounts.google.com"'
  };

  const verdict = calculateRisk(url, [], null, domSignals, null);
  assert.equal(verdict.action, 'block', 'BitB attack must trigger BLOCK');
  assert.ok(verdict.score >= 85, `Score must be >= 85, got ${verdict.score}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_BITB_FAKE_POPUP_SPOOF'));
});

test('Web3 Trap: Raw hash signing (eth_sign) triggers critical block', () => {
  const url = 'https://pink-drainer-crypto-airdrop.xyz/claim';
  const domSignals = {
    web3DrainerRawSign: true,
    web3Method: 'eth_sign'
  };

  const verdict = calculateRisk(url, [], null, domSignals, null);
  assert.equal(verdict.action, 'block', 'eth_sign drainer attempt must trigger BLOCK');
  assert.ok(verdict.score >= 90, `Score must be >= 90, got ${verdict.score}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_WEB3_DRAINER_RAW_SIGN'));
});

test('Web3 Trap: Unlimited token/NFT approval (setApprovalForAll/permit) triggers critical block', () => {
  const url = 'https://seaport-claim-reward.top/nft';
  const domSignals = {
    web3UnlimitedApproval: true,
    web3Data: '0xa22cb465'
  };

  const verdict = calculateRisk(url, [], null, domSignals, null);
  assert.equal(verdict.action, 'block', 'Unlimited approval drainer must trigger BLOCK');
  assert.ok(verdict.score >= 90, `Score must be >= 90, got ${verdict.score}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_WEB3_UNLIMITED_APPROVAL'));
});

test('Form Action Hijack: Cross-origin credential post triggers critical block', () => {
  const url = 'https://compromised-blog.com/login.html';
  const domSignals = {
    crossOriginCredentialPost: true,
    crossOriginTarget: 'https://attacker-c2.ru/post.php'
  };

  const verdict = calculateRisk(url, [], null, domSignals, null);
  assert.equal(verdict.action, 'block', 'Cross-origin credential post must trigger BLOCK');
  assert.ok(verdict.score >= 90, `Score must be >= 90, got ${verdict.score}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_CROSS_ORIGIN_CREDENTIAL_POST'));
});

test('26-Feature ML Pipeline: extract26Features returns 26 consistent lexical and structural signals', () => {
  const url = 'https://subdomain.login-verification-paypal.com.bank-security.xyz:8443/auth/wp-content/plugins/verify.php?token=xyz_123';
  const brands = [{ name: 'paypal' }, { name: 'google' }];

  const features = extract26Features(url, brands);
  assert.equal(features.length, 26, `Feature vector must contain exactly 26 features, got ${features.length}`);

  for (let i = 0; i < 26; i++) {
    assert.equal(typeof features[i], 'number', `Feature index ${i} must be a number`);
    assert.ok(!isNaN(features[i]), `Feature index ${i} must not be NaN`);
  }
});

test('DNR Fast-Blocker: syncMalwareDomainsToDNR handles rule syncing safely', async () => {
  const domains = ['evil-drainer.xyz', 'c2-botnet.top'];
  const res = await syncMalwareDomainsToDNR(domains);
  assert.equal(typeof res, 'object');
  assert.equal(typeof res.rulesAdded, 'number');
});
