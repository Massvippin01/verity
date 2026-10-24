/**
 * shared/payment-gateway-allowlist.js
 *
 * Comprehensive registry of PCI-DSS authorized payment gateways, processor endpoints,
 * and verified merchant checkout contexts.
 *
 * Used to eliminate false positives when citizens and users perform legitimate
 * e-commerce, SaaS subscriptions, or utility payments via Stripe, Razorpay, PayU,
 * BillDesk, Cashfree, Juspay, etc.
 *
 * 100% pure JavaScript with zero DOM and zero browser API dependencies.
 */

'use strict';

/**
 * Recognized PCI-DSS compliant payment gateways, processors, and verified merchants.
 */
export const AUTHORIZED_PAYMENT_GATEWAY_DOMAINS = [
  // Global & Indian Payment Gateways
  'stripe.com',
  'stripe.network',
  'checkout.stripe.com',
  'js.stripe.com',
  'razorpay.com',
  'api.razorpay.com',
  'checkout.razorpay.com',
  'payu.in',
  'payumoney.com',
  'secure.payu.in',
  'billdesk.com',
  'pgi.billdesk.com',
  'ccavenue.com',
  'cashfree.com',
  'sdk.cashfree.com',
  'juspay.in',
  'api.juspay.in',
  'payments.juspay.in',
  'phonepe.com',
  'merchants.phonepe.com',
  'paytm.com',
  'securegw.paytm.in',
  'bhimupi.org.in',
  'npci.org.in',
  'paypal.com',
  'braintreegateway.com',
  'adyen.com',
  'paddle.com',
  'checkout.paddle.com',
  'lemonsqueezy.com',
  'polar.sh',
  'simpl.xyz',
  'pinelabs.com',

  // Top Verified Digital Platforms with Native Embedded Billing
  'openai.com',
  'pay.openai.com',
  'chatgpt.com',
  'anthropic.com',
  'claude.ai',
  'amazon.in',
  'amazon.com',
  'flipkart.com',
  'zomato.com',
  'swiggy.com',
  'irctc.co.in',
  'bookmyshow.com',
  'makemytrip.com'
];

/**
 * Verified third-party payment gateway SDK script or iframe patterns.
 */
export const VERIFIED_GATEWAY_SCRIPT_PATTERNS = [
  'js.stripe.com',
  'checkout.stripe.com',
  'checkout.razorpay.com',
  'api.razorpay.com',
  'secure.payu.in',
  'pgi.billdesk.com',
  'sdk.cashfree.com',
  'payments.juspay.in',
  'assets.braintreegateway.com',
  'paypal.com/sdk/js'
];

/**
 * Common honest payment checkout UI phrases that signify intentional payment.
 */
export const HONEST_CHECKOUT_PHRASES = [
  'authorize payment',
  'scan this qr code using your preferred upi app',
  'scan this qr code with your upi app',
  'scan this qr code using any upi app',
  'scan qr code to pay',
  'scan the qr code to pay',
  'powered by stripe',
  'powered by razorpay',
  'powered by payu',
  'powered by billdesk',
  'powered by cashfree',
  'powered by juspay',
  'billing address',
  'payment method',
  'select a payment method',
  'order summary',
  'total due',
  'total payable',
  'amount to pay',
  'upi is supported in multiple apps',
  'pay with upi',
  'pay via upi'
];

/**
 * Unambiguous deceptive phrases used by scammers claiming that funds will be received.
 */
export const DECEPTIVE_RECEIVE_LURES_STRICT = [
  'scan to receive',
  'receive cashback',
  'claim reward',
  'claim bonus',
  'get refund',
  'prize money',
  'lottery prize',
  'olx buyer payment',
  'money will be credited',
  'paise milega',
  'cashback milega',
  'refund aayega',
  'scan karke paise',
  'scan qr to get money',
  'scan code to accept',
  'scan to accept payment'
];

/**
 * Checks if a given hostname matches an authorized payment gateway or merchant domain.
 *
 * @param {string} hostname
 * @returns {boolean}
 */
export function matchesGatewayDomain(hostname) {
  if (!hostname || typeof hostname !== 'string') return false;
  const clean = hostname.toLowerCase().trim().replace(/^www\./, '');
  return AUTHORIZED_PAYMENT_GATEWAY_DOMAINS.some(d => clean === d || clean.endsWith('.' + d));
}

/**
 * Checks if a page is hosted on or embeds an authorized payment gateway.
 *
 * @param {string} hostname - Target hostname
 * @param {object} [domSignals={}] - Page DOM signals
 * @returns {boolean}
 */
export function isAuthorizedPaymentGatewayOrMerchant(hostname, domSignals = {}) {
  const cleanHost = (hostname || (typeof location !== 'undefined' ? location.hostname : '') || '').toLowerCase().trim().replace(/^www\./, '');

  if (cleanHost && matchesGatewayDomain(cleanHost)) {
    return true;
  }

  if (domSignals) {
    if (domSignals.isAuthorizedGateway) return true;

    // Check embedded gateway scripts/iframes
    const scripts = domSignals.scriptSrcs || domSignals.embeddedScripts || [];
    const iframes = domSignals.iframeSrcs || domSignals.embeddedIframes || [];
    const hasGatewayEmbed = [...scripts, ...iframes].some(src =>
      typeof src === 'string' && VERIFIED_GATEWAY_SCRIPT_PATTERNS.some(pat => src.toLowerCase().includes(pat))
    );
    if (hasGatewayEmbed) return true;
  }

  return false;
}

/**
 * Checks if a page context represents a legitimate checkout flow.
 * Must have honest checkout terms AND no deceptive receive lures AND no illegal web PIN inputs.
 *
 * @param {string} [pageText='']
 * @param {object} [domSignals={}]
 * @returns {boolean}
 */
export function isLegitimateCheckoutFlow(pageText = '', domSignals = {}) {
  const text = (pageText || domSignals?.pageText || '').toLowerCase();

  // If page is flagged for cyber fraud, fake provider domain mismatch, or illegal PIN harvest, strictly disqualify
  if (
    domSignals?.domainMismatch ||
    domSignals?.claimedProviderMismatch ||
    domSignals?.kycCyberFraud ||
    domSignals?.illegalWebPinCollection ||
    domSignals?.asksForUpiPinInInput ||
    domSignals?.hasIllegalWebPinInput ||
    domSignals?.hasCrossDomainCredentialAction
  ) {
    return false;
  }

  // Deceptive receive lures strictly disqualify legitimate checkout status
  const hasDeceptiveReceiveLure = DECEPTIVE_RECEIVE_LURES_STRICT.some(lure => text.includes(lure));
  if (hasDeceptiveReceiveLure) {
    return false;
  }

  // Check if text asks for secret UPI PIN or ATM PIN in web form
  if (/\b(?:upi|mpin|atm)\s*pin\b/i.test(text) && /\b(?:enter|type|input|submit)\b/i.test(text)) {
    return false;
  }

  // Check if text has KYC update / account blocked threat
  if (text.includes('kyc') && (text.includes('blocked') || text.includes('pan card') || text.includes('mandatory kyc'))) {
    return false;
  }

  const hasHonestPhrase = HONEST_CHECKOUT_PHRASES.some(phrase => text.includes(phrase));
  const hasGatewayBrand = isAuthorizedPaymentGatewayOrMerchant(domSignals?.hostname || '', domSignals);

  return hasHonestPhrase || hasGatewayBrand;
}

/**
 * Identifies payment badges/logos (Visa, GPay, Paytm, PhonePe, etc.) on checkout pages.
 *
 * @param {string} assetUrl
 * @param {string} [brandName='']
 * @returns {boolean}
 */
export function isPaymentBrandBadgeAsset(assetUrl, brandName = '') {
  if (!assetUrl || typeof assetUrl !== 'string') return false;
  const lowerUrl = assetUrl.toLowerCase();
  const lowerBrand = (brandName || '').toLowerCase();

  const badgeKeywords = [
    'gpay', 'googlepay', 'google-pay', 'phonepe', 'paytm', 'bhim', 'upi',
    'visa', 'mastercard', 'master-card', 'amex', 'rupay', 'maestro',
    'diners', 'discover', 'stripe', 'razorpay', 'payu', 'billdesk',
    'cashfree', 'payment-method', 'payment_method', 'payment_options',
    'payment-options', 'checkout', 'card-icon', 'payment-icon'
  ];

  return badgeKeywords.some(kw => lowerUrl.includes(kw) || lowerBrand.includes(kw));
}

export default {
  AUTHORIZED_PAYMENT_GATEWAY_DOMAINS,
  VERIFIED_GATEWAY_SCRIPT_PATTERNS,
  HONEST_CHECKOUT_PHRASES,
  DECEPTIVE_RECEIVE_LURES_STRICT,
  matchesGatewayDomain,
  isAuthorizedPaymentGatewayOrMerchant,
  isLegitimateCheckoutFlow,
  isPaymentBrandBadgeAsset
};
