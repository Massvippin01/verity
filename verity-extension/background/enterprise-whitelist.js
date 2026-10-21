/**
 * background/enterprise-whitelist.js - Enterprise Identity & Federated Login Boundary Matrix
 *
 * Prevents false positives on legitimate enterprise single sign-on (SSO), SAML, OIDC,
 * and OAuth2 federation flows (Okta, Ping Identity, Microsoft Entra ID, Google Workspace,
 * Auth0, OneLogin, AWS Cognito, PingFederate).
 */

const KNOWN_IDP_PATTERNS = [
  /\.okta(-emea)?\.com$/,
  /\.oktapreview\.com$/,
  /\.pingidentity\.com$/,
  /\.auth0\.com$/,
  /\.b2clogin\.com$/,
  /\.onelogin\.com$/,
  /login\.microsoftonline\.com$/,
  /accounts\.google\.com$/,
  /identity\.oraclecloud\.com$/,
  /\.cognito\.[a-z0-9-]+\.amazonaws\.com$/
];

/**
 * Checks if a URL represents a legitimate enterprise identity provider federation flow.
 * Requires:
 * 1. Matching a verified IdP root domain / pattern.
 * 2. Standard OAuth2 / SAML / OIDC authentication endpoint path.
 * 3. Standard authorization parameters (client_id, response_type, SAMLRequest, code, state).
 *
 * @param {string} urlString
 * @returns {boolean}
 */
export function isLegitimateFederatedLogin(urlString) {
  if (!urlString || typeof urlString !== 'string') return false;

  let parsed = null;
  try {
    parsed = new URL(urlString);
  } catch (_) {
    return false;
  }

  const host = parsed.hostname.toLowerCase();
  const isIdpHost = KNOWN_IDP_PATTERNS.some(pattern => pattern.test(host));
  if (!isIdpHost) return false;

  // Verify standard IdP authentication paths
  const pathname = parsed.pathname.toLowerCase();
  const isValidAuthPath = /^\/(oauth2|adfs|saml|authorize|common|v2\.0|login|idp|auth|as|protocol)/i.test(pathname);

  // Verify presence of standard federated tokens or parameters
  const sp = parsed.searchParams;
  const hasAuthParams = sp && (
    sp.has('client_id') ||
    sp.has('response_type') ||
    sp.has('SAMLRequest') ||
    sp.has('SAMLResponse') ||
    sp.has('id_token') ||
    sp.has('code') ||
    sp.has('state') ||
    sp.has('RelayState')
  );

  return isValidAuthPath && hasAuthParams;
}
