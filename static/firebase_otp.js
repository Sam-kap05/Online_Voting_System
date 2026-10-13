/*
 * Thin wrapper around Firebase Authentication phone sign-in (loaded only when SMS_PROVIDER=firebase).
 *
 *   await FirebaseOtp.init(config)                   // once, with the public web config from the server
 *   await FirebaseOtp.sendCode('9812345678', 'id')   // Firebase texts a code to +91 9812345678
 *   const idToken = await FirebaseOtp.confirmCode('123456')   // -> signed token for OUR server to verify
 *
 * The browser never decides anything: the server verifies the token's signature, project, phone number
 * and freshness (see firebase_auth.py). Firebase's own session is signed out immediately - we only
 * need the one-time proof, not a Firebase login.
 */
(function () {
  'use strict';
  const SDK_VERSION = '10.14.1';
  const SDK_BASE = 'https://www.gstatic.com/firebasejs/' + SDK_VERSION;

  let sdk = null, auth = null, verifier = null, confirmation = null;

  async function loadSdk() {
    if (sdk) { return sdk; }
    const [app, authMod] = await Promise.all([
      import(SDK_BASE + '/firebase-app.js'),
      import(SDK_BASE + '/firebase-auth.js'),
    ]);
    sdk = Object.assign({}, app, authMod);
    return sdk;
  }

  // Log the full Firebase error where a developer can read it (browser DevTools > Console).
  function logError(where, err) {
    console.error('[FirebaseOtp] ' + where + ' failed:', err && err.code, err && err.message, err);
  }

  async function init(config) {
    const m = await loadSdk();
    const testMode = !!config.testMode;
    const fbConfig = Object.assign({}, config); delete fbConfig.testMode;   // not a Firebase option
    const app = m.getApps().length ? m.getApp() : m.initializeApp(fbConfig);
    auth = m.getAuth(app);
    auth.languageCode = 'en';
    if (testMode) {
      // DEV ONLY: skips reCAPTCHA so Firebase's fictional "test phone numbers" work. Real numbers still need reCAPTCHA.
      auth.settings.appVerificationDisabledForTesting = true;
      console.warn('[FirebaseOtp] TEST MODE: reCAPTCHA is disabled; only Firebase test phone numbers will work.');
    }
    if (/^[0-9.]+$/.test(window.location.hostname) || window.location.hostname.indexOf(':') >= 0) {
      console.warn('[FirebaseOtp] You are on an IP address (' + window.location.hostname + '). Firebase reCAPTCHA only accepts ' +
                   'hostnames listed under Authentication > Settings > Authorized domains. Prefer http://localhost or a real domain.');
    }
    return auth;
  }

  // Firebase needs a FRESH element for every reCAPTCHA verifier (re-using one after clear() fails).
  function freshVerifier(m, containerId) {
    if (verifier) { try { verifier.clear(); } catch (e) { /* already cleared */ } verifier = null; }
    const holder = document.getElementById(containerId);
    holder.textContent = '';
    const el = document.createElement('div');
    holder.appendChild(el);
    verifier = new m.RecaptchaVerifier(auth, el, { size: 'invisible' });
    return verifier;
  }

  async function sendCode(phone10, containerId) {
    if (!auth) { throw Object.assign(new Error('not initialised'), { code: 'app/not-initialised' }); }
    if (!/^[6-9][0-9]{9}$/.test(phone10)) { throw Object.assign(new Error('bad phone'), { code: 'auth/invalid-phone-number' }); }
    const m = await loadSdk();
    confirmation = null;
    try {
      confirmation = await m.signInWithPhoneNumber(auth, '+91' + phone10, freshVerifier(m, containerId || 'recaptcha-container'));
    } catch (err) {
      logError('sendCode', err);
      throw err;
    }
    // Firebase answers "accepted" the moment it queues the SMS; it never reports delivery to the browser.
    console.info('[FirebaseOtp] Firebase accepted the code request for +91 ' + phone10.slice(0, 2) + 'XXXXXX' + phone10.slice(-2) +
                 ' at ' + new Date().toLocaleTimeString() + '. If no SMS arrives, the problem is delivery (test number, carrier/DND ' +
                 'filtering, region policy, billing) - not this app. See README: "Firebase accepted the request but no SMS arrives".');
  }

  async function confirmCode(code) {
    if (!confirmation) { throw Object.assign(new Error('no code requested'), { code: 'app/no-pending-code' }); }
    let credential;
    try {
      credential = await confirmation.confirm(String(code));
    } catch (err) {
      logError('confirmCode', err);
      throw err;
    }
    const token = await credential.user.getIdToken();
    try { await auth.signOut(); } catch (e) { /* not needed */ }
    confirmation = null;
    return token;
  }

  const MESSAGES = {
    'auth/invalid-phone-number': 'That mobile number looks invalid.',
    'auth/missing-phone-number': 'Please enter your mobile number.',
    'auth/too-many-requests': 'Too many attempts. Please wait a while and try again.',
    'auth/quota-exceeded': 'The SMS limit has been reached. Please try again later.',
    'auth/invalid-verification-code': 'Incorrect code. Please check it and try again.',
    'auth/code-expired': 'That code has expired. Please request a new one.',
    'auth/network-request-failed': 'Network problem. Please check your connection and try again.',
    'auth/operation-not-allowed': 'Phone sign-in is not enabled for this project, or SMS to your region is blocked.',
    'auth/billing-not-enabled': 'Real SMS needs the Firebase Blaze plan. Use a Firebase test number, or upgrade the plan.',
    'auth/unauthorized-domain': 'This website address is not authorised in the Firebase console (Authentication > Settings > Authorized domains).',
    'app/no-pending-code': 'Please request a verification code first.',
  };

  // reCAPTCHA / domain problems all look alike to the voter but have one fix: the web address in the browser bar
  // must be listed in Firebase. Name that address so the operator can add exactly it.
  const DOMAIN_CODES = ['auth/captcha-check-failed', 'auth/missing-app-credential', 'auth/invalid-app-credential',
                        'auth/unauthorized-domain', 'auth/app-not-authorized'];

  function describeError(err) {
    const code = (err && err.code) || '';
    if (DOMAIN_CODES.indexOf(code) >= 0) {
      return 'Security check failed (' + code + '). Firebase did not accept the web address "' + window.location.host +
             '". Open the Firebase console > Authentication > Settings > Authorized domains and add "' + window.location.hostname +
             '". Also turn off ad-blockers or a VPN for this page, then reload.';
    }
    const base = MESSAGES[code] || 'Could not verify the mobile number. Please try again.';
    return code ? base + ' (' + code + ')' : base;
  }

  window.FirebaseOtp = {
    init: init, sendCode: sendCode, confirmCode: confirmCode, describeError: describeError,
    _setSdkForTests: function (fake) { sdk = fake; },   // lets the unit tests run without the network
  };
}());
