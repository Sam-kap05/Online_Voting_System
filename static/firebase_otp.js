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

  async function init(config) {
    const m = await loadSdk();
    const app = m.getApps().length ? m.getApp() : m.initializeApp(config);
    auth = m.getAuth(app);
    auth.languageCode = 'en';
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
    confirmation = await m.signInWithPhoneNumber(auth, '+91' + phone10, freshVerifier(m, containerId || 'recaptcha-container'));
  }

  async function confirmCode(code) {
    if (!confirmation) { throw Object.assign(new Error('no code requested'), { code: 'app/no-pending-code' }); }
    const credential = await confirmation.confirm(String(code));
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
    'auth/captcha-check-failed': 'Security check failed. Please reload the page and try again.',
    'auth/missing-app-credential': 'Security check failed. Please reload the page and try again.',
    'auth/network-request-failed': 'Network problem. Please check your connection and try again.',
    'auth/operation-not-allowed': 'Phone sign-in is not enabled for this project, or SMS to your region is blocked.',
    'auth/billing-not-enabled': 'Real SMS needs the Firebase Blaze plan. Use a Firebase test number, or upgrade the plan.',
    'auth/unauthorized-domain': 'This website address is not authorised in the Firebase console (Authentication > Settings > Authorized domains).',
    'app/no-pending-code': 'Please request a verification code first.',
  };

  function describeError(err) {
    return MESSAGES[err && err.code] || 'Could not verify the mobile number. Please try again.';
  }

  window.FirebaseOtp = {
    init: init, sendCode: sendCode, confirmCode: confirmCode, describeError: describeError,
    _setSdkForTests: function (fake) { sdk = fake; },   // lets the unit tests run without the network
  };
}());
