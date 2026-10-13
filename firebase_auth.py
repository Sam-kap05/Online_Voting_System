"""
Server-side verification of Firebase Authentication ID tokens (phone sign-in).

How the OTP flow works with Firebase
------------------------------------
1. The BROWSER (Firebase JS SDK + invisible reCAPTCHA) asks Firebase to text a code to a phone.
2. The voter types the code; the SDK confirms it with Firebase and receives a signed ID token (a JWT).
3. The browser sends that token to OUR server, which verifies - without trusting the browser:
     * RS256 signature against Google's published signing certificates
     * audience == our Firebase project id, issuer == https://securetoken.google.com/<project>
     * not expired, not issued in the future, authenticated recently (auth_time)
     * sign-in provider is "phone", and the phone number is the one registered for this voter
   and then treats each token as SINGLE-USE (replay protection, done by the caller).

This avoids the heavy firebase-admin SDK: only PyJWT + cryptography are needed.
"""
import json
import re
import threading
import time
import urllib.error
import urllib.request

import jwt
from cryptography import x509

CERTS_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"


class FirebaseAuthError(Exception):
    """The token is not acceptable (message is for server logs, not for users)."""


def _fetch_certs(timeout=10):
    """-> ({kid: pem_certificate}, max_age_seconds). Network errors raise FirebaseAuthError."""
    try:
        with urllib.request.urlopen(urllib.request.Request(CERTS_URL), timeout=timeout) as resp:
            certs = json.loads(resp.read().decode())
            match = re.search(r"max-age=(\d+)", resp.headers.get("Cache-Control", ""))
            return certs, int(match.group(1)) if match else 3600
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise FirebaseAuthError(f"could not fetch Google signing certificates: {exc}")


class CertCache:
    """Caches Google's signing certs. Refetches when they expire, or ONCE per `min_refresh`
    seconds if a token names a key we don't know (key rotation) - never hammering Google."""

    def __init__(self, fetcher=None, min_refresh=60):
        self._fetch = fetcher or _fetch_certs
        self._certs, self._expires, self._fetched_at = {}, 0.0, 0.0
        self._min_refresh = min_refresh
        self._lock = threading.Lock()

    def public_key(self, kid, now=None):
        now = time.time() if now is None else now
        with self._lock:
            stale = now >= self._expires
            unknown = kid not in self._certs and now - self._fetched_at >= self._min_refresh
            if stale or unknown:
                certs, max_age = self._fetch()
                self._certs, self._expires, self._fetched_at = dict(certs), now + max_age, now
            pem = self._certs.get(kid)
        if pem is None:
            raise FirebaseAuthError("token signed with an unknown key id")
        try:
            return x509.load_pem_x509_certificate(pem.encode()).public_key()
        except ValueError as exc:
            raise FirebaseAuthError(f"bad signing certificate: {exc}")


def verify_id_token(token, project_id, cache, now=None, max_age=300, leeway=10):
    """Return the verified claims of a Firebase PHONE sign-in ID token, or raise FirebaseAuthError.

    max_age: how recent (seconds) the phone sign-in must be. The SMS code is typed seconds
    before the token is sent, so a short window keeps stolen tokens nearly useless.
    """
    now = time.time() if now is None else now
    if not project_id:
        raise FirebaseAuthError("FIREBASE_PROJECT_ID is not configured")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise FirebaseAuthError("malformed token")
    if header.get("alg") != "RS256":                      # blocks alg=none and HS256 key-confusion
        raise FirebaseAuthError("unexpected signing algorithm")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise FirebaseAuthError("token has no key id")
    key = cache.public_key(kid, now)
    try:
        claims = jwt.decode(
            token, key, algorithms=["RS256"], audience=project_id,
            issuer=f"https://securetoken.google.com/{project_id}", leeway=leeway,
            options={"require": ["exp", "iat", "aud", "iss", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise FirebaseAuthError(f"token rejected: {type(exc).__name__}")

    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub or len(sub) > 128:
        raise FirebaseAuthError("bad subject")
    auth_time = claims.get("auth_time")
    if not isinstance(auth_time, (int, float)) or auth_time > now + leeway:
        raise FirebaseAuthError("bad auth_time")
    if now - auth_time > max_age:
        raise FirebaseAuthError("phone sign-in is too old")
    if (claims.get("firebase") or {}).get("sign_in_provider") != "phone":
        raise FirebaseAuthError("not a phone sign-in token")
    phone = claims.get("phone_number")
    if not isinstance(phone, str) or not re.fullmatch(r"\+[0-9]{8,15}", phone):
        raise FirebaseAuthError("token has no phone number")
    return claims
