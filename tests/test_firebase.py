"""
Firebase phone-OTP verification: token checks + the login/registration flows.

No network and no Firebase project needed: tokens are signed with a locally generated RSA key and the
server is given the matching certificate, so the REAL signature / audience / expiry logic runs.
(What this cannot test: Google actually sending an SMS - see the README setup steps for that.)
"""
import datetime
import hashlib
import hmac
import io
import json
import os
import sqlite3
import sys
import time
import uuid

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

os.environ["DESHGARV_NO_DOTENV"] = "1"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as appmod  # noqa: E402
import firebase_auth as fa  # noqa: E402
from firebase_auth import CertCache, FirebaseAuthError  # noqa: E402
from test_app import FakeFaceService, add_candidates, jpeg  # noqa: E402
from test_liveness import FakePose  # noqa: E402

PROJECT = "demo-vote-proj"
ENV = {"SMS_PROVIDER": "firebase", "FIREBASE_API_KEY": "AIzaFAKEKEY", "FIREBASE_PROJECT_ID": PROJECT}


def make_keypair(kid="kid-1"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            cert.public_bytes(serialization.Encoding.PEM).decode(), kid)


ORIGINAL_SEND_SMS = appmod.send_sms          # before any fixture replaces it
PRIV, CERT, KID = make_keypair()
OTHER_PRIV, OTHER_CERT, _ = make_keypair()


def token(phone="+919812345678", *, project=PROJECT, priv=PRIV, kid=KID, alg="RS256", provider="phone",
          auth_age=5, exp_in=3600, iat_off=0, sub="uid-abc", drop=(), extra=None):
    now = int(time.time())
    claims = {"iss": f"https://securetoken.google.com/{project}", "aud": project, "sub": sub, "user_id": sub,
              "iat": now + iat_off, "exp": now + exp_in, "auth_time": now - auth_age, "phone_number": phone,
              "firebase": {"sign_in_provider": provider, "identities": {"phone": [phone]}},
              "_uniq": uuid.uuid4().hex}     # tests only: two sign-ins in one second must not be byte-identical
    claims.update(extra or {})
    for k in drop:
        claims.pop(k, None)
    return jwt.encode(claims, priv, algorithm=alg, headers={"kid": kid} if kid else {})


def cache(certs=None, counter=None):
    def fetch():
        if counter is not None:
            counter.append(1)
        return (certs if certs is not None else {KID: CERT}), 3600
    return CertCache(fetcher=fetch)


# ====================================================== verify_id_token (pure)
class TestVerifier:
    def test_valid_phone_token(self):
        c = fa.verify_id_token(token(), PROJECT, cache())
        assert c["phone_number"] == "+919812345678" and c["firebase"]["sign_in_provider"] == "phone"

    @pytest.mark.parametrize("label,kwargs", [
        ("wrong audience / other firebase project", dict(project="someone-elses-project")),
        ("expired", dict(exp_in=-120)),
        ("issued in the future", dict(iat_off=3600)),
        ("phone sign-in too old", dict(auth_age=900)),
        ("auth_time in the future", dict(auth_age=-3600)),
        ("not a phone sign-in (e.g. Google/anonymous)", dict(provider="google.com")),
        ("missing phone_number", dict(drop=("phone_number",))),
        ("garbage phone_number", dict(phone="not-a-number")),
        ("missing subject", dict(drop=("sub",))),
        ("missing auth_time", dict(drop=("auth_time",))),
        ("empty subject", dict(sub="")),
        ("signed by someone else's key", dict(priv=OTHER_PRIV)),
        ("unknown key id", dict(kid="kid-unknown")),
        ("no key id at all", dict(kid=None)),
    ])
    def test_rejected(self, label, kwargs):
        with pytest.raises(FirebaseAuthError):
            fa.verify_id_token(token(**kwargs), PROJECT, cache())

    def test_wrong_issuer_rejected(self):
        with pytest.raises(FirebaseAuthError):
            fa.verify_id_token(token(extra={"iss": "https://securetoken.google.com/other"}), PROJECT, cache())

    def test_tampered_payload_rejected(self):
        h, p, s = token().split(".")
        import base64
        body = json.loads(base64.urlsafe_b64decode(p + "=="))
        body["phone_number"] = "+911111111111"
        forged = base64.urlsafe_b64encode(json.dumps(body).encode()).rstrip(b"=").decode()
        with pytest.raises(FirebaseAuthError):
            fa.verify_id_token(f"{h}.{forged}.{s}", PROJECT, cache())

    def test_alg_none_rejected(self):
        import base64
        enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        now = int(time.time())
        forged = enc({"alg": "none", "kid": KID}) + "." + enc({
            "iss": f"https://securetoken.google.com/{PROJECT}", "aud": PROJECT, "sub": "x", "iat": now, "exp": now + 99,
            "auth_time": now, "phone_number": "+919812345678", "firebase": {"sign_in_provider": "phone"}}) + "."
        with pytest.raises(FirebaseAuthError, match="algorithm"):
            fa.verify_id_token(forged, PROJECT, cache())

    def test_hs256_key_confusion_rejected(self):
        """Classic attack: sign with HS256 using the (public) certificate text as the HMAC secret.
        Built by hand because PyJWT itself refuses to create such a token."""
        import base64
        enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=")
        now = int(time.time())
        signing = enc({"alg": "HS256", "kid": KID, "typ": "JWT"}) + b"." + enc({
            "iss": f"https://securetoken.google.com/{PROJECT}", "aud": PROJECT, "sub": "x", "iat": now, "exp": now + 99,
            "auth_time": now, "phone_number": "+919812345678", "firebase": {"sign_in_provider": "phone"}})
        sig = base64.urlsafe_b64encode(hmac.new(CERT.encode(), signing, hashlib.sha256).digest()).rstrip(b"=")
        with pytest.raises(FirebaseAuthError, match="algorithm"):
            fa.verify_id_token((signing + b"." + sig).decode(), PROJECT, cache())

    @pytest.mark.parametrize("junk", ["", "abc", "a.b.c", "....", "x" * 5000])
    def test_garbage_rejected(self, junk):
        with pytest.raises(FirebaseAuthError):
            fa.verify_id_token(junk, PROJECT, cache())

    def test_missing_project_id_is_a_config_error(self):
        with pytest.raises(FirebaseAuthError, match="not configured"):
            fa.verify_id_token(token(), "", cache())

    def test_max_age_is_configurable(self):
        t = token(auth_age=100)
        assert fa.verify_id_token(t, PROJECT, cache(), max_age=300)
        with pytest.raises(FirebaseAuthError):
            fa.verify_id_token(t, PROJECT, cache(), max_age=30)


class TestCertCache:
    def test_certs_fetched_once_while_fresh(self):
        calls = []
        c = cache(counter=calls)
        for _ in range(5):
            fa.verify_id_token(token(), PROJECT, c)
        assert len(calls) == 1

    def test_unknown_key_triggers_one_refetch_then_is_throttled(self):
        calls = []
        c = cache(counter=calls)
        fa.verify_id_token(token(), PROJECT, c)
        for _ in range(5):                                    # attacker spraying unknown key ids
            with pytest.raises(FirebaseAuthError):
                fa.verify_id_token(token(kid="nope"), PROJECT, c)
        assert len(calls) == 1                                # never hammers Google (min_refresh=60s)

    def test_key_rotation_is_picked_up(self):
        certs = {KID: CERT}
        calls = []
        c = CertCache(fetcher=lambda: (calls.append(1) or dict(certs), 3600), min_refresh=0)
        fa.verify_id_token(token(), PROJECT, c)
        certs["kid-2"] = OTHER_CERT                           # Google publishes a new key
        assert fa.verify_id_token(token(priv=OTHER_PRIV, kid="kid-2"), PROJECT, c)
        assert len(calls) == 2

    def test_fetch_failure_is_an_auth_error_not_a_crash(self):
        def boom():
            raise FirebaseAuthError("network down")
        with pytest.raises(FirebaseAuthError):
            fa.verify_id_token(token(), PROJECT, CertCache(fetcher=boom))


# ====================================================== app flows (firebase mode)
@pytest.fixture
def ctx(tmp_path, monkeypatch):
    for k in [k for k in os.environ if k.startswith(("SMS_", "TWILIO_", "MSG91_", "FIREBASE_"))]:
        monkeypatch.delenv(k)
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    sent, fake = [], FakeFaceService()
    monkeypatch.setattr(appmod, "send_sms", lambda p, m: sent.append((p, m)))
    app = appmod.create_app({
        "TESTING": True, "SECRET_KEY": "k", "PEPPER": "p", "DATABASE": str(tmp_path / "t.db"),
        "PHOTO_DIR": str(tmp_path / "ph"), "SEED_DEMO": False, "RATELIMIT_ENABLED": False,
        "LIVENESS_ENABLED": False, "FACE_SERVICE": fake, "POSE_ANALYZER": FakePose(),
        "FIREBASE_CERTS": cache(), "ADMIN_PASSWORD_HASH": appmod.generate_password_hash("x")})
    return type("C", (), dict(app=app, fake=fake, sent=sent, tmp=tmp_path))


def db_of(ctx):
    conn = sqlite3.connect(ctx.app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    return conn


def reg_start(ctx, client, aadhaar="234567890123", phone="9812345678", name="Test Voter"):
    ctx.fake.faces = [FakeFaceService.face([1.0, 0, 0, 0])]
    return client.post("/register/start", data={
        "name": name, "aadhaar": aadhaar, "phone": phone, "constituency": "New Delhi",
        "photo": (io.BytesIO(jpeg()), "me.jpg")}, content_type="multipart/form-data")


def register(ctx, client, aadhaar="234567890123", phone="9812345678", face=None):
    if face:
        ctx.fake.faces = [FakeFaceService.face(face)]
    r = reg_start(ctx, client, aadhaar, phone)
    assert r.status_code == 200, r.get_json()
    if face:
        ctx.fake.faces = [FakeFaceService.face(face)]
    r = client.post("/register/verify", json={"id_token": token(f"+91{phone}")})
    assert r.status_code == 200, r.get_json()


class TestRegistrationWithFirebase:
    def test_start_defers_to_the_browser_and_sends_nothing_itself(self, ctx):
        r = reg_start(ctx, ctx.app.test_client())
        body = r.get_json()
        assert r.status_code == 200 and body["mode"] == "firebase" and body["phone"] == "9812345678"
        assert "otp" not in body and ctx.sent == []                          # no server OTP, no server SMS
        assert db_of(ctx).execute("SELECT COUNT(*) FROM otp_codes").fetchone()[0] == 0
        assert db_of(ctx).execute("SELECT COUNT(*) FROM voters").fetchone()[0] == 0   # not registered yet

    def test_valid_token_completes_registration(self, ctx):
        c = ctx.app.test_client()
        register(ctx, c)
        row = db_of(ctx).execute("SELECT name, aadhaar_last4 FROM voters").fetchone()
        assert row["name"] == "Test Voter" and row["aadhaar_last4"] == "0123"

    def test_token_for_a_different_phone_is_refused(self, ctx):
        c = ctx.app.test_client()
        reg_start(ctx, c, phone="9812345678")
        r = c.post("/register/verify", json={"id_token": token("+919999999999")})   # attacker proved ANOTHER number
        assert r.status_code == 400 and "not the mobile number" in r.get_json()["message"]
        assert db_of(ctx).execute("SELECT COUNT(*) FROM voters").fetchone()[0] == 0

    @pytest.mark.parametrize("bad", [dict(project="evil"), dict(exp_in=-100), dict(auth_age=1000),
                                     dict(priv=OTHER_PRIV), dict(provider="google.com")])
    def test_bad_tokens_never_register_anyone(self, ctx, bad):
        c = ctx.app.test_client()
        reg_start(ctx, c)
        r = c.post("/register/verify", json={"id_token": token(**bad)})
        assert r.status_code == 400
        assert db_of(ctx).execute("SELECT COUNT(*) FROM voters").fetchone()[0] == 0

    def test_old_style_otp_field_is_ignored_in_firebase_mode(self, ctx):
        c = ctx.app.test_client()
        reg_start(ctx, c)
        assert c.post("/register/verify", json={"otp": "123456"}).status_code == 400

    def test_token_is_single_use(self, ctx):
        t = token("+919812345678")
        a, b = ctx.app.test_client(), ctx.app.test_client()
        reg_start(ctx, a)
        reg_start(ctx, b, aadhaar="345678901234", phone="9812345678")      # same phone, other Aadhaar
        ctx.fake.faces = [FakeFaceService.face([0, 1.0, 0, 0])]
        assert a.post("/register/verify", json={"id_token": t}).status_code == 200
        r = b.post("/register/verify", json={"id_token": t})                # replay of the same proof
        assert r.status_code == 400 and "already used" in r.get_json()["message"]
        assert db_of(ctx).execute("SELECT COUNT(*) FROM voters").fetchone()[0] == 1

    def test_cannot_verify_without_a_registration_session(self, ctx):
        assert ctx.app.test_client().post("/register/verify", json={"id_token": token()}).status_code == 410

    def test_resend_just_points_the_browser_back_to_firebase(self, ctx):
        c = ctx.app.test_client()
        reg_start(ctx, c)
        body = c.post("/register/resend").get_json()
        assert body["mode"] == "firebase" and body["phone"] == "9812345678" and ctx.sent == []


class TestLoginWithFirebase:
    def voter(self, ctx):
        register(ctx, ctx.app.test_client())
        return ctx.app.test_client()

    def test_send_otp_sends_no_sms_and_reveals_only_a_hint(self, ctx):
        c = self.voter(ctx)
        r = c.post("/send_otp", json={"aadhaar": "234567890123"})
        body = r.get_json()
        assert r.status_code == 200 and body["mode"] == "firebase" and "otp" not in body and ctx.sent == []
        assert body["phone_hint"] == "98XXXXXX78" and "9812345678" not in json.dumps(body)   # number NOT disclosed
        assert db_of(ctx).execute("SELECT COUNT(*) FROM otp_codes").fetchone()[0] == 0

    def test_valid_token_logs_in_and_starts_the_face_step(self, ctx):
        c = self.voter(ctx)
        c.post("/send_otp", json={"aadhaar": "234567890123"})
        r = c.post("/verify_otp", json={"aadhaar": "234567890123", "id_token": token("+919812345678")})
        assert r.status_code == 200 and r.get_json()["success"]
        assert c.get("/voter_details").status_code == 401                    # face check still required
        ctx.fake.faces = [FakeFaceService.face([1.0, 0, 0, 0])]
        for _ in range(3):
            r = c.post("/verify_face", data={"frame": (io.BytesIO(jpeg()), "f.jpg")}, content_type="multipart/form-data")
        assert r.get_json()["verified"] is True

    def test_someone_elses_verified_phone_cannot_log_in_as_this_voter(self, ctx):
        """Knowing a victim's Aadhaar and verifying YOUR OWN phone must not log you in as them."""
        c = self.voter(ctx)
        r = c.post("/verify_otp", json={"aadhaar": "234567890123", "id_token": token("+917777777777")})
        assert r.status_code == 400 and c.get("/voter_details").status_code == 401

    def test_token_replay_is_blocked(self, ctx):
        self.voter(ctx)
        t = token("+919812345678")
        first, second = ctx.app.test_client(), ctx.app.test_client()
        assert first.post("/verify_otp", json={"aadhaar": "234567890123", "id_token": t}).status_code == 200
        r = second.post("/verify_otp", json={"aadhaar": "234567890123", "id_token": t})
        assert r.status_code == 400

    @pytest.mark.parametrize("payload", [{}, {"id_token": ""}, {"id_token": 123}, {"otp": "123456"},
                                         {"id_token": "a.b.c"}, {"id_token": "x" * 5000}])
    def test_missing_or_garbage_tokens_rejected(self, ctx, payload):
        c = self.voter(ctx)
        r = c.post("/verify_otp", json={"aadhaar": "234567890123", **payload})
        assert r.status_code == 400 and c.get("/voter_details").status_code == 401

    def test_already_voted_citizen_still_blocked(self, ctx):
        c = self.voter(ctx)
        conn = db_of(ctx); conn.execute("UPDATE voters SET has_voted = 1"); conn.commit()
        assert c.post("/send_otp", json={"aadhaar": "234567890123"}).status_code == 400
        assert c.post("/verify_otp", json={"aadhaar": "234567890123", "id_token": token()}).status_code == 400

    def test_unknown_aadhaar(self, ctx):
        c = ctx.app.test_client()
        assert c.post("/send_otp", json={"aadhaar": "999999999999"}).status_code == 404
        assert c.post("/verify_otp", json={"aadhaar": "999999999999", "id_token": token()}).status_code == 404

    def test_used_tokens_are_purged_after_they_expire(self, ctx):
        c = self.voter(ctx)
        c.post("/verify_otp", json={"aadhaar": "234567890123", "id_token": token()})
        conn = db_of(ctx); conn.execute("UPDATE used_tokens SET expires_at = 1"); conn.commit()
        with ctx.app.test_request_context():
            appmod.purge_expired(appmod.get_db())
        assert db_of(ctx).execute("SELECT COUNT(*) FROM used_tokens").fetchone()[0] == 0


class TestPagesAndConfig:
    def test_pages_receive_only_the_public_firebase_config(self, ctx, monkeypatch):
        monkeypatch.setenv("TWILIO_AUTH_TOKEN", "super-secret-should-never-leak")
        monkeypatch.setenv("SECRET_KEY", "also-secret")
        for path in ("/verify", "/register"):
            html = ctx.app.test_client().get(path).get_data(as_text=True)
            assert "firebase_otp.js" in html and "AIzaFAKEKEY" in html and PROJECT in html
            assert "super-secret" not in html and "also-secret" not in html
            assert 'id="recaptcha-container"' in html

    def test_pages_without_firebase_do_not_load_it(self, tmp_path, monkeypatch):
        for k in [k for k in os.environ if k.startswith(("SMS_", "FIREBASE_"))]:
            monkeypatch.delenv(k)
        app = appmod.create_app({"TESTING": True, "SECRET_KEY": "k", "PEPPER": "p", "DATABASE": str(tmp_path / "x.db"),
                                 "PHOTO_DIR": str(tmp_path / "p"), "SEED_DEMO": False, "LIVENESS_ENABLED": False,
                                 "FACE_SERVICE": FakeFaceService(), "POSE_ANALYZER": FakePose(), "ADMIN_PASSWORD_HASH": "x"})
        html = app.test_client().get("/verify").get_data(as_text=True)
        assert "firebase_otp.js" not in html and "const FIREBASE_CONFIG = null" in html

    @pytest.mark.parametrize("missing", ["FIREBASE_API_KEY", "FIREBASE_PROJECT_ID"])
    def test_startup_fails_fast_when_firebase_settings_are_incomplete(self, tmp_path, monkeypatch, missing):
        for k, v in ENV.items():
            monkeypatch.setenv(k, v)
        monkeypatch.delenv(missing)
        with pytest.raises(RuntimeError, match=missing):
            appmod.create_app({"TESTING": True, "SECRET_KEY": "k", "PEPPER": "p", "DATABASE": str(tmp_path / "x.db"),
                               "PHOTO_DIR": str(tmp_path / "p"), "SEED_DEMO": False, "FACE_SERVICE": FakeFaceService(),
                               "ADMIN_PASSWORD_HASH": "x"})

    def test_production_mode_accepts_firebase_as_the_otp_provider(self, tmp_path, monkeypatch):
        for k, v in ENV.items():
            monkeypatch.setenv(k, v)
        app = appmod.create_app({"TESTING": True, "SECRET_KEY": "k", "PEPPER": "p", "DEMO_MODE": False, "SEED_DEMO": False,
                                 "DATABASE": str(tmp_path / "x.db"), "PHOTO_DIR": str(tmp_path / "p"),
                                 "FACE_SERVICE": FakeFaceService(), "POSE_ANALYZER": FakePose(), "ADMIN_PASSWORD_HASH": "x"})
        assert app.config["DEMO_MODE"] is False

    def test_client_config_helper(self):
        assert sms_cfg({"FIREBASE_API_KEY": "k", "FIREBASE_PROJECT_ID": "p"}) == {
            "apiKey": "k", "projectId": "p", "authDomain": "p.firebaseapp.com"}
        assert sms_cfg({"FIREBASE_API_KEY": "k", "FIREBASE_PROJECT_ID": "p", "FIREBASE_AUTH_DOMAIN": "vote.example.com",
                        "FIREBASE_APP_ID": "1:2:web:3"})["authDomain"] == "vote.example.com"

    def test_test_sms_command_explains_firebase_mode(self, ctx, monkeypatch):
        monkeypatch.setattr(appmod, "send_sms", ORIGINAL_SEND_SMS)
        out = ctx.app.test_cli_runner().invoke(args=["test-sms", "9812345678"])
        assert out.exit_code != 0 and "firebase" in out.output.lower()


def sms_cfg(env):
    import sms_gateway
    return sms_gateway.firebase_client_config(env)


class TestDeliveryHelp:
    def test_both_pages_tell_voters_what_to_do_when_the_code_does_not_arrive(self, ctx):
        for path in ("/register", "/verify"):
            html = ctx.app.test_client().get(path).get_data(as_text=True)
            assert "Didn't receive the code?" in html and "Wait up to 2 minutes" in html and "blocked / spam" in html
            assert "requested at" in html                       # timestamp to correlate with Firebase's records
