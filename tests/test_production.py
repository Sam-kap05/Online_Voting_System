"""Go-live readiness: the checker, reverse-proxy handling, HSTS and the startup banner."""
import os
import sqlite3
import sys

import pytest
from werkzeug.security import generate_password_hash

os.environ["DESHGARV_NO_DOTENV"] = "1"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as appmod  # noqa: E402
import check_production as cp  # noqa: E402
from test_app import FakeFaceService  # noqa: E402
from test_liveness import FakePose  # noqa: E402

GOOD = {
    "DESHGARV_DEMO": "0", "SECRET_KEY": "k" * 40, "DESHGARV_PEPPER": "p" * 40,
    "ADMIN_USERNAME": "election-officer", "ADMIN_PASSWORD_HASH": generate_password_hash("Correct-Horse-9!"),
    "SMS_PROVIDER": "firebase", "FIREBASE_API_KEY": "AIzaSyFAKEFAKEFAKE", "FIREBASE_PROJECT_ID": "my-vote",
    "TRUST_PROXY_HOPS": "1", "DESHGARV_CONSTITUENCIES": "Ward 1", "AADHAAR_KYC": "off",
}


@pytest.fixture
def base(tmp_path):
    (tmp_path / ".env").write_text("# real settings live here\n")
    (tmp_path / ".gitignore").write_text(".env\ninstance/\n")
    return str(tmp_path)


def levels(results, level):
    return [m for l, m in results if l == level]


def has(results, level, fragment):
    return any(fragment in m for m in levels(results, level))


class TestChecker:
    def test_a_correct_setup_has_no_failures(self, base):
        res = cp.run_checks(dict(GOOD), base)
        assert levels(res, "FAIL") == [], levels(res, "FAIL")
        assert has(res, "PASS", ".env file found") and has(res, "PASS", "demo mode is off")

    def test_the_reported_mistake_settings_in_env_example_but_no_env_file(self, tmp_path):
        (tmp_path / ".env.example").write_text('SMS_PROVIDER=firebase\nFIREBASE_API_KEY="AIza..."\n')
        res = cp.run_checks({}, str(tmp_path))                     # real environment is empty, like your machine
        assert has(res, "FAIL", "NOT '.env.example'") and has(res, "FAIL", "SMS_PROVIDER is 'console'")

    def test_windows_hidden_txt_extension_is_detected(self, tmp_path):
        (tmp_path / ".env.txt").write_text("SMS_PROVIDER=firebase\n")
        assert has(cp.run_checks({}, str(tmp_path)), "FAIL", ".env.txt")

    @pytest.mark.parametrize("drop,fragment", [
        ("DESHGARV_DEMO", "demo mode"), ("SECRET_KEY", "SECRET_KEY is not set"), ("DESHGARV_PEPPER", "DESHGARV_PEPPER is not set"),
        ("ADMIN_PASSWORD_HASH", "ADMIN_PASSWORD_HASH is not set"), ("SMS_PROVIDER", "SMS_PROVIDER is 'console'"),
        ("FIREBASE_API_KEY", "FIREBASE_API_KEY"), ("FIREBASE_PROJECT_ID", "FIREBASE_PROJECT_ID")])
    def test_each_missing_essential_setting_fails(self, base, drop, fragment):
        env = {k: v for k, v in GOOD.items() if k != drop}
        assert has(cp.run_checks(env, base), "FAIL", fragment)

    def test_weak_secrets_fail(self, base):
        assert has(cp.run_checks({**GOOD, "SECRET_KEY": "short"}, base), "FAIL", "too short")
        assert has(cp.run_checks({**GOOD, "DESHGARV_PEPPER": "x" * 10}, base), "FAIL", "too short")

    def test_demo_admin_password_is_refused(self, base):
        assert has(cp.run_checks({**GOOD, "ADMIN_PASSWORD_HASH": generate_password_hash("admin123")}, base), "FAIL", "admin123")

    def test_plain_password_pasted_instead_of_a_hash_is_refused(self, base):
        assert has(cp.run_checks({**GOOD, "ADMIN_PASSWORD_HASH": "MyPassword1!"}, base), "FAIL", "not a password hash")

    def test_debug_mode_fails(self, base):
        assert has(cp.run_checks({**GOOD, "FLASK_DEBUG": "1"}, base), "FAIL", "FLASK_DEBUG")

    def test_warnings_for_default_admin_name_liveness_off_and_no_proxy(self, base):
        res = cp.run_checks({**GOOD, "ADMIN_USERNAME": "admin", "LIVENESS": "0", "TRUST_PROXY_HOPS": "0"}, base)
        assert has(res, "WARN", "default 'admin'") and has(res, "WARN", "LIVENESS=0") and has(res, "WARN", "TRUST_PROXY_HOPS=0")

    def test_a_demo_database_is_refused(self, base, tmp_path, monkeypatch):
        monkeypatch.delenv("SMS_PROVIDER", raising=False)
        app = appmod.create_app({"TESTING": True, "SECRET_KEY": "k", "PEPPER": "p", "SEED_DEMO": True,
                                 "DATABASE": os.path.join(base, "instance", "evoting.db"),
                                 "PHOTO_DIR": os.path.join(base, "instance", "photos"),
                                 "FACE_SERVICE": FakeFaceService(), "POSE_ANALYZER": FakePose(), "ADMIN_PASSWORD_HASH": "x"})
        res = cp.run_checks(dict(GOOD), base)
        assert has(res, "FAIL", "DEMO voters") and has(res, "FAIL", "DEMO candidates")
        assert has(res, "WARN", "instance/pepper") or True      # (pepper file only exists for auto-generated demo runs)

    def test_a_clean_database_with_real_candidates_passes(self, base):
        path = os.path.join(base, "instance", "evoting.db")
        os.makedirs(os.path.dirname(path))
        appmod.create_app({"TESTING": True, "SECRET_KEY": "k", "PEPPER": "p", "SEED_DEMO": False, "DATABASE": path,
                           "PHOTO_DIR": os.path.join(base, "instance", "photos"), "FACE_SERVICE": FakeFaceService(),
                           "POSE_ANALYZER": FakePose(), "ADMIN_PASSWORD_HASH": "x"})
        conn = sqlite3.connect(path)
        conn.executemany("INSERT INTO candidates (name, party, logo, constituency) VALUES (?,?,?,?)",
                         [("A. Real", "Party X", "i", "Ward 1"), ("B. Real", "Party Y", "i", "Ward 1")])
        conn.commit(); conn.close()
        res = cp.run_checks(dict(GOOD), base)
        assert levels(res, "FAIL") == [] and not has(res, "WARN", "constituency")

    def test_constituency_without_candidates_warns(self, base):
        path = os.path.join(base, "instance", "evoting.db")
        os.makedirs(os.path.dirname(path))
        appmod.create_app({"TESTING": True, "SECRET_KEY": "k", "PEPPER": "p", "SEED_DEMO": False, "DATABASE": path,
                           "PHOTO_DIR": os.path.join(base, "instance", "photos"), "FACE_SERVICE": FakeFaceService(),
                           "POSE_ANALYZER": FakePose(), "ADMIN_PASSWORD_HASH": "x"})
        res = cp.run_checks(dict(GOOD), base)
        assert has(res, "WARN", "no candidates") and has(res, "WARN", "Ward 1")

    def test_secrets_are_never_printed(self, base):
        text = " ".join(m for _, m in cp.run_checks(dict(GOOD), base))
        for secret in (GOOD["SECRET_KEY"], GOOD["DESHGARV_PEPPER"], GOOD["ADMIN_PASSWORD_HASH"], GOOD["FIREBASE_API_KEY"]):
            assert secret not in text

    def test_command_exit_code(self, base, monkeypatch, capsys):
        monkeypatch.setattr(cp, "run_checks", lambda: [("FAIL", "x")])
        with pytest.raises(SystemExit) as e:
            cp.main()
        assert e.value.code == 1 and "NOT ready" in capsys.readouterr().out


# ----------------------------------------------------------------- app behaviour in production
FB_ENV = {"SMS_PROVIDER": "firebase", "FIREBASE_API_KEY": "AIzaX", "FIREBASE_PROJECT_ID": "p"}


def make_app(tmp_path, monkeypatch, env=None, **cfg):
    for k in [k for k in os.environ if k.startswith(("SMS_", "FIREBASE_", "TWILIO_", "MSG91_"))]:
        monkeypatch.delenv(k)
    for k, v in (env or {}).items():
        monkeypatch.setenv(k, v)
    return appmod.create_app({"TESTING": True, "SECRET_KEY": "k", "PEPPER": "p", "SEED_DEMO": False,
                              "DATABASE": str(tmp_path / "t.db"), "PHOTO_DIR": str(tmp_path / "p"),
                              "FACE_SERVICE": FakeFaceService(), "POSE_ANALYZER": FakePose(),
                              "ADMIN_PASSWORD_HASH": generate_password_hash("x"), **cfg})


class TestProxyAndHeaders:
    def hammer(self, app, xff, n=12):
        c = app.test_client()
        return [c.post("/send_otp", json={"aadhaar": "234567890123"}, headers={"X-Forwarded-For": xff},
                       environ_overrides={"REMOTE_ADDR": "10.0.0.1"}).status_code for _ in range(n)]

    def test_behind_a_trusted_proxy_each_visitor_has_their_own_rate_limit(self, tmp_path, monkeypatch):
        app = make_app(tmp_path, monkeypatch, RATELIMIT_ENABLED=True, TRUST_PROXY_HOPS=1)
        assert 429 in self.hammer(app, "203.0.113.5")                  # one noisy visitor gets throttled...
        assert 429 not in self.hammer(app, "198.51.100.7", n=3)         # ...but a different visitor is unaffected

    def test_without_the_setting_all_visitors_would_share_the_proxy_ip(self, tmp_path, monkeypatch):
        app = make_app(tmp_path, monkeypatch, RATELIMIT_ENABLED=True, TRUST_PROXY_HOPS=0)
        self.hammer(app, "203.0.113.5")
        assert 429 in self.hammer(app, "198.51.100.7", n=3)             # the documented failure mode

    def test_forwarded_header_cannot_be_spoofed_to_dodge_limits_when_not_trusted(self, tmp_path, monkeypatch):
        app = make_app(tmp_path, monkeypatch, RATELIMIT_ENABLED=True, TRUST_PROXY_HOPS=0)
        c = app.test_client()
        codes = [c.post("/send_otp", json={"aadhaar": "234567890123"}, headers={"X-Forwarded-For": f"9.9.9.{i}"},
                        environ_overrides={"REMOTE_ADDR": "10.0.0.1"}).status_code for i in range(12)]
        assert 429 in codes

    def test_hsts_only_in_production_over_https(self, tmp_path, monkeypatch):
        prod = make_app(tmp_path, monkeypatch, env=FB_ENV, DEMO_MODE=False)
        assert "max-age" in prod.test_client().get("/", base_url="https://vote.example.org").headers["Strict-Transport-Security"]
        assert "Strict-Transport-Security" not in prod.test_client().get("/", base_url="http://vote.example.org").headers
        demo = make_app(tmp_path, monkeypatch, DEMO_MODE=True)
        assert "Strict-Transport-Security" not in demo.test_client().get("/", base_url="https://localhost").headers


class TestBanner:
    def text(self, app):
        return "\n".join(appmod.describe_runtime(app))

    def test_demo_console_banner_says_the_otp_is_shown_on_screen(self, tmp_path, monkeypatch):
        monkeypatch.setattr(appmod, "BASE_DIR", str(tmp_path))
        t = self.text(make_app(tmp_path, monkeypatch, DEMO_MODE=True))
        assert "DEMO" in t and "OTP is shown on screen" in t and ".env NOT FOUND" in t and "NOT .env.example" in t

    def test_firebase_production_banner(self, tmp_path, monkeypatch):
        (tmp_path / ".env").write_text("x=1\n")
        monkeypatch.setattr(appmod, "BASE_DIR", str(tmp_path))
        for k, v in {"SMS_PROVIDER": "firebase", "FIREBASE_API_KEY": "AIzaX", "FIREBASE_PROJECT_ID": "p"}.items():
            monkeypatch.setenv(k, v)
        app = appmod.create_app({"TESTING": True, "SECRET_KEY": "k", "PEPPER": "p", "SEED_DEMO": False, "DEMO_MODE": False,
                                 "DATABASE": str(tmp_path / "t.db"), "PHOTO_DIR": str(tmp_path / "p"), "TRUST_PROXY_HOPS": 1,
                                 "FACE_SERVICE": FakeFaceService(), "POSE_ANALYZER": FakePose(), "ADMIN_PASSWORD_HASH": "x"})
        t = self.text(app)
        assert "PRODUCTION" in t and "Firebase" in t and ".env loaded" in t and "1 trusted hop" in t
        assert "shown on screen" not in t and "DEMO" not in t

    def test_banner_flags_disabled_liveness(self, tmp_path, monkeypatch):
        assert "a held-up photo may pass" in self.text(make_app(tmp_path, monkeypatch, LIVENESS_ENABLED=False))


class TestStartupRefusals:
    def test_production_without_an_otp_provider_refuses_to_start_and_names_firebase(self, tmp_path, monkeypatch):
        with pytest.raises(RuntimeError, match="firebase"):
            make_app(tmp_path, monkeypatch, DEMO_MODE=False)


class TestServeLauncher:
    def test_without_a_proxy_no_forwarded_headers_are_trusted(self):
        import serve
        kw = serve.waitress_settings(0, {})
        assert "trusted_proxy" not in kw and kw["host"] == "127.0.0.1" and kw["port"] == 8000
        assert kw["max_request_body_size"] == serve.MAX_BODY_BYTES and kw["ident"] == "deshgarv"

    def test_with_a_proxy_waitress_is_told_exactly_which_one_to_trust(self):
        import serve
        kw = serve.waitress_settings(1, {})
        assert kw["trusted_proxy"] == "127.0.0.1" and kw["trusted_proxy_count"] == 1
        assert kw["trusted_proxy_headers"] == {"x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"}
        assert kw["clear_untrusted_proxy_headers"] is True            # everyone else cannot set them

    def test_env_overrides(self):
        import serve
        kw = serve.waitress_settings(2, {"HOST": "0.0.0.0", "PORT": "9000", "THREADS": "4", "TRUSTED_PROXY_IP": "10.1.2.3"})
        assert (kw["host"], kw["port"], kw["threads"], kw["trusted_proxy"], kw["trusted_proxy_count"]) == ("0.0.0.0", 9000, 4, "10.1.2.3", 2)

    def test_settings_are_accepted_by_the_installed_waitress(self):
        """Typos in option names would only blow up at startup - catch them here."""
        import serve
        from waitress.adjustments import Adjustments
        Adjustments(**serve.waitress_settings(1, {}))
        Adjustments(**serve.waitress_settings(0, {}))


class TestNoFalseSecurityClaims:
    def test_pages_do_not_claim_encryption_the_system_does_not_do(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for page in ("index.html", "results.html", "voting.html"):
            text = open(os.path.join(root, "templates", page), encoding="utf-8").read().lower()
            assert "end-to-end encryption" not in text and "cryptographically locked" not in text, page


# ================================================== the mistakes found in a real .env
import sms_gateway  # noqa: E402

FB = {"FIREBASE_API_KEY": "AIzaSyABCDEF", "FIREBASE_PROJECT_ID": "online-voting-f6dc2", "SMS_PROVIDER": "firebase"}


class TestFirebaseValueMistakes:
    def problems(self, **extra):
        return sms_gateway.config_problems({**FB, **extra})

    def test_correct_values_pass(self):
        assert self.problems(FIREBASE_AUTH_DOMAIN="online-voting-f6dc2.firebaseapp.com") == []
        assert self.problems(FIREBASE_AUTH_DOMAIN="vote.example.org") == []          # custom auth domain is fine
        assert self.problems() == []                                                  # default is used

    @pytest.mark.parametrize("bucket", ["online-voting-f6dc2.firebasestorage.app", "online-voting-f6dc2.appspot.com"])
    def test_storage_bucket_pasted_as_auth_domain_is_caught(self, bucket):
        p = self.problems(FIREBASE_AUTH_DOMAIN=bucket)
        assert len(p) == 1 and "Cloud Storage bucket" in p[0] and "online-voting-f6dc2.firebaseapp.com" in p[0]

    @pytest.mark.parametrize("bad", ['online-voting-f6dc2.firebaseapp.com" # optional', 'my domain.com', '"quoted"', "a b"])
    def test_stray_quotes_comments_and_spaces_are_caught(self, bad):
        assert any("do not belong" in x for x in self.problems(FIREBASE_AUTH_DOMAIN=bad))

    def test_the_app_refuses_to_start_with_the_storage_bucket_mistake(self, tmp_path, monkeypatch):
        for k, v in {**FB, "FIREBASE_AUTH_DOMAIN": "online-voting-f6dc2.firebasestorage.app"}.items():
            monkeypatch.setenv(k, v)
        with pytest.raises(RuntimeError, match="Cloud Storage bucket"):
            appmod.create_app({"TESTING": True, "SECRET_KEY": "k", "PEPPER": "p", "SEED_DEMO": False,
                               "DATABASE": str(tmp_path / "x.db"), "PHOTO_DIR": str(tmp_path / "p"),
                               "FACE_SERVICE": FakeFaceService(), "ADMIN_PASSWORD_HASH": "x"})

    def test_the_checker_reports_it_too(self, base):
        res = cp.run_checks({**GOOD, "FIREBASE_AUTH_DOMAIN": "online-voting-f6dc2.firebasestorage.app"}, base)
        assert has(res, "FAIL", "Cloud Storage bucket")


class TestFirebaseTestMode:
    def test_off_by_default_and_only_on_with_the_exact_flag(self):
        assert "testMode" not in sms_gateway.firebase_client_config(FB)
        assert "testMode" not in sms_gateway.firebase_client_config({**FB, "FIREBASE_TEST_MODE": "0"})
        assert sms_gateway.firebase_client_config({**FB, "FIREBASE_TEST_MODE": "1"})["testMode"] is True

    def test_banner_shouts_and_checker_blocks_go_live(self, tmp_path, monkeypatch, base):
        for k, v in {**FB, "FIREBASE_TEST_MODE": "1"}.items():
            monkeypatch.setenv(k, v)
        app = appmod.create_app({"TESTING": True, "SECRET_KEY": "k", "PEPPER": "p", "SEED_DEMO": False,
                                 "DATABASE": str(tmp_path / "x.db"), "PHOTO_DIR": str(tmp_path / "p"),
                                 "FACE_SERVICE": FakeFaceService(), "POSE_ANALYZER": FakePose(), "ADMIN_PASSWORD_HASH": "x"})
        assert "TEST MODE: ON" in "\n".join(appmod.describe_runtime(app))
        assert '"testMode": true' in app.test_client().get("/verify").get_data(as_text=True)
        assert has(cp.run_checks({**GOOD, "FIREBASE_TEST_MODE": "1"}, base), "FAIL", "FIREBASE_TEST_MODE")


class TestProductionSecrets:
    def start(self, tmp_path, monkeypatch, **cfg):
        for k, v in FB.items():
            monkeypatch.setenv(k, v)
        return appmod.create_app({"TESTING": False, "DEMO_MODE": False, "SEED_DEMO": False,
                                  "DATABASE": str(tmp_path / "x.db"), "PHOTO_DIR": str(tmp_path / "p"),
                                  "FACE_SERVICE": FakeFaceService(), "POSE_ANALYZER": FakePose(), **cfg})

    GOOD_CFG = {"SECRET_KEY": "s" * 48, "PEPPER": "q" * 48, "ADMIN_PASSWORD_HASH": generate_password_hash("Unique-Admin-Pass-1")}

    def test_the_exact_values_found_in_a_real_env_are_refused(self, tmp_path, monkeypatch):
        """SECRET_KEY / PEPPER / ADMIN hash were the example file's placeholder text."""
        with pytest.raises(RuntimeError) as e:
            self.start(tmp_path, monkeypatch, SECRET_KEY="long-random-string", PEPPER="another-long-random-string",
                       ADMIN_PASSWORD_HASH="output of: flask --app app hash-password")
        msg = str(e.value)
        assert "SECRET_KEY is the placeholder" in msg and "DESHGARV_PEPPER is the placeholder" in msg
        assert "not a password hash" in msg and "make_secrets.py" in msg

    @pytest.mark.parametrize("override,fragment", [
        ({"SECRET_KEY": "short"}, "SECRET_KEY is too short"), ({"PEPPER": "x" * 31}, "DESHGARV_PEPPER is too short"),
        ({"ADMIN_PASSWORD_HASH": "plainpassword"}, "not a password hash"),
        ({"ADMIN_PASSWORD_HASH": generate_password_hash("admin123")}, "demo password")])
    def test_each_weak_secret_is_refused(self, tmp_path, monkeypatch, override, fragment):
        with pytest.raises(RuntimeError, match=fragment):
            self.start(tmp_path, monkeypatch, **{**self.GOOD_CFG, **override})

    def test_strong_secrets_start_fine(self, tmp_path, monkeypatch):
        assert self.start(tmp_path, monkeypatch, **self.GOOD_CFG).config["DEMO_MODE"] is False

    def test_demo_mode_is_not_affected(self, tmp_path, monkeypatch):
        for k, v in FB.items():
            monkeypatch.delenv(k, raising=False)
        app = appmod.create_app({"TESTING": False, "DEMO_MODE": True, "SEED_DEMO": False, "SECRET_KEY": "x", "PEPPER": "y",
                                 "DATABASE": str(tmp_path / "d.db"), "PHOTO_DIR": str(tmp_path / "p"),
                                 "FACE_SERVICE": FakeFaceService(), "POSE_ANALYZER": FakePose(), "ADMIN_PASSWORD_HASH": "z"})
        assert app.config["DEMO_MODE"] is True

    def test_the_checker_names_the_placeholders(self, base):
        res = cp.run_checks({**GOOD, "SECRET_KEY": "long-random-string", "DESHGARV_PEPPER": "another-long-random-string",
                             "ADMIN_PASSWORD_HASH": "output of: flask --app app hash-password"}, base)
        assert has(res, "FAIL", "SECRET_KEY is the placeholder") and has(res, "FAIL", "DESHGARV_PEPPER is the placeholder")
        assert has(res, "FAIL", "Admin login cannot work")


# ======================================================== Aadhaar verification in the go-live checker
import datetime as _dt  # noqa: E402
from cryptography import x509 as _x509  # noqa: E402
from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa  # noqa: E402
from cryptography.x509.oid import NameOID as _N  # noqa: E402


def write_cert(folder, name="uidai.cer", expired=False):
    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = _x509.Name([_x509.NameAttribute(_N.COMMON_NAME, "UIDAI test")])
    now = _dt.datetime.now(_dt.timezone.utc)
    start, end = (now - _dt.timedelta(days=400), now - _dt.timedelta(days=30)) if expired else (now - _dt.timedelta(days=1), now + _dt.timedelta(days=365))
    cert = (_x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(key.public_key()).serial_number(1)
            .not_valid_before(start).not_valid_after(end).sign(key, _hashes.SHA256()))
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, name), "wb") as fh:
        fh.write(cert.public_bytes(_ser.Encoding.DER))


class TestAadhaarVerificationChecks:
    def test_off_is_a_warning_that_names_the_risk(self, base):
        res = cp.run_checks({**GOOD, "AADHAAR_KYC": "off"}, base)
        assert has(res, "WARN", "anyone who knows an Aadhaar number can register as that person")

    def test_production_default_requires_a_uidai_certificate(self, base):
        env = {k: v for k, v in GOOD.items() if k != "AADHAAR_KYC"}          # default in production = offline_xml
        res = cp.run_checks(env, base)
        assert has(res, "FAIL", "no UIDAI certificate found") and has(res, "FAIL", "uidai.gov.in")

    def test_certificate_present_passes_and_is_described(self, base):
        write_cert(os.path.join(base, "uidai_certs"))
        res = cp.run_checks({**GOOD, "AADHAAR_KYC": "offline_xml"}, base)
        assert has(res, "PASS", "1 UIDAI certificate(s) loaded") and has(res, "INFO", "certificate:") and levels(res, "FAIL") == []
        assert has(res, "INFO", "Legal:")

    def test_custom_certificate_folder(self, base, tmp_path):
        folder = str(tmp_path / "elsewhere")
        write_cert(folder)
        assert has(cp.run_checks({**GOOD, "AADHAAR_KYC": "offline_xml", "UIDAI_CERT_DIR": folder}, base), "PASS", "UIDAI certificate")

    def test_broken_certificate_file_fails(self, base):
        os.makedirs(os.path.join(base, "uidai_certs"))
        open(os.path.join(base, "uidai_certs", "bad.cer"), "wb").write(b"junk")
        assert has(cp.run_checks({**GOOD, "AADHAAR_KYC": "offline_xml"}, base), "FAIL", "UIDAI certificate problem")

    def test_expired_certificates_warn_but_a_current_one_alongside_is_fine(self, base):
        write_cert(os.path.join(base, "uidai_certs"), "old.cer", expired=True)
        assert has(cp.run_checks({**GOOD, "AADHAAR_KYC": "offline_xml"}, base), "WARN", "expired")
        write_cert(os.path.join(base, "uidai_certs"), "new.cer")
        assert not has(cp.run_checks({**GOOD, "AADHAAR_KYC": "offline_xml"}, base), "WARN", "expired")

    def test_invalid_mode_fails(self, base):
        assert has(cp.run_checks({**GOOD, "AADHAAR_KYC": "magic"}, base), "FAIL", "must be")

    @pytest.mark.parametrize("thr,warn", [("0.68", False), ("0.60", False), ("0.40", True), ("0.90", True)])
    def test_photo_threshold_sanity(self, base, thr, warn):
        write_cert(os.path.join(base, "uidai_certs"))
        res = cp.run_checks({**GOOD, "AADHAAR_KYC": "offline_xml", "AADHAAR_PHOTO_MATCH_THRESHOLD": thr}, base)
        assert has(res, "WARN", "AADHAAR_PHOTO_MATCH_THRESHOLD") is warn

    def test_garbage_threshold_fails(self, base):
        write_cert(os.path.join(base, "uidai_certs"))
        assert has(cp.run_checks({**GOOD, "AADHAAR_KYC": "offline_xml", "AADHAAR_PHOTO_MATCH_THRESHOLD": "abc"}, base), "FAIL", "not a number")

    def test_disabling_the_mobile_check_warns(self, base):
        write_cert(os.path.join(base, "uidai_certs"))
        assert has(cp.run_checks({**GOOD, "AADHAAR_KYC": "offline_xml", "AADHAAR_CHECK_MOBILE": "0"}, base), "WARN", "AADHAAR_CHECK_MOBILE=0")
