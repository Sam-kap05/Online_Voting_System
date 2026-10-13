"""Aadhaar (UIDAI offline e-KYC) registration flow + one-person-one-registration (duplicate faces)."""
import io
import json
import math
import os
import re
import sqlite3
import sys

import pytest

os.environ["DESHGARV_NO_DOTENV"] = "1"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as appmod  # noqa: E402
import kyc_helpers as kh  # noqa: E402
from face_service import cosine_distance  # noqa: E402
from test_app import FakeFaceService, add_candidates, jpeg, last_otp, login_to_face_step  # noqa: E402
from test_liveness import FakePose  # noqa: E402


def at(deg):
    """Embedding at an angle: cosine distance between at(a) and at(b) = 1 - cos(a-b)."""
    return [math.cos(math.radians(deg)), math.sin(math.radians(deg)), 0.0, 0.0]


def dist_to_deg(d):
    return math.degrees(math.acos(1 - d))


@pytest.fixture
def kctx(tmp_path, monkeypatch):
    for key in [k for k in os.environ if k.startswith(("SMS_", "TWILIO_", "MSG91_", "FIREBASE_", "AADHAAR_", "MIN_VOTING"))]:
        monkeypatch.delenv(key)
    sent, fake = [], FakeFaceService()
    monkeypatch.setattr(appmod, "send_sms", lambda p, m: sent.append((p, m)))
    app = appmod.create_app({
        "TESTING": True, "SECRET_KEY": "k", "PEPPER": "pepper-for-tests", "DATABASE": str(tmp_path / "t.db"),
        "PHOTO_DIR": str(tmp_path / "photos"), "SEED_DEMO": False, "RATELIMIT_ENABLED": False, "OTP_RESEND_COOLDOWN": 0,
        "LIVENESS_ENABLED": False, "AADHAAR_KYC": "offline_xml", "UIDAI_CERTS": [kh.CERT],
        "FACE_SERVICE": fake, "POSE_ANALYZER": FakePose(), "ADMIN_PASSWORD_HASH": appmod.generate_password_hash("x")})
    return type("K", (), dict(app=app, fake=fake, sent=sent, tmp=tmp_path))


def db_of(ctx):
    conn = sqlite3.connect(ctx.app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    return conn


def start(ctx, client, *, zip_bytes=None, share="Lock@487", aadhaar="234567890123", phone="9812345678",
          selfie=at(0), xml_photo=at(10), typed_name="Typed Name", **kyc_kw):
    """POST /register/start with a (by default valid) Aadhaar file. `selfie` / `xml_photo` = what the face engine sees."""
    zip_bytes = zip_bytes if zip_bytes is not None else kh.kyc_zip(share=share, aadhaar=aadhaar, mobile=phone, **kyc_kw)
    ctx.fake.queue = [[FakeFaceService.face(selfie)]] + ([[FakeFaceService.face(xml_photo)]] if xml_photo is not None else [[]])
    data = {"name": typed_name, "aadhaar": aadhaar, "phone": phone, "constituency": "New Delhi", "share_code": share,
            "photo": (io.BytesIO(jpeg()), "me.jpg")}
    if zip_bytes is not False:
        data["kyc_zip"] = (io.BytesIO(zip_bytes), "offlineaadhaar.zip")
    return client.post("/register/start", data=data, content_type="multipart/form-data")


def finish(ctx, client):
    r = client.post("/register/verify", json={"otp": last_otp(ctx)})
    assert r.status_code == 200, r.get_json()
    return r


def no_one_registered(ctx):
    return db_of(ctx).execute("SELECT COUNT(*) FROM voters").fetchone()[0] == 0


# ============================================================ KYC registration: the happy path
class TestKycRegistration:
    def test_a_valid_file_registers_a_verified_voter_with_the_name_from_uidai(self, kctx):
        c = kctx.app.test_client()
        r = start(kctx, c)
        assert r.status_code == 200 and r.get_json()["verified_name"] == "Asha Rao"
        assert no_one_registered(kctx)                                   # not yet: the phone OTP is still pending
        finish(kctx, c)
        v = db_of(kctx).execute("SELECT * FROM voters").fetchone()
        assert v["name"] == "Asha Rao" and v["kyc_verified"] == 1 and v["identity_key"] and v["aadhaar_last4"] == "0123"
        assert "Typed Name" not in json.dumps(dict(v))                   # the unverified typed name is ignored
        assert len(json.loads(v["face_gallery"])) == 1                   # the UIDAI-signed photo is kept as a template

    def test_register_page_shows_the_upload_fields_instead_of_a_name_box(self, kctx):
        html = kctx.app.test_client().get("/register").get_data(as_text=True)
        assert 'id="kyc-file"' in html and 'id="kyc-share"' in html and 'id="reg-name"' not in html
        assert "const KYC_REQUIRED = true" in html

    def test_without_kyc_the_page_is_unchanged(self, kctx):
        kctx.app.config["AADHAAR_KYC"] = "off"
        html = kctx.app.test_client().get("/register").get_data(as_text=True)
        assert 'id="reg-name"' in html and 'id="kyc-file"' not in html and "const KYC_REQUIRED = false" in html


# ========================================================= every way the file can be wrong
class TestKycRejections:
    def rejected(self, kctx, fragment, status=400, **kw):
        c = kctx.app.test_client()
        r = start(kctx, c, **kw)
        assert r.status_code == status and fragment in r.get_json()["message"], r.get_json()
        assert no_one_registered(kctx)
        assert db_of(kctx).execute("SELECT COUNT(*) FROM pending_registrations").fetchone()[0] == 0
        return r

    def test_missing_file(self, kctx):
        self.rejected(kctx, "upload your Aadhaar", zip_bytes=False)

    def test_not_a_zip(self, kctx):
        self.rejected(kctx, "not a valid", zip_bytes=b"hello")

    def test_wrong_share_code(self, kctx):
        z = kh.kyc_zip(share="Lock@487")
        self.rejected(kctx, "share code", zip_bytes=z, share="WRONG")

    def test_tampered_file(self, kctx):
        z = kh.make_zip(kh.build_xml().replace(b"Asha Rao", b"Evil Person"))
        self.rejected(kctx, "signature", zip_bytes=z)

    def test_file_signed_by_someone_other_than_uidai(self, kctx):
        self.rejected(kctx, "signature", zip_bytes=kh.kyc_zip(priv=kh.OTHER_PRIV))

    def test_stale_file(self, kctx):
        import datetime
        old = datetime.datetime.now(kh.uidai_kyc.IST) - datetime.timedelta(days=9)
        self.rejected(kctx, "too old", generated=old)

    def test_aadhaar_number_that_does_not_match_the_file(self, kctx):
        """Attacker knows a victim's number but only has their OWN file."""
        z = kh.kyc_zip(aadhaar="234567890123", mobile="9812345678")
        self.rejected(kctx, "ending in 0123", zip_bytes=z, aadhaar="999988887777", phone="9812345678")

    def test_mobile_that_is_not_the_one_linked_to_the_aadhaar(self, kctx):
        z = kh.kyc_zip(mobile="9812345678")
        self.rejected(kctx, "linked to your Aadhaar", zip_bytes=z, phone="9000000001")

    def test_mobile_check_can_be_switched_off(self, kctx):
        kctx.app.config["AADHAAR_CHECK_MOBILE"] = False
        z = kh.kyc_zip(mobile="9812345678")
        assert start(kctx, kctx.app.test_client(), zip_bytes=z, phone="9000000001").status_code == 200

    def test_under_age(self, kctx):
        import datetime
        young = (datetime.date.today() - datetime.timedelta(days=365 * 16)).isoformat()
        self.rejected(kctx, "at least 18", dob=young)

    def test_age_limit_is_configurable(self, kctx):
        import datetime
        kctx.app.config["MIN_VOTING_AGE"] = 16
        young = (datetime.date.today() - datetime.timedelta(days=365 * 17)).isoformat()
        assert start(kctx, kctx.app.test_client(), dob=young).status_code == 200

    def test_someone_elses_valid_file_with_my_own_face(self, kctx):
        """Attacker has the victim's file (and phone) but their own face: the photo must match the UIDAI photo."""
        self.rejected(kctx, "does not match the photo", selfie=at(0), xml_photo=at(100))        # distance 0.83

    def test_photo_just_inside_the_limit_is_accepted(self, kctx):
        lim = kctx.app.config["AADHAAR_PHOTO_MATCH_THRESHOLD"]
        assert lim == 0.68        # measured on Aadhaar-like low-resolution photos, see README
        assert start(kctx, kctx.app.test_client(), selfie=at(0), xml_photo=at(dist_to_deg(lim - 0.02))).status_code == 200

    def test_photo_just_outside_the_limit_is_refused(self, kctx):
        lim = kctx.app.config["AADHAAR_PHOTO_MATCH_THRESHOLD"]
        self.rejected(kctx, "does not match the photo", selfie=at(0), xml_photo=at(dist_to_deg(lim + 0.02)))

    def test_unusable_photo_inside_the_file(self, kctx):
        self.rejected(kctx, "clear face in the photo inside", xml_photo=None)


# ============================================ one real person -> one registration
class TestOnePersonOneRegistration:
    def test_the_same_person_cannot_register_again_with_another_number_phone_and_face(self, kctx):
        """The reported scenario: register, then try again with a different photo / different details."""
        c = kctx.app.test_client()
        start(kctx, c)
        finish(kctx, c)
        again = kctx.app.test_client()
        # same UIDAI identity (name/dob/gender/last4), different first 8 digits, phone and a different-looking selfie
        r = start(kctx, again, aadhaar="999999990123", phone="9000000002", selfie=at(120), xml_photo=at(125))
        assert r.status_code == 409 and "already registered" in r.get_json()["message"]
        assert db_of(kctx).execute("SELECT COUNT(*) FROM voters").fetchone()[0] == 1

    def test_a_different_person_is_fine(self, kctx):
        c = kctx.app.test_client()
        start(kctx, c)
        finish(kctx, c)
        other = kctx.app.test_client()
        assert start(kctx, other, name="Ravi Kumar", aadhaar="345678901234", phone="9811111111",
                     selfie=at(150), xml_photo=at(155)).status_code == 200

    def test_the_identity_key_is_not_derived_from_anything_the_voter_can_vary(self, kctx):
        keys = []
        for aad, ph, share in (("234567890123", "9812345678", "Lock@487"), ("111111110123", "9000000009", "Other#1")):
            kctx.app.config["AADHAAR_PHOTO_MATCH_THRESHOLD"] = 0.6
            c = kctx.app.test_client()
            r = start(kctx, c, aadhaar=aad, phone=ph, share=share, selfie=at(0), xml_photo=at(5))
            if r.status_code == 200:
                finish(kctx, c)
        keys = [r["identity_key"] for r in db_of(kctx).execute("SELECT identity_key FROM voters")]
        assert len(keys) == 1                                          # the second attempt (same person) was refused

    def test_the_file_share_code_and_photo_are_never_stored(self, kctx):
        c = kctx.app.test_client()
        zip_bytes = kh.kyc_zip()
        start(kctx, c, zip_bytes=zip_bytes)
        finish(kctx, c)
        conn = sqlite3.connect(kctx.app.config["DATABASE"])
        dump = "\n".join(str(tuple(r)) for t in ("voters", "pending_registrations", "otp_codes", "votes_audit")
                         for r in conn.execute(f"SELECT * FROM {t}"))
        assert "Lock@487" not in dump and "UidData" not in dump
        files = os.listdir(kctx.app.config["PHOTO_DIR"])
        assert len(files) == 1 and files[0].endswith(".jpg")           # only the voter's own selfie is on disk

    def test_old_registrations_without_kyc_keep_working(self, kctx):
        kctx.app.config["AADHAAR_KYC"] = "off"
        c = kctx.app.test_client()
        kctx.fake.queue = []
        kctx.fake.faces = [FakeFaceService.face(at(0))]
        r = c.post("/register/start", data={"name": "Old Style", "aadhaar": "456789012345", "phone": "9822222222",
                   "constituency": "New Delhi", "photo": (io.BytesIO(jpeg()), "m.jpg")}, content_type="multipart/form-data")
        assert r.status_code == 200 and "verified_name" not in r.get_json()
        finish(kctx, c)
        assert db_of(kctx).execute("SELECT kyc_verified, identity_key FROM voters").fetchone()[:] == (0, None)

    def test_two_people_without_identity_keys_do_not_collide(self, kctx):
        conn = db_of(kctx)
        for i in range(2):                                              # NULL identity keys must not trip the unique index
            conn.execute("INSERT INTO voters (aadhaar_hash,aadhaar_last4,name,phone,constituency,photo_file,registered_at)"
                         " VALUES (?,?,?,?,?,?,?)", (f"h{i}", "0000", "x", "9", "c", "p", "now"))
        conn.commit()


# ================================================== duplicate faces (the "different photo" hole)
class TestDuplicateFaces:
    def register_plain(self, ctx, client, face, aadhaar, phone):
        ctx.app.config["AADHAAR_KYC"] = "off"
        ctx.fake.queue, ctx.fake.faces = [], [FakeFaceService.face(face)]
        return client.post("/register/start", data={"name": "Some Body", "aadhaar": aadhaar, "phone": phone, "constituency": "New Delhi",
                           "photo": (io.BytesIO(jpeg()), "m.jpg")}, content_type="multipart/form-data")

    def first_voter(self, kctx, face=at(0)):
        c = kctx.app.test_client()
        assert self.register_plain(kctx, c, face, "234567890123", "9812345678").status_code == 200
        finish(kctx, c)

    def test_default_limit_is_0_60(self, monkeypatch):
        monkeypatch.delenv("FACE_DUPLICATE_THRESHOLD", raising=False)
        from face_service import DeepFaceService
        assert DeepFaceService().duplicate_threshold == 0.60

    @pytest.mark.parametrize("d,caught", [(0.0, True), (0.20, True), (0.43, True), (0.55, True), (0.59, True),
                                           (0.62, False), (0.70, False), (0.90, False)])
    def test_a_different_photo_of_the_same_person_is_now_caught(self, kctx, d, caught):
        """Same person, new photo/webcam capture sits at 0.4-0.6. The old 0.35 limit let all of these through."""
        self.first_voter(kctx)
        r = self.register_plain(kctx, kctx.app.test_client(), at(dist_to_deg(d)), "345678901234", "9811111111")
        assert (r.status_code == 409) is caught, (d, r.get_json())

    def test_live_login_faces_become_extra_templates(self, kctx):
        """Registered with photo A; logs in with a webcam face B (matches A at login); a NEW registration that looks
        like B but is far from A must be caught through the stored live template."""
        kctx.app.config["LIVENESS_ENABLED"] = False
        add_candidates(kctx)
        self.first_voter(kctx, face=at(0))
        c = kctx.app.test_client()
        login_to_face_step(kctx, c)
        kctx.fake.queue, kctx.fake.faces = [], [FakeFaceService.face(at(50))]          # webcam face: 0.36 from the photo
        for _ in range(3):
            c.post("/verify_face", data={"frame": (io.BytesIO(jpeg()), "f.jpg")}, content_type="multipart/form-data")
        gallery = json.loads(db_of(kctx).execute("SELECT face_gallery FROM voters").fetchone()[0])
        assert len(gallery) == 1
        r = self.register_plain(kctx, kctx.app.test_client(), at(80), "345678901234", "9811111111")   # 0.83 from photo, 0.13 from live
        assert r.status_code == 409 and "matching face" in r.get_json()["message"]

    def test_gallery_skips_near_identical_templates_and_is_capped(self, kctx):
        self.first_voter(kctx)
        with kctx.app.test_request_context():
            db = appmod.get_db()
            svc = kctx.fake
            for deg in (30, 30.5, 30.2):                      # near-identical -> only one kept
                appmod.add_to_gallery(db, svc, 1, at(deg))
            assert len(json.loads(db.execute("SELECT face_gallery FROM voters").fetchone()[0])) == 1
            for deg in (70, 110, 150, 190, 230, 270, 310):
                appmod.add_to_gallery(db, svc, 1, at(deg))
            gallery = json.loads(db.execute("SELECT face_gallery FROM voters").fetchone()[0])
            assert len(gallery) == appmod.MAX_GALLERY and cosine_distance(gallery[-1], at(310)) < 1e-9

    def test_a_failed_login_attempt_never_pollutes_the_gallery(self, kctx):
        add_candidates(kctx)
        self.first_voter(kctx, face=at(0))
        c = kctx.app.test_client()
        login_to_face_step(kctx, c)
        kctx.fake.queue, kctx.fake.faces = [], [FakeFaceService.face(at(150))]          # someone else
        for _ in range(5):
            c.post("/verify_face", data={"frame": (io.BytesIO(jpeg()), "f.jpg")}, content_type="multipart/form-data")
        assert db_of(kctx).execute("SELECT face_gallery FROM voters").fetchone()[0] is None

    def test_the_limit_can_be_tuned_or_disabled(self, kctx):
        self.first_voter(kctx)
        kctx.fake.duplicate_threshold = 0.30
        assert self.register_plain(kctx, kctx.app.test_client(), at(dist_to_deg(0.45)), "345678901234", "9811111111").status_code == 200
        kctx.fake.duplicate_threshold = 0
        assert self.register_plain(kctx, kctx.app.test_client(), at(0), "456789012345", "9822222222").status_code == 200


# ===================================================================== startup + migration
def base_cfg(tmp):
    return {"TESTING": False, "SECRET_KEY": "k", "PEPPER": "p", "SEED_DEMO": False, "DATABASE": str(tmp / "s.db"),
            "PHOTO_DIR": str(tmp / "p"), "FACE_SERVICE": FakeFaceService(), "POSE_ANALYZER": FakePose(),
            "ADMIN_PASSWORD_HASH": "x", "DEMO_MODE": True}


class TestStartupAndMigration:

    def test_kyc_without_a_uidai_certificate_refuses_to_start_and_explains(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AADHAAR_KYC", raising=False)
        with pytest.raises(RuntimeError) as e:
            appmod.create_app({**base_cfg(tmp_path), "AADHAAR_KYC": "offline_xml", "UIDAI_CERT_DIR": str(tmp_path / "empty")})
        assert "uidai.gov.in" in str(e.value) and "AADHAAR_KYC=off" in str(e.value) and "empty" in str(e.value)

    def test_certificates_are_loaded_from_the_folder(self, tmp_path):
        d = tmp_path / "certs"; d.mkdir()
        (d / "uidai.cer").write_bytes(kh.CERT.public_bytes(kh.serialization.Encoding.DER))
        app = appmod.create_app({**base_cfg(tmp_path), "AADHAAR_KYC": "offline_xml", "UIDAI_CERT_DIR": str(d)})
        assert len(app.extensions["uidai_certs"]) == 1
        assert "UIDAI offline e-KYC (1 certificate(s))" in "\n".join(appmod.describe_runtime(app))

    def test_a_broken_certificate_file_is_reported_clearly(self, tmp_path):
        d = tmp_path / "certs"; d.mkdir()
        (d / "bad.cer").write_bytes(b"nope")
        with pytest.raises(RuntimeError, match="UIDAI certificate problem"):
            appmod.create_app({**base_cfg(tmp_path), "AADHAAR_KYC": "offline_xml", "UIDAI_CERT_DIR": str(d)})

    def test_unknown_mode_is_refused(self, tmp_path):
        with pytest.raises(RuntimeError, match="offline_xml"):
            appmod.create_app({**base_cfg(tmp_path), "AADHAAR_KYC": "magic"})

    def test_defaults_demo_off_production_on(self, tmp_path, monkeypatch):
        for k in ("AADHAAR_KYC", "SMS_PROVIDER"):
            monkeypatch.delenv(k, raising=False)
        assert appmod.create_app({**base_cfg(tmp_path), "TESTING": True}).config["AADHAAR_KYC"] == "off"
        for k, v in {"DESHGARV_DEMO": "0"}.items():
            monkeypatch.setenv(k, v)
        monkeypatch.setenv("SMS_PROVIDER", "firebase"); monkeypatch.setenv("FIREBASE_API_KEY", "AIzaX"); monkeypatch.setenv("FIREBASE_PROJECT_ID", "p")
        prod = appmod.create_app({**base_cfg(tmp_path), "TESTING": True, "DEMO_MODE": False, "DATABASE": str(tmp_path / "p.db")})
        assert prod.config["AADHAAR_KYC"] == "offline_xml"

    def test_banner_warns_when_the_check_is_off(self, tmp_path):
        app = appmod.create_app({**base_cfg(tmp_path), "AADHAAR_KYC": "off"})
        assert "anyone who knows an Aadhaar number can register as that person" in "\n".join(appmod.describe_runtime(app))

    def test_a_database_from_an_older_version_is_upgraded_in_place(self, tmp_path):
        path = str(tmp_path / "old.db")
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE voters (id INTEGER PRIMARY KEY AUTOINCREMENT, aadhaar_hash TEXT UNIQUE NOT NULL, aadhaar_last4 TEXT NOT NULL,"
                     " name TEXT NOT NULL, phone TEXT NOT NULL, constituency TEXT NOT NULL, photo_file TEXT NOT NULL, face_embedding TEXT,"
                     " has_voted INTEGER NOT NULL DEFAULT 0, voted_at TEXT, registered_at TEXT NOT NULL)")
        conn.execute("INSERT INTO voters (aadhaar_hash,aadhaar_last4,name,phone,constituency,photo_file,registered_at) VALUES ('h','1234','Old Voter','9','c','p','t')")
        conn.execute("CREATE TABLE pending_registrations (token TEXT PRIMARY KEY, name TEXT NOT NULL, aadhaar_hash TEXT NOT NULL, aadhaar_last4 TEXT NOT NULL,"
                     " phone TEXT NOT NULL, constituency TEXT NOT NULL, photo_file TEXT NOT NULL, face_embedding TEXT NOT NULL, expires_at REAL NOT NULL)")
        conn.commit(); conn.close()
        appmod.create_app({**base_cfg(tmp_path), "DATABASE": path, "AADHAAR_KYC": "off"})
        c = sqlite3.connect(path)
        cols = {r[1] for r in c.execute("PRAGMA table_info(voters)")}
        assert {"identity_key", "kyc_verified", "face_gallery"} <= cols
        assert c.execute("SELECT name, kyc_verified FROM voters").fetchone() == ("Old Voter", 0)
        assert "identity_key" in {r[1] for r in c.execute("PRAGMA table_info(pending_registrations)")}
        assert any("ux_voters_identity" in r[1] for r in c.execute("PRAGMA index_list(voters)"))
