"""
Behavioural tests for the DeshGarv voting flow.

A fake face engine is used so these run in a second without TensorFlow.
(`tests/e2e_real_face.py` exercises the real DeepFace pipeline.)
"""
import hashlib
import json
import os
import re
import sqlite3
import sys
import threading

import cv2
import numpy as np
import pytest

os.environ["DESHGARV_NO_DOTENV"] = "1"   # never let a developer's .env leak into tests
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as appmod  # noqa: E402
from face_service import Face, cosine_distance  # noqa: E402

PERSON_A = [1.0, 0.0, 0.0, 0.0]
PERSON_B = [0.0, 1.0, 0.0, 0.0]
PERSON_C = [0.0, 0.0, 1.0, 0.0]


class FakeFaceService:
    """Stands in for DeepFaceService; tests choose what 'the camera sees'."""
    match_threshold = 0.55
    duplicate_threshold = 0.35

    def __init__(self):
        self.faces = [self.face(PERSON_A)]
        self.crop_embedding = PERSON_A          # what embed_crop() "sees" (used by the liveness step)

    @staticmethod
    def face(emb, ratio=0.4):
        return Face(embedding=emb, confidence=0.95, x=0, y=0, w=100, h=100, ratio=ratio)

    def available(self):
        return True

    def detect(self, img):
        return list(self.faces)

    def embed_crop(self, face_bgr):
        return list(self.crop_embedding)

    def distance(self, a, b):
        return cosine_distance(a, b)


def jpeg(w=320, h=320):
    ok, buf = cv2.imencode(".jpg", np.random.randint(0, 255, (h, w, 3), dtype=np.uint8))
    assert ok
    return buf.tobytes()


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    for key in [k for k in os.environ if k.startswith(("SMS_", "TWILIO_", "MSG91_"))]:
        monkeypatch.delenv(key)
    sent = []                                       # captured SMS messages
    monkeypatch.setattr(appmod, "send_sms", lambda phone, msg: sent.append((phone, msg)))
    fake = FakeFaceService()
    app = appmod.create_app({
        "TESTING": True, "SECRET_KEY": "test-secret", "PEPPER": "test-pepper",
        "DATABASE": str(tmp_path / "t.db"), "PHOTO_DIR": str(tmp_path / "photos"),
        "SEED_DEMO": False, "RATELIMIT_ENABLED": False, "OTP_RESEND_COOLDOWN": 0,
        "LIVENESS_ENABLED": False,   # liveness has its own suite (test_liveness.py)
        "FACE_SERVICE": fake, "ADMIN_PASSWORD_HASH": appmod.generate_password_hash("s3cret!"),
    })
    return type("Ctx", (), dict(app=app, fake=fake, sent=sent, tmp=tmp_path))


def last_otp(ctx):
    return re.match(r"(\d{6})", ctx.sent[-1][1]).group(1)


def db_of(ctx):
    conn = sqlite3.connect(ctx.app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    return conn


def add_candidates(ctx):
    conn = db_of(ctx)
    conn.executemany("INSERT INTO candidates (name, party, logo, constituency) VALUES (?,?,?,?)", [
        ("Alice", "Party A", "x", "New Delhi"), ("Bob", "Party B", "x", "New Delhi"),
        ("Carol", "Party C", "x", "Mumbai South")])
    conn.commit()
    conn.close()


def register(ctx, client, aadhaar="234567890123", phone="9812345678", name="Test Voter",
             const="New Delhi", face=PERSON_A, finish=True):
    ctx.fake.faces = [FakeFaceService.face(face)]
    r = client.post("/register/start", data={
        "name": name, "aadhaar": aadhaar, "phone": phone, "constituency": const,
        "photo": (__import__("io").BytesIO(jpeg()), "me.jpg")}, content_type="multipart/form-data")
    if finish and r.status_code == 200:
        r2 = client.post("/register/verify", json={"otp": last_otp(ctx)})
        assert r2.status_code == 200, r2.get_json()
    return r


def login_to_face_step(ctx, client, aadhaar="234567890123"):
    assert client.post("/send_otp", json={"aadhaar": aadhaar}).status_code == 200
    r = client.post("/verify_otp", json={"aadhaar": aadhaar, "otp": last_otp(ctx)})
    assert r.status_code == 200, r.get_json()


def pass_face_check(ctx, client, face=PERSON_A):
    ctx.fake.faces = [FakeFaceService.face(face)]
    for _ in range(ctx.app.config["FACE_STREAK_REQUIRED"]):
        r = client.post("/verify_face", data={"frame": (__import__("io").BytesIO(jpeg()), "f.jpg")},
                        content_type="multipart/form-data")
    assert r.get_json()["verified"] is True


def frame(client):
    return client.post("/verify_face", data={"frame": (__import__("io").BytesIO(jpeg()), "f.jpg")},
                       content_type="multipart/form-data")


@pytest.fixture
def voter(ctx):
    """A registered voter who has completed OTP + face check."""
    add_candidates(ctx)
    c = ctx.app.test_client()
    register(ctx, c)
    login_to_face_step(ctx, c)
    pass_face_check(ctx, c)
    return c


# ============================================================ registration ====
class TestRegistration:
    def test_happy_path_creates_voter_who_can_log_in(self, ctx):
        c = ctx.app.test_client()
        r = register(ctx, c)
        assert r.status_code == 200 and r.get_json()["success"]
        assert "otp" in r.get_json()                     # demo mode echoes the OTP
        login_to_face_step(ctx, c)                       # the new voter can authenticate

    def test_aadhaar_is_never_stored_in_clear(self, ctx):
        register(ctx, ctx.app.test_client(), aadhaar="234567890123")
        dump = "".join(str(tuple(r)) for r in db_of(ctx).execute("SELECT * FROM voters"))
        assert "234567890123" not in dump
        assert db_of(ctx).execute("SELECT aadhaar_last4 FROM voters").fetchone()[0] == "0123"

    def test_photo_is_not_web_accessible(self, ctx):
        c = ctx.app.test_client()
        register(ctx, c)
        photo = db_of(ctx).execute("SELECT photo_file FROM voters").fetchone()[0]
        assert os.path.exists(os.path.join(ctx.app.config["PHOTO_DIR"], photo))
        assert c.get(f"/static/uploads/{photo}").status_code == 404
        assert c.get(f"/static/{photo}").status_code == 404

    @pytest.mark.parametrize("field,value", [
        ("aadhaar", "12345"), ("aadhaar", "12345678901a"), ("phone", "12345"),
        ("phone", "1234567890"),                          # Indian mobiles start 6-9
        ("name", "A"), ("name", "<script>alert(1)</script>"), ("name", "Bob123"),
        ("const", "Atlantis"),
    ])
    def test_rejects_bad_fields(self, ctx, field, value):
        kw = {field: value}
        r = register(ctx, ctx.app.test_client(), finish=False, **kw)
        assert r.status_code == 400 and not r.get_json()["success"]
        assert db_of(ctx).execute("SELECT COUNT(*) FROM voters").fetchone()[0] == 0

    def test_unicode_names_are_accepted(self, ctx):
        r = register(ctx, ctx.app.test_client(), name="सामर्थ कपूर")   # Devanagari with matras
        assert r.status_code == 200

    def test_rejects_non_image_upload(self, ctx):
        r = ctx.app.test_client().post("/register/start", data={
            "name": "X Y", "aadhaar": "234567890123", "phone": "9812345678",
            "constituency": "New Delhi",
            "photo": (__import__("io").BytesIO(b"<?php evil(); ?>"), "me.jpg")},
            content_type="multipart/form-data")
        assert r.status_code == 400

    def test_rejects_photo_without_a_face(self, ctx):
        ctx.fake.faces = []
        c = ctx.app.test_client()
        r = c.post("/register/start", data={
            "name": "X Y", "aadhaar": "234567890123", "phone": "9812345678",
            "constituency": "New Delhi", "photo": (__import__("io").BytesIO(jpeg()), "m.jpg")},
            content_type="multipart/form-data")
        assert r.status_code == 400 and "No face" in r.get_json()["message"]

    def test_rejects_photo_with_several_faces(self, ctx):
        ctx.fake.faces = [FakeFaceService.face(PERSON_A), FakeFaceService.face(PERSON_B)]
        r = ctx.app.test_client().post("/register/start", data={
            "name": "X Y", "aadhaar": "234567890123", "phone": "9812345678",
            "constituency": "New Delhi", "photo": (__import__("io").BytesIO(jpeg()), "m.jpg")},
            content_type="multipart/form-data")
        assert r.status_code == 400 and "exactly one" in r.get_json()["message"]

    def test_rejects_tiny_face(self, ctx):
        ctx.fake.faces = [FakeFaceService.face(PERSON_A, ratio=0.05)]
        r = ctx.app.test_client().post("/register/start", data={
            "name": "X Y", "aadhaar": "234567890123", "phone": "9812345678",
            "constituency": "New Delhi", "photo": (__import__("io").BytesIO(jpeg()), "m.jpg")},
            content_type="multipart/form-data")
        assert r.status_code == 400 and "too small" in r.get_json()["message"]

    def test_duplicate_aadhaar_rejected(self, ctx):
        register(ctx, ctx.app.test_client())
        r = register(ctx, ctx.app.test_client(), face=PERSON_B, finish=False)
        assert r.status_code == 409 and "already registered" in r.get_json()["message"]

    def test_same_face_under_a_second_aadhaar_rejected(self, ctx):
        register(ctx, ctx.app.test_client(), aadhaar="234567890123")
        r = register(ctx, ctx.app.test_client(), aadhaar="345678901234", phone="9811111111",
                     face=PERSON_A, finish=False)
        assert r.status_code == 409 and "matching face" in r.get_json()["message"]
        # ...but a genuinely different person is fine
        assert register(ctx, ctx.app.test_client(), aadhaar="345678901234", phone="9811111111",
                        face=PERSON_C).status_code == 200

    def test_no_voter_is_created_until_otp_confirmed(self, ctx):
        register(ctx, ctx.app.test_client(), finish=False)
        assert db_of(ctx).execute("SELECT COUNT(*) FROM voters").fetchone()[0] == 0

    def test_wrong_registration_otp_does_not_register(self, ctx):
        c = ctx.app.test_client()
        register(ctx, c, finish=False)
        r = c.post("/register/verify", json={"otp": "000000" if last_otp(ctx) != "000000" else "111111"})
        assert r.status_code == 400
        assert db_of(ctx).execute("SELECT COUNT(*) FROM voters").fetchone()[0] == 0

    def test_registration_otp_goes_to_the_phone_given(self, ctx):
        register(ctx, ctx.app.test_client(), phone="9876501234", finish=False)
        assert ctx.sent[-1][0] == "9876501234"

    def test_verify_without_starting_is_rejected(self, ctx):
        assert ctx.app.test_client().post("/register/verify", json={"otp": "123456"}).status_code == 410

    def test_cannot_complete_someone_elses_pending_registration(self, ctx):
        alice, mallory = ctx.app.test_client(), ctx.app.test_client()
        register(ctx, alice, finish=False)
        otp = last_otp(ctx)
        assert mallory.post("/register/verify", json={"otp": otp}).status_code == 410  # no reg session
        assert db_of(ctx).execute("SELECT COUNT(*) FROM voters").fetchone()[0] == 0

    def test_resend_issues_new_otp(self, ctx):
        c = ctx.app.test_client()
        register(ctx, c, finish=False)
        n = len(ctx.sent)
        assert c.post("/register/resend").status_code == 200 and len(ctx.sent) == n + 1


# ===================================================================== OTP ====
class TestOtp:
    def setup_voter(self, ctx):
        c = ctx.app.test_client()
        register(ctx, c)
        return ctx.app.test_client()

    def test_otp_not_echoed_outside_demo_mode(self, ctx):
        ctx.app.config["DEMO_MODE"] = False
        c = self.setup_voter(ctx)
        r = c.post("/send_otp", json={"aadhaar": "234567890123"})
        assert r.status_code == 200 and "otp" not in r.get_json()
        assert re.match(r"\d{6} is your DeshGarv", ctx.sent[-1][1])      # but SMS was "sent"

    def test_lockout_after_too_many_wrong_attempts(self, ctx):
        c = self.setup_voter(ctx)
        c.post("/send_otp", json={"aadhaar": "234567890123"})
        good = last_otp(ctx)
        bad = "000000" if good != "000000" else "111111"
        for _ in range(ctx.app.config["OTP_MAX_ATTEMPTS"]):
            assert c.post("/verify_otp", json={"aadhaar": "234567890123", "otp": bad}).status_code == 400
        r = c.post("/verify_otp", json={"aadhaar": "234567890123", "otp": good})   # even the right code
        assert r.status_code == 400 and "Too many" in r.get_json()["message"]

    def test_otp_is_single_use(self, ctx):
        c = self.setup_voter(ctx)
        c.post("/send_otp", json={"aadhaar": "234567890123"})
        otp = last_otp(ctx)
        assert c.post("/verify_otp", json={"aadhaar": "234567890123", "otp": otp}).status_code == 200
        assert ctx.app.test_client().post("/verify_otp", json={"aadhaar": "234567890123", "otp": otp}).status_code == 400

    def test_otp_expires(self, ctx):
        c = self.setup_voter(ctx)
        c.post("/send_otp", json={"aadhaar": "234567890123"})
        conn = db_of(ctx); conn.execute("UPDATE otp_codes SET expires_at = 1"); conn.commit()
        r = c.post("/verify_otp", json={"aadhaar": "234567890123", "otp": last_otp(ctx)})
        assert r.status_code == 400 and "expired" in r.get_json()["message"]

    def test_otp_is_stored_hashed(self, ctx):
        c = self.setup_voter(ctx)
        c.post("/send_otp", json={"aadhaar": "234567890123"})
        stored = db_of(ctx).execute("SELECT code_hash FROM otp_codes").fetchone()[0]
        assert last_otp(ctx) not in stored and len(stored) == 64

    def test_resend_cooldown(self, ctx):
        ctx.app.config["OTP_RESEND_COOLDOWN"] = 60
        c = self.setup_voter(ctx)
        assert c.post("/send_otp", json={"aadhaar": "234567890123"}).status_code == 200
        assert c.post("/send_otp", json={"aadhaar": "234567890123"}).status_code == 429

    def test_unknown_aadhaar_and_already_voted(self, ctx):
        c = self.setup_voter(ctx)
        assert c.post("/send_otp", json={"aadhaar": "999999999999"}).status_code == 404
        conn = db_of(ctx); conn.execute("UPDATE voters SET has_voted = 1"); conn.commit()
        r = c.post("/send_otp", json={"aadhaar": "234567890123"})
        assert r.status_code == 400 and "already cast" in r.get_json()["message"]

    def test_sms_outage_returns_503_and_leaves_no_otp(self, ctx, monkeypatch):
        c = self.setup_voter(ctx)
        def boom(*a): raise appmod.SmsUnavailable("down")
        monkeypatch.setattr(appmod, "send_sms", boom)
        assert c.post("/send_otp", json={"aadhaar": "234567890123"}).status_code == 503
        assert db_of(ctx).execute("SELECT COUNT(*) FROM otp_codes").fetchone()[0] == 0


# ============================================ flow enforcement (the big fix) ====
class TestFlowEnforcement:
    def test_ballot_is_unreachable_without_any_login(self, ctx):
        add_candidates(ctx)
        c = ctx.app.test_client()
        assert c.get("/voting-page").status_code == 302
        assert c.get("/voter_details").status_code == 401
        assert c.post("/cast_vote", json={"candidate_id": 1}).status_code == 401

    def test_otp_alone_does_not_unlock_the_ballot(self, ctx):
        """Old behaviour: after OTP you could open /voting-page directly and skip the face check."""
        add_candidates(ctx)
        c = ctx.app.test_client()
        register(ctx, c)
        login_to_face_step(ctx, c)
        r = c.get("/voting-page")
        assert r.status_code == 302 and r.headers["Location"].endswith("/verify")
        assert c.get("/voter_details").status_code == 401
        assert c.post("/cast_vote", json={"candidate_id": 1}).status_code == 401
        assert db_of(ctx).execute("SELECT SUM(votes) FROM candidates").fetchone()[0] == 0

    def test_face_check_unlocks_the_ballot(self, voter):
        assert voter.get("/voting-page").status_code == 200
        d = voter.get("/voter_details").get_json()
        assert d["voter"]["constituency"] == "New Delhi" and d["voter"]["aadhaar"].endswith("0123")
        assert {c["name"] for c in d["candidates"]} == {"Alice", "Bob"}

    def test_wrong_person_never_unlocks_the_ballot(self, ctx):
        add_candidates(ctx)
        c = ctx.app.test_client()
        register(ctx, c)
        login_to_face_step(ctx, c)
        ctx.fake.faces = [FakeFaceService.face(PERSON_B)]
        for _ in range(10):
            r = frame(c).get_json()
            assert r["status"] == "no_match" and r["verified"] is False
        assert c.get("/voter_details").status_code == 401

    def test_two_people_in_frame_blocked(self, ctx):
        add_candidates(ctx)
        c = ctx.app.test_client()
        register(ctx, c)
        login_to_face_step(ctx, c)
        ctx.fake.faces = [FakeFaceService.face(PERSON_A), FakeFaceService.face(PERSON_B)]
        r = frame(c).get_json()
        assert r["status"] == "multiple_faces" and r["verified"] is False

    def test_empty_frame_blocked(self, ctx):
        c = ctx.app.test_client()
        register(ctx, c); login_to_face_step(ctx, c)
        ctx.fake.faces = []
        assert frame(c).get_json()["status"] == "no_face"

    def test_needs_consecutive_matches_and_resets_on_a_miss(self, ctx):
        c = ctx.app.test_client()
        register(ctx, c); login_to_face_step(ctx, c)
        need = ctx.app.config["FACE_STREAK_REQUIRED"]
        ctx.fake.faces = [FakeFaceService.face(PERSON_A)]
        for i in range(need - 1):
            assert frame(c).get_json()["verified"] is False
        ctx.fake.faces = [FakeFaceService.face(PERSON_A), FakeFaceService.face(PERSON_B)]
        assert frame(c).get_json()["streak"] == 0                       # reset
        ctx.fake.faces = [FakeFaceService.face(PERSON_A)]
        for i in range(need - 1):
            assert frame(c).get_json()["verified"] is False
        assert frame(c).get_json()["verified"] is True

    def test_frame_budget_then_lockout(self, ctx):
        ctx.app.config["FACE_MAX_FRAMES"] = 5
        c = ctx.app.test_client()
        register(ctx, c); login_to_face_step(ctx, c)
        ctx.fake.faces = [FakeFaceService.face(PERSON_B)]
        for _ in range(5):
            frame(c)
        assert frame(c).status_code == 429
        assert frame(c).status_code == 401                              # session destroyed

    def test_face_endpoint_needs_otp_session(self, ctx):
        assert frame(ctx.app.test_client()).status_code == 401

    def test_garbage_frame_rejected(self, ctx):
        c = ctx.app.test_client()
        register(ctx, c); login_to_face_step(ctx, c)
        r = c.post("/verify_face", data={"frame": (__import__("io").BytesIO(b"nope"), "f.jpg")},
                   content_type="multipart/form-data")
        assert r.status_code == 400

    def test_session_expires(self, voter, ctx):
        conn = db_of(ctx); conn.execute("UPDATE auth_sessions SET expires_at = 1"); conn.commit()
        assert voter.get("/voter_details").status_code == 401

    def test_cancel_session(self, voter):
        voter.post("/cancel_session")
        assert voter.get("/voter_details").status_code == 401

    def test_forged_session_cookie_token_is_useless(self, ctx):
        add_candidates(ctx)
        c = ctx.app.test_client()
        with c.session_transaction() as s:
            s["auth"] = "made-up-token"
        assert c.get("/voter_details").status_code == 401


# =========================================================== voting integrity ====
class TestVoting:
    def cid(self, ctx, name):
        return db_of(ctx).execute("SELECT id FROM candidates WHERE name=?", (name,)).fetchone()[0]

    def test_vote_is_counted_and_receipt_returned(self, voter, ctx):
        r = voter.post("/cast_vote", json={"candidate_id": self.cid(ctx, "Alice")})
        assert r.status_code == 200
        body = r.get_json()
        assert re.fullmatch(r"[0-9a-f]{64}", body["audit_hash"])
        votes = dict(db_of(ctx).execute("SELECT name, votes FROM candidates").fetchall())
        assert votes["Alice"] == 1 and votes["Bob"] == 0

    def test_cannot_vote_twice(self, voter, ctx):
        cid = self.cid(ctx, "Alice")
        assert voter.post("/cast_vote", json={"candidate_id": cid}).status_code == 200
        assert voter.post("/cast_vote", json={"candidate_id": cid}).status_code == 401   # session gone
        assert db_of(ctx).execute("SELECT SUM(votes) FROM candidates").fetchone()[0] == 1

    def test_cannot_log_in_again_after_voting(self, voter, ctx):
        voter.post("/cast_vote", json={"candidate_id": self.cid(ctx, "Alice")})
        r = ctx.app.test_client().post("/send_otp", json={"aadhaar": "234567890123"})
        assert r.status_code == 400 and "already cast" in r.get_json()["message"]

    def test_old_cookie_cannot_be_replayed_after_voting(self, voter, ctx):
        """Server-side invalidation: a copy of the pre-vote cookie must not work after voting."""
        with voter.session_transaction() as s:
            saved = dict(s)
        voter.post("/cast_vote", json={"candidate_id": self.cid(ctx, "Alice")})
        replay = ctx.app.test_client()
        with replay.session_transaction() as s:
            s.update(saved)
        assert replay.post("/cast_vote", json={"candidate_id": self.cid(ctx, "Bob")}).status_code == 401
        assert db_of(ctx).execute("SELECT SUM(votes) FROM candidates").fetchone()[0] == 1

    def test_simultaneous_requests_count_exactly_one_vote(self, voter, ctx):
        """Race condition: 12 parallel requests on the same verified session."""
        with voter.session_transaction() as s:
            saved = dict(s)
        cid = self.cid(ctx, "Alice")
        results = []

        def attempt():
            cl = ctx.app.test_client()
            with cl.session_transaction() as s:
                s.update(saved)
            results.append(cl.post("/cast_vote", json={"candidate_id": cid}).status_code)

        threads = [threading.Thread(target=attempt) for _ in range(12)]
        [t.start() for t in threads]; [t.join() for t in threads]
        assert results.count(200) == 1, results
        assert db_of(ctx).execute("SELECT SUM(votes) FROM candidates").fetchone()[0] == 1
        assert db_of(ctx).execute("SELECT COUNT(*) FROM votes_audit").fetchone()[0] == 1

    def test_candidate_from_other_constituency_rejected(self, voter, ctx):
        r = voter.post("/cast_vote", json={"candidate_id": self.cid(ctx, "Carol")})
        assert r.status_code == 400
        assert db_of(ctx).execute("SELECT has_voted FROM voters").fetchone()[0] == 0   # not burned

    @pytest.mark.parametrize("bad", [None, "1", 99999, True, -1, [1], {"a": 1}])
    def test_bad_candidate_ids_rejected(self, voter, bad):
        assert voter.post("/cast_vote", json={"candidate_id": bad}).status_code == 400
        assert voter.get("/voter_details").status_code == 200       # voter can still vote properly

    def test_ledger_cannot_be_joined_to_voter_or_candidate(self, voter, ctx):
        """Ballot secrecy. Old code stored the same timestamp in `voters` and the audit table and
        hashed (candidate, constituency, timestamp, constant salt) - linkable and brute-forceable."""
        cid = self.cid(ctx, "Alice")
        receipt = voter.post("/cast_vote", json={"candidate_id": cid}).get_json()["audit_hash"]
        cols = [r[1] for r in db_of(ctx).execute("PRAGMA table_info(votes_audit)")]
        assert not {"timestamp", "voter_id", "candidate_id", "name"} & set(cols)
        row = db_of(ctx).execute("SELECT * FROM votes_audit").fetchone()
        assert row["ballot_hash"] == receipt
        # Not reproducible from the public facts (candidate, constituency) by brute force:
        for cand in ("Alice", "Bob", "1", "2"):
            for salt in ("", "DESHGARV_CYBERSEC_SALT_2026"):
                assert hashlib.sha256(f"{cand}_New Delhi_{salt}".encode()).hexdigest() != receipt

    def test_receipts_are_unique_even_for_identical_votes(self, ctx):
        add_candidates(ctx)
        receipts = []
        for i, (aad, ph) in enumerate([("234567890123", "9812345678"), ("345678901234", "9811111111")]):
            c = ctx.app.test_client()
            register(ctx, c, aadhaar=aad, phone=ph, face=[PERSON_A, PERSON_C][i])
            login_to_face_step(ctx, c, aad)
            pass_face_check(ctx, c, [PERSON_A, PERSON_C][i])
            receipts.append(c.post("/cast_vote", json={"candidate_id": self.cid(ctx, "Alice")}).get_json()["audit_hash"])
        assert receipts[0] != receipts[1]

    def test_ledger_hash_chain_detects_tampering(self, ctx):
        add_candidates(ctx)
        for i, (aad, ph) in enumerate([("234567890123", "9812345678"), ("345678901234", "9811111111"),
                                       ("456789012345", "9822222222")]):
            c = ctx.app.test_client()
            face = [PERSON_A, PERSON_B, PERSON_C][i]
            register(ctx, c, aadhaar=aad, phone=ph, face=face)
            login_to_face_step(ctx, c, aad)
            pass_face_check(ctx, c, face)
            assert c.post("/cast_vote", json={"candidate_id": self.cid(ctx, "Alice")}).status_code == 200
        with ctx.app.app_context():
            ctx.app.test_request_context().push()
            assert appmod.verify_ledger(appmod.get_db()) == (True, 3)
        conn = db_of(ctx)
        conn.execute("DELETE FROM votes_audit WHERE id = 2"); conn.commit()          # delete a ballot
        with ctx.app.test_request_context():
            assert appmod.verify_ledger(appmod.get_db())[0] is False


# ================================================================ admin/results ====
class TestAdmin:
    def login(self, ctx):
        c = ctx.app.test_client()
        assert c.post("/admin/login", json={"username": "admin", "password": "s3cret!"}).status_code == 200
        return c

    def test_results_require_admin(self, ctx):
        c = ctx.app.test_client()
        assert c.get("/results").status_code == 302
        assert c.get("/results_data").status_code == 401

    def test_login_checks_both_fields(self, ctx):
        c = ctx.app.test_client()
        assert c.post("/admin/login", json={"username": "admin", "password": "admin123"}).status_code == 401
        assert c.post("/admin/login", json={"username": "root", "password": "s3cret!"}).status_code == 401
        assert c.post("/admin/login", json={}).status_code == 401

    def test_voter_session_is_not_admin(self, voter):
        assert voter.get("/results_data").status_code == 401

    def test_results_payload_is_masked_and_reports_ledger(self, voter, ctx):
        voter.post("/cast_vote", json={"candidate_id": 1})
        data = self.login(ctx).get("/results_data").get_json()
        assert data["ledger"] == {"ok": True, "ballots": 1}
        assert data["total_registered"] == 1
        v = data["voters"][0]
        assert v["aadhaar"] == "XXXX-XXXX-0123" and "*" in v["name"] and "Test Voter" not in json.dumps(data)

    def test_results_page_lists_configured_constituencies(self, ctx):
        html = self.login(ctx).get("/results").get_data(as_text=True)
        assert "Mumbai South Constituency" in html and "New Delhi Constituency" in html

    def test_login_is_rate_limited(self, ctx):
        ctx.app.config["RATELIMIT_ENABLED"] = True
        c = ctx.app.test_client()
        codes = [c.post("/admin/login", json={"username": "a", "password": "b"}).status_code for _ in range(12)]
        assert 429 in codes


# ============================================================ misc hardening ====
class TestHardening:
    def test_security_headers_and_no_caching(self, ctx):
        r = ctx.app.test_client().get("/register")
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["X-Frame-Options"] == "DENY"
        assert "camera=(self)" in r.headers["Permissions-Policy"]
        assert r.headers["Cache-Control"] == "no-store"

    def test_register_page_lists_constituencies(self, ctx):
        html = ctx.app.test_client().get("/register").get_data(as_text=True)
        assert 'value="New Delhi"' in html and 'value="Mumbai South"' in html

    def test_upload_size_limit(self, ctx):
        ctx.app.config["MAX_CONTENT_LENGTH"] = 1000
        r = ctx.app.test_client().post("/register/start", data={
            "name": "X Y", "aadhaar": "234567890123", "phone": "9812345678", "constituency": "New Delhi",
            "photo": (__import__("io").BytesIO(jpeg(1200, 1200)), "m.jpg")}, content_type="multipart/form-data")
        assert r.status_code == 413

    def test_endpoint_rate_limits(self, ctx):
        ctx.app.config["RATELIMIT_ENABLED"] = True
        c = ctx.app.test_client()
        codes = [c.post("/send_otp", json={"aadhaar": "234567890123"}).status_code for _ in range(12)]
        assert 429 in codes

    def test_production_mode_refuses_to_start_without_secrets(self, monkeypatch, tmp_path):
        monkeypatch.delenv("SECRET_KEY", raising=False)
        monkeypatch.delenv("ADMIN_PASSWORD_HASH", raising=False)
        with pytest.raises(RuntimeError):
            appmod.create_app({"DEMO_MODE": False, "SEED_DEMO": False, "DATABASE": str(tmp_path / "x.db"),
                               "PHOTO_DIR": str(tmp_path / "p"), "FACE_SERVICE": FakeFaceService()})

    def test_admin_secrets_not_hardcoded(self):
        src = open(os.path.join(os.path.dirname(appmod.__file__), "app.py")).read()
        assert "DESHGARV_E_VOTING_SECRET_KEY_2026" not in src and "debug=True" not in src


# ============================================================ demo seed data ====
class TestDemoSeed:
    def test_seed_is_consistent_and_scenarios_work(self, tmp_path, monkeypatch):
        sent = []
        monkeypatch.setattr(appmod, "send_sms", lambda p, m: sent.append(m))
        app = appmod.create_app({
            "TESTING": True, "SECRET_KEY": "k", "PEPPER": "p", "DATABASE": str(tmp_path / "s.db"),
            "PHOTO_DIR": str(tmp_path / "ph"), "SEED_DEMO": True, "RATELIMIT_ENABLED": False, "LIVENESS_ENABLED": False,
            "FACE_SERVICE": FakeFaceService(), "ADMIN_PASSWORD_HASH": appmod.generate_password_hash("x")})
        conn = sqlite3.connect(str(tmp_path / "s.db"))
        voted = conn.execute("SELECT COUNT(*) FROM voters WHERE has_voted=1").fetchone()[0]
        ballots = conn.execute("SELECT COUNT(*) FROM votes_audit").fetchone()[0]
        tally = conn.execute("SELECT SUM(votes) FROM candidates").fetchone()[0]
        assert voted == ballots == tally == 1                       # no phantom voters
        assert conn.execute("SELECT voted_at FROM voters WHERE has_voted=1").fetchone()[0]
        with app.test_request_context():
            assert appmod.verify_ledger(appmod.get_db()) == (True, 1)
        c = app.test_client()
        # README scenario B: already-voted citizen is blocked
        r = c.post("/send_otp", json={"aadhaar": "444455556666"})
        assert r.status_code == 400 and "already cast" in r.get_json()["message"]
        # README scenario A: Samarth can start the flow
        assert c.post("/send_otp", json={"aadhaar": "123456789012"}).status_code == 200
        # every seeded photo exists privately on disk
        for (f,) in conn.execute("SELECT photo_file FROM voters"):
            assert os.path.exists(os.path.join(str(tmp_path / "ph"), f))
