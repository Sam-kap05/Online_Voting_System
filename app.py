"""
DeshGarv - secure online voting portal (Flask).

Voter flow (every step is enforced on the SERVER, not just hidden in the UI):

    Aadhaar  ->  SMS OTP  ->  live face match (browser webcam)  ->  ballot  ->  receipt

Self-registration flow:

    details + photo  ->  face check on photo  ->  SMS OTP to the phone  ->  registered

Run locally (demo mode, OTP is shown on screen):   python app.py
Production:                                         see README ("Going to production")
"""
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import threading
import time
import unicodedata
import uuid
from contextlib import contextmanager
from datetime import date, datetime, timezone
from functools import wraps

import click
import cv2
import numpy as np
from flask import (Blueprint, Flask, current_app, g, jsonify, redirect,
                   render_template, request, session)
from PIL import Image
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

import firebase_auth
import liveness
import sms_gateway
import uidai_kyc
from face_service import DeepFaceService

if not os.environ.get("DESHGARV_NO_DOTENV"):       # optional: read settings from a .env file
    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    except ImportError:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
GENESIS_HASH = "0" * 64
# Example values that have appeared in templates/docs: publicly known, so never acceptable as real secrets.
KNOWN_PLACEHOLDERS = {"long-random-string", "another-long-random-string", "changeme", "change-me", "secret",
                      "password", "your-secret-key", "your_secret_key"}


def production_secret_problems(cfg):
    """Why the secrets are unsafe for real voters ([] = fine). Used at startup in production mode."""
    problems = []
    for key, label in (("SECRET_KEY", "SECRET_KEY"), ("PEPPER", "DESHGARV_PEPPER")):
        value = cfg.get(key) or ""
        if value.lower() in KNOWN_PLACEHOLDERS:
            problems.append(f"{label} is the placeholder text from the example file (publicly known)")
        elif len(value) < 32:
            problems.append(f"{label} is too short ({len(value)} characters; needs 32+ random ones)")
    h = cfg.get("ADMIN_PASSWORD_HASH") or ""
    if not re.match(r"^(scrypt|pbkdf2):", h):
        problems.append("ADMIN_PASSWORD_HASH is not a password hash (it must start with 'scrypt:' or 'pbkdf2:'; "
                        "it looks like placeholder text)")
    elif check_password_hash(h, "admin123"):
        problems.append("ADMIN_PASSWORD_HASH is the hash of the demo password 'admin123'")
    return problems

bp = Blueprint("main", __name__)


# =============================================================================
# Schema & seed data
# =============================================================================
SCHEMA = """
CREATE TABLE IF NOT EXISTS voters (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    aadhaar_hash   TEXT UNIQUE NOT NULL,   -- HMAC of the Aadhaar number (never stored in clear)
    aadhaar_last4  TEXT NOT NULL,          -- for masked display only
    name           TEXT NOT NULL,
    phone          TEXT NOT NULL,
    constituency   TEXT NOT NULL,
    photo_file     TEXT NOT NULL,          -- file name inside PHOTO_DIR (NOT web-accessible)
    face_embedding TEXT,                   -- JSON list, cached face template
    has_voted      INTEGER NOT NULL DEFAULT 0,
    voted_at       TEXT,
    registered_at  TEXT NOT NULL,
    identity_key   TEXT,                   -- HMAC(name|dob|gender|last4) from the UIDAI-signed file: one real person
    kyc_verified   INTEGER NOT NULL DEFAULT 0,
    face_gallery   TEXT                    -- JSON list of extra face templates (UIDAI photo, successful live logins)
);
CREATE TABLE IF NOT EXISTS candidates (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    party        TEXT NOT NULL,
    logo         TEXT,
    constituency TEXT NOT NULL,
    votes        INTEGER NOT NULL DEFAULT 0
);
-- Public ledger. Rows hold NO voter id, NO candidate and NO timestamp, so the
-- ledger cannot be joined back to a voter. Rows are hash-chained so that
-- editing / deleting / re-ordering any row is detectable.
CREATE TABLE IF NOT EXISTS votes_audit (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ballot_hash  TEXT NOT NULL,
    constituency TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    chain_hash   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS otp_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    purpose    TEXT NOT NULL,              -- 'login' | 'register'
    subject    TEXT NOT NULL,              -- voter id | pending-registration token
    code_hash  TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    UNIQUE (purpose, subject)
);
CREATE TABLE IF NOT EXISTS pending_registrations (
    token          TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    aadhaar_hash   TEXT NOT NULL,
    aadhaar_last4  TEXT NOT NULL,
    phone          TEXT NOT NULL,
    constituency   TEXT NOT NULL,
    photo_file     TEXT NOT NULL,
    face_embedding TEXT NOT NULL,
    identity_key   TEXT,
    kyc_verified   INTEGER NOT NULL DEFAULT 0,
    gallery        TEXT,
    expires_at     REAL NOT NULL
);
-- Firebase ID tokens already redeemed: each phone verification can be used exactly once.
CREATE TABLE IF NOT EXISTS used_tokens (
    token_hash TEXT PRIMARY KEY,
    expires_at REAL NOT NULL
);
-- Server-side state of a voter's verification. The browser only holds a random
-- token, so a voter cannot skip the face step or replay an old session.
CREATE TABLE IF NOT EXISTS auth_sessions (
    token          TEXT PRIMARY KEY,
    voter_id       INTEGER NOT NULL REFERENCES voters(id),
    face_verified  INTEGER NOT NULL DEFAULT 0,
    face_streak    INTEGER NOT NULL DEFAULT 0,
    frames_checked INTEGER NOT NULL DEFAULT 0,
    live_verified  INTEGER NOT NULL DEFAULT 0,   -- head-turn liveness challenge passed
    live_state     TEXT,                         -- JSON challenge state (server-side only)
    live_frames    INTEGER NOT NULL DEFAULT 0,
    live_challenges INTEGER NOT NULL DEFAULT 0,
    live_anchor    TEXT,                         -- JSON: this session's verified face (identity anchor)
    expires_at     REAL NOT NULL
);
"""

DEMO_CANDIDATES = [
    ("Rahul Sharma", "Bharatiya Janata Party (BJP)", "lotus", "New Delhi"),
    ("Priya Patel", "Indian National Congress (INC)", "hand", "New Delhi"),
    ("Amit Singh", "Aam Aadmi Party (AAP)", "broom", "New Delhi"),
    ("None of the Above (NOTA)", "NOTA", "nota", "New Delhi"),
    ("Vikram Rao", "Bharatiya Janata Party (BJP)", "lotus", "Mumbai South"),
    ("Sanjay Dutt", "Indian National Congress (INC)", "hand", "Mumbai South"),
    ("Anjali Menon", "Independent", "ind", "Mumbai South"),
    ("None of the Above (NOTA)", "NOTA", "nota", "Mumbai South"),
]
# (aadhaar, name, phone, constituency, photo in demo_data/, has_voted)
DEMO_VOTERS = [
    ("123456789012", "Samarth Kapoor", "9876543210", "New Delhi", "reference.jpg", 0),
    ("444455556666", "Aarav Sharma", "8877665544", "New Delhi", "reference.jpg", 1),
    ("111122223333", "Vipul Mehta", "9988776655", "Mumbai South", "reference2.jpg", 0),
]


# =============================================================================
# Small utilities
# =============================================================================
def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def jerr(message, code=400, **extra):
    return jsonify(success=False, message=message, **extra), code


def keyed_hash(value, *parts):
    """HMAC-SHA256 keyed with the server pepper (Aadhaar lookup key, OTP digests)."""
    msg = ":".join((*parts, value)).encode()
    return hmac.new(current_app.config["PEPPER"].encode(), msg, hashlib.sha256).hexdigest()


def aadhaar_hash(aadhaar):
    return keyed_hash(aadhaar, "aadhaar")


def mask_aadhaar(last4):
    return f"XXXX-XXXX-{last4}"


def mask_phone(phone):
    return f"+91 {phone[:2]}XXXXXX{phone[-2:]}"


def mask_name(name):
    if len(name) <= 2:
        return name[0] + "*"
    return name[0] + "*" * (len(name) - 2) + name[-1]


class RateLimiter:
    """Tiny in-process sliding-window limiter (single-process deployments only)."""

    def __init__(self):
        self._hits, self._lock = {}, threading.Lock()

    def allow(self, key, limit, window):
        now = time.monotonic()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < window]
            if len(hits) >= limit:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True


def rate_limited(name, limit, window=60):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if current_app.config["RATELIMIT_ENABLED"] and not current_app.extensions["limiter"].allow(
                f"{name}:{request.remote_addr}", limit, window
            ):
                return jerr("Too many requests. Please wait a minute and try again.", 429)
            return fn(*args, **kwargs)
        return wrapper
    return deco


# ---- input validation --------------------------------------------------------
def clean_name(raw):
    name = " ".join(unicodedata.normalize("NFC", raw or "").split())
    if not 2 <= len(name) <= 80:
        return None
    # letters + combining marks (so Devanagari matras work) + a few separators
    for ch in name:
        cat = unicodedata.category(ch)
        if not (cat[0] in "LM" or ch in " .'-"):
            return None
    return name


def valid_aadhaar(value):
    return bool(re.fullmatch(r"[0-9]{12}", value or ""))


def valid_phone(value):
    return bool(re.fullmatch(r"[6-9][0-9]{9}", value or ""))  # Indian mobile numbers


# ---- images ----------------------------------------------------------------------
MAX_PIXELS = 25_000_000


def decode_image(data):
    """bytes -> BGR ndarray, or None if it isn't a sane JPEG/PNG."""
    try:  # Pillow reads only the header here: guards against decompression bombs
        with Image.open(io.BytesIO(data)) as im:
            if im.format not in ("JPEG", "PNG") or im.width * im.height > MAX_PIXELS:
                return None
    except Exception:
        return None
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None or min(img.shape[:2]) < 120:
        return None
    return img


def downscale(img, longest=1280):
    h, w = img.shape[:2]
    if max(h, w) <= longest:
        return img
    s = longest / float(max(h, w))
    return cv2.resize(img, (int(w * s), int(h * s)), interpolation=cv2.INTER_AREA)


def save_photo(img):
    """Re-encode (strips EXIF / embedded junk) into the private photo directory."""
    name = f"{uuid.uuid4().hex}.jpg"
    path = os.path.join(current_app.config["PHOTO_DIR"], name)
    cv2.imwrite(path, downscale(img), [cv2.IMWRITE_JPEG_QUALITY, 92])
    return name


def delete_photo(name):
    try:
        os.remove(os.path.join(current_app.config["PHOTO_DIR"], os.path.basename(name)))
    except OSError:
        pass


def face_service():
    return current_app.extensions["face_service"]


# =============================================================================
# Database helpers
# =============================================================================
def get_db():
    if "db" not in g:
        conn = sqlite3.connect(current_app.config["DATABASE"], timeout=15, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@contextmanager
def transaction(db):
    """Write transaction that takes the write lock up-front (no lost updates)."""
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        db.execute("ROLLBACK")
        raise
    db.execute("COMMIT")


def init_db(app):
    os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)
    os.makedirs(app.config["PHOTO_DIR"], exist_ok=True)
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.execute("PRAGMA journal_mode = WAL")
    pcols = {r[1] for r in conn.execute("PRAGMA table_info(pending_registrations)")}
    if pcols and "identity_key" not in pcols:     # pending registrations are short-lived: rebuild
        conn.execute("DROP TABLE pending_registrations")
    cols = {r[1] for r in conn.execute("PRAGMA table_info(auth_sessions)")}
    if cols and not {"live_verified", "live_anchor"} <= cols:      # older database: sessions are short-lived, rebuild
        conn.execute("DROP TABLE auth_sessions")
    conn.executescript(SCHEMA)
    vcols = {r[1] for r in conn.execute("PRAGMA table_info(voters)")}
    for col, ddl in (("identity_key", "TEXT"), ("kyc_verified", "INTEGER NOT NULL DEFAULT 0"), ("face_gallery", "TEXT")):
        if col not in vcols:                      # database created by an older version
            conn.execute(f"ALTER TABLE voters ADD COLUMN {col} {ddl}")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_voters_identity ON voters(identity_key) WHERE identity_key IS NOT NULL")
    conn.commit()
    conn.close()


def append_ballot(db, constituency):
    """Add one random-id ballot to the hash-chained ledger; returns its receipt id.

    The receipt id is random: it proves a ballot was recorded but reveals nothing about
    the choice, so it can't be used to prove (or sell) how you voted."""
    ballot_hash = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    last = db.execute("SELECT chain_hash FROM votes_audit ORDER BY id DESC LIMIT 1").fetchone()
    prev = last[0] if last else GENESIS_HASH
    chain = hashlib.sha256(f"{prev}|{ballot_hash}|{constituency}".encode()).hexdigest()
    db.execute("INSERT INTO votes_audit (ballot_hash, constituency, prev_hash, chain_hash)"
               " VALUES (?,?,?,?)", (ballot_hash, constituency, prev, chain))
    return ballot_hash


def seed_demo_data(app):
    """Demo voters / candidates so the README scenarios work out of the box."""
    conn = sqlite3.connect(app.config["DATABASE"])
    if conn.execute("SELECT COUNT(*) FROM candidates").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO candidates (name, party, logo, constituency) VALUES (?,?,?,?)",
            DEMO_CANDIDATES,
        )
    if conn.execute("SELECT COUNT(*) FROM voters").fetchone()[0] == 0:
        with app.app_context():
            for aadhaar, name, phone, const, photo, voted in DEMO_VOTERS:
                src = os.path.join(BASE_DIR, "demo_data", photo)
                if not os.path.exists(src):
                    print(f"[seed] missing demo photo {src}; skipping {name}")
                    continue
                dest = f"{uuid.uuid4().hex}.jpg"
                shutil.copy(src, os.path.join(app.config["PHOTO_DIR"], dest))
                conn.execute(
                    "INSERT INTO voters (aadhaar_hash, aadhaar_last4, name, phone, constituency,"
                    " photo_file, has_voted, voted_at, registered_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (aadhaar_hash(aadhaar), aadhaar[-4:], name, phone, const, dest, voted,
                     now_iso() if voted else None, now_iso()),
                )
                if voted:  # keep invariants: voters who voted == ballots == sum of tallies
                    first = conn.execute("SELECT id FROM candidates WHERE constituency=? ORDER BY id LIMIT 1",
                                         (const,)).fetchone()
                    conn.execute("UPDATE candidates SET votes = votes + 1 WHERE id=?", (first[0],))
                    append_ballot(conn, const)
    conn.commit()
    conn.close()


# =============================================================================
# SMS / OTP
# =============================================================================
class SmsUnavailable(Exception):
    pass


class OtpCooldown(Exception):
    """Too soon / too many OTP requests. `.message` is safe to show the user."""

    def __init__(self, wait, message=None):
        super().__init__(wait)
        self.wait = wait
        self.message = message or f"Please wait {wait} seconds before requesting another OTP."


def send_sms(phone, message):
    """Deliver an SMS through the configured provider (see sms_gateway.py)."""
    provider = sms_gateway.provider_name()
    if provider == "console":
        if not current_app.config["DEMO_MODE"]:
            raise SmsUnavailable("no SMS provider configured")
        print(f"\n[SMS GATEWAY - demo] to +91{phone}: {message}\n")   # demo only: shows the OTP
        return
    try:
        sms_gateway.send_sms(phone, message)
    except sms_gateway.SmsError as exc:
        print(f"[SMS ERROR] provider={provider}: {exc}")             # never log the message body
        raise SmsUnavailable(str(exc))


def issue_otp(db, purpose, subject, phone):
    cfg, now = current_app.config, time.time()
    row = db.execute("SELECT created_at FROM otp_codes WHERE purpose=? AND subject=?",
                     (purpose, subject)).fetchone()
    if row and now - row["created_at"] < cfg["OTP_RESEND_COOLDOWN"]:
        raise OtpCooldown(int(cfg["OTP_RESEND_COOLDOWN"] - (now - row["created_at"])) + 1)
    if cfg["RATELIMIT_ENABLED"] and not current_app.extensions["limiter"].allow(
            f"sms:{phone}", cfg["SMS_PER_PHONE_PER_HOUR"], 3600):
        raise OtpCooldown(0, "Too many OTPs have been requested for this mobile number. "
                             "Please try again in an hour.")
    code = f"{secrets.randbelow(10 ** 6):06d}"
    db.execute(
        "INSERT OR REPLACE INTO otp_codes (purpose, subject, code_hash, created_at, expires_at)"
        " VALUES (?,?,?,?,?)",
        (purpose, subject, keyed_hash(code, "otp", purpose, subject), now, now + cfg["OTP_TTL"]),
    )
    try:
        send_sms(phone, f"{code} is your DeshGarv one-time password. Valid for "
                        f"{cfg['OTP_TTL'] // 60} minutes. Do not share it with anyone.")
    except SmsUnavailable:
        db.execute("DELETE FROM otp_codes WHERE purpose=? AND subject=?", (purpose, subject))
        raise
    return code


def check_otp(db, purpose, subject, code):
    """-> (ok, message). A correct code is consumed (single use)."""
    cfg = current_app.config
    row = db.execute("SELECT * FROM otp_codes WHERE purpose=? AND subject=?",
                     (purpose, subject)).fetchone()
    if not row or row["expires_at"] < time.time():
        if row:
            db.execute("DELETE FROM otp_codes WHERE id=?", (row["id"],))
        return False, "No valid OTP found or it has expired. Please request a new one."
    if row["attempts"] >= cfg["OTP_MAX_ATTEMPTS"]:
        return False, "Too many incorrect attempts. Please request a new OTP."
    db.execute("UPDATE otp_codes SET attempts = attempts + 1 WHERE id=?", (row["id"],))
    if not hmac.compare_digest(row["code_hash"], keyed_hash(code or "", "otp", purpose, subject)):
        left = cfg["OTP_MAX_ATTEMPTS"] - row["attempts"] - 1
        if left:
            return False, f"Incorrect OTP entered. {left} attempt(s) left."
        return False, "Incorrect OTP. No attempts left - please request a new OTP."
    db.execute("DELETE FROM otp_codes WHERE id=?", (row["id"],))
    return True, ""


def otp_response(code, message, **extra):
    body = {"success": True, "message": message, **extra}
    if current_app.config["DEMO_MODE"] and sms_gateway.provider_name() == "console":
        body["otp"] = code  # local demo only; never when a real SMS provider is configured
    return jsonify(body)


def otp_mode():
    """'firebase': Firebase sends/checks the SMS code in the browser, we verify its signed result.
    'sms': this server generates the OTP and delivers it through sms_gateway."""
    return "firebase" if sms_gateway.provider_name() == "firebase" else "sms"


def check_firebase_token(db, id_token, phone):
    """Verify a Firebase phone-sign-in token for the 10-digit registered `phone`. -> (ok, user message).
    Detailed reasons are logged, never shown (they would help an attacker)."""
    generic = "Phone verification failed or expired. Please request a new code and try again."
    if not isinstance(id_token, str) or not 20 < len(id_token) < 4096:
        return False, "Missing phone verification. Please enter the code sent to your mobile."
    try:
        claims = firebase_auth.verify_id_token(
            id_token, sms_gateway.firebase_project_id(), current_app.extensions["firebase_certs"],
            max_age=current_app.config["FIREBASE_TOKEN_MAX_AGE"])
    except firebase_auth.FirebaseAuthError as exc:
        print(f"[FIREBASE] token rejected: {exc}")
        return False, generic
    if not hmac.compare_digest(claims["phone_number"], f"+91{phone}"):
        return False, "That is not the mobile number registered for this voter."
    try:   # single use: a captured token can't be replayed
        db.execute("INSERT INTO used_tokens (token_hash, expires_at) VALUES (?,?)",
                   (hashlib.sha256(id_token.encode()).hexdigest(), time.time() + 3600))
    except sqlite3.IntegrityError:
        return False, "This verification was already used. Please request a new code."
    return True, ""


# =============================================================================
# Voter verification state (server-side)
# =============================================================================
def current_auth(require_face=False, require_live=False):
    token = session.get("auth")
    if not token:
        return None
    row = get_db().execute(
        "SELECT a.token, a.voter_id, a.face_verified, a.face_streak, a.frames_checked,"
        "       a.live_verified, a.live_state, a.live_frames, a.live_challenges, a.live_anchor,"
        "       v.name, v.constituency, v.aadhaar_last4, v.has_voted, v.photo_file, v.face_embedding"
        "  FROM auth_sessions a JOIN voters v ON v.id = a.voter_id"
        " WHERE a.token = ? AND a.expires_at > ?",
        (token, time.time()),
    ).fetchone()
    if row is None or (require_face and not row["face_verified"]) \
            or (require_live and not row["live_verified"]):
        return None
    return row


def ballot_auth():
    """The voter may see / cast the ballot only after OTP + face match (+ liveness, if enabled)."""
    return current_auth(require_face=True, require_live=current_app.config["LIVENESS_ENABLED"])


def end_voter_session():
    token = session.pop("auth", None)
    if token:
        get_db().execute("DELETE FROM auth_sessions WHERE token=?", (token,))


def reference_embedding(db, auth):
    """The voter's stored face template (computed once from their photo, then cached)."""
    if auth["face_embedding"]:
        return json.loads(auth["face_embedding"])
    img = cv2.imread(os.path.join(current_app.config["PHOTO_DIR"], auth["photo_file"]))
    faces = face_service().detect(img) if img is not None else []
    if not faces:
        return None
    best = max(faces, key=lambda f: f.w * f.h)
    db.execute("UPDATE voters SET face_embedding=? WHERE id=?",
               (json.dumps(best.embedding), auth["voter_id"]))
    return best.embedding


# =============================================================================
# Face templates (one person can be recognised from several stored faces)
# =============================================================================
MAX_GALLERY = 5


def voter_templates(row):
    """Every stored face template of a voter: the registration photo + UIDAI photo + past successful live logins."""
    out = []
    if row["face_embedding"]:
        out.append(json.loads(row["face_embedding"]))
    if row["face_gallery"]:
        out += json.loads(row["face_gallery"])
    return out


def find_duplicate_face(db, svc, embedding):
    """Is this face already enrolled? Compare against ALL templates of ALL voters.

    The old single-photo / 0.35 check only caught the *same photo*; a new photo or a webcam capture of the same
    person sits at 0.4-0.6 (measured: same person across different photos median 0.42, max 0.62; different people
    never closer than 0.69), so the limit is 0.60 and live-login faces are kept as extra templates."""
    limit = getattr(svc, "duplicate_threshold", 0)
    if limit <= 0:
        return None
    for row in db.execute("SELECT id, face_embedding, face_gallery FROM voters WHERE face_embedding IS NOT NULL"):
        for template in voter_templates(row):
            if svc.distance(embedding, template) <= limit:
                return row["id"]
    return None


def add_to_gallery(db, svc, voter_id, embedding):
    row = db.execute("SELECT face_gallery FROM voters WHERE id=?", (voter_id,)).fetchone()
    gallery = json.loads(row["face_gallery"]) if row and row["face_gallery"] else []
    new = [float(x) for x in embedding]
    if all(svc.distance(new, g) > 0.05 for g in gallery):          # skip near-identical templates
        gallery = (gallery + [new])[-MAX_GALLERY:]
        db.execute("UPDATE voters SET face_gallery=? WHERE id=?", (json.dumps(gallery), voter_id))


def verify_kyc(svc, selfie_face, aadhaar, phone):
    """Check the uploaded UIDAI offline e-KYC file against everything the voter typed. -> (info | None, error response | None)"""
    cfg, db = current_app.config, get_db()
    upload = request.files.get("kyc_zip")
    share = (request.form.get("share_code") or "").strip()
    if upload is None or not upload.filename:
        return None, jerr("Please upload your Aadhaar offline e-KYC ZIP file (instructions are on this page).")
    try:
        record = uidai_kyc.verify_offline_kyc(upload.read(), share, current_app.extensions["uidai_certs"],
                                              max_age_days=cfg["AADHAAR_XML_MAX_AGE_DAYS"])
        if not uidai_kyc.is_old_enough(record.dob, date.today(), cfg["MIN_VOTING_AGE"]):
            return None, jerr(f"You must be at least {cfg['MIN_VOTING_AGE']} years old to register.")
        xml_img = uidai_kyc.decode_photo(record.photo)
    except uidai_kyc.KycError as exc:
        return None, jerr(str(exc))
    if record.last4 != aadhaar[-4:]:
        return None, jerr(f"This file belongs to an Aadhaar number ending in {record.last4}, but the number you typed "
                          f"ends in {aadhaar[-4:]}.")
    if cfg["AADHAAR_CHECK_MOBILE"] and not uidai_kyc.check_mobile(record, phone, share, aadhaar):
        return None, jerr("This mobile number is not the one linked to your Aadhaar (or the share code is not the one you "
                          "chose when downloading). Use your Aadhaar-linked mobile number.")
    xml_faces = svc.detect(xml_img)
    if not xml_faces:
        return None, jerr("We could not find a clear face in the photo inside your Aadhaar file.")
    xml_face = max(xml_faces, key=lambda f: f.w * f.h)
    dist = svc.distance(selfie_face.embedding, xml_face.embedding)
    print(f"[KYC] selfie vs Aadhaar photo distance {dist:.3f} (limit {cfg['AADHAAR_PHOTO_MATCH_THRESHOLD']})")
    if dist > cfg["AADHAAR_PHOTO_MATCH_THRESHOLD"]:
        return None, jerr("Your photo does not match the photo in your Aadhaar file. Please take a clear, front-facing "
                          "photo of yourself.")
    key = uidai_kyc.identity_key(record, cfg["PEPPER"])
    if db.execute("SELECT 1 FROM voters WHERE identity_key=?", (key,)).fetchone():
        return None, jerr("This person is already registered. Each person may register only once.", 409)
    return {"record": record, "identity_key": key, "xml_embedding": xml_face.embedding}, None


# =============================================================================
# Pages
# =============================================================================
@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/verify")
def verify():
    return render_template("verify.html")


@bp.route("/register", methods=["GET"])
def register_page():
    cfg = current_app.config
    return render_template("register.html", constituencies=cfg["CONSTITUENCIES"],
                           kyc_required=cfg["AADHAAR_KYC"] == "offline_xml", min_age=cfg["MIN_VOTING_AGE"])


@bp.route("/voting-page")
def voting_page():
    if ballot_auth() is None:
        return redirect("/verify")
    return render_template("voting.html")


# =============================================================================
# Self-registration  (details + photo  ->  phone OTP  ->  voter created)
# =============================================================================
def purge_expired(db):
    now = time.time()
    for row in db.execute("SELECT token, photo_file FROM pending_registrations WHERE expires_at < ?",
                          (now,)).fetchall():
        delete_photo(row["photo_file"])
        db.execute("DELETE FROM pending_registrations WHERE token=?", (row["token"],))
        db.execute("DELETE FROM otp_codes WHERE purpose='register' AND subject=?", (row["token"],))
    db.execute("DELETE FROM auth_sessions WHERE expires_at < ?", (now,))
    db.execute("DELETE FROM used_tokens WHERE expires_at < ?", (now,))


def drop_pending(db, token):
    prev = db.execute("SELECT photo_file FROM pending_registrations WHERE token=?", (token,)).fetchone()
    if prev:
        delete_photo(prev["photo_file"])
    db.execute("DELETE FROM pending_registrations WHERE token=?", (token,))
    db.execute("DELETE FROM otp_codes WHERE purpose='register' AND subject=?", (token,))


@bp.post("/register/start")
@rate_limited("register_start", 6)
def register_start():
    cfg, db = current_app.config, get_db()
    kyc_on = cfg["AADHAAR_KYC"] == "offline_xml"
    name = None if kyc_on else clean_name(request.form.get("name"))     # with KYC the name comes from UIDAI's file
    aadhaar = (request.form.get("aadhaar") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    constituency = (request.form.get("constituency") or "").strip()
    upload = request.files.get("photo")

    if not kyc_on and not name:
        return jerr("Please enter your full name (letters only, 2-80 characters).")
    if not valid_aadhaar(aadhaar):
        return jerr("Invalid Aadhaar number. It must be exactly 12 digits.")
    if not valid_phone(phone):
        return jerr("Invalid mobile number. Enter a 10-digit Indian mobile number.")
    if constituency not in cfg["CONSTITUENCIES"]:
        return jerr("Invalid constituency selection.")
    if upload is None or not upload.filename:
        return jerr("Please provide a face photo.")

    img = decode_image(upload.read())
    if img is None:
        return jerr("The photo could not be read. Please use a JPG or PNG image "
                    "(at least 120x120 pixels).")

    svc = face_service()
    if not svc.available():
        return jerr("Face recognition engine is not available on the server.", 503)
    faces = svc.detect(img)
    if not faces:
        return jerr("No face detected in the photo. Use a clear, well-lit, front-facing photo.")
    if len(faces) > 1:
        return jerr("The photo must contain exactly one face.")
    if faces[0].ratio < 0.15:
        return jerr("The face is too small in the photo. Move closer or crop the picture.")

    purge_expired(db)
    a_hash = aadhaar_hash(aadhaar)
    if db.execute("SELECT 1 FROM voters WHERE aadhaar_hash=?", (a_hash,)).fetchone():
        return jerr("This Aadhaar number is already registered.", 409)

    kyc = None
    if kyc_on:                              # proves the person really holds this Aadhaar (UIDAI-signed file)
        kyc, error = verify_kyc(svc, faces[0], aadhaar, phone)
        if error:
            return error
        name = kyc["record"].name

    # One person, one identity: reject a face that is already enrolled (any stored template of any voter).
    if find_duplicate_face(db, svc, faces[0].embedding) is not None:
        return jerr("A voter with a matching face is already registered. Each person may register only once.", 409)

    old = session.pop("reg_token", None)   # replace an earlier pending attempt
    if old:
        drop_pending(db, old)

    token = secrets.token_urlsafe(24)
    photo_file = save_photo(img)
    db.execute(
        "INSERT INTO pending_registrations (token, name, aadhaar_hash, aadhaar_last4, phone,"
        " constituency, photo_file, face_embedding, identity_key, kyc_verified, gallery, expires_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (token, name, a_hash, aadhaar[-4:], phone, constituency, photo_file, json.dumps(faces[0].embedding),
         kyc["identity_key"] if kyc else None, 1 if kyc else 0,
         json.dumps([kyc["xml_embedding"]]) if kyc else None, time.time() + 30 * 60),
    )
    extra = {"verified_name": name} if kyc else {}
    if otp_mode() == "firebase":      # the browser will ask Firebase to text the code
        session["reg_token"] = token
        return jsonify(success=True, mode="firebase", phone=phone, **extra,
                       message=f"We will send a verification code to {mask_phone(phone)}.")
    try:
        code = issue_otp(db, "register", token, phone)
    except OtpCooldown as c:
        drop_pending(db, token)
        return jerr(c.message, 429)
    except SmsUnavailable:
        drop_pending(db, token)
        return jerr("Could not send the OTP right now. Please try again later.", 503)
    session["reg_token"] = token
    return otp_response(code, f"A 6-digit OTP has been sent to {mask_phone(phone)}.", **extra)


def _pending():
    token = session.get("reg_token")
    if not token:
        return None
    return get_db().execute("SELECT * FROM pending_registrations WHERE token=? AND expires_at>?",
                            (token, time.time())).fetchone()


@bp.post("/register/resend")
@rate_limited("register_resend", 6)
def register_resend():
    pend = _pending()
    if pend is None:
        return jerr("Your registration session expired. Please start again.", 410)
    if otp_mode() == "firebase":
        return jsonify(success=True, mode="firebase", phone=pend["phone"], message="You can request a new code.")
    try:
        code = issue_otp(get_db(), "register", pend["token"], pend["phone"])
    except OtpCooldown as c:
        return jerr(c.message, 429)
    except SmsUnavailable:
        return jerr("Could not send the OTP right now. Please try again later.", 503)
    return otp_response(code, "A new OTP has been sent.")


@bp.post("/register/verify")
@rate_limited("register_verify", 15)
def register_verify():
    db = get_db()
    pend = _pending()
    if pend is None:
        return jerr("Your registration session expired. Please start again.", 410)
    data = request.get_json(silent=True) or {}
    if otp_mode() == "firebase":
        ok, msg = check_firebase_token(db, data.get("id_token"), pend["phone"])
    else:
        ok, msg = check_otp(db, "register", pend["token"], str(data.get("otp", "")).strip())
    if not ok:
        return jerr(msg)
    try:
        with transaction(db):
            db.execute(
                "INSERT INTO voters (aadhaar_hash, aadhaar_last4, name, phone, constituency,"
                " photo_file, face_embedding, registered_at, identity_key, kyc_verified, face_gallery)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (pend["aadhaar_hash"], pend["aadhaar_last4"], pend["name"], pend["phone"],
                 pend["constituency"], pend["photo_file"], pend["face_embedding"], now_iso(),
                 pend["identity_key"], pend["kyc_verified"], pend["gallery"]),
            )
            db.execute("DELETE FROM pending_registrations WHERE token=?", (pend["token"],))
    except sqlite3.IntegrityError:  # someone else completed this Aadhaar first
        drop_pending(db, pend["token"])
        session.pop("reg_token", None)
        return jerr("This Aadhaar number or person is already registered.", 409)
    session.pop("reg_token", None)
    return jsonify(success=True, message=f"Voter {pend['name']} registered successfully.",
                   voter={"name": pend["name"], "aadhaar": mask_aadhaar(pend["aadhaar_last4"]),
                          "phone": mask_phone(pend["phone"]), "constituency": pend["constituency"]})


# =============================================================================
# Voter login  (Aadhaar -> OTP -> face)
# =============================================================================
@bp.post("/send_otp")
@rate_limited("send_otp", 8)
def send_otp():
    aadhaar = ((request.get_json(silent=True) or {}).get("aadhaar") or "").strip()
    if not valid_aadhaar(aadhaar):
        return jerr("Invalid Aadhaar number format.")
    db = get_db()
    voter = db.execute("SELECT id, phone, has_voted FROM voters WHERE aadhaar_hash=?",
                       (aadhaar_hash(aadhaar),)).fetchone()
    if voter is None:
        return jerr("Aadhaar number not registered.", 404)
    if voter["has_voted"]:
        return jerr("This citizen has already cast their vote.")
    if otp_mode() == "firebase":      # voter types their number; Firebase sends the code from the browser
        return jsonify(success=True, mode="firebase", phone_hint=mask_phone(voter["phone"])[4:],
                       message="Enter your registered mobile number to receive a verification code.")
    try:
        code = issue_otp(db, "login", str(voter["id"]), voter["phone"])
    except OtpCooldown as c:
        return jerr(c.message, 429)
    except SmsUnavailable:
        return jerr("Could not send the OTP right now. Please try again later.", 503)
    return otp_response(code, "OTP sent successfully to your registered mobile number.")


@bp.post("/verify_otp")
@rate_limited("verify_otp", 15)
def verify_otp():
    data = request.get_json(silent=True) or {}
    aadhaar, otp = (data.get("aadhaar") or "").strip(), str(data.get("otp") or "").strip()
    firebase = otp_mode() == "firebase"
    if not valid_aadhaar(aadhaar) or not (data.get("id_token") if firebase else otp):
        return jerr("Aadhaar and OTP are required.")
    db = get_db()
    voter = db.execute("SELECT id, phone, has_voted FROM voters WHERE aadhaar_hash=?",
                       (aadhaar_hash(aadhaar),)).fetchone()
    if voter is None:
        return jerr("Voter lookup error.", 404)
    if voter["has_voted"]:
        return jerr("This citizen has already cast their vote.")
    if firebase:
        ok, msg = check_firebase_token(db, data.get("id_token"), voter["phone"])
    else:
        ok, msg = check_otp(db, "login", str(voter["id"]), otp)
    if not ok:
        return jerr(msg)

    admin = session.get("admin_logged_in")
    session.clear()                      # new identity -> new session (no fixation)
    if admin:
        session["admin_logged_in"] = True
    token = secrets.token_urlsafe(32)
    with transaction(db):
        db.execute("DELETE FROM auth_sessions WHERE voter_id=?", (voter["id"],))
        db.execute("INSERT INTO auth_sessions (token, voter_id, expires_at) VALUES (?,?,?)",
                   (token, voter["id"], time.time() + current_app.config["AUTH_TTL"]))
    session["auth"] = token
    return jsonify(success=True, message="OTP verified. Please complete the face check.",
                   required_matches=current_app.config["FACE_STREAK_REQUIRED"],
                   liveness_required=current_app.config["LIVENESS_ENABLED"])


@bp.post("/verify_face")
def verify_face():
    """Browser uploads a webcam frame; the server decides. The ballot needs this to pass."""
    cfg, db = current_app.config, get_db()
    auth = current_auth()
    if auth is None:
        return jerr("Your session has expired. Please start verification again.", 401,
                    status="expired")
    need = cfg["FACE_STREAK_REQUIRED"]
    if auth["face_verified"]:
        return jsonify(success=True, verified=True, status="match", streak=need, required=need,
                       liveness_required=cfg["LIVENESS_ENABLED"])
    if auth["frames_checked"] >= cfg["FACE_MAX_FRAMES"]:
        end_voter_session()
        return jerr("Too many failed face checks. Please start verification again.", 429,
                    status="locked")

    frame = request.files.get("frame")
    img = decode_image(frame.read()) if frame else None
    if img is None:
        return jerr("No usable camera frame received.", 400, status="bad_frame")

    svc = face_service()
    if not svc.available():
        return jerr("Face recognition engine is not available on the server.", 503, status="error")
    ref = reference_embedding(db, auth)
    if ref is None:
        return jerr("Your registered photo has no detectable face. Please contact the "
                    "election office.", 503, status="error")

    faces = svc.detect(img)
    streak, anchor = 0, None
    if not faces:
        status = "no_face"
    elif len(faces) > 1:
        status = "multiple_faces"        # anti-coercion: exactly one person in frame
    elif svc.distance(faces[0].embedding, ref) <= svc.match_threshold:
        status, streak = "match", auth["face_streak"] + 1
        # Identity ANCHOR for the liveness step: mean embedding of the consecutive matching frames
        # of THIS session (same camera + lighting), reset by any non-matching frame.
        prev = json.loads(auth["live_anchor"]) if auth["live_anchor"] and streak > 1 else None
        emb = np.asarray(faces[0].embedding, dtype=float)
        anchor = emb if prev is None else (np.asarray(prev, dtype=float) * (streak - 1) + emb) / streak
    else:
        status = "no_match"
    verified = streak >= need            # N consecutive matching frames, not one lucky frame
    db.execute("UPDATE auth_sessions SET face_streak=?, face_verified=?, live_anchor=?,"
               " frames_checked=frames_checked+1 WHERE token=?",
               (streak, 1 if verified else 0, json.dumps(anchor.tolist()) if anchor is not None else None,
                auth["token"]))
    if verified and anchor is not None:      # this live face matched: keep it, so webcam look-alikes are caught later
        add_to_gallery(db, svc, auth["voter_id"], anchor)
    return jsonify(success=True, verified=verified, status=status, streak=streak, required=need,
                   liveness_required=cfg["LIVENESS_ENABLED"])


# =============================================================================
# Liveness (anti-spoofing): server-issued random head-turn challenge
# =============================================================================
def liveness_cfg():
    return current_app.extensions["liveness_cfg"]


@bp.post("/liveness/start")
def liveness_start():
    cfg, db = current_app.config, get_db()
    auth = current_auth(require_face=True)
    if auth is None:
        return jerr("Complete the face check first.", 401, status="expired")
    if not cfg["LIVENESS_ENABLED"] or auth["live_verified"]:
        return jsonify(success=True, required=cfg["LIVENESS_ENABLED"], verified=True)
    lcfg = liveness_cfg()
    if auth["live_challenges"] >= lcfg.max_challenges:
        end_voter_session()
        return jerr("Too many liveness attempts. Please start verification again.", 429, status="locked")
    state = liveness.new_challenge(time.time(), lcfg)
    db.execute("UPDATE auth_sessions SET live_state=?, live_challenges=live_challenges+1 WHERE token=?",
               (json.dumps(state), auth["token"]))
    return jsonify(success=True, required=True, verified=False, status="started",
                   **liveness.public_view(state, lcfg))


@bp.post("/liveness/frame")
def liveness_frame():
    """One webcam frame of the head-turn challenge. Every frame must (a) contain exactly one face,
    (b) be the registered voter, and (c) advance the server-held challenge state."""
    cfg, db, lcfg = current_app.config, get_db(), liveness_cfg()
    auth = current_auth(require_face=True)
    if auth is None:
        return jerr("Your session has expired. Please start verification again.", 401, status="expired")
    if not cfg["LIVENESS_ENABLED"] or auth["live_verified"]:
        return jsonify(success=True, verified=True, status="done")
    if not auth["live_state"]:
        return jerr("Start a liveness challenge first.", 409, status="no_challenge")
    if auth["live_frames"] >= lcfg.max_frames:
        end_voter_session()
        return jerr("Too many liveness frames. Please start verification again.", 429, status="locked")

    frame = request.files.get("frame")
    img = decode_image(frame.read()) if frame else None
    if img is None:
        return jerr("No usable camera frame received.", 400, status="bad_frame")
    svc, analyzer = face_service(), current_app.extensions["pose_analyzer"]
    if not (svc.available() and analyzer.available()):
        return jerr("Face recognition engine is not available on the server.", 503, status="error")
    ref = reference_embedding(db, auth)
    if ref is None:
        return jerr("Your registered photo has no detectable face. Please contact the "
                    "election office.", 503, status="error")

    state, now = json.loads(auth["live_state"]), time.time()

    def persist(new_state, verified=False):
        # optimistic lock on the frame counter: parallel requests can't both advance one state
        return db.execute(
            "UPDATE auth_sessions SET live_state=?, live_verified=?, live_frames=live_frames+1"
            " WHERE token=? AND live_frames=?",
            (json.dumps(new_state) if new_state is not None else None, 1 if verified else 0,
             auth["token"], auth["live_frames"])).rowcount == 1

    def reply(status, **extra):
        body = dict(success=True, status=status, verified=False, **liveness.public_view(state, lcfg))
        if cfg["DEMO_MODE"] and pose_yaw is not None:  # calibration aid; never exposed in production
            body["yaw"] = round(pose_yaw, 3)
            if dist is not None:
                body["dist"], body["limit"] = round(dist, 3), limit
        body.update(extra)
        return jsonify(body)

    pose_yaw, dist, limit = None, None, None
    if liveness.expired(state, now, lcfg):            # clock runs even if no valid frames arrive
        persist(None)
        return reply("challenge_failed", can_retry=auth["live_challenges"] < lcfg.max_challenges)

    pose = analyzer.analyze(img)                      # RetinaFace: finds turned heads, gives landmarks
    status = None
    if pose.n_faces == 0:
        status = "no_face"
    elif pose.n_faces > 1:
        status = "multiple_faces"
    else:
        pose_yaw = pose.yaw
        # Identity from a RetinaFace crop (NOT the frontal-only Haar detector), compared to the face that
        # passed the match moments ago in this same session: same camera + lighting, so genuine users sit
        # well inside the limits while a different person is far outside them.
        emb = svc.embed_crop(liveness.aligned_face_crop(img, pose))
        centered = liveness.zone(state, pose.yaw, lcfg) == "center"
        if auth["live_anchor"]:
            dist, limit = svc.distance(emb, json.loads(auth["live_anchor"])), \
                (lcfg.anchor_center if centered else lcfg.anchor_turned)
        else:
            dist, limit = svc.distance(emb, ref), lcfg.registered_fallback
        if dist > limit:
            status = "no_match"                       # someone else, or the face was swapped

    if status is not None:                            # invalid frame: breaks any hold in progress
        state = {**state, "hold": 0, **({"base": []} if state["phase"] == "calibrate" else {})}
        if not persist(state):
            return reply("busy")
        return reply(status)

    # Some cameras / drivers deliver a mirrored picture. LIVENESS_FLIP_DIRECTIONS fixes that for the whole site and the
    # voter's own "swap" switch (a form field) fixes it per device; the two combine (XOR).
    flip = lcfg.flip_directions != (request.form.get("swap") == "1")
    state, status = liveness.step(state, pose.yaw, now, lcfg, flip=flip)
    if status == "timeout":
        persist(None)
        return reply("challenge_failed", can_retry=auth["live_challenges"] < lcfg.max_challenges)
    done = status == "done"
    if not persist(state, verified=done):
        return reply("busy")
    return reply(status, verified=done)


@bp.route("/voter_details")
def voter_details():
    auth = ballot_auth()
    if auth is None:
        return jerr("Unauthorized access.", 401)
    cands = get_db().execute(
        "SELECT id, name, party, logo FROM candidates WHERE constituency=? ORDER BY id",
        (auth["constituency"],)).fetchall()
    return jsonify(success=True,
                   voter={"name": auth["name"], "constituency": auth["constituency"],
                          "aadhaar": mask_aadhaar(auth["aadhaar_last4"])},
                   candidates=[dict(c) for c in cands])


class VoteError(Exception):
    def __init__(self, message, code=400):
        super().__init__(message)
        self.message, self.code = message, code


@bp.post("/cast_vote")
@rate_limited("cast_vote", 10)
def cast_vote():
    auth = ballot_auth()
    if auth is None:
        return jerr("Unauthorized access. Please complete verification first.", 401)
    candidate_id = (request.get_json(silent=True) or {}).get("candidate_id")
    if not isinstance(candidate_id, int) or isinstance(candidate_id, bool):
        return jerr("No candidate selected.")

    db = get_db()
    try:
        with transaction(db):
            cand = db.execute("SELECT id, constituency FROM candidates WHERE id=?",
                              (candidate_id,)).fetchone()
            if cand is None or cand["constituency"] != auth["constituency"]:
                raise VoteError("Invalid candidate selected for your constituency.")
            # Atomic compare-and-set: of two simultaneous requests only one can win.
            won = db.execute("UPDATE voters SET has_voted=1, voted_at=? WHERE id=? AND has_voted=0",
                             (now_iso(), auth["voter_id"])).rowcount
            if won != 1:
                raise VoteError("Double voting error: vote already cast.", 409)
            db.execute("UPDATE candidates SET votes = votes + 1 WHERE id=?", (candidate_id,))

            ballot_hash = append_ballot(db, cand["constituency"])
            db.execute("DELETE FROM auth_sessions WHERE voter_id=?", (auth["voter_id"],))
    except VoteError as e:
        return jerr(e.message, e.code)

    session.clear()
    return jsonify(success=True, message="Vote cast successfully and added to the audit ledger.",
                   audit_hash=ballot_hash)


@bp.post("/cancel_session")
def cancel_session():
    end_voter_session()
    return jsonify(success=True)


# =============================================================================
# Admin & results
# =============================================================================
def admin_required(api=False):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get("admin_logged_in"):
                return jerr("Unauthorized.", 401) if api else redirect("/admin")
            return fn(*args, **kwargs)
        return wrapper
    return deco


@bp.route("/admin")
def admin_login_page():
    if session.get("admin_logged_in"):
        return redirect("/results")
    return render_template("admin.html")


@bp.post("/admin/login")
@rate_limited("admin_login", 8)
def admin_login():
    data = request.get_json(silent=True) or {}
    cfg = current_app.config
    user_ok = hmac.compare_digest(str(data.get("username", "")), cfg["ADMIN_USERNAME"])
    pass_ok = check_password_hash(cfg["ADMIN_PASSWORD_HASH"], str(data.get("password", "")))
    if not (user_ok and pass_ok):
        return jerr("Invalid username or password.", 401)
    session.clear()
    session["admin_logged_in"] = True
    session.permanent = True
    return jsonify(success=True, message="Login successful.")


@bp.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    return redirect("/")


@bp.route("/results")
@admin_required()
def results():
    return render_template("results.html", constituencies=current_app.config["CONSTITUENCIES"])


def verify_ledger(db):
    """Recompute the hash chain. -> (intact?, number of ballots checked)."""
    prev, count = GENESIS_HASH, 0
    for row in db.execute("SELECT * FROM votes_audit ORDER BY id"):
        expect = hashlib.sha256(f"{prev}|{row['ballot_hash']}|{row['constituency']}".encode()).hexdigest()
        if row["prev_hash"] != prev or row["chain_hash"] != expect:
            return False, count
        prev, count = row["chain_hash"], count + 1
    return True, count


@bp.route("/results_data")
@admin_required(api=True)
def results_data():
    db = get_db()
    cands = db.execute("SELECT name, party, votes, constituency FROM candidates ORDER BY id").fetchall()
    voted = db.execute("SELECT name, constituency, voted_at, aadhaar_last4 FROM voters"
                       " WHERE has_voted=1 ORDER BY voted_at").fetchall()
    total = db.execute("SELECT COUNT(*) FROM voters").fetchone()[0]
    per_const = {r["constituency"]: r["n"] for r in db.execute(
        "SELECT constituency, COUNT(*) AS n FROM voters GROUP BY constituency")}
    ok, count = verify_ledger(db)
    return jsonify(
        success=True,
        candidates=[dict(c) for c in cands],
        voters=[{"name": mask_name(v["name"]), "aadhaar": mask_aadhaar(v["aadhaar_last4"]),
                 "constituency": v["constituency"], "timestamp": v["voted_at"]} for v in voted],
        total_registered=total,
        registered_by_constituency=per_const,
        ledger={"ok": ok, "ballots": count},
    )


# =============================================================================
# App factory
# =============================================================================
def _secret(env_name, filename, demo):
    value = os.environ.get(env_name)
    if value:
        return value
    if not demo:
        raise RuntimeError(f"{env_name} must be set when DESHGARV_DEMO=0")
    path = os.path.join(INSTANCE_DIR, filename)
    if os.path.exists(path):
        with open(path) as fh:
            return fh.read().strip()
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    value = secrets.token_hex(32)
    with open(path, "w") as fh:
        fh.write(value)
    os.chmod(path, 0o600)
    return value


def create_app(test_config=None):
    app = Flask(__name__)
    demo = os.environ.get("DESHGARV_DEMO", "1") == "1"
    app.config.update(
        DEMO_MODE=demo,
        SEED_DEMO=demo,
        DATABASE=os.environ.get("DESHGARV_DB", os.path.join(INSTANCE_DIR, "evoting.db")),
        PHOTO_DIR=os.environ.get("DESHGARV_PHOTO_DIR", os.path.join(INSTANCE_DIR, "photos")),
        CONSTITUENCIES=[c.strip() for c in os.environ.get(
            "DESHGARV_CONSTITUENCIES", "New Delhi,Mumbai South").split(",") if c.strip()],
        ADMIN_USERNAME=os.environ.get("ADMIN_USERNAME", "admin"),
        OTP_TTL=300, OTP_MAX_ATTEMPTS=5, OTP_RESEND_COOLDOWN=30, SMS_PER_PHONE_PER_HOUR=5,
        AUTH_TTL=15 * 60, FACE_STREAK_REQUIRED=3, FACE_MAX_FRAMES=150,
        RATELIMIT_ENABLED=True,
        FIREBASE_TOKEN_MAX_AGE=300,
        TRUST_PROXY_HOPS=int(os.environ.get("TRUST_PROXY_HOPS", "0")),
        AADHAAR_KYC=os.environ.get("AADHAAR_KYC", "off" if demo else "offline_xml").strip().lower(),
        UIDAI_CERT_DIR=os.environ.get("UIDAI_CERT_DIR", os.path.join(BASE_DIR, "uidai_certs")),
        AADHAAR_XML_MAX_AGE_DAYS=float(os.environ.get("AADHAAR_XML_MAX_AGE_DAYS", "3")),
        AADHAAR_PHOTO_MATCH_THRESHOLD=float(os.environ.get("AADHAAR_PHOTO_MATCH_THRESHOLD", "0.68")),
        AADHAAR_CHECK_MOBILE=os.environ.get("AADHAAR_CHECK_MOBILE", "1") != "0",
        MIN_VOTING_AGE=int(os.environ.get("MIN_VOTING_AGE", "18")),
        LIVENESS_ENABLED=os.environ.get("LIVENESS", "1") != "0",
        MAX_CONTENT_LENGTH=8 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=not demo,
        PERMANENT_SESSION_LIFETIME=2 * 60 * 60,
    )
    if test_config:
        app.config.update(test_config)
    cfg = app.config

    if not cfg.get("SECRET_KEY"):
        cfg["SECRET_KEY"] = _secret("SECRET_KEY", "secret_key", cfg["DEMO_MODE"])
    if not cfg.get("PEPPER"):
        cfg["PEPPER"] = _secret("DESHGARV_PEPPER", "pepper", cfg["DEMO_MODE"])
    if not cfg.get("ADMIN_PASSWORD_HASH"):
        cfg["ADMIN_PASSWORD_HASH"] = os.environ.get("ADMIN_PASSWORD_HASH") or ""
        if not cfg["ADMIN_PASSWORD_HASH"]:
            if not cfg["DEMO_MODE"]:
                raise RuntimeError("ADMIN_PASSWORD_HASH must be set when DESHGARV_DEMO=0 "
                                   "(generate it with: python make_secrets.py)")
            cfg["ADMIN_PASSWORD_HASH"] = generate_password_hash("admin123")

    if cfg["AADHAAR_KYC"] not in ("off", "offline_xml"):
        raise RuntimeError("AADHAAR_KYC must be 'offline_xml' or 'off'")
    certs = cfg.get("UIDAI_CERTS")
    if certs is None:
        certs = []
        if cfg["AADHAAR_KYC"] == "offline_xml":
            try:
                certs = uidai_kyc.load_certs(cfg["UIDAI_CERT_DIR"])
            except ValueError as exc:
                raise RuntimeError(f"UIDAI certificate problem: {exc}")
    if cfg["AADHAAR_KYC"] == "offline_xml" and not certs and not cfg.get("TESTING"):
        raise RuntimeError(
            "Aadhaar verification (AADHAAR_KYC=offline_xml) needs UIDAI's public certificate. Download it from "
            "https://uidai.gov.in/en/aadhaar-paperless-offline-e-kyc (\"Get Certificate\") and save the .cer file in the "
            f"folder '{cfg['UIDAI_CERT_DIR']}'. To run without Aadhaar verification set AADHAAR_KYC=off (anyone who knows an "
            "Aadhaar number can then register as that person).")
    app.extensions["uidai_certs"] = certs

    if not cfg["DEMO_MODE"] and not cfg.get("TESTING"):
        unsafe = production_secret_problems(cfg)
        if unsafe:
            raise RuntimeError("Unsafe secrets for production: " + "; ".join(unsafe) +
                               ". Generate real ones with:  python make_secrets.py")

    if not cfg.get("SKIP_SMS_CHECK"):             # fail fast instead of at the first voter
        problems = sms_gateway.config_problems()
        if sms_gateway.provider_name() == "console" and not cfg["DEMO_MODE"]:
            problems.append("DESHGARV_DEMO=0 needs SMS_PROVIDER=firebase, twilio or msg91")
        if problems:
            raise RuntimeError("SMS configuration error: " + "; ".join(problems))

    if cfg["TRUST_PROXY_HOPS"] > 0:
        # Behind nginx/Caddy/a cloud load balancer every request would otherwise look like it comes from the
        # proxy's IP, so the per-IP rate limits would throttle ALL voters together. Only trust as many
        # forwarded hops as you really have: more would let clients spoof their IP and dodge the limits.
        n = cfg["TRUST_PROXY_HOPS"]
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)
    app.extensions["firebase_certs"] = cfg.get("FIREBASE_CERTS") or firebase_auth.CertCache()

    @app.context_processor
    def inject_otp_mode():                        # used by verify.html / register.html
        firebase = otp_mode() == "firebase"
        return {"otp_mode": otp_mode(), "firebase_config": sms_gateway.firebase_client_config() if firebase else None,
                "liveness_flip": bool(app.extensions["liveness_cfg"].flip_directions)}

    app.extensions["limiter"] = RateLimiter()
    app.extensions["face_service"] = cfg.get("FACE_SERVICE") or DeepFaceService(
        model_name=os.environ.get("FACE_MODEL", "VGG-Face"),
        detector_backend=os.environ.get("FACE_DETECTOR", "opencv"),
        match_threshold=float(os.environ.get("FACE_MATCH_THRESHOLD", "0.55")),
        duplicate_threshold=float(os.environ.get("FACE_DUPLICATE_THRESHOLD", "0.60")),
    )

    app.extensions["liveness_cfg"] = cfg.get("LIVENESS_CFG") or liveness.LivenessConfig.from_env()
    app.extensions["pose_analyzer"] = cfg.get("POSE_ANALYZER") or liveness.PoseAnalyzer()
    if not cfg["LIVENESS_ENABLED"]:
        print("[WARNING] Liveness detection is DISABLED (LIVENESS=0): a held-up photo may pass the face check.")

    init_db(app)
    if cfg["SEED_DEMO"]:
        seed_demo_data(app)
    app.register_blueprint(bp)

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Permissions-Policy", "camera=(self), microphone=(), geolocation=()")
        if not cfg["DEMO_MODE"] and request.is_secure:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")  # browsers: HTTPS only
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"  # never cache ballots / voter data
        return resp

    @app.errorhandler(413)
    def too_large(_e):
        return jerr("The uploaded file is too large (limit 8 MB).", 413)

    # ---- CLI helpers ---------------------------------------------------------
    @app.cli.command("add-candidate")
    @click.argument("name")
    @click.argument("party")
    @click.argument("constituency")
    def add_candidate(name, party, constituency):
        """Add a candidate:  flask --app app add-candidate NAME PARTY CONSTITUENCY"""
        conn = sqlite3.connect(cfg["DATABASE"])
        conn.execute("INSERT INTO candidates (name, party, logo, constituency) VALUES (?,?,?,?)",
                     (name, party, "ind", constituency))
        conn.commit()
        conn.close()
        click.echo(f"Added {name} ({party}) to {constituency}.")

    @app.cli.command("test-sms")
    @click.argument("mobile")
    def test_sms(mobile):
        """Send a test OTP to MOBILE (10 digits) to verify your SMS provider settings."""
        if not valid_phone(mobile):
            raise click.BadParameter("enter a 10-digit Indian mobile number")
        click.echo(f"Provider: {sms_gateway.provider_name()}")
        with app.app_context():
            try:
                send_sms(mobile, "123456 is a DeshGarv test code. Valid for 5 minutes. Do not share it.")
            except SmsUnavailable as exc:
                raise click.ClickException(f"FAILED: {exc}")
        click.echo("Sent. Check the phone.")

    @app.cli.command("hash-password")
    @click.password_option()
    def hash_password(password):
        """Print a value for ADMIN_PASSWORD_HASH."""
        click.echo(generate_password_hash(password))

    return app


def describe_runtime(app):
    """Plain-English summary of what is ACTUALLY active (so a wrong/missing .env can't hide)."""
    cfg, provider = app.config, sms_gateway.provider_name()
    env_file = os.path.exists(os.path.join(BASE_DIR, ".env"))
    if cfg["DEMO_MODE"]:
        mode = "DEMO  (fake data seeded, admin is admin/admin123, NOT for real voters)"
    else:
        mode = "PRODUCTION"
    otp = {"firebase": "Firebase (Firebase sends and checks the SMS code)",
           "twilio": "Twilio SMS", "msg91": "MSG91 SMS",
           "console": "console  <-- DEMO: the OTP is shown on screen and no SMS is sent"}[provider]
    lines = ["", "=" * 74, f" DeshGarv  |  mode: {mode}",
             f"   OTP delivery   : {otp}",
             f"   Liveness check : {'ON' if cfg['LIVENESS_ENABLED'] else 'OFF  <-- a held-up photo may pass'}",
             f"   Settings file  : {'.env loaded' if env_file else '.env NOT FOUND  <-- the app reads .env, NOT .env.example (copy it to .env)'}",
             f"   Secure cookies : {'yes (needs HTTPS)' if cfg['SESSION_COOKIE_SECURE'] else 'no (demo)'}",
             f"   Behind a proxy : {cfg['TRUST_PROXY_HOPS']} trusted hop(s)",
             "   Aadhaar check  : " + (f"UIDAI offline e-KYC ({len(app.extensions['uidai_certs'])} certificate(s))"
                                       if cfg["AADHAAR_KYC"] == "offline_xml" else
                                       "OFF  <-- anyone who knows an Aadhaar number can register as that person")]
    if provider == "firebase" and sms_gateway.firebase_client_config().get("testMode"):
        lines.append("   Firebase TEST MODE: ON  <-- DEV ONLY: reCAPTCHA is skipped, only Firebase test numbers work")
    lines += ["=" * 74, ""]
    return lines


if __name__ == "__main__":
    application = create_app()
    print("\n".join(describe_runtime(application)))
    # Warm the model in the background so the first voter doesn't wait ~10s.
    threading.Thread(target=application.extensions["face_service"].warmup, daemon=True).start()
    if application.config["LIVENESS_ENABLED"]:
        threading.Thread(target=application.extensions["pose_analyzer"].warmup, daemon=True).start()
    # debug is OFF by default: Flask's debugger allows remote code execution if exposed.
    application.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")),
                    debug=os.environ.get("FLASK_DEBUG") == "1", threaded=True)
