"""
Go-live checker. Run it BEFORE you open the site to real voters:

    python check_production.py

It reads the same settings the app reads (your .env + environment variables), looks at your database, and prints
PASS / WARN / FAIL for every item. Exit code 1 if anything FAILs. It is read-only and never prints a secret.
"""
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone

from werkzeug.security import check_password_hash

import app as appmod              # importing app loads .env exactly like the real server does
import sms_gateway
import uidai_kyc

BASE = os.path.dirname(os.path.abspath(__file__))
DEMO_VOTER_NAMES = {v[1] for v in appmod.DEMO_VOTERS}
DEMO_CANDIDATE_KEYS = {(c[0], c[1], c[3]) for c in appmod.DEMO_CANDIDATES}


def run_checks(env=None, base_dir=BASE):
    """-> list of (level, message); level in PASS | WARN | FAIL | INFO."""
    env = os.environ if env is None else env
    out = []
    add = lambda level, msg: out.append((level, msg))

    # ---- settings file --------------------------------------------------------------------------
    env_path = os.path.join(base_dir, ".env")
    if os.path.exists(env_path):
        add("PASS", ".env file found")
    elif os.path.exists(env_path + ".txt"):
        add("FAIL", "found '.env.txt' - Windows added a hidden .txt. Rename it to exactly '.env' "
                    "(File Explorer > View > File name extensions)")
    elif env.get("SECRET_KEY"):
        add("INFO", "no .env file; using real environment variables instead")
    else:
        add("FAIL", ".env not found. The app reads '.env' - NOT '.env.example'. Copy .env.example to .env and edit that")

    # ---- mode / secrets ---------------------------------------------------------------------------
    if env.get("DESHGARV_DEMO", "1") != "0":
        add("FAIL", "DESHGARV_DEMO is not 0 -> demo mode: fake voters are seeded, admin is admin/admin123, secrets are "
                    "auto-generated files. Set DESHGARV_DEMO=0")
    else:
        add("PASS", "demo mode is off (DESHGARV_DEMO=0)")
    for name in ("SECRET_KEY", "DESHGARV_PEPPER"):
        v = env.get(name, "")
        if not v:
            add("FAIL", f"{name} is not set (generate one: python make_secrets.py)")
        elif v.lower() in appmod.KNOWN_PLACEHOLDERS:
            add("FAIL", f"{name} is the placeholder text from the example file. It is PUBLICLY KNOWN, so anyone could "
                        f"forge sessions / reverse Aadhaar hashes. Generate a real one: python make_secrets.py")
        elif len(v) < 32:
            add("FAIL", f"{name} is too short ({len(v)} chars) - use at least 32 random characters")
        else:
            add("PASS", f"{name} is set ({len(v)} chars)")
    if env.get("DESHGARV_PEPPER") and os.path.exists(os.path.join(base_dir, "instance", "pepper")):
        add("WARN", "an old instance/pepper from demo mode exists; Aadhaar hashes made with a different pepper will NOT "
                    "match. Start with a fresh instance/ folder (see README) instead of reusing a demo database")

    # ---- admin ---------------------------------------------------------------------------------
    h = env.get("ADMIN_PASSWORD_HASH", "")
    if not h:
        add("FAIL", "ADMIN_PASSWORD_HASH is not set (create it: python make_secrets.py)")
    elif not re.match(r"^(scrypt|pbkdf2):", h):
        add("FAIL", "ADMIN_PASSWORD_HASH is not a password hash (it must start with 'scrypt:'). Placeholder text or a plain "
                    "password was pasted. Admin login cannot work. Generate it with: python make_secrets.py")
    elif check_password_hash(h, "admin123"):
        add("FAIL", "ADMIN_PASSWORD_HASH is the hash of the demo password 'admin123'")
    else:
        add("PASS", "admin password hash is set and is not the demo password")
    if env.get("ADMIN_USERNAME", "admin") == "admin":
        add("WARN", "admin username is the default 'admin' - consider ADMIN_USERNAME=<something less guessable>")

    # ---- OTP provider --------------------------------------------------------------------------
    provider = sms_gateway.provider_name(env)
    if provider == "console":
        add("FAIL", "SMS_PROVIDER is 'console' (or not read) -> the OTP is shown on screen and no SMS is sent. "
                    "Set SMS_PROVIDER=firebase (or twilio/msg91) in .env")
    else:
        problems = sms_gateway.config_problems(env)
        for p in problems:
            add("FAIL", f"OTP provider '{provider}': {p}")
        if not problems:
            add("PASS", f"OTP provider '{provider}' is configured")
        if provider == "firebase":
            key = env.get("FIREBASE_API_KEY", "").strip().strip("\"'")
            if key and not key.startswith("AIza"):
                add("WARN", "FIREBASE_API_KEY does not look like a Firebase web API key (they start with 'AIza')")
            add("INFO", "Firebase console - check by hand: (1) Authentication > Settings > Authorized domains lists your "
                        "production domain, (2) SMS region policy allows only India, (3) a budget alert exists, "
                        "(4) the API key is restricted to your domain (Google Cloud > APIs & Services > Credentials)")

    if env.get("FIREBASE_TEST_MODE", "").strip() == "1":
        add("FAIL", "FIREBASE_TEST_MODE=1 skips reCAPTCHA (development only). Remove it before going live")

    # ---- Aadhaar verification (UIDAI offline e-KYC) ---------------------------------------------------
    demo_on = env.get("DESHGARV_DEMO", "1") != "0"
    kyc = env.get("AADHAAR_KYC", "off" if demo_on else "offline_xml").strip().lower()
    cert_dir = env.get("UIDAI_CERT_DIR", os.path.join(base_dir, "uidai_certs"))
    if kyc == "off":
        add("WARN", "AADHAAR_KYC=off: nothing proves a registrant is the Aadhaar holder - anyone who knows an Aadhaar number "
                    "can register as that person. Set AADHAAR_KYC=offline_xml")
    elif kyc == "offline_xml":
        try:
            certs = uidai_kyc.load_certs(cert_dir)
        except ValueError as exc:
            certs = []
            add("FAIL", f"UIDAI certificate problem: {exc}")
        else:
            if not certs:
                add("FAIL", f"no UIDAI certificate found in '{cert_dir}'. Download UIDAI's public certificate from "
                            "https://uidai.gov.in/en/aadhaar-paperless-offline-e-kyc and save the .cer file there")
            else:
                add("PASS", f"{len(certs)} UIDAI certificate(s) loaded for Aadhaar verification")
                for cert in certs:
                    add("INFO", "certificate: " + uidai_kyc.describe_cert(cert))
                if all(cert.not_valid_after_utc < datetime.now(timezone.utc) for cert in certs):
                    add("WARN", "every UIDAI certificate has expired - download the current one from UIDAI")
        try:
            thr = float(env.get("AADHAAR_PHOTO_MATCH_THRESHOLD", "0.68"))
            if not 0.5 <= thr <= 0.72:
                add("WARN", f"AADHAAR_PHOTO_MATCH_THRESHOLD={thr}: below ~0.55 rejects genuine voters (UIDAI's photo is tiny); "
                            "above ~0.72 starts accepting look-alikes (see README)")
        except ValueError:
            add("FAIL", "AADHAAR_PHOTO_MATCH_THRESHOLD is not a number")
        if env.get("AADHAAR_CHECK_MOBILE", "1") == "0":
            add("WARN", "AADHAAR_CHECK_MOBILE=0: the OTP may go to a phone that is not linked to the Aadhaar")
        add("INFO", "Legal: check whether your organisation must register with UIDAI to use offline Aadhaar verification and what "
                    "consent notice you must show. The ZIP and share code must not be stored or shared (this app doesn't).")
    else:
        add("FAIL", "AADHAAR_KYC must be 'offline_xml' or 'off'")

    # ---- safety switches ---------------------------------------------------------------------------
    if env.get("LIVENESS", "1") == "0":
        add("WARN", "LIVENESS=0 -> a held-up photo may pass the face check")
    else:
        add("PASS", "liveness check is on")
    if env.get("FLASK_DEBUG") == "1":
        add("FAIL", "FLASK_DEBUG=1 -> Flask's debugger lets visitors run code on your server")
    if env.get("TRUST_PROXY_HOPS", "0") == "0":
        add("WARN", "TRUST_PROXY_HOPS=0. If the site sits behind HTTPS (Caddy/nginx/cloud load balancer) set it to 1, "
                    "otherwise every voter looks like the same IP and the rate limits block them together")
    else:
        add("PASS", f"trusting {env.get('TRUST_PROXY_HOPS')} reverse-proxy hop(s) for visitor IPs")
    add("INFO", "HTTPS is required in production: browsers block the camera and Firebase on plain http (except localhost)")

    # ---- database ------------------------------------------------------------------------------------
    db_path = env.get("DESHGARV_DB", os.path.join(base_dir, "instance", "evoting.db"))
    if not os.path.exists(db_path):
        add("INFO", "no database yet - it is created on first start. Then add candidates: "
                    "flask --app app add-candidate \"Name\" \"Party\" \"Constituency\"")
    else:
        conn = sqlite3.connect(db_path)
        try:
            voters = {r[0] for r in conn.execute("SELECT name FROM voters")}
            cands = conn.execute("SELECT name, party, constituency FROM candidates").fetchall()
            ballots = conn.execute("SELECT COUNT(*) FROM votes_audit").fetchone()[0]
        except sqlite3.Error as exc:
            add("FAIL", f"cannot read the database: {exc}")
            voters, cands, ballots = set(), [], 0
        finally:
            conn.close()
        if voters & DEMO_VOTER_NAMES:
            add("FAIL", "the database contains the DEMO voters (Samarth Kapoor / Aarav Sharma / Vipul Mehta) and a fake "
                        "ballot. Do not go live with it: move instance/ aside so a fresh database is created")
        if any((n, p, c) in DEMO_CANDIDATE_KEYS for n, p, c in cands):
            add("FAIL", "the database contains the DEMO candidates (Rahul Sharma, Priya Patel, ...). Start a fresh database "
                        "and add your real candidates")
        if not cands:
            add("WARN", "no candidates in the database - add them with: flask --app app add-candidate ...")
        constituencies = [c.strip() for c in env.get("DESHGARV_CONSTITUENCIES", "New Delhi,Mumbai South").split(",") if c.strip()]
        for c in constituencies:
            n = sum(1 for _, _, cc in cands if cc == c)
            if n < 2:
                add("WARN", f"constituency '{c}' has {n} candidate(s) - set DESHGARV_CONSTITUENCIES and add candidates")
        if ballots:
            add("INFO", f"the ledger already holds {ballots} ballot(s)")

    # ---- machine ----------------------------------------------------------------------------------
    weights = os.path.expanduser("~/.deepface/weights")
    have = [f for f in ("vgg_face_weights.h5", "retinaface.h5") if os.path.exists(os.path.join(weights, f))]
    if len(have) < 2:
        add("WARN", "AI model files are not downloaded yet (~700 MB). The first start downloads them - start the server "
                    "once and wait for '[ready] face models loaded' before opening it to voters")
    else:
        add("PASS", "AI model files are present")
    try:
        import waitress  # noqa: F401
        add("PASS", "waitress (production web server) is installed")
    except ImportError:
        add("WARN", "waitress is not installed: pip install waitress (works on Windows and Linux)")
    gi = os.path.join(base_dir, ".gitignore")
    if os.path.exists(gi) and re.search(r"^\.env\s*$", open(gi).read(), re.M):
        add("PASS", ".env is in .gitignore (secrets won't be committed)")
    else:
        add("WARN", ".env is not in .gitignore - you could commit secrets by accident")
    return out


def main():
    results = run_checks()
    icons = {"PASS": "[ OK ]", "WARN": "[WARN]", "FAIL": "[FAIL]", "INFO": "[info]"}
    print("\nDeshGarv go-live check\n" + "-" * 70)
    for level, msg in results:
        print(f"{icons[level]} {msg}")
    fails = sum(1 for lvl, _ in results if lvl == "FAIL")
    warns = sum(1 for lvl, _ in results if lvl == "WARN")
    print("-" * 70)
    print(f"{fails} problem(s) to fix, {warns} warning(s)." + ("  NOT ready to go live." if fails else "  No blocking problems found."))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
