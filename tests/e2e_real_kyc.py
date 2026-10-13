"""
End-to-end check of Aadhaar (offline e-KYC) registration with the REAL face models.

    python tests/e2e_real_kyc.py
    E2E_OTHER_PERSON_PHOTO=friend.jpg python tests/e2e_real_kyc.py      # also test the impersonation case

The UIDAI-style files are signed with a LOCAL test key (a genuine UIDAI file cannot be made here). The Aadhaar photo is
the demo photo shrunk to Aadhaar size and heavily compressed, so the printed distances show how a small, low-quality
Aadhaar photo compares with a normal selfie - use them to judge AADHAAR_PHOTO_MATCH_THRESHOLD.
"""
import io
import os
import re
import sys
import tempfile
import time

import cv2
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
tmp = tempfile.mkdtemp()
os.environ.update(DESHGARV_DB=os.path.join(tmp, "e2e.db"), DESHGARV_PHOTO_DIR=os.path.join(tmp, "photos"),
                  DESHGARV_NO_DOTENV="1")
for k in [k for k in os.environ if k.startswith(("SMS_", "FIREBASE_", "AADHAAR_"))]:
    del os.environ[k]

import app as appmod  # noqa: E402
import kyc_helpers as kh  # noqa: E402

sent = []
appmod.send_sms = lambda phone, msg: sent.append(msg)
app = appmod.create_app({"TESTING": True, "SECRET_KEY": "e2e", "PEPPER": "e2e", "RATELIMIT_ENABLED": False,
                         "OTP_RESEND_COOLDOWN": 0, "LIVENESS_ENABLED": False, "SEED_DEMO": False,
                         "AADHAAR_KYC": "offline_xml", "UIDAI_CERTS": [kh.CERT]})
svc = app.extensions["face_service"]
ok = True


def check(label, cond, extra=""):
    global ok
    ok &= bool(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label} {extra}")


def photo(name):
    return cv2.imread(os.path.join(ROOT, "demo_data", name))


def jpg(img, width=800, q=90):
    h, w = img.shape[:2]
    img = cv2.resize(img, (width, int(h * width / w)), interpolation=cv2.INTER_AREA)
    return cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, q])[1].tobytes()


def aadhaar_sized(img, width=150):
    """UIDAI's photo is a LOW-resolution JPEG 2000 'for visual inspection only'. 150 px is a typical guess, 110 px a bad case."""
    h, w = img.shape[:2]
    small = cv2.resize(img, (width, int(h * width / w)), interpolation=cv2.INTER_AREA)
    return kh.jp2_bytes(small)


def register(client, selfie, aadhaar_photo_bytes, **kw):
    aadhaar, phone, share = kw.pop("aadhaar", "234567890123"), kw.pop("phone", "9812345678"), kw.pop("share", "Lock@487")
    zip_bytes = kw.pop("zip_bytes", None) or kh.kyc_zip(aadhaar=aadhaar, mobile=phone, share=share, photo=aadhaar_photo_bytes, **kw)
    return client.post("/register/start", data={
        "aadhaar": aadhaar, "phone": phone, "constituency": "New Delhi", "share_code": share,
        "photo": (io.BytesIO(jpg(selfie, 900)), "me.jpg"), "kyc_zip": (io.BytesIO(zip_bytes), "offlineaadhaar.zip")},
        content_type="multipart/form-data")


print("loading models ...")
t0 = time.time()
svc.warmup()
print(f"  ready in {time.time() - t0:.1f}s\n")
A, B = photo("reference.jpg"), photo("reference2.jpg")
ap = aadhaar_sized(A)
fa = svc.detect(cv2.imdecode(np.frombuffer(jpg(A, 900), np.uint8), 1))[0]
import uidai_kyc as uk  # noqa: E402
fb = svc.detect(cv2.imdecode(np.frombuffer(jpg(B, 900), np.uint8), 1))[0]
print("distances with the real models (limit for the Aadhaar photo = "
      f"{app.config['AADHAAR_PHOTO_MATCH_THRESHOLD']}); 'selfie' = full-size photo, 'Aadhaar photo' = shrunk JPEG 2000:")
for wdt in (200, 150, 110):
    fxx = max(svc.detect(uk.decode_photo(aadhaar_sized(A, wdt))), key=lambda f: f.w * f.h)
    print(f"   {wdt:3d}px Aadhaar photo: same picture {svc.distance(fa.embedding, fxx.embedding):.3f} | the 2nd demo photo {svc.distance(fb.embedding, fxx.embedding):.3f}")
print()

print("1) a genuine-looking file")
c = app.test_client()
r = register(c, A, ap)
check("valid file + matching selfie accepted", r.status_code == 200 and r.get_json().get("verified_name") == "Asha Rao", r.get_json().get("message", ""))
if r.status_code != 200:
    print("\nRESULT: SOME CHECKS FAILED (stopping: the genuine file was refused - see the [KYC] distance line above)")
    sys.exit(1)
r2 = c.post("/register/verify", json={"otp": re.match(r"(\d{6})", sent[-1]).group(1)})
check("registration completes after the phone OTP", r2.status_code == 200)

print("\n2) forged / wrong inputs are refused (nothing is registered)")
for label, kw, frag in [
        ("a mobile number that is not the Aadhaar-linked one", dict(phone="9000000001", aadhaar="345678901234",
         zip_bytes=kh.kyc_zip(aadhaar="345678901234", mobile="9812345678", photo=ap)), "linked to your Aadhaar"),
        ("a wrong share code", dict(share="Lock@487", zip_bytes=kh.kyc_zip(share="OTHER", photo=ap, aadhaar="345678901234", mobile="9812345678"), aadhaar="345678901234"), "share code"),
        ("an edited file", dict(zip_bytes=kh.make_zip(kh.build_xml(photo=ap, aadhaar="345678901234").replace(b"Asha Rao", b"Evil Person")), aadhaar="345678901234"), "signature"),
        ("a file signed by someone else", dict(priv=kh.OTHER_PRIV, aadhaar="345678901234"), "signature"),
        ("a number that does not match the file", dict(zip_bytes=kh.kyc_zip(photo=ap), aadhaar="111111118888"), "ending in")]:
    r = register(app.test_client(), A, ap, **kw)
    check(f"{label} -> refused", r.status_code == 400 and frag in r.get_json()["message"], r.get_json()["message"][:70])

print("\n3) one real person -> one registration")
r = register(app.test_client(), B, aadhaar_sized(B), aadhaar="999999990123", phone="9000000002")
check("same UIDAI identity again (other number, phone, selfie) -> refused", r.status_code == 409 and "already registered" in r.get_json()["message"], r.get_json()["message"][:70])
r = register(app.test_client(), B, aadhaar_sized(B), aadhaar="456789012345", phone="9822222222", name="Another Person", dob="1992-02-02")
check("a different identity but a face that is ALREADY enrolled -> refused (face check)",
      r.status_code in (400, 409) and ("matching face" in r.get_json()["message"] or "does not match" in r.get_json()["message"]),
      r.get_json()["message"][:80])

other = os.environ.get("E2E_OTHER_PERSON_PHOTO")
if other and os.path.exists(other):
    print("\n4) impersonation: the victim's file, but the attacker's face")
    r = register(app.test_client(), cv2.imread(other), ap, aadhaar="567890123456", phone="9833333333")
    check("a different person's selfie does not match the Aadhaar photo -> refused", r.status_code == 400 and "does not match the photo" in r.get_json()["message"], r.get_json()["message"][:70])
else:
    print("\n4) (skipped) set E2E_OTHER_PERSON_PHOTO=<photo of a different person> to test the impersonation case")

print("\nRESULT:", "ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED")
sys.exit(0 if ok else 1)
