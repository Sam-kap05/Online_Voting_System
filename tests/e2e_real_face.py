"""
End-to-end check with the REAL DeepFace pipeline (no fakes).

    python tests/e2e_real_face.py

Simulates browser webcam frames using the demo photos, drives the Flask app through
register -> OTP -> face match -> vote, and prints the cosine distances so you can
judge the threshold on your own data. First run downloads ~580 MB of VGG-Face weights.
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
tmp = tempfile.mkdtemp()
os.environ.update(DESHGARV_DB=os.path.join(tmp, "e2e.db"), DESHGARV_PHOTO_DIR=os.path.join(tmp, "photos"))

import app as appmod  # noqa: E402

sent = []
appmod.send_sms = lambda phone, msg: sent.append(msg)
app = appmod.create_app({"TESTING": True, "SECRET_KEY": "e2e", "PEPPER": "e2e", "LIVENESS_ENABLED": False,  # liveness: see e2e_real_liveness.py
                         "RATELIMIT_ENABLED": False, "OTP_RESEND_COOLDOWN": 0})
svc = app.extensions["face_service"]


def photo(name):
    return cv2.imread(os.path.join(ROOT, "demo_data", name))


def jpg_bytes(img, width=480):
    h, w = img.shape[:2]
    img = cv2.resize(img, (width, int(h * width / w)), interpolation=cv2.INTER_AREA)
    return cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 85])[1].tobytes()


def webcam_degrade(img):
    """Make a clean photo look like a mediocre webcam frame."""
    img = cv2.GaussianBlur((img * 0.8).astype(np.uint8), (3, 3), 0)
    return np.clip(img.astype(int) + np.random.normal(0, 8, img.shape), 0, 255).astype(np.uint8)


def send_frame(client, img_bytes):
    return client.post("/verify_face", data={"frame": (io.BytesIO(img_bytes), "f.jpg")},
                       content_type="multipart/form-data").get_json()


def otp():
    return re.match(r"(\d{6})", sent[-1]).group(1)


def login(client, aadhaar):
    assert client.post("/send_otp", json={"aadhaar": aadhaar}).status_code == 200
    assert client.post("/verify_otp", json={"aadhaar": aadhaar, "otp": otp()}).status_code == 200


ok = True


def check(label, cond, extra=""):
    global ok
    ok &= bool(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label} {extra}")


print("loading model + warming up ...")
t = time.time()
svc.warmup()
print(f"  ready in {time.time() - t:.1f}s  (match threshold {svc.match_threshold}, "
      f"duplicate threshold {svc.duplicate_threshold})\n")

A, B = photo("reference.jpg"), photo("reference2.jpg")
fa, fb = svc.detect(A), svc.detect(B)
print(f"demo photos: reference.jpg faces={len(fa)}, reference2.jpg faces={len(fb)}")
print(f"cosine distance reference.jpg vs reference2.jpg = {svc.distance(fa[0].embedding, fb[0].embedding):.3f}"
      f"   (<= {svc.match_threshold} would be treated as the SAME person)\n")

print("1) Registered voter (Samarth) - live face check with webcam-like frames")
c = app.test_client()
login(c, "123456789012")
check("ballot locked right after OTP", c.get("/voting-page").status_code == 302)
r = send_frame(c, jpg_bytes(np.full((480, 640, 3), 127, np.uint8), 480))
check("blank frame -> no_face", r["status"] == "no_face", r)
two = np.hstack([cv2.resize(A, (A.shape[1] * 540 // A.shape[0], 540)),
                 cv2.resize(B, (B.shape[1] * 540 // B.shape[0], 540))])
r = send_frame(c, jpg_bytes(two, 640))
check("two people in frame -> multiple_faces", r["status"] == "multiple_faces", r)
for i in range(3):
    r = send_frame(c, jpg_bytes(webcam_degrade(A)))
    print(f"     frame {i + 1}: {r}")
check("3 consecutive webcam-like frames of the right person -> verified", r["verified"] is True)
check("ballot now unlocked", c.get("/voting-page").status_code == 200)
cand = c.get("/voter_details").get_json()["candidates"][0]["id"]
check("vote accepted", c.post("/cast_vote", json={"candidate_id": cand}).status_code == 200)

print("\n2) Self-registration with a real photo")
cr = app.test_client()
r = cr.post("/register/start", data={"name": "Priya Nair", "aadhaar": "234567890123", "phone": "9812345678",
                                      "constituency": "New Delhi", "photo": (io.BytesIO(jpg_bytes(B, 1000)), "p.jpg")},
            content_type="multipart/form-data")
check("valid photo accepted, OTP sent", r.status_code == 200, r.get_json().get("message", ""))
check("registration completes with correct OTP",
      cr.post("/register/verify", json={"otp": otp()}).status_code == 200)

r = app.test_client().post("/register/start", data={
    "name": "Impostor", "aadhaar": "345678901234", "phone": "9811111111", "constituency": "New Delhi",
    "photo": (io.BytesIO(jpg_bytes(webcam_degrade(B), 1000)), "p.jpg")}, content_type="multipart/form-data")
check("same face under a 2nd Aadhaar -> rejected", r.status_code == 409, r.get_json()["message"])

noface = np.full((600, 600, 3), 90, np.uint8)
cv2.circle(noface, (300, 300), 150, (200, 200, 200), -1)
r = app.test_client().post("/register/start", data={
    "name": "No Face", "aadhaar": "456789012345", "phone": "9822222222", "constituency": "New Delhi",
    "photo": (io.BytesIO(jpg_bytes(noface, 600)), "p.jpg")}, content_type="multipart/form-data")
check("photo with no face -> rejected", r.status_code == 400 and "No face" in r.get_json()["message"],
      r.get_json()["message"])

print("\n3) The newly registered voter logs in and passes the face check")
cn = app.test_client()
login(cn, "234567890123")
for _ in range(3):
    r = send_frame(cn, jpg_bytes(webcam_degrade(B)))
check("new voter verified by live face match", r["verified"] is True, r)

print("\n4) Impersonation: someone else's face against Vipul's account")
ci = app.test_client()
login(ci, "111122223333")
r = send_frame(ci, jpg_bytes(webcam_degrade(A)))
print(f"     status={r['status']}  (Vipul's reference is reference2.jpg; sending reference.jpg)")

print("\nRESULT:", "ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED")
sys.exit(0 if ok else 1)
