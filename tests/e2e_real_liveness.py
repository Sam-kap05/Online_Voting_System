"""
Real-pipeline liveness check (real RetinaFace + real VGG-Face, no fakes):

    python tests/e2e_real_liveness.py

Plays PRESENTATION ATTACKS against the real endpoints using the demo voter's photo:
  A. a static photo held in front of the camera
  B. a flat photo tilted by hand toward the direction the server asks for (up to 60 degrees)
and checks the ballot stays locked. It also reports per-frame latency.

It cannot play a genuine live head turn (no webcam in CI) - for that run
`python tests/liveness_probe.py` on a machine with a camera.
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
os.environ.update(DESHGARV_DB=os.path.join(tmp, "e2e.db"), DESHGARV_PHOTO_DIR=os.path.join(tmp, "photos"),
                  DESHGARV_NO_DOTENV="1")

import app as appmod  # noqa: E402

sent = []
appmod.send_sms = lambda phone, msg: sent.append(msg)
app = appmod.create_app({"TESTING": True, "SECRET_KEY": "e2e", "PEPPER": "e2e", "RATELIMIT_ENABLED": False,
                         "OTP_RESEND_COOLDOWN": 0})
assert app.config["LIVENESS_ENABLED"], "liveness must be enabled by default"
ok = True


def check(label, cond, extra=""):
    global ok
    ok &= bool(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label} {extra}")


def tilt_photo(img, yaw_deg, cam_dist=2.2):
    """A flat card showing `img`, rotated about its vertical axis, seen by a pinhole camera."""
    h, w = img.shape[:2]
    a = np.radians(yaw_deg)
    corners = np.array([[-1, -h / w, 0], [1, -h / w, 0], [1, h / w, 0], [-1, h / w, 0]], float)
    Ry = np.array([[np.cos(a), 0, np.sin(a)], [0, 1, 0], [-np.sin(a), 0, np.cos(a)]])
    P = corners @ Ry.T + np.array([0, 0, cam_dist])
    f = 1.2 * w / 2
    proj = np.stack([f * P[:, 0] / P[:, 2] + w / 2, f * P[:, 1] / P[:, 2] + h / 2], 1).astype(np.float32)
    M = cv2.getPerspectiveTransform(np.float32([[0, 0], [w, 0], [w, h], [0, h]]), proj)
    return cv2.warpPerspective(img, M, (w, h), borderValue=(110, 110, 110))


def degrade(img):
    img = cv2.GaussianBlur((img * 0.85).astype(np.uint8), (3, 3), 0)
    return np.clip(img.astype(int) + np.random.normal(0, 6, img.shape), 0, 255).astype(np.uint8)


def jpg(img, width=480):
    h, w = img.shape[:2]
    img = cv2.resize(img, (width, int(h * width / w)), interpolation=cv2.INTER_AREA)
    return cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 85])[1].tobytes()


def post(client, url, img=None):
    data = {"frame": (io.BytesIO(jpg(img)), "f.jpg")} if img is not None else None
    return client.post(url, data=data, content_type="multipart/form-data" if data else None).get_json()


def start_session():
    c = app.test_client()
    assert c.post("/send_otp", json={"aadhaar": "123456789012"}).status_code == 200
    assert c.post("/verify_otp", json={"aadhaar": "123456789012", "otp": re.match(r"(\d{6})", sent[-1]).group(1)}).status_code == 200
    for _ in range(3):
        r = post(c, "/verify_face", degrade(PHOTO))
    assert r["verified"] and r["liveness_required"], r
    return c


print("loading models ...")
t0 = time.time()
app.extensions["face_service"].warmup()
app.extensions["pose_analyzer"].warmup()
print(f"  ready in {time.time() - t0:.1f}s\n")
PHOTO = cv2.imread(os.path.join(ROOT, "demo_data", "reference.jpg"))
PHOTO = cv2.resize(PHOTO, (960, int(PHOTO.shape[0] * 960 / PHOTO.shape[1])), interpolation=cv2.INTER_AREA)

print("0) Face match passes with the real photo, but the ballot is still locked")
c = start_session()
check("ballot locked after face match (liveness pending)", c.get("/voting-page").status_code == 302)
st = c.post("/liveness/start").get_json()
check("challenge issued, full sequence not revealed", st["status"] == "started" and "seq" not in st and st["total"] == 3)

print("\n1) Attack A: static photo held up to the camera")
times, statuses = [], []
for i in range(10):
    t = time.time(); r = post(c, "/liveness/frame", degrade(PHOTO)); times.append(time.time() - t); statuses.append(r["status"])
print("     statuses:", statuses, "| yaw:", [r.get("yaw") for r in [r]])
check("a held photo never passes", r["verified"] is False and "done" not in statuses)
check("real frames do get through detection + identity (reaches 'turn' prompt)", "turn" in statuses, f"(saw {sorted(set(statuses))})")
print(f"     latency per liveness frame: median {np.median(times):.2f}s, max {max(times):.2f}s")

print("\n2) Attack B: photo tilted by hand toward whatever direction is asked (up to 60 degrees)")
best = {}
for angle in (30, 45, 60):
    c = start_session()
    c.post("/liveness/start")
    seq, yaws = [], []
    for i in range(14):
        # look at what the server wants right now and tilt the photo that way (subject's left = image +x)
        want = (seq[-1] if seq else None)
        img = PHOTO
        if want == "left":
            img = tilt_photo(PHOTO, -angle)
        elif want == "right":
            img = tilt_photo(PHOTO, +angle)
        r = post(c, "/liveness/frame", degrade(img))
        seq.append(r.get("direction") or want)
        if r.get("yaw") is not None:
            yaws.append(r["yaw"])
        if r["verified"]:
            break
    best[angle] = (r["verified"], r["step"], (min(yaws), max(yaws)) if yaws else None)
    print(f"     tilt {angle:2d} deg: verified={r['verified']} stuck at step {r['step']}/3  yaw range seen {best[angle][2]}")
    check(f"tilting a flat photo {angle} deg does not pass liveness", r["verified"] is False)
    check("ballot still locked", c.get("/voter_details").status_code == 401)

print("\nRESULT:", "ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED")
sys.exit(0 if ok else 1)
