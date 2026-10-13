"""
Liveness detection (anti-spoofing) for DeshGarv: an active head-turn challenge.

WHY THIS WORKS (and where it stops working)
-------------------------------------------
A real head is 3-D: the nose tip sticks out ~3 cm in front of the eye plane, so when the
head turns, the nose moves sideways relative to the eyes. A photo or phone screen is
FLAT: tilting it squashes everything by the same factor, so the nose stays put relative
to the eyes. We measure that relative offset:

        yaw_ratio = (nose offset from the eye midpoint, along the eye axis) / eye distance

* frontal face            -> ~0           (measured on real photos: median -0.01)
* real head turned 25-45  -> ~0.2 - 0.45  (model: 0.44 * tan(angle))
* flat photo tilted 45    -> |r| < ~0.05  (measured with the real detector; one steep case 0.14)

On top of that the SERVER picks a random sequence of turns (always both directions), reveals
it one step at a time, enforces time limits, and checks that the same person is in front
of the camera in every frame - so a pre-recorded clip or a swapped-in face doesn't pass.

WHAT THIS DOES NOT STOP
-----------------------
A real-time deepfake / virtual camera that performs the requested turns, a good 3-D mask,
or an attacker who films the victim performing every possible turn and switches clips in
real time. The camera of a remote voter can never be fully trusted; for high-stakes
elections add attested devices or in-person verification.

Thresholds are env-tunable (LIVENESS_*); use ``python tests/liveness_probe.py`` to see your
own live yaw_ratio values and calibrate.
"""
from __future__ import annotations

import os
import secrets
import threading
from dataclasses import dataclass
from typing import List, Optional, Tuple

import numpy as np

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
os.environ.setdefault("TF_USE_LEGACY_KERAS", "1")

DIRECTIONS = ("left", "right")   # the SUBJECT's left/right (left == nose toward image right)


# ============================================================================ geometry
def yaw_ratio(landmarks: dict) -> float:
    """Roll-invariant head-turn measure from 5-point landmarks (needs left_eye, right_eye, nose).

    Positive  = nose displaced toward the right of the *unmirrored* camera image,
                i.e. the subject turned to THEIR LEFT.
    Eyes are ordered by image x (not by name) so the detector's naming convention is irrelevant.
    """
    pts = {k: np.asarray(v, dtype=float) for k, v in landmarks.items()}
    a, b = sorted((pts["left_eye"], pts["right_eye"]), key=lambda p: p[0])
    d = float(np.linalg.norm(b - a))
    if d < 1e-6:
        raise ValueError("eyes coincide")
    mid = (a + b) / 2.0
    return float(np.dot(pts["nose"] - mid, (b - a) / d) / d)


# ============================================================================== config
@dataclass
class LivenessConfig:
    steps: int = 3                 # number of head turns
    turn_min: float = 0.20         # |yaw - baseline| needed to count as a turn (~24 degrees)
    center_max: float = 0.10       # |yaw - baseline| allowed to count as "facing the camera"
    hold_frames: int = 2           # consecutive frames the turn must be held
    base_frames: int = 2           # frames used to measure the person's own frontal baseline
    base_spread: float = 0.06      # max yaw wobble allowed while measuring the baseline
    step_timeout: float = 20.0     # seconds allowed per prompt
    total_timeout: float = 75.0    # seconds allowed for the whole challenge
    max_frames: int = 120          # frame budget per verification session
    max_challenges: int = 3        # new challenges allowed per session before restart
    # Identity during the challenge = "same person as the face verified moments ago in THIS session"
    # (same camera and lighting), measured as VGG-Face cosine distance. Real data: the same person across
    # different photos is 0.42 median / 0.62 max, different people never came closer than 0.69.
    anchor_center: float = 0.40    # max distance to the session face while facing the camera
    anchor_turned: float = 0.55    # max distance while the head is turned (VGG is pose-sensitive)
    registered_fallback: float = 0.60  # only used if a session somehow has no anchor

    @classmethod
    def from_env(cls, env=None) -> "LivenessConfig":
        env = os.environ if env is None else env
        cfg = cls()
        for name, kind in (("steps", int), ("turn_min", float), ("center_max", float),
                           ("hold_frames", int), ("base_frames", int), ("base_spread", float),
                           ("step_timeout", float), ("total_timeout", float), ("max_frames", int),
                           ("max_challenges", int), ("anchor_center", float), ("anchor_turned", float),
                           ("registered_fallback", float)):
            raw = env.get(f"LIVENESS_{name.upper()}")
            if raw not in (None, ""):
                setattr(cfg, name, kind(raw))
        if cfg.steps < 2:
            raise ValueError("LIVENESS_STEPS must be at least 2 (both directions are required)")
        if cfg.center_max >= cfg.turn_min:
            raise ValueError("LIVENESS_CENTER_MAX must be smaller than LIVENESS_TURN_MIN")
        if cfg.anchor_center > cfg.anchor_turned:
            raise ValueError("LIVENESS_ANCHOR_CENTER must not exceed LIVENESS_ANCHOR_TURNED")
        return cfg


# ============================================================================ challenge
def _choice(options):                       # indirection so tests can force a sequence
    return secrets.choice(options)


def new_challenge(now: float, cfg: LivenessConfig) -> dict:
    """Random turn sequence from the server's CSPRNG; always contains BOTH directions."""
    while True:
        seq = [_choice(DIRECTIONS) for _ in range(cfg.steps)]
        if len(set(seq)) == len(DIRECTIONS):
            break
    return {"seq": seq, "phase": "calibrate", "idx": 0, "hold": 0, "base": [],
            "base_yaw": None, "started": now, "step_started": now}


def zone(state: dict, yaw: float, cfg: LivenessConfig) -> str:
    """'center' (facing the camera) or 'off_center'. Used to pick the identity threshold."""
    if state["phase"] == "calibrate" or state["base_yaw"] is None:
        return "center"
    return "center" if abs(yaw - state["base_yaw"]) <= cfg.center_max else "off_center"


def expired(state: dict, now: float, cfg: LivenessConfig) -> bool:
    return state["phase"] != "done" and (now - state["started"] > cfg.total_timeout
                                         or now - state["step_started"] > cfg.step_timeout)


def step(state: dict, yaw: float, now: float, cfg: LivenessConfig) -> Tuple[dict, str]:
    """Advance the challenge with one validated frame. Returns (new_state, status).

    status: calibrating | recalibrate | turn | holding | step_done | return_center |
            wrong_way | done | timeout
    """
    s = dict(state)
    if s["phase"] == "done":
        return s, "done"
    if now - s["started"] > cfg.total_timeout or now - s["step_started"] > cfg.step_timeout:
        return s, "timeout"

    if s["phase"] == "calibrate":                 # learn this person's own "straight ahead"
        base = list(s["base"]) + [yaw]
        if max(base) - min(base) > cfg.base_spread:
            s["base"] = [yaw]
            return s, "recalibrate"
        s["base"] = base
        if len(base) < cfg.base_frames:
            return s, "calibrating"
        s.update(base_yaw=float(np.mean(base)), phase="turn", hold=0, step_started=now)
        return s, "turn"

    rel = yaw - s["base_yaw"]
    if s["phase"] == "return":                    # must come back to centre between turns
        if abs(rel) <= cfg.center_max:
            s.update(phase="turn", hold=0, step_started=now)
            return s, "turn"
        return s, "return_center"

    want = s["seq"][s["idx"]]                     # phase == "turn"
    signed = rel if want == "left" else -rel
    if signed >= cfg.turn_min:
        s["hold"] += 1
        if s["hold"] < cfg.hold_frames:
            return s, "holding"
        s["idx"] += 1
        s["hold"] = 0
        if s["idx"] >= len(s["seq"]):
            s["phase"] = "done"
            return s, "done"
        s.update(phase="return", step_started=now)
        return s, "step_done"
    s["hold"] = 0
    return s, ("wrong_way" if signed <= -cfg.turn_min else "turn")


def public_view(state: dict, cfg: LivenessConfig) -> dict:
    """What the browser may see: only the CURRENT instruction, never the whole sequence."""
    in_turn = state["phase"] in ("turn",)
    return {"step": min(state["idx"] + 1, len(state["seq"])), "total": len(state["seq"]),
            "direction": state["seq"][state["idx"]] if in_turn and state["idx"] < len(state["seq"]) else None,
            "hold": state["hold"], "hold_needed": cfg.hold_frames, "phase": state["phase"]}


# =============================================================================== pose
@dataclass
class PoseReading:
    n_faces: int
    yaw: Optional[float] = None
    box: Optional[tuple] = None          # (x1, y1, x2, y2) in ORIGINAL frame pixels
    landmarks: Optional[dict] = None     # name -> (x, y) in ORIGINAL frame pixels


class PoseAnalyzer:
    """RetinaFace 5-point landmarks -> yaw_ratio. (Ships with DeepFace; weights auto-download.)"""

    def __init__(self, threshold: Optional[float] = None, max_width: int = 480):
        # 0.8 (not 0.9): strongly turned faces score lower, and a missed turned face = "no face detected"
        self.threshold = float(os.environ.get("LIVENESS_DETECT_THRESHOLD", 0.8)) if threshold is None else threshold
        self.max_width = max_width
        self._lock = threading.Lock()
        self._rf = None

    def _load(self):
        if self._rf is None:
            from retinaface import RetinaFace
            self._rf = RetinaFace
        return self._rf

    def available(self) -> bool:
        try:
            self._load()
            return True
        except Exception:
            return False

    def warmup(self) -> None:
        try:
            self.analyze(np.full((240, 320, 3), 127, dtype=np.uint8))
        except Exception as exc:  # pragma: no cover
            print(f"[liveness] warm-up failed: {exc}")

    def analyze(self, img_bgr: np.ndarray) -> PoseReading:
        import cv2

        rf = self._load()
        h, w = img_bgr.shape[:2]
        scale = 1.0
        if w > self.max_width:
            scale = self.max_width / float(w)
            img_bgr = cv2.resize(img_bgr, (self.max_width, int(h * scale)), interpolation=cv2.INTER_AREA)
        with self._lock:
            # allow_upscaling=False: the default upscales every frame and is ~15x slower
            found = rf.detect_faces(img_bgr, threshold=self.threshold, allow_upscaling=False)
        faces = [f for f in (found or {}).values() if "landmarks" in f]
        if len(faces) != 1:
            return PoseReading(n_faces=len(faces))
        try:
            f = faces[0]
            return PoseReading(
                n_faces=1, yaw=yaw_ratio(f["landmarks"]),
                box=tuple(float(v) / scale for v in f["facial_area"]),
                landmarks={k: (float(v[0]) / scale, float(v[1]) / scale) for k, v in f["landmarks"].items()})
        except (KeyError, ValueError, TypeError):
            return PoseReading(n_faces=0)


def aligned_face_crop(img_bgr: np.ndarray, reading: PoseReading) -> np.ndarray:
    """Tight, eye-levelled crop of the face found by RetinaFace (which, unlike the frontal-only Haar
    detector, still finds turned heads). Measured on 57 real photos: embeddings from this crop differ
    from the proven Haar-path embeddings by only 0.067 (median). Returns the frame itself if the reading
    carries no geometry (test doubles)."""
    import cv2
    if reading.box is None or not reading.landmarks:
        return img_bgr
    x1, y1, x2, y2 = reading.box
    cx, cy, side = (x1 + x2) / 2, (y1 + y2) / 2, max(x2 - x1, y2 - y1)
    try:
        a, b = sorted((reading.landmarks["left_eye"], reading.landmarks["right_eye"]), key=lambda p: p[0])
        angle = float(np.degrees(np.arctan2(b[1] - a[1], b[0] - a[0])))
        M = cv2.getRotationMatrix2D(((a[0] + b[0]) / 2, (a[1] + b[1]) / 2), angle, 1.0)
        img_bgr = cv2.warpAffine(img_bgr, M, (img_bgr.shape[1], img_bgr.shape[0]), borderMode=cv2.BORDER_REFLECT)
        cx, cy = M @ np.array([cx, cy, 1.0])
    except (KeyError, ValueError):
        pass
    h, w = img_bgr.shape[:2]
    X1, Y1 = int(max(0, cx - side / 2)), int(max(0, cy - side / 2))
    X2, Y2 = int(min(w, cx + side / 2)), int(min(h, cy + side / 2))
    crop = img_bgr[Y1:Y2, X1:X2]
    return crop if crop.size else img_bgr
