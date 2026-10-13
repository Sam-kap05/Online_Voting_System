"""
Face detection / matching for DeshGarv.

This replaces the old ``camera.py``, which opened the *server's* webcam
(``cv2.VideoCapture(0)``). That only works when the server is the voter's own
laptop. Here the browser captures frames (``getUserMedia``) and uploads them;
this module only ever sees images, never a camera.

Design notes
------------
* One ``DeepFace.represent`` call per image returns every detected face with a
  detection confidence and an embedding, so we can count faces *and* compare
  identity in a single pass.
* The old code used ``enforce_detection=False``. With that flag DeepFace treats
  an image with *no face at all* as a single "face" with confidence 0.0 and
  still compares it. We keep the flag (so it never raises) but discard
  detections below ``min_confidence`` and below ``min_face_ratio`` (tiny
  background false-positives).
* The deepface/TensorFlow import is lazy so the web app (and its tests) can
  start without it; ``available()`` reports whether it can be used.
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from typing import List, Sequence

import numpy as np

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
os.environ.setdefault("TF_USE_LEGACY_KERAS", "1")  # deepface expects tf-keras


@dataclass
class Face:
    embedding: List[float]
    confidence: float
    x: int
    y: int
    w: int
    h: int
    ratio: float = 0.0  # face width / image width (after downscaling)


def cosine_distance(a: Sequence[float], b: Sequence[float]) -> float:
    a = np.asarray(a, dtype=np.float64)
    b = np.asarray(b, dtype=np.float64)
    denom = float(np.linalg.norm(a) * np.linalg.norm(b))
    if denom == 0.0:
        return 1.0
    return 1.0 - float(np.dot(a, b) / denom)


class DeepFaceService:
    def __init__(
        self,
        model_name: str = "VGG-Face",
        detector_backend: str = "opencv",
        min_confidence: float = 0.6,
        min_face_ratio: float = 0.08,
        match_threshold: float = 0.55,
        duplicate_threshold: float = 0.35,
        max_width: int = 640,
    ):
        self.model_name = model_name
        self.detector_backend = detector_backend
        self.min_confidence = min_confidence
        self.min_face_ratio = min_face_ratio
        # cosine distance: <= match_threshold  => same person (login check)
        self.match_threshold = match_threshold
        # stricter: <= duplicate_threshold => "this face is already registered"
        self.duplicate_threshold = duplicate_threshold
        self.max_width = max_width
        self._lock = threading.Lock()  # TensorFlow models are not re-entrant
        self._deepface = None

    # ------------------------------------------------------------------ setup
    def available(self) -> bool:
        try:
            self._load()
            return True
        except Exception:
            return False

    def _load(self):
        if self._deepface is None:
            from deepface import DeepFace  # heavy import, done lazily

            self._deepface = DeepFace
        return self._deepface

    def warmup(self) -> None:
        """Load model weights up-front so the first voter doesn't wait."""
        try:
            self.detect(np.full((240, 320, 3), 127, dtype=np.uint8))
        except Exception as exc:  # pragma: no cover - best effort
            print(f"[face] warm-up failed: {exc}")

    # -------------------------------------------------------------- detection
    def detect(self, img_bgr: np.ndarray) -> List[Face]:
        """Return the real faces in a BGR image (low-confidence ones dropped)."""
        import cv2

        deepface = self._load()
        h, w = img_bgr.shape[:2]
        scale = 1.0
        if w > self.max_width:
            scale = self.max_width / float(w)
            img_bgr = cv2.resize(
                img_bgr, (self.max_width, int(h * scale)), interpolation=cv2.INTER_AREA
            )
            w = self.max_width

        with self._lock:
            results = deepface.represent(
                img_path=img_bgr,
                model_name=self.model_name,
                detector_backend=self.detector_backend,
                enforce_detection=False,
            )

        faces: List[Face] = []
        for r in results:
            conf = float(r.get("face_confidence") or 0.0)
            area = r.get("facial_area") or {}
            fw = int(area.get("w", 0))
            if conf < self.min_confidence or fw < self.min_face_ratio * w:
                continue
            faces.append(
                Face(
                    embedding=list(r["embedding"]),
                    confidence=conf,
                    x=int(area.get("x", 0)),
                    y=int(area.get("y", 0)),
                    w=fw,
                    h=int(area.get("h", 0)),
                    ratio=fw / float(w),
                )
            )
        return faces

    def embed_crop(self, face_bgr: np.ndarray) -> List[float]:
        """Embedding of an image that is ALREADY a cropped face (no detector involved), so it works on
        turned heads that the frontal-only Haar detector cannot see."""
        deepface = self._load()
        with self._lock:
            result = deepface.represent(img_path=face_bgr, model_name=self.model_name,
                                        detector_backend="skip", enforce_detection=False, align=False)
        return list(result[0]["embedding"])

    def distance(self, a: Sequence[float], b: Sequence[float]) -> float:
        return cosine_distance(a, b)
