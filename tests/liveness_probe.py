"""
Calibrate / rehearse the head-turn liveness check on YOUR machine.

    python tests/liveness_probe.py                  # webcam, shows live yaw_ratio (press q to quit)
    python tests/liveness_probe.py --challenge      # rehearse the real challenge logic (no identity check)
    python tests/liveness_probe.py --identity       # ALSO print identity distance to your own face (calibration)
    python tests/liveness_probe.py --source clip.mp4 --no-gui   # run on a video file, print values

yaw_ratio is ~0 when you face the camera, grows when you turn your head. A turn counts once
|yaw - your baseline| >= LIVENESS_TURN_MIN (default 0.20) and "facing the camera" is
|yaw - baseline| <= LIVENESS_CENTER_MAX (default 0.10). --identity: look straight at the camera for the first few frames (they define "you"), then turn your head
slowly both ways. It prints dist = distance to your own face. Your dist while turned must stay below
LIVENESS_ANCHOR_TURNED (default 0.55), and while facing the camera below LIVENESS_ANCHOR_CENTER (0.40).
If you see larger numbers, raise those two values in .env (keep them well below ~0.65: different people were never
closer than 0.69 in testing).
If you can't reach the turn threshold
comfortably, lower LIVENESS_TURN_MIN in .env (keep it above ~0.14: tilted flat photos reached 0.137).
Positive values = you turned to YOUR LEFT (towards the left of the mirrored preview).
"""
import argparse
import os
import sys
import time

import cv2

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import liveness as lv  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--source", default="0", help="camera index or video file")
ap.add_argument("--challenge", action="store_true", help="run the real challenge state machine")
ap.add_argument("--no-gui", action="store_true", help="print only (no window)")
ap.add_argument("--identity", action="store_true", help="also measure identity distance to your own face")
args = ap.parse_args()

cfg = lv.LivenessConfig.from_env()
cap = cv2.VideoCapture(int(args.source) if args.source.isdigit() else args.source)
if not cap.isOpened():
    sys.exit("Could not open the video source.")
analyzer = lv.PoseAnalyzer()
svc, anchor_frames = None, []
if args.identity:
    from face_service import DeepFaceService
    svc = DeepFaceService()
state = lv.new_challenge(time.time(), cfg) if args.challenge else None
last_t, shown = 0.0, "starting..."
print("Loading face model (first run downloads weights)...")
while True:
    ok, frame = cap.read()
    if not ok:
        break
    now = time.time()
    if now - last_t > 0.4:                       # same cadence as the browser (~2 fps)
        last_t = now
        pose = analyzer.analyze(frame)
        if pose.n_faces != 1:
            shown = f"faces detected: {pose.n_faces}"
        elif state is None:
            side = "LEFT" if pose.yaw >= cfg.turn_min else "RIGHT" if pose.yaw <= -cfg.turn_min else "centre"
            shown = f"yaw_ratio = {pose.yaw:+.3f}   ({side})"
            if svc is not None:
                emb = svc.embed_crop(lv.aligned_face_crop(frame, pose))
                if len(anchor_frames) < 3 and abs(pose.yaw) < 0.12:
                    anchor_frames.append(emb)
                    shown += f"   [learning your face {len(anchor_frames)}/3]"
                elif anchor_frames:
                    import numpy as _np
                    dist = svc.distance(emb, list(_np.mean(anchor_frames, axis=0)))
                    lim = cfg.anchor_center if abs(pose.yaw) <= cfg.center_max else cfg.anchor_turned
                    shown += f"   dist = {dist:.3f}  (limit {lim:.2f})  {'OK' if dist <= lim else 'TOO FAR'}"
        else:
            state, status = lv.step(state, pose.yaw, now, cfg)
            want = state["seq"][state["idx"]] if state["idx"] < len(state["seq"]) else "-"
            shown = f"yaw {pose.yaw:+.2f} | {status} | step {min(state['idx'] + 1, len(state['seq']))}/{len(state['seq'])} want={want}"
            if status in ("done", "timeout"):
                print(shown); print("PASSED" if status == "done" else "TIMED OUT"); break
        print(shown)
    if not args.no_gui:
        view = cv2.flip(frame, 1)                # mirrored preview, like the website
        cv2.putText(view, shown, (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
        cv2.imshow("liveness probe (q to quit)", view)
        if cv2.waitKey(1) & 0xFF == ord("q"):
            break
cap.release()
cv2.destroyAllWindows()
