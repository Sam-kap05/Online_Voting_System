"""Liveness (head-turn challenge): geometry, state machine, and attack scenarios."""
import io
import itertools
import json
import math
import os
import re
import sqlite3
import sys
import time

import cv2
import numpy as np
import pytest

os.environ["DESHGARV_NO_DOTENV"] = "1"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as appmod  # noqa: E402
import liveness as lv  # noqa: E402
from liveness import LivenessConfig, PoseReading  # noqa: E402
from test_app import (PERSON_A, PERSON_B, FakeFaceService, add_candidates, jpeg,  # noqa: E402
                      last_otp, login_to_face_step, pass_face_check, register)

CFG = LivenessConfig()


def emb_at_distance(d):
    """An embedding whose cosine distance from PERSON_A is exactly d."""
    c = 1.0 - d
    return [c, math.sqrt(1 - c * c), 0.0, 0.0]


# =================================================================== geometry
def lm(eye_l=(-32, 0), eye_r=(32, 0), nose=(0, 40)):
    return {"left_eye": eye_l, "right_eye": eye_r, "nose": nose}


def rot(points, deg):
    a = math.radians(deg)
    R = np.array([[math.cos(a), -math.sin(a)], [math.sin(a), math.cos(a)]])
    return {k: tuple(R @ np.array(v)) for k, v in points.items()}


def head_landmarks(yaw_deg, nose_depth=28.0):
    """Synthetic 3-D head (mm): eyes 64 mm apart, nose tip `nose_depth` in front. Orthographic camera.
    Positive yaw = subject turns to THEIR left = nose moves toward image +x."""
    a = math.radians(yaw_deg)
    def project(x, y, z):
        return (x * math.cos(a) + z * math.sin(a), y)
    return {"left_eye": project(-32, 0, 0), "right_eye": project(32, 0, 0), "nose": project(0, 40, nose_depth)}


class TestGeometry:
    def test_frontal_is_zero(self):
        assert lv.yaw_ratio(lm()) == pytest.approx(0.0)

    def test_sign_convention(self):
        assert lv.yaw_ratio(lm(nose=(10, 40))) > 0       # nose toward image-right = subject's LEFT
        assert lv.yaw_ratio(lm(nose=(-10, 40))) < 0

    def test_roll_invariant(self):
        base = lm(nose=(8, 40))
        for deg in (-40, -15, 10, 35):
            assert lv.yaw_ratio(rot(base, deg)) == pytest.approx(lv.yaw_ratio(base), abs=1e-9)

    def test_independent_of_landmark_naming_convention(self):
        a = lm(eye_l=(-32, 0), eye_r=(32, 0), nose=(9, 40))
        b = lm(eye_l=(32, 0), eye_r=(-32, 0), nose=(9, 40))      # names swapped, positions same
        assert lv.yaw_ratio(a) == pytest.approx(lv.yaw_ratio(b))

    def test_degenerate_eyes_rejected(self):
        with pytest.raises(ValueError):
            lv.yaw_ratio(lm(eye_l=(5, 5), eye_r=(5, 5)))

    def test_real_3d_head_turn_is_large_and_monotonic(self):
        r = [lv.yaw_ratio(head_landmarks(d)) for d in (0, 10, 20, 30, 45)]
        assert r[0] == pytest.approx(0, abs=1e-9)
        assert r == sorted(r)                                      # monotonic in angle
        assert r[1] < CFG.center_max                               # 10 deg still counts as "centre"
        assert r[3] > CFG.turn_min and r[4] > r[3]                 # 30+ deg counts as a turn
        assert lv.yaw_ratio(head_landmarks(-30)) < -CFG.turn_min   # and the other way is negative

    def test_flat_photo_cannot_fake_a_turn(self):
        """A planar spoof has no nose depth: tilting it rotates/squashes everything equally."""
        for deg in (0, 15, 30, 45, 60, -45):
            assert abs(lv.yaw_ratio(head_landmarks(deg, nose_depth=0.0))) < 1e-9


# ====================================================================== config
class TestConfig:
    def test_defaults_are_sane(self):
        assert CFG.center_max < CFG.turn_min and CFG.steps >= 2

    def test_env_overrides(self):
        c = LivenessConfig.from_env({"LIVENESS_STEPS": "4", "LIVENESS_TURN_MIN": "0.25"})
        assert c.steps == 4 and c.turn_min == 0.25

    @pytest.mark.parametrize("env", [{"LIVENESS_STEPS": "1"},
                                     {"LIVENESS_CENTER_MAX": "0.3", "LIVENESS_TURN_MIN": "0.2"},
                                     {"LIVENESS_ANCHOR_CENTER": "0.7", "LIVENESS_ANCHOR_TURNED": "0.5"}])
    def test_dangerous_settings_rejected(self, env):
        with pytest.raises(ValueError):
            LivenessConfig.from_env(env)


class TestPoseAnalyzerAndCrop:
    def test_analyzer_maps_geometry_back_to_original_pixels_and_uses_a_lenient_threshold(self, monkeypatch):
        monkeypatch.delenv("LIVENESS_DETECT_THRESHOLD", raising=False)
        seen = {}

        class FakeRF:
            def detect_faces(self, img, threshold, allow_upscaling):
                seen.update(shape=img.shape, threshold=threshold, up=allow_upscaling)
                return {"face_1": {"score": .99, "facial_area": [48, 60, 144, 180],
                                   "landmarks": {"left_eye": (120, 100), "right_eye": (72, 100), "nose": (96, 130),
                                                 "mouth_left": (115, 160), "mouth_right": (77, 160)}}}
        an = lv.PoseAnalyzer(max_width=480)
        an._rf = FakeRF()
        r = an.analyze(np.zeros((1080, 1920, 3), np.uint8))               # frame is 4x wider than the analysed copy
        assert seen["shape"][1] == 480 and seen["threshold"] == 0.8 and seen["up"] is False
        assert r.n_faces == 1 and r.box == (192.0, 240.0, 576.0, 720.0)    # x4 back to original pixels
        assert r.landmarks["nose"] == (384.0, 520.0) and r.yaw == pytest.approx(0.0)

    def test_detect_threshold_is_env_tunable(self, monkeypatch):
        monkeypatch.setenv("LIVENESS_DETECT_THRESHOLD", "0.6")
        assert lv.PoseAnalyzer().threshold == 0.6

    def test_crop_is_a_tight_square_around_the_face(self):
        img = np.zeros((400, 600, 3), np.uint8)
        img[100:300, 200:400] = 255                                       # the "face"
        r = PoseReading(1, 0.0, box=(200, 100, 400, 300),
                        landmarks={"left_eye": (340, 170), "right_eye": (260, 170), "nose": (300, 220)})
        crop = lv.aligned_face_crop(img, r)
        assert abs(crop.shape[0] - 200) <= 2 and abs(crop.shape[1] - 200) <= 2 and crop.mean() > 240

    def test_crop_levels_a_tilted_head(self):
        img = np.zeros((400, 400, 3), np.uint8)
        cv2.line(img, (140, 160), (260, 200), (255, 255, 255), 6)         # eye line tilted ~18 degrees
        r = PoseReading(1, 0.0, box=(120, 120, 280, 280),
                        landmarks={"left_eye": (260, 200), "right_eye": (140, 160), "nose": (200, 230)})
        crop = lv.aligned_face_crop(img, r)
        ys, xs = np.nonzero(crop[:, :, 0] > 200)
        slope = np.polyfit(xs, ys, 1)[0]
        assert abs(slope) < 0.08                                           # the tilted line is now ~horizontal

    def test_crop_falls_back_to_the_frame_without_geometry_or_when_the_box_is_off_image(self):
        img = np.ones((100, 100, 3), np.uint8)
        assert lv.aligned_face_crop(img, PoseReading(1, 0.0)) is img
        off = PoseReading(1, 0.0, box=(500, 500, 600, 600), landmarks={"left_eye": (510, 510), "right_eye": (590, 510), "nose": (550, 550)})
        assert lv.aligned_face_crop(img, off).shape == img.shape


# ============================================================ challenge machine
def run(seq_yaws, state=None, cfg=CFG, t0=1000.0, dt=0.5):
    state = state or lv.new_challenge(t0, cfg)
    statuses, t = [], t0
    for y in seq_yaws:
        t += dt
        state, st = lv.step(state, y, t, cfg)
        statuses.append(st)
    return state, statuses


def forced(monkeypatch, seq):
    it = itertools.cycle(seq)
    monkeypatch.setattr(lv, "_choice", lambda options: next(it))


class TestChallenge:
    def test_always_contains_both_directions_and_all_sequences_occur(self):
        seen = set()
        for _ in range(600):
            seq = tuple(lv.new_challenge(0, CFG)["seq"])
            assert len(seq) == CFG.steps and set(seq) == {"left", "right"}
            seen.add(seq)
        assert len(seen) == 6          # 2^3 minus the two single-direction sequences

    def test_happy_path(self, monkeypatch):
        forced(monkeypatch, ["left", "right", "left"])
        state, st = run([0, 0,             # calibrate
                         .3, .3,           # turn left, hold      -> step_done
                         0,                # back to centre
                         -.3, -.3,         # turn right           -> step_done
                         0.02,             # centre
                         .3, .3])          # turn left            -> done
        assert st == ["calibrating", "turn", "holding", "step_done", "turn",
                      "holding", "step_done", "turn", "holding", "done"]
        assert state["phase"] == "done"

    def test_baseline_cancels_a_naturally_off_centre_face(self, monkeypatch):
        forced(monkeypatch, ["left", "right", "left"])
        b = 0.09                                   # this person's "straight ahead" reads +0.09
        state, st = run([b, b, b + .3, b + .3, b, b - .3, b - .3, b, b + .3, b + .3])
        assert st[-1] == "done"

    def test_static_photo_never_completes(self):
        _, st = run([0.01, -0.01] * 200, dt=0.1)
        assert "done" not in st and st[-1] in ("turn", "timeout")

    def test_tilted_flat_photo_never_completes(self, monkeypatch):
        """Worst flat-photo yaw measured with the real detector: 0.137. An attacker who knows the
        sequence and tilts the photo to exactly that on cue must still fall short of turn_min."""
        forced(monkeypatch, ["left", "right", "left"])
        p = 0.137
        _, st = run([0, 0, p, p, p, 0, -p, -p, -p, 0, p, p, p])
        assert "done" not in st and "step_done" not in st

    def test_threshold_leaves_a_margin_above_the_worst_flat_photo(self):
        assert CFG.turn_min >= 0.137 + 0.05 and CFG.center_max < CFG.turn_min

    def test_wrong_direction_does_not_count(self, monkeypatch):
        forced(monkeypatch, ["left", "right", "left"])
        _, st = run([0, 0, -.3, -.3, -.3])        # first prompt is LEFT; user turns right
        assert st[2:] == ["wrong_way"] * 3

    def test_hold_must_be_consecutive(self, monkeypatch):
        forced(monkeypatch, ["left", "right", "left"])
        _, st = run([0, 0, .3, 0, .3, 0, .3])
        assert "step_done" not in st

    def test_must_return_to_centre_between_turns(self, monkeypatch):
        forced(monkeypatch, ["left", "left", "right"])
        state, st = run([0, 0, .3, .3])           # first LEFT done
        assert st[-1] == "step_done"
        state, st2 = run([.3, .3, .3], state=state)   # stays turned: the next LEFT must NOT count
        assert st2 == ["return_center"] * 3 and state["idx"] == 1
        state, st3 = run([0, .3, .3], state=state)
        assert st3 == ["turn", "holding", "step_done"] and state["idx"] == 2

    def test_unsteady_baseline_is_remeasured(self):
        state, st = run([0.0, 0.3])
        assert st == ["calibrating", "recalibrate"]

    def test_timeouts(self, monkeypatch):
        forced(monkeypatch, ["left", "right", "left"])
        _, st = run([0, 0, 0], dt=CFG.step_timeout + 1)
        assert st[-1] == "timeout"
        state = lv.new_challenge(0.0, CFG)
        assert lv.expired(state, CFG.step_timeout + 1, CFG) and not lv.expired(state, 1.0, CFG)

    def test_public_view_reveals_only_the_current_step(self, monkeypatch):
        forced(monkeypatch, ["left", "right", "left"])
        state, _ = run([0, 0])
        view = lv.public_view(state, CFG)
        assert view["direction"] == "left" and view["step"] == 1 and view["total"] == 3
        assert "seq" not in view and "right" not in json.dumps(view)


# ================================================================== endpoints
class FakePose:
    def __init__(self):
        self.reading = PoseReading(1, 0.0)

    def available(self):
        return True

    def analyze(self, img):
        return self.reading


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    for key in [k for k in os.environ if k.startswith(("SMS_", "TWILIO_", "MSG91_"))]:
        monkeypatch.delenv(key)
    sent, fake, pose = [], FakeFaceService(), FakePose()
    monkeypatch.setattr(appmod, "send_sms", lambda p, m: sent.append((p, m)))
    app = appmod.create_app({
        "TESTING": True, "SECRET_KEY": "k", "PEPPER": "p", "DATABASE": str(tmp_path / "t.db"),
        "PHOTO_DIR": str(tmp_path / "ph"), "SEED_DEMO": False, "RATELIMIT_ENABLED": False,
        "OTP_RESEND_COOLDOWN": 0, "LIVENESS_ENABLED": True, "FACE_SERVICE": fake, "POSE_ANALYZER": pose,
        "ADMIN_PASSWORD_HASH": appmod.generate_password_hash("x")})
    return type("Ctx", (), dict(app=app, fake=fake, pose=pose, sent=sent, tmp=tmp_path))


def db_of(ctx):
    conn = sqlite3.connect(ctx.app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    return conn


@pytest.fixture
def face_ok(ctx):
    """Voter who passed OTP + face match but NOT liveness yet (the session now holds their identity anchor)."""
    add_candidates(ctx)
    c = ctx.app.test_client()
    register(ctx, c)
    login_to_face_step(ctx, c)
    pass_face_check(ctx, c)
    return c


def lframe(ctx, client, yaw=0.0, n_pose_faces=1, identity=PERSON_A):
    """One liveness frame. `identity` = what the RetinaFace crop embeds to; the pose analyzer decides
    how many faces are in view. The frontal (Haar) detector must NOT be needed here."""
    ctx.pose.reading = PoseReading(n_pose_faces, yaw if n_pose_faces == 1 else None)
    ctx.fake.crop_embedding = identity
    r = client.post("/liveness/frame", data={"frame": (io.BytesIO(jpeg()), "f.jpg")},
                    content_type="multipart/form-data")
    return r.status_code, r.get_json()


def play(ctx, client, yaws):
    out = None
    for y in yaws:
        code, out = lframe(ctx, client, y)
        assert code == 200, out
    return out


HAPPY = [0, 0, .3, .3, 0, -.3, -.3, 0, .3, .3]          # for the sequence left, right, left


class TestEndpoints:
    def test_defaults_enforce_liveness(self, tmp_path):
        app = appmod.create_app({"TESTING": True, "SECRET_KEY": "k", "PEPPER": "p", "SEED_DEMO": False,
                                 "DATABASE": str(tmp_path / "d.db"), "PHOTO_DIR": str(tmp_path / "p"),
                                 "FACE_SERVICE": FakeFaceService(), "POSE_ANALYZER": FakePose(),
                                 "ADMIN_PASSWORD_HASH": "x"})
        assert app.config["LIVENESS_ENABLED"] is True

    def test_ui_is_told_liveness_follows(self, ctx):
        add_candidates(ctx)
        c = ctx.app.test_client()
        register(ctx, c)
        assert c.post("/send_otp", json={"aadhaar": "234567890123"}).status_code == 200
        r = c.post("/verify_otp", json={"aadhaar": "234567890123", "otp": last_otp(ctx)}).get_json()
        assert r["liveness_required"] is True

    def test_face_match_alone_no_longer_unlocks_the_ballot(self, face_ok):
        assert face_ok.get("/voting-page").status_code == 302
        assert face_ok.get("/voter_details").status_code == 401
        assert face_ok.post("/cast_vote", json={"candidate_id": 1}).status_code == 401

    def test_cannot_start_or_play_without_face_match(self, ctx):
        add_candidates(ctx)
        c = ctx.app.test_client()
        assert c.post("/liveness/start").status_code == 401
        assert lframe(ctx, c)[0] == 401
        register(ctx, c)
        login_to_face_step(ctx, c)                               # OTP only
        assert c.post("/liveness/start").status_code == 401
        assert lframe(ctx, c)[0] == 401

    def test_frame_before_start_is_rejected(self, ctx, face_ok):
        code, body = lframe(ctx, face_ok)
        assert code == 409 and body["status"] == "no_challenge"

    def test_full_run_unlocks_ballot_and_vote_works(self, ctx, face_ok, monkeypatch):
        forced(monkeypatch, ["left", "right", "left"])
        start = face_ok.post("/liveness/start").get_json()
        assert start["status"] == "started" and start["total"] == 3 and "seq" not in start
        out = play(ctx, face_ok, HAPPY)
        assert out["verified"] is True and out["status"] == "done"
        assert face_ok.get("/voting-page").status_code == 200
        cid = db_of(ctx).execute("SELECT id FROM candidates WHERE name='Alice'").fetchone()[0]
        assert face_ok.post("/cast_vote", json={"candidate_id": cid}).status_code == 200

    def test_each_response_shows_only_the_current_instruction(self, ctx, face_ok, monkeypatch):
        forced(monkeypatch, ["left", "right", "left"])
        face_ok.post("/liveness/start")
        seen = [lframe(ctx, face_ok, y)[1] for y in HAPPY[:4]]          # up to and including step 1 done
        assert {r["direction"] for r in seen if r["direction"]} == {"left"}      # 'right' not leaked yet
        assert all("seq" not in r for r in seen)
        nxt = lframe(ctx, face_ok, 0)[1]                                  # back at centre -> step 2 revealed
        assert nxt["direction"] == "right" and nxt["step"] == 2

    def test_static_photo_attack_fails_and_locks_out(self, ctx, face_ok):
        face_ok.post("/liveness/start")
        ctx.app.extensions["liveness_cfg"].max_frames = 25
        last = None
        for i in range(25):
            _, last = lframe(ctx, face_ok, 0.005 * (-1) ** i)       # a held photo: tiny jitter only
            assert last["verified"] is False
        code, body = lframe(ctx, face_ok, 0.0)
        assert code == 429 and body["status"] == "locked"
        assert face_ok.get("/voting-page").status_code == 302          # session was destroyed
        assert face_ok.post("/liveness/start").status_code == 401

    def test_tilted_photo_attack_fails(self, ctx, face_ok, monkeypatch):
        forced(monkeypatch, ["left", "right", "left"])
        face_ok.post("/liveness/start")
        p = 0.137                                   # max yaw a tilted flat photo produced in testing
        out = play(ctx, face_ok, [0, 0, p, p, p, 0, -p, -p, -p, 0, p, p, p])
        assert out["verified"] is False and out["step"] == 1

    def test_replaying_a_recorded_run_against_a_new_challenge_fails(self, ctx, face_ok, monkeypatch):
        """Attacker recorded the yaw script that solved sequence L,R,L; the server now asks R,L,R."""
        forced(monkeypatch, ["right", "left", "right"])
        face_ok.post("/liveness/start")
        out = play(ctx, face_ok, HAPPY)
        assert out["verified"] is False

    def test_wrong_way_turn_makes_no_progress(self, ctx, face_ok, monkeypatch):
        forced(monkeypatch, ["left", "right", "left"])
        face_ok.post("/liveness/start")
        out = play(ctx, face_ok, [0, 0] + [-.3] * 6)
        assert out["status"] == "wrong_way" and out["step"] == 1

    def test_different_person_is_rejected_even_with_perfect_head_turns(self, ctx, face_ok, monkeypatch):
        forced(monkeypatch, ["left", "right", "left"])
        face_ok.post("/liveness/start")
        for y in HAPPY:
            _, out = lframe(ctx, face_ok, y, identity=PERSON_B)
            assert out["status"] == "no_match" and out["verified"] is False
        assert face_ok.get("/voter_details").status_code == 401

    def test_face_swapped_in_during_the_turn_is_rejected(self, ctx, face_ok, monkeypatch):
        """Right person looks straight at the camera, then a different person does the turning."""
        forced(monkeypatch, ["left", "right", "left"])
        face_ok.post("/liveness/start")
        play(ctx, face_ok, [0, 0])                                          # genuine calibration
        far = emb_at_distance(CFG.anchor_turned + 0.1)
        for _ in range(6):
            _, out = lframe(ctx, face_ok, 0.3, identity=far)
            assert out["status"] == "no_match"
        assert out["step"] == 1 and out["hold"] == 0

    def test_identity_check_is_relaxed_but_not_removed_while_turned(self, ctx, face_ok, monkeypatch):
        forced(monkeypatch, ["left", "right", "left"])
        face_ok.post("/liveness/start")
        play(ctx, face_ok, [0, 0])
        mid = emb_at_distance((CFG.anchor_center + CFG.anchor_turned) / 2)
        _, out = lframe(ctx, face_ok, 0.3, identity=mid)          # turned: allowed to drift a bit
        assert out["status"] == "holding"
        _, out = lframe(ctx, face_ok, 0.0, identity=mid)          # facing the camera: must be tighter
        assert out["status"] == "no_match"

    def test_second_person_in_frame_blocks_progress(self, ctx, face_ok, monkeypatch):
        forced(monkeypatch, ["left", "right", "left"])
        face_ok.post("/liveness/start")
        play(ctx, face_ok, [0, 0, .3])                                      # one frame held
        _, out = lframe(ctx, face_ok, 0.3, n_pose_faces=2)
        assert out["status"] == "multiple_faces" and out["hold"] == 0
        _, out = lframe(ctx, face_ok, n_pose_faces=0)
        assert out["status"] == "no_face"

    # ---- regressions for the bug reported on a real webcam: "no face detected / no match as soon as I turn"
    def test_turned_head_does_not_depend_on_the_frontal_haar_detector(self, ctx, face_ok, monkeypatch):
        """The frontal-only detector cannot see a turned head. Liveness must never call it."""
        forced(monkeypatch, ["left", "right", "left"])
        def blind(img):
            raise AssertionError("liveness must not use the frontal-only detector")
        monkeypatch.setattr(ctx.fake, "detect", blind)
        face_ok.post("/liveness/start")
        out = play(ctx, face_ok, HAPPY)
        assert out["verified"] is True

    def test_genuine_user_borderline_to_the_registered_photo_still_passes(self, ctx, monkeypatch):
        """Cross-photo distance can be borderline (~0.5-0.6) even for the real person. Liveness compares to the
        face verified moments ago in the SAME session, so such a user must still pass."""
        import math
        forced(monkeypatch, ["left", "right", "left"])
        add_candidates(ctx)
        c = ctx.app.test_client()
        register(ctx, c)                                              # registered photo embedding = PERSON_A (angle 0)
        login_to_face_step(ctx, c)
        at = lambda deg: [math.cos(math.radians(deg)), math.sin(math.radians(deg)), 0.0, 0.0]
        ctx.fake.faces = [FakeFaceService.face(at(60))]                # 1-cos(60deg)=0.50 from the registered photo
        for _ in range(3):
            c.post("/verify_face", data={"frame": (io.BytesIO(jpeg()), "f.jpg")}, content_type="multipart/form-data")
        c.post("/liveness/start")
        live = at(66)                                                  # 0.59 from registered (fails a strict check), 0.005 from the session face
        for y in HAPPY:
            _, out = lframe(ctx, c, y, identity=live)
            assert out["status"] != "no_match", out
        assert out["verified"] is True

    def test_anchor_tracks_the_matching_streak_and_is_reset_by_a_miss(self, ctx):
        add_candidates(ctx)
        c = ctx.app.test_client()
        register(ctx, c)
        login_to_face_step(ctx, c)
        anchor = lambda: db_of(ctx).execute("SELECT live_anchor FROM auth_sessions").fetchone()[0]
        assert anchor() is None
        ctx.fake.faces = [FakeFaceService.face(PERSON_A)]
        post = lambda: c.post("/verify_face", data={"frame": (io.BytesIO(jpeg()), "f.jpg")}, content_type="multipart/form-data").get_json()
        post()
        assert json.loads(anchor()) == pytest.approx(PERSON_A)
        ctx.fake.faces = [FakeFaceService.face(emb_at_distance(0.2))]  # still matches, slightly different
        post()
        a = json.loads(anchor())
        assert a == pytest.approx([(1 + emb_at_distance(0.2)[0]) / 2, emb_at_distance(0.2)[1] / 2, 0, 0])   # running mean
        ctx.fake.faces = [FakeFaceService.face(PERSON_B)]              # a different person: streak AND anchor reset
        assert post()["status"] == "no_match" and anchor() is None

    def test_the_anchor_is_never_sent_to_the_browser(self, ctx, face_ok):
        face_ok.post("/liveness/start")
        for payload in (lframe(ctx, face_ok, 0.0)[1], face_ok.post("/liveness/start").get_json()):
            assert "anchor" not in json.dumps(payload).lower() and "embedding" not in json.dumps(payload).lower()

    def test_demo_mode_reports_distance_and_limit_for_calibration(self, ctx, face_ok):
        face_ok.post("/liveness/start")
        out = lframe(ctx, face_ok, 0.0, identity=emb_at_distance(0.2))[1]
        assert out["dist"] == pytest.approx(0.2, abs=0.01) and out["limit"] == CFG.anchor_center
        ctx.app.config["DEMO_MODE"] = False
        assert "dist" not in lframe(ctx, face_ok, 0.0)[1]

    def test_timeout_fails_challenge_and_new_one_is_random(self, ctx, face_ok):
        cfg = ctx.app.extensions["liveness_cfg"]
        cfg.step_timeout = 0.2
        face_ok.post("/liveness/start")
        time.sleep(0.35)
        code, out = lframe(ctx, face_ok, 0.0)
        assert out["status"] == "challenge_failed" and out["can_retry"] is True
        assert lframe(ctx, face_ok)[0] == 409                              # old challenge is gone
        cfg.step_timeout = 20
        assert face_ok.post("/liveness/start").get_json()["status"] == "started"

    def test_stalling_without_valid_frames_still_times_out(self, ctx, face_ok):
        """The clock runs even when no face is visible (no 'wait until I'm ready' loophole)."""
        cfg = ctx.app.extensions["liveness_cfg"]
        cfg.step_timeout = 0.2
        face_ok.post("/liveness/start")
        lframe(ctx, face_ok, n_pose_faces=0)
        time.sleep(0.35)
        assert lframe(ctx, face_ok, n_pose_faces=0)[1]["status"] == "challenge_failed"

    def test_limited_number_of_challenges_per_session(self, ctx, face_ok):
        cfg = ctx.app.extensions["liveness_cfg"]
        for _ in range(cfg.max_challenges):
            assert face_ok.post("/liveness/start").status_code == 200
        r = face_ok.post("/liveness/start")
        assert r.status_code == 429 and r.get_json()["status"] == "locked"
        assert face_ok.get("/voting-page").status_code == 302

    def test_garbage_frame_rejected(self, ctx, face_ok):
        face_ok.post("/liveness/start")
        r = face_ok.post("/liveness/frame", data={"frame": (io.BytesIO(b"nope"), "f.jpg")},
                         content_type="multipart/form-data")
        assert r.status_code == 400

    def test_challenge_state_lives_on_the_server_not_in_the_cookie(self, ctx, face_ok):
        face_ok.post("/liveness/start")
        with face_ok.session_transaction() as s:
            assert set(s.keys()) == {"auth"} and "seq" not in json.dumps(dict(s))
            s["live_verified"] = 1                                          # forging cookie fields...
            s["liveness"] = "done"
        assert face_ok.get("/voter_details").status_code == 401             # ...changes nothing

    def test_liveness_flag_cannot_be_skipped_via_direct_ballot_calls(self, ctx, face_ok):
        for _ in range(3):
            assert face_ok.post("/cast_vote", json={"candidate_id": 1}).status_code == 401
        assert db_of(ctx).execute("SELECT SUM(votes) FROM candidates").fetchone()[0] == 0

    def test_yaw_is_only_exposed_in_demo_mode(self, ctx, face_ok):
        face_ok.post("/liveness/start")
        assert "yaw" in lframe(ctx, face_ok, 0.05)[1]
        ctx.app.config["DEMO_MODE"] = False
        assert "yaw" not in lframe(ctx, face_ok, 0.05)[1]

    def test_old_database_is_migrated(self, tmp_path):
        path = str(tmp_path / "old.db")
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE auth_sessions (token TEXT PRIMARY KEY, voter_id INTEGER NOT NULL,"
                     " face_verified INTEGER NOT NULL DEFAULT 0, face_streak INTEGER NOT NULL DEFAULT 0,"
                     " frames_checked INTEGER NOT NULL DEFAULT 0, expires_at REAL NOT NULL)")
        conn.commit(); conn.close()
        app = appmod.create_app({"TESTING": True, "SECRET_KEY": "k", "PEPPER": "p", "DATABASE": path,
                                 "PHOTO_DIR": str(tmp_path / "p"), "SEED_DEMO": False,
                                 "FACE_SERVICE": FakeFaceService(), "POSE_ANALYZER": FakePose(),
                                 "ADMIN_PASSWORD_HASH": "x"})
        cols = {r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(auth_sessions)")}
        assert {"live_verified", "live_state", "live_frames", "live_challenges"} <= cols

    def test_disabled_flag_skips_liveness_only_when_explicitly_configured(self, ctx, face_ok):
        ctx.app.config["LIVENESS_ENABLED"] = False
        assert face_ok.get("/voting-page").status_code == 200
        body = face_ok.post("/liveness/start").get_json()
        assert body["required"] is False and body["verified"] is True
