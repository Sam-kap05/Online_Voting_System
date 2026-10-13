"""
Production entry point (use this instead of `python app.py`, which is Flask's development server).

    Windows / Linux / macOS:   python serve.py            (recommended: configures waitress + proxy headers correctly)
    Linux / macOS (alternative): gunicorn -w 1 --threads 8 -b 127.0.0.1:8000 wsgi:application
                                 (set TRUST_PROXY_HOPS=1 behind a proxy; do NOT use bare `waitress-serve`: it
                                  discards X-Forwarded-* headers, see serve.py)

Run ONE process (several threads are fine): the face models need ~2 GB RAM each copy, and the
rate limiter and TensorFlow are per-process. Put HTTPS in front (Caddy / nginx / a cloud load balancer) and
set TRUST_PROXY_HOPS=1 so the app sees each visitor's real IP address.
"""
import threading

from app import create_app, describe_runtime

application = create_app()
print("\n".join(describe_runtime(application)))


def _warm_up():
    """Load the AI models now, so the first voter doesn't wait (or time out) while they load."""
    application.extensions["face_service"].warmup()
    if application.config["LIVENESS_ENABLED"]:
        application.extensions["pose_analyzer"].warmup()
    print("[ready] face models loaded")


threading.Thread(target=_warm_up, daemon=True).start()
