"""
Real SMS delivery for OTPs.

Pick a provider with the SMS_PROVIDER environment variable (or in a .env file):

    console   print to the server console - DEMO MODE ONLY (default)
    twilio    https://www.twilio.com           (global)
    msg91     https://msg91.com                (India-focused, handles DLT templates)
    firebase  Firebase Authentication phone sign-in. Firebase (not this server) sends the SMS
              from the voter's browser; the server only verifies the signed result.
              Real SMS needs the paid Blaze plan; Firebase "test phone numbers" are free.

Uses only the standard library (no extra packages). All provider calls go through
``_http_post`` so tests can replace it; these providers have NOT been exercised against
live accounts by the author - use ``flask --app app test-sms <mobile>`` to verify yours.

INDIA NOTE: by TRAI regulation, SMS to Indian numbers must use a DLT-registered sender ID
and message template. Both Twilio and MSG91 walk you through this; until it is approved,
messages to Indian numbers will be blocked by the carriers.
"""
import base64
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request


class SmsError(Exception):
    """Delivery failed (bad credentials, network, provider rejection...)."""


PROVIDERS = ("console", "twilio", "msg91", "firebase")

_REQUIRED = {
    "console": [],
    "twilio": ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"],   # + FROM number or messaging service
    "msg91": ["MSG91_AUTH_KEY", "MSG91_TEMPLATE_ID"],
    "firebase": ["FIREBASE_API_KEY", "FIREBASE_PROJECT_ID"],
}


def provider_name(env=None):
    env = os.environ if env is None else env
    return (env.get("SMS_PROVIDER") or "console").strip().lower()


def config_problems(env=None):
    """Human-readable list of what's wrong with the SMS configuration ([] = fine)."""
    env = os.environ if env is None else env
    name = provider_name(env)
    if name not in PROVIDERS:
        return [f"SMS_PROVIDER must be one of {', '.join(PROVIDERS)} (got '{name}')"]
    problems = [f"{k} is not set" for k in _REQUIRED[name] if not env.get(k)]
    if name == "twilio" and not (env.get("TWILIO_FROM_NUMBER") or env.get("TWILIO_MESSAGING_SERVICE_SID")):
        problems.append("set TWILIO_FROM_NUMBER or TWILIO_MESSAGING_SERVICE_SID")
    return problems


def firebase_project_id(env=None):
    env = os.environ if env is None else env
    return (env.get("FIREBASE_PROJECT_ID") or "").strip()


def firebase_client_config(env=None):
    """The PUBLIC web-app config the browser needs (Firebase web API keys are not secrets;
    access is controlled by authorized domains, reCAPTCHA and quotas). Only these keys are exposed."""
    env = os.environ if env is None else env
    project = firebase_project_id(env)
    cfg = {"apiKey": (env.get("FIREBASE_API_KEY") or "").strip(), "projectId": project,
           "authDomain": (env.get("FIREBASE_AUTH_DOMAIN") or f"{project}.firebaseapp.com").strip()}
    if env.get("FIREBASE_APP_ID"):
        cfg["appId"] = env["FIREBASE_APP_ID"].strip()
    return cfg


def _http_post(url, data=None, headers=None, timeout=10):
    """-> (status_code, response_text). Network failures raise SmsError."""
    body = urllib.parse.urlencode(data).encode() if data is not None else b""
    req = urllib.request.Request(url, data=body, headers=headers or {}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SmsError(f"network error: {exc}")


def _error_text(body):
    try:
        data = json.loads(body)
        return str(data.get("message") or data.get("error") or body)[:200]
    except Exception:
        return body[:200]


def _send_twilio(phone, message, env):
    sid, token = env["TWILIO_ACCOUNT_SID"], env["TWILIO_AUTH_TOKEN"]
    data = {"To": f"+91{phone}", "Body": message}
    if env.get("TWILIO_MESSAGING_SERVICE_SID"):
        data["MessagingServiceSid"] = env["TWILIO_MESSAGING_SERVICE_SID"]
    else:
        data["From"] = env["TWILIO_FROM_NUMBER"]
    auth = base64.b64encode(f"{sid}:{token}".encode()).decode()
    status, body = _http_post(
        f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
        data=data, headers={"Authorization": f"Basic {auth}"})
    if not 200 <= status < 300:
        raise SmsError(f"Twilio rejected the message ({status}): {_error_text(body)}")


def _send_msg91(phone, message, env):
    # MSG91's OTP API fills the OTP into your DLT-approved template (the ##OTP## variable),
    # so we pass the code itself rather than the full sentence.
    match = re.match(r"\s*(\d{4,8})\b", message)
    if not match:
        raise SmsError("could not find the OTP in the message")
    params = urllib.parse.urlencode({
        "template_id": env["MSG91_TEMPLATE_ID"], "mobile": f"91{phone}",
        "authkey": env["MSG91_AUTH_KEY"], "otp": match.group(1),
        "otp_expiry": env.get("MSG91_OTP_EXPIRY_MIN", "5"),
    })
    status, body = _http_post(f"https://control.msg91.com/api/v5/otp?{params}",
                              data={}, headers={"Accept": "application/json"})
    try:
        ok_type = json.loads(body).get("type") != "error"
    except Exception:
        ok_type = False
    if not (200 <= status < 300 and ok_type):
        raise SmsError(f"MSG91 rejected the message ({status}): {_error_text(body)}")


def send_sms(phone, message, env=None):
    """Send `message` to the 10-digit Indian mobile `phone` via the configured provider."""
    env = os.environ if env is None else env
    name = provider_name(env)
    problems = config_problems(env)
    if problems:
        raise SmsError("; ".join(problems))
    if name == "twilio":
        _send_twilio(phone, message, env)
    elif name == "msg91":
        _send_msg91(phone, message, env)
    elif name == "firebase":
        raise SmsError("with the 'firebase' provider the SMS is sent by Firebase from the voter's "
                       "browser; use the website (or a Firebase test number) to try it")
    else:
        raise SmsError("provider 'console' does not send real SMS")
