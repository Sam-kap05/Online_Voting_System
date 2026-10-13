"""SMS delivery: request formats (mocked HTTP), error handling and app integration."""
import io
import os
import sys
import urllib.parse

import pytest

os.environ["DESHGARV_NO_DOTENV"] = "1"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as appmod  # noqa: E402
import sms_gateway as gw  # noqa: E402
from test_app import FakeFaceService, jpeg  # noqa: E402

TWILIO = {"SMS_PROVIDER": "twilio", "TWILIO_ACCOUNT_SID": "ACtest123", "TWILIO_AUTH_TOKEN": "tok",
          "TWILIO_FROM_NUMBER": "+15005550006"}
MSG91 = {"SMS_PROVIDER": "msg91", "MSG91_AUTH_KEY": "key123", "MSG91_TEMPLATE_ID": "tmpl456"}
MSG = "482913 is your DeshGarv one-time password. Valid for 5 minutes. Do not share it with anyone."


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for key in [k for k in os.environ if k.startswith(("SMS_", "TWILIO_", "MSG91_"))]:
        monkeypatch.delenv(key)


@pytest.fixture
def http(monkeypatch):
    """Capture outgoing provider requests instead of hitting the network."""
    calls, reply = [], {"status": 201, "body": '{"sid": "SM1"}'}

    def fake(url, data=None, headers=None, timeout=10):
        calls.append({"url": url, "data": data, "headers": headers or {}})
        if isinstance(reply.get("raise"), Exception):
            raise reply["raise"]
        return reply["status"], reply["body"]

    monkeypatch.setattr(gw, "_http_post", fake)
    return type("Http", (), {"calls": calls, "reply": reply})


# ------------------------------------------------------------------ config
class TestConfig:
    def test_default_is_console(self):
        assert gw.provider_name({}) == "console" and gw.config_problems({}) == []

    def test_unknown_provider(self):
        assert "must be one of" in gw.config_problems({"SMS_PROVIDER": "pigeon"})[0]

    def test_twilio_requires_credentials_and_a_sender(self):
        p = gw.config_problems({"SMS_PROVIDER": "twilio"})
        assert any("TWILIO_ACCOUNT_SID" in x for x in p) and any("FROM_NUMBER" in x for x in p)
        assert gw.config_problems(TWILIO) == []
        svc = {k: v for k, v in TWILIO.items() if k != "TWILIO_FROM_NUMBER"}
        svc["TWILIO_MESSAGING_SERVICE_SID"] = "MG1"
        assert gw.config_problems(svc) == []

    def test_msg91_requires_key_and_template(self):
        assert len(gw.config_problems({"SMS_PROVIDER": "msg91"})) == 2
        assert gw.config_problems(MSG91) == []


# ------------------------------------------------------------------ Twilio
class TestTwilio:
    def test_request_format(self, http):
        gw.send_sms("9812345678", MSG, TWILIO)
        call = http.calls[0]
        assert call["url"] == "https://api.twilio.com/2010-04-01/Accounts/ACtest123/Messages.json"
        assert call["data"] == {"To": "+919812345678", "Body": MSG, "From": "+15005550006"}
        import base64
        assert call["headers"]["Authorization"] == "Basic " + base64.b64encode(b"ACtest123:tok").decode()

    def test_messaging_service_replaces_from(self, http):
        env = {**TWILIO, "TWILIO_MESSAGING_SERVICE_SID": "MG99"}
        gw.send_sms("9812345678", MSG, env)
        assert http.calls[0]["data"]["MessagingServiceSid"] == "MG99" and "From" not in http.calls[0]["data"]

    def test_provider_rejection_becomes_smserror(self, http):
        http.reply.update(status=401, body='{"message": "Authenticate", "code": 20003}')
        with pytest.raises(gw.SmsError, match="401.*Authenticate"):
            gw.send_sms("9812345678", MSG, TWILIO)

    def test_network_failure_becomes_smserror(self, http):
        http.reply["raise"] = gw.SmsError("network error: timed out")
        with pytest.raises(gw.SmsError, match="network"):
            gw.send_sms("9812345678", MSG, TWILIO)

    def test_missing_config_never_calls_network(self, http):
        with pytest.raises(gw.SmsError):
            gw.send_sms("9812345678", MSG, {"SMS_PROVIDER": "twilio"})
        assert http.calls == []


# ------------------------------------------------------------------- MSG91
class TestMsg91:
    def test_request_format(self, http):
        http.reply.update(status=200, body='{"type": "success", "message": "abc"}')
        gw.send_sms("9812345678", MSG, MSG91)
        url = urllib.parse.urlparse(http.calls[0]["url"])
        q = dict(urllib.parse.parse_qsl(url.query))
        assert url.netloc == "control.msg91.com" and url.path == "/api/v5/otp"
        assert q == {"template_id": "tmpl456", "mobile": "919812345678", "authkey": "key123",
                     "otp": "482913", "otp_expiry": "5"}

    def test_error_type_in_200_response_is_a_failure(self, http):
        http.reply.update(status=200, body='{"type": "error", "message": "Template not found"}')
        with pytest.raises(gw.SmsError, match="Template not found"):
            gw.send_sms("9812345678", MSG, MSG91)

    def test_http_error_is_a_failure(self, http):
        http.reply.update(status=401, body="denied")
        with pytest.raises(gw.SmsError):
            gw.send_sms("9812345678", MSG, MSG91)

    def test_message_without_code_rejected(self, http):
        with pytest.raises(gw.SmsError, match="OTP"):
            gw.send_sms("9812345678", "hello there", MSG91)
        assert http.calls == []


# ------------------------------------------------------------ app integration
def make_app(tmp_path, **cfg):
    return appmod.create_app({
        "TESTING": True, "SECRET_KEY": "k", "PEPPER": "p", "DATABASE": str(tmp_path / "t.db"),
        "PHOTO_DIR": str(tmp_path / "ph"), "SEED_DEMO": False, "RATELIMIT_ENABLED": False,
        "OTP_RESEND_COOLDOWN": 0, "LIVENESS_ENABLED": False, "FACE_SERVICE": FakeFaceService(),
        "ADMIN_PASSWORD_HASH": appmod.generate_password_hash("x"), **cfg})


def start_registration(client, aadhaar="234567890123", phone="9812345678"):
    return client.post("/register/start", data={
        "name": "Test Voter", "aadhaar": aadhaar, "phone": phone, "constituency": "New Delhi",
        "photo": (io.BytesIO(jpeg()), "me.jpg")}, content_type="multipart/form-data")


class TestAppIntegration:
    def use(self, monkeypatch, env):
        for k, v in env.items():
            monkeypatch.setenv(k, v)

    def test_real_provider_is_used_and_otp_is_not_echoed(self, tmp_path, monkeypatch, http):
        self.use(monkeypatch, TWILIO)
        app = make_app(tmp_path)                      # DEMO_MODE is on, but a real provider is set
        r = start_registration(app.test_client())
        assert r.status_code == 200
        assert "otp" not in r.get_json()              # must NOT leak the code to the screen
        assert len(http.calls) == 1 and http.calls[0]["data"]["To"] == "+919812345678"
        code = http.calls[0]["data"]["Body"][:6]
        assert code.isdigit()                         # the SMS carries the real code

    def test_end_to_end_with_sms_delivered_code(self, tmp_path, monkeypatch, http):
        self.use(monkeypatch, TWILIO)
        app = make_app(tmp_path)
        c = app.test_client()
        start_registration(c)
        code = http.calls[-1]["data"]["Body"][:6]
        assert c.post("/register/verify", json={"otp": code}).status_code == 200

    def test_provider_outage_gives_503_and_leaves_nothing_behind(self, tmp_path, monkeypatch, http):
        self.use(monkeypatch, TWILIO)
        http.reply.update(status=500, body="boom")
        app = make_app(tmp_path)
        r = start_registration(app.test_client())
        assert r.status_code == 503 and "boom" not in r.get_data(as_text=True)   # no provider internals leaked
        import sqlite3
        conn = sqlite3.connect(str(tmp_path / "t.db"))
        assert conn.execute("SELECT COUNT(*) FROM otp_codes").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM pending_registrations").fetchone()[0] == 0
        assert os.listdir(str(tmp_path / "ph")) == []                              # photo cleaned up

    def test_console_provider_in_demo_still_echoes(self, tmp_path, capsys):
        app = make_app(tmp_path)
        r = start_registration(app.test_client())
        assert r.get_json()["otp"].isdigit() and "[SMS GATEWAY - demo]" in capsys.readouterr().out

    def test_startup_fails_fast_on_incomplete_config(self, tmp_path, monkeypatch):
        self.use(monkeypatch, {"SMS_PROVIDER": "twilio"})
        with pytest.raises(RuntimeError, match="SMS configuration"):
            make_app(tmp_path)

    def test_production_without_provider_refuses_to_start(self, tmp_path):
        with pytest.raises(RuntimeError, match="SMS"):
            make_app(tmp_path, DEMO_MODE=False)

    def test_production_with_provider_starts(self, tmp_path, monkeypatch):
        self.use(monkeypatch, MSG91)
        app = make_app(tmp_path, DEMO_MODE=False)
        assert app.config["DEMO_MODE"] is False

    def test_per_phone_limit_stops_sms_bombing(self, tmp_path, monkeypatch, http):
        self.use(monkeypatch, TWILIO)
        app = make_app(tmp_path, RATELIMIT_ENABLED=True, SMS_PER_PHONE_PER_HOUR=2)
        c = app.test_client()
        codes = [start_registration(c, aadhaar=f"23456789012{i}", phone="9812345678").status_code
                 for i in range(4)]
        assert codes[:2] == [200, 200] and codes[2:] == [429, 429]
        assert len(http.calls) == 2                                               # only 2 SMS actually sent
        assert start_registration(c, aadhaar="234567890199", phone="9899999999").status_code == 200

    def test_login_otp_goes_through_provider(self, tmp_path, monkeypatch, http):
        self.use(monkeypatch, MSG91)
        http.reply.update(status=200, body='{"type": "success"}')
        app = make_app(tmp_path)
        c = app.test_client()
        start_registration(c)
        code = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(http.calls[-1]["url"]).query))["otp"]
        assert c.post("/register/verify", json={"otp": code}).status_code == 200
        r = app.test_client().post("/send_otp", json={"aadhaar": "234567890123"})
        assert r.status_code == 200 and "otp" not in r.get_json() and len(http.calls) == 2

    def test_test_sms_command(self, tmp_path, monkeypatch, http):
        self.use(monkeypatch, TWILIO)
        app = make_app(tmp_path)
        runner = app.test_cli_runner()
        ok = runner.invoke(args=["test-sms", "9812345678"])
        assert ok.exit_code == 0 and "Sent" in ok.output and len(http.calls) == 1
        assert runner.invoke(args=["test-sms", "123"]).exit_code != 0
        http.reply.update(status=401, body='{"message": "bad creds"}')
        bad = runner.invoke(args=["test-sms", "9812345678"])
        assert bad.exit_code != 0 and "FAILED" in bad.output


# ------------------------------------------- the REAL transport (no mocks), local server
class TestRealTransport:
    @pytest.fixture
    def server(self):
        import http.server, threading
        seen = {}

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                seen.update(path=self.path, body=self.rfile.read(n).decode(), auth=self.headers.get("Authorization"),
                            ctype=self.headers.get("Content-Type"))
                code = 401 if "fail" in self.path else 201
                out = b'{"message": "nope"}' if code == 401 else b'{"sid": "SM1"}'
                self.send_response(code); self.send_header("Content-Length", str(len(out))); self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        yield type("S", (), {"url": f"http://127.0.0.1:{srv.server_port}", "seen": seen})
        srv.shutdown()

    def test_form_body_and_headers_arrive_intact(self, server):
        status, body = gw._http_post(server.url + "/ok", data={"To": "+919812345678", "Body": "a b&c=d"},
                                     headers={"Authorization": "Basic abc"})
        assert status == 201 and "SM1" in body
        assert server.seen["auth"] == "Basic abc"
        assert urllib.parse.parse_qs(server.seen["body"]) == {"To": ["+919812345678"], "Body": ["a b&c=d"]}
        assert "x-www-form-urlencoded" in server.seen["ctype"]

    def test_error_status_is_returned_not_raised(self, server):
        status, body = gw._http_post(server.url + "/fail", data={"a": "b"})
        assert status == 401 and "nope" in body

    def test_unreachable_host_raises_smserror(self):
        with pytest.raises(gw.SmsError, match="network"):
            gw._http_post("http://127.0.0.1:9/unreachable", data={}, timeout=2)
