import os
import sys

import pytest
from werkzeug.security import check_password_hash

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import make_secrets as ms  # noqa: E402
from dotenv import dotenv_values  # noqa: E402


def test_lines_are_strong_unique_and_the_hash_verifies(tmp_path):
    a, b = ms.build_lines("A-Long-Unique-Pass-1"), ms.build_lines("A-Long-Unique-Pass-1")
    key, pepper, hashed = (l.split("=", 1) for l in a)
    assert key[0] == "SECRET_KEY" and len(key[1]) == 64 and pepper[0] == "DESHGARV_PEPPER" and len(pepper[1]) == 64
    assert a[0] != b[0] and a[1] != b[1] and key[1] != pepper[1]                  # fresh randomness every time
    (tmp_path / ".env").write_text("\n".join(a) + "\n")
    env = dotenv_values(tmp_path / ".env")                                         # exactly how the app reads it
    assert check_password_hash(env["ADMIN_PASSWORD_HASH"], "A-Long-Unique-Pass-1")
    assert env["SECRET_KEY"] == key[1] and env["DESHGARV_PEPPER"] == pepper[1]


@pytest.mark.parametrize("weak", ["short", "admin123", "x" * 11, "Administrator", ""])
def test_weak_passwords_are_refused(weak):
    with pytest.raises(ValueError):
        ms.build_lines(weak)


def test_interactive_flow_retries_until_valid(monkeypatch, capsys):
    answers = iter(["tiny", "tiny", "Good-Pass-Phrase-77", "different", "Good-Pass-Phrase-77", "Good-Pass-Phrase-77"])
    monkeypatch.setattr(ms.getpass, "getpass", lambda prompt="": next(answers))
    assert ms.main() == 0
    out = capsys.readouterr().out
    assert "at least 12" in out and "do not match" in out and "SECRET_KEY=" in out and "ADMIN_PASSWORD_HASH='scrypt:" in out
    assert "Good-Pass-Phrase-77" not in out                                         # the password is never echoed
