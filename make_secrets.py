"""
Generate the secrets for your production .env in one step (does not start the app, writes no files):

    python make_secrets.py

It prints three lines. Paste them into your .env file. Keep that file private and back it up:
if you lose DESHGARV_PEPPER, every registered voter's Aadhaar lookup stops working.
"""
import getpass
import secrets
import sys

from werkzeug.security import generate_password_hash

MIN_PASSWORD_LENGTH = 12


def build_lines(admin_password):
    """-> the three .env lines. Raises ValueError for a weak password."""
    if len(admin_password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"The admin password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if admin_password.lower() in {"admin123", "password1234", "123456789012", "administrator"}:
        raise ValueError("That password is far too common. Choose something unique.")
    return [
        f"SECRET_KEY={secrets.token_hex(32)}",
        f"DESHGARV_PEPPER={secrets.token_hex(32)}",
        f"ADMIN_PASSWORD_HASH='{generate_password_hash(admin_password)}'",   # single quotes: the hash contains $
    ]


def main():
    print("Choose the admin password for the results dashboard (hidden as you type).")
    while True:
        first = getpass.getpass("Admin password: ")
        if getpass.getpass("Repeat it:      ") != first:
            print("They do not match - try again.\n")
            continue
        try:
            lines = build_lines(first)
        except ValueError as exc:
            print(f"{exc}\n")
            continue
        break
    print("\nPaste these 3 lines into your .env file:\n")
    print("\n".join(lines))
    print("\n(Keep .env private and back it up. Never commit it or share it.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
