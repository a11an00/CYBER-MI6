"""One-off administration commands. The setup script wraps these.

    python -m app.manage create-admin
    python -m app.manage reset-password <username>

Passwords are read with getpass, so they never appear in the shell history or in ``ps``.
"""

import argparse
import getpass
import sys

from app import passwords, storage
from app.config import get_settings
from app.db import open_database
from app.models import MAX_PASSWORD_LEN, MIN_PASSWORD_LEN, Username
from pydantic import TypeAdapter, ValidationError


def _ask_password() -> str:
    while True:
        first = getpass.getpass(f"Password (min {MIN_PASSWORD_LEN} characters): ")
        if not MIN_PASSWORD_LEN <= len(first) <= MAX_PASSWORD_LEN:
            print(f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters.", file=sys.stderr)
            continue
        if getpass.getpass("Repeat password: ") != first:
            print("Passwords do not match.", file=sys.stderr)
            continue
        return first


def create_admin(db, username: str, password: str) -> None:
    username = TypeAdapter(Username).validate_python(username)
    storage.create_user(db, username=username, password_hash=passwords.hash_password(password), role="admin")


def reset_password(db, username: str, password: str) -> bool:
    user = storage.get_user_by_username(db, username)
    if user is None:
        return False
    storage.update_user(db, user.id, password_hash=passwords.hash_password(password))
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.manage")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("create-admin", help="create an admin account (prompts for the username and password)")
    reset = sub.add_parser("reset-password", help="set a new password for an existing account")
    reset.add_argument("username")
    args = parser.parse_args(argv)

    db = open_database(get_settings().database_path)
    try:
        if args.command == "create-admin":
            username = input("Admin username: ").strip()
            try:
                create_admin(db, username, _ask_password())
            except ValidationError:
                print("Username must be 3-64 characters: letters, digits, . _ @ -", file=sys.stderr)
                return 1
            except storage.UsernameTakenError:
                print("That username already exists.", file=sys.stderr)
                return 1
            print(f"Admin {username!r} created.")
        else:
            if not reset_password(db, args.username, _ask_password()):
                print("No such user.", file=sys.stderr)
                return 1
            print("Password updated.")
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
