"""Password hashing with argon2id (argon2-cffi).

The library defaults follow RFC 9106's low-memory recommendation, and the hash string records
its own parameters, so they can be raised later: old hashes keep verifying and
``needs_rehash`` tells the login route to upgrade them on the user's next successful login.
"""

from functools import cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """True only for a matching password. Any other outcome (mismatch, malformed hash) is False."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


@cache
def dummy_hash() -> str:
    """A hash nobody can match. Login verifies against it when the username doesn't exist, so an
    unknown user and a wrong password take about the same time (no username enumeration by timing)."""
    return _hasher.hash("not-a-real-account-password")
