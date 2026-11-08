from argon2 import PasswordHasher

from app import passwords


def test_hash_is_argon2id_and_never_contains_the_password():
    h = passwords.hash_password("correct horse battery")
    assert h.startswith("$argon2id$")
    assert "correct horse" not in h


def test_same_password_gets_different_hashes():
    assert passwords.hash_password("same-password-123") != passwords.hash_password("same-password-123")


def test_verify_right_and_wrong_password():
    h = passwords.hash_password("right-password-123")
    assert passwords.verify_password(h, "right-password-123") is True
    assert passwords.verify_password(h, "wrong-password-123") is False


def test_malformed_hash_is_a_failed_login_not_a_crash():
    assert passwords.verify_password("not a hash at all", "whatever") is False
    assert passwords.verify_password("", "whatever") is False


def test_needs_rehash_when_parameters_changed(monkeypatch):
    old = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash("pw-for-rehash-test")
    monkeypatch.setattr(passwords, "_hasher", PasswordHasher(time_cost=2, memory_cost=16, parallelism=1))
    assert passwords.needs_rehash(old) is True
    assert passwords.needs_rehash(passwords.hash_password("pw-for-rehash-test")) is False
    assert passwords.verify_password(old, "pw-for-rehash-test") is True  # old hashes keep working


def test_dummy_hash_never_matches_a_realistic_password():
    assert passwords.verify_password(passwords.dummy_hash(), "correct horse battery") is False
    assert passwords.dummy_hash() == passwords.dummy_hash()  # computed once
