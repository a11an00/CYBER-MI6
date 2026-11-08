"""Login, token checking, route protection, user administration, the WebSocket handshake."""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app import storage
from backend.auth import ALGORITHM, ISSUER, WS_CLOSE_UNAUTHORIZED
from app.config import Settings, get_settings
from backend.main import create_app
from tests.conftest import JWT_SECRET, bearer, make_user, token_for

GOOD_PASSWORD = "correct horse battery"


def login(client, username="analyst1", password=GOOD_PASSWORD):
    return client.post("/api/token", json={"username": username, "password": password})


# ---- POST /api/token ---------------------------------------------------------
def test_login_success_returns_token_and_profile_the_frontend_expects(anon):
    make_user(anon.app_ref)
    r = login(anon)
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer" and body["access_token"]
    user = body["user"]
    assert set(user) == {"id", "username", "role", "permissions", "status", "lastLogin"}
    assert user["username"] == "analyst1" and user["role"] == "analyst" and user["status"] == "active"
    assert "users:manage" not in user["permissions"]
    assert "password" not in str(body) and "argon2" not in str(body)


def test_login_sets_last_login(anon):
    u = make_user(anon.app_ref)
    assert storage.get_user(anon.app_ref.state.db, u.id).last_login is None
    assert login(anon).json()["user"]["lastLogin"] is not None
    assert storage.get_user(anon.app_ref.state.db, u.id).last_login is not None


def test_username_is_case_insensitive(anon):
    make_user(anon.app_ref, username="Analyst1")
    assert login(anon, username="analyst1").status_code == 200


def test_wrong_password_and_unknown_user_look_identical(anon):
    make_user(anon.app_ref)
    wrong = login(anon, password="not the password")
    unknown = login(anon, username="nobody")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()
    assert wrong.headers["www-authenticate"] == "Bearer"


def test_disabled_user_cannot_log_in_and_gets_the_same_error(anon):
    make_user(anon.app_ref, status="disabled")
    r = login(anon)
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid username or password"


def test_login_is_rate_limited_per_ip(anon):
    make_user(anon.app_ref)
    anon.app_ref.state.login_limiter = type(anon.app_ref.state.login_limiter)(3, 60)
    for _ in range(3):
        assert login(anon, password="bad").status_code == 401
    r = login(anon)  # even the right password is refused once throttled
    assert r.status_code == 429 and r.headers["retry-after"] == "60"


def test_login_body_is_validated(anon):
    assert anon.post("/api/token", json={"username": "x"}).status_code == 422
    assert anon.post("/api/token", json={"username": "x", "password": "y" * 2000}).status_code == 422
    assert anon.post("/api/token", json={"username": "x", "password": "y", "extra": 1}).status_code == 422


def test_login_disabled_without_jwt_secret(app_env, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "")
    get_settings.cache_clear()
    with TestClient(create_app(mount_static=False)) as c:
        make_user(c.app)
        assert login(c).status_code == 503
        assert c.get("/api/stats").status_code == 503


def test_short_jwt_secret_is_rejected_at_startup(monkeypatch):
    with pytest.raises(ValueError):
        Settings(jwt_secret="too-short")


def test_password_is_upgraded_when_hash_parameters_are_outdated(anon, monkeypatch):
    from argon2 import PasswordHasher

    from app import passwords

    u = make_user(anon.app_ref)
    old_hash = storage.get_user(anon.app_ref.state.db, u.id).password_hash
    monkeypatch.setattr(passwords, "_hasher", PasswordHasher(time_cost=2, memory_cost=16, parallelism=1))
    assert login(anon).status_code == 200
    new_hash = storage.get_user(anon.app_ref.state.db, u.id).password_hash
    assert new_hash != old_hash and not passwords.needs_rehash(new_hash)


# ---- route protection --------------------------------------------------------
PROTECTED = [
    ("get", "/api/stats"),
    ("get", "/api/alerts"),
    ("get", "/api/alerts/1"),
    ("patch", "/api/alerts/1"),
    ("get", "/api/events"),
    ("get", "/api/blocklist"),
    ("post", "/api/blocklist"),
    ("delete", "/api/blocklist/1.2.3.4"),
    ("get", "/api/users"),
    ("post", "/api/users"),
    ("patch", "/api/users/abc"),
    ("patch", "/api/users/abc/status"),
]


@pytest.mark.parametrize("method,path", PROTECTED)
def test_protected_routes_reject_anonymous(anon, method, path):
    r = getattr(anon, method)(path, **({"json": {}} if method in ("post", "patch") else {}))
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"
    assert r.json()["error"] == "http_401"


def test_valid_token_opens_the_dashboard_routes(anon):
    token = token_for(anon.app_ref, make_user(anon.app_ref))
    for path in ("/api/stats", "/api/alerts", "/api/events"):
        assert anon.get(path, headers=bearer(token)).status_code == 200


def test_api_key_is_not_a_login(anon):
    assert anon.get("/api/stats", headers={"X-API-Key": "test-ingest-key"}).status_code == 401


def test_ingestion_still_uses_the_api_key_not_a_login(anon):
    from tests.conftest import event_json

    token = token_for(anon.app_ref, make_user(anon.app_ref, role="admin", username="root_admin"))
    assert anon.post("/api/events", json=event_json(), headers=bearer(token)).status_code == 401
    assert anon.post("/api/events", json=event_json(), headers={"X-API-Key": "test-ingest-key"}).status_code == 201


def _claims(user_id, **over):
    now = datetime.now(timezone.utc)
    claims = {"iss": ISSUER, "sub": user_id, "iat": now, "exp": now + timedelta(minutes=5)}
    claims.update(over)
    return claims


@pytest.mark.parametrize(
    "tamper",
    [
        lambda uid: jwt.encode(_claims(uid), "a-different-secret-of-32-characters!!", algorithm=ALGORITHM),
        lambda uid: jwt.encode(_claims(uid, exp=datetime.now(timezone.utc) - timedelta(seconds=5)), JWT_SECRET, algorithm=ALGORITHM),
        lambda uid: jwt.encode(_claims(uid, iss="someone-else"), JWT_SECRET, algorithm=ALGORITHM),
        lambda uid: jwt.encode({k: v for k, v in _claims(uid).items() if k != "exp"}, JWT_SECRET, algorithm=ALGORITHM),
        lambda uid: jwt.encode({k: v for k, v in _claims(uid).items() if k != "sub"}, JWT_SECRET, algorithm=ALGORITHM),
        lambda uid: jwt.encode(_claims("no-such-user"), JWT_SECRET, algorithm=ALGORITHM),
        lambda uid: jwt.encode(_claims(uid), JWT_SECRET, algorithm="HS512"),  # wrong algorithm
        lambda uid: jwt.encode(_claims(uid), None, algorithm="none"),  # unsigned
        lambda uid: "not.a.jwt",
    ],
    ids=["bad-signature", "expired", "wrong-issuer", "no-exp", "no-sub", "unknown-user", "wrong-alg", "alg-none", "garbage"],
)
def test_bad_tokens_are_401(anon, tamper):
    user = make_user(anon.app_ref)
    assert anon.get("/api/stats", headers=bearer(tamper(user.id))).status_code == 401


def test_non_bearer_scheme_is_401(anon):
    token = token_for(anon.app_ref, make_user(anon.app_ref))
    assert anon.get("/api/stats", headers={"Authorization": f"Basic {token}"}).status_code == 401


def test_disabling_a_user_kills_their_existing_token_immediately(anon):
    user = make_user(anon.app_ref)
    token = token_for(anon.app_ref, user)
    assert anon.get("/api/stats", headers=bearer(token)).status_code == 200
    storage.update_user(anon.app_ref.state.db, user.id, status="disabled")
    assert anon.get("/api/stats", headers=bearer(token)).status_code == 401


def test_role_comes_from_the_database_not_the_token(anon):
    user = make_user(anon.app_ref, role="admin", username="boss_user")
    other = make_user(anon.app_ref, role="admin", username="other_admin")
    token = token_for(anon.app_ref, user)
    assert anon.get("/api/users", headers=bearer(token)).status_code == 200
    storage.update_user(anon.app_ref.state.db, user.id, role="analyst")  # demoted after login
    assert anon.get("/api/users", headers=bearer(token)).status_code == 403
    assert other.role == "admin"


# ---- /api/users --------------------------------------------------------------
@pytest.fixture
def admin(anon):
    user = make_user(anon.app_ref, username="root_admin", role="admin")
    anon.headers.update(bearer(token_for(anon.app_ref, user)))
    anon.admin_user = user
    return anon


def test_analyst_gets_403_on_every_users_route(anon):
    anon.headers.update(bearer(token_for(anon.app_ref, make_user(anon.app_ref))))
    assert anon.get("/api/users").status_code == 403
    assert anon.post("/api/users", json={"username": "newbie", "password": "x" * 12}).status_code == 403
    assert anon.patch("/api/users/abc", json={}).status_code == 403
    assert anon.patch("/api/users/abc/status", json={"status": "disabled"}).status_code == 403


def test_list_users_never_leaks_hashes(admin):
    make_user(admin.app_ref, username="second_user")
    r = admin.get("/api/users")
    assert r.status_code == 200
    assert [u["username"] for u in r.json()] == ["root_admin", "second_user"]
    assert "password" not in r.text and "argon2" not in r.text


def test_create_user_then_that_user_can_log_in(admin):
    r = admin.post("/api/users", json={"username": "new_analyst", "password": "a-long-enough-pass", "role": "analyst"})
    assert r.status_code == 201
    assert r.json()["role"] == "analyst" and r.json()["status"] == "active"
    assert login(admin, "new_analyst", "a-long-enough-pass").status_code == 200


def test_create_user_ignores_client_supplied_permissions_and_id(admin):
    # The dashboard's form sends a 'permissions' list; it must never be believed.
    r = admin.post("/api/users", json={
        "username": "sneaky", "password": "a-long-enough-pass", "role": "analyst",
        "permissions": ["users:manage"], "id": "chosen-by-client",
    })
    assert r.status_code == 201
    assert "users:manage" not in r.json()["permissions"]
    assert r.json()["id"] != "chosen-by-client"


@pytest.mark.parametrize("bad", [
    {"username": "ab", "password": "a-long-enough-pass"},                       # too short
    {"username": "has space", "password": "a-long-enough-pass"},               # bad characters
    {"username": "fine_name", "password": "short"},                            # password too short
    {"username": "fine_name", "password": "x" * 200},                          # password too long
    {"username": "fine_name", "password": "a-long-enough-pass", "role": "root"},
    {"username": "fine_name"},                                                 # password required
])
def test_create_user_validation(admin, bad):
    assert admin.post("/api/users", json=bad).status_code == 422


def test_duplicate_username_is_409_case_insensitively(admin):
    body = {"username": "dupe_user", "password": "a-long-enough-pass"}
    assert admin.post("/api/users", json=body).status_code == 201
    assert admin.post("/api/users", json={**body, "username": "DUPE_USER"}).status_code == 409


def test_edit_user_the_way_the_dashboard_does(admin):
    target = make_user(admin.app_ref, username="edit_me")
    # AdminDashboard.svelte PATCHes the whole row it was shown, plus an optional password.
    payload = {"id": target.id, "username": "edited_name", "role": "admin", "permissions": ["x"],
               "status": "active", "lastLogin": None, "password": "brand-new-password"}
    r = admin.patch(f"/api/users/{target.id}", json=payload)
    assert r.status_code == 200 and r.json()["username"] == "edited_name" and r.json()["role"] == "admin"
    assert login(admin, "edited_name", "brand-new-password").status_code == 200
    assert login(admin, "edited_name", GOOD_PASSWORD).status_code == 401


def test_edit_without_password_keeps_the_old_one(admin):
    target = make_user(admin.app_ref, username="keep_pw")
    assert admin.patch(f"/api/users/{target.id}", json={"role": "analyst"}).status_code == 200
    assert login(admin, "keep_pw", GOOD_PASSWORD).status_code == 200


def test_edit_to_a_taken_username_is_409(admin):
    make_user(admin.app_ref, username="taken_name")
    target = make_user(admin.app_ref, username="other_name")
    assert admin.patch(f"/api/users/{target.id}", json={"username": "taken_name"}).status_code == 409


def test_unknown_user_is_404(admin):
    assert admin.patch("/api/users/nope", json={"role": "analyst"}).status_code == 404
    assert admin.patch("/api/users/nope/status", json={"status": "disabled"}).status_code == 404


def test_status_endpoint_toggles_and_blocks_login(admin):
    target = make_user(admin.app_ref, username="toggle_me")
    r = admin.patch(f"/api/users/{target.id}/status", json={"status": "disabled"})
    assert r.status_code == 200 and r.json()["status"] == "disabled"
    assert login(admin, "toggle_me").status_code == 401
    admin.patch(f"/api/users/{target.id}/status", json={"status": "active"})
    assert login(admin, "toggle_me").status_code == 200


def test_status_endpoint_rejects_unknown_values_and_extra_fields(admin):
    target = make_user(admin.app_ref, username="strict_one")
    assert admin.patch(f"/api/users/{target.id}/status", json={"status": "deleted"}).status_code == 422
    assert admin.patch(f"/api/users/{target.id}/status", json={"status": "active", "role": "admin"}).status_code == 422


def test_cannot_disable_or_demote_the_last_active_admin(admin):
    me = admin.admin_user.id
    assert admin.patch(f"/api/users/{me}/status", json={"status": "disabled"}).status_code == 409
    assert admin.patch(f"/api/users/{me}", json={"role": "analyst"}).status_code == 409
    assert storage.get_user(admin.app_ref.state.db, me).role == "admin"


def test_can_remove_an_admin_when_another_active_admin_exists(admin):
    second = make_user(admin.app_ref, username="second_admin", role="admin")
    assert admin.patch(f"/api/users/{second.id}/status", json={"status": "disabled"}).status_code == 200
    # ...but now root_admin is the last one again.
    assert admin.patch(f"/api/users/{admin.admin_user.id}", json={"role": "analyst"}).status_code == 409


def test_a_disabled_admin_does_not_count_as_the_safety_net(admin):
    make_user(admin.app_ref, username="sleeping_admin", role="admin", status="disabled")
    assert admin.patch(f"/api/users/{admin.admin_user.id}/status", json={"status": "disabled"}).status_code == 409


def test_resaving_an_unchanged_last_admin_is_fine(admin):
    me = admin.admin_user.id
    r = admin.patch(f"/api/users/{me}", json={"role": "admin", "status": "active", "username": "root_admin"})
    assert r.status_code == 200


# ---- WebSocket handshake -------------------------------------------------------
def test_ws_streams_only_after_a_valid_auth_message(anon):
    token = token_for(anon.app_ref, make_user(anon.app_ref))
    with anon.websocket_connect("/ws") as ws:
        ws.send_json({"type": "auth", "token": token})
        anon.post("/api/events", json=__import__("tests.conftest", fromlist=["x"]).event_json(),
                  headers={"X-API-Key": "test-ingest-key"})
        msg = ws.receive_json()
        assert msg["kind"] == "event"


@pytest.mark.parametrize("first_message", [
    {"type": "auth", "token": "garbage"},
    {"type": "auth"},
    {"type": "hello", "token": "x"},
    {"token": "x"},
    ["auth", "x"],
])
def test_ws_rejects_bad_handshakes_with_4401(anon, first_message):
    with anon.websocket_connect("/ws") as ws:
        ws.send_json(first_message)
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
        assert closed.value.code == WS_CLOSE_UNAUTHORIZED


def test_ws_rejects_non_json_first_frame(anon):
    with anon.websocket_connect("/ws") as ws:
        ws.send_text("not json")
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
        assert closed.value.code == WS_CLOSE_UNAUTHORIZED


def test_ws_rejects_a_disabled_users_token(anon):
    user = make_user(anon.app_ref)
    token = token_for(anon.app_ref, user)
    storage.update_user(anon.app_ref.state.db, user.id, status="disabled")
    with anon.websocket_connect("/ws") as ws:
        ws.send_json({"type": "auth", "token": token})
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
        assert closed.value.code == WS_CLOSE_UNAUTHORIZED


def test_ws_silent_client_is_dropped_after_the_timeout(anon, monkeypatch):
    from backend import auth

    monkeypatch.setattr(auth, "WS_AUTH_TIMEOUT_SECONDS", 0.2)
    with anon.websocket_connect("/ws") as ws:
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
        assert closed.value.code == WS_CLOSE_UNAUTHORIZED


def test_unauthenticated_socket_never_receives_broadcasts(anon):
    from backend.routes import websocket as ws_module
    from tests.conftest import event_json

    with anon.websocket_connect("/ws") as ws:
        anon.post("/api/events", json=event_json(), headers={"X-API-Key": "test-ingest-key"})
        assert ws_module.manager.count == 0
        ws.send_json({"type": "auth", "token": "garbage"})
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()


# ---- manage CLI helpers -----------------------------------------------------
def test_create_admin_and_reset_password_helpers(db):
    from app import manage, passwords

    manage.create_admin(db, "first_admin", "a-long-enough-pass")
    user = storage.get_user_by_username(db, "first_admin")
    assert user.role == "admin" and user.status == "active"
    assert passwords.verify_password(user.password_hash, "a-long-enough-pass")

    assert manage.reset_password(db, "FIRST_ADMIN", "another-long-pass-1") is True
    assert passwords.verify_password(storage.get_user(db, user.id).password_hash, "another-long-pass-1")
    assert manage.reset_password(db, "ghost", "another-long-pass-1") is False

    with pytest.raises(storage.UsernameTakenError):
        manage.create_admin(db, "first_admin", "a-long-enough-pass")


def test_unknown_username_still_costs_one_password_verification(anon, monkeypatch):
    # Timing equalisation: skipping the hash check for unknown users would let an attacker tell
    # real usernames from fake ones by response time.
    from app import passwords

    calls = []
    real = passwords.verify_password
    monkeypatch.setattr(passwords, "verify_password", lambda h, p: calls.append(h) or real(h, p))
    assert login(anon, username="nobody-here").status_code == 401
    assert calls == [passwords.dummy_hash()]
