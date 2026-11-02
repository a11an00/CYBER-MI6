"""Tests for the application's outer shell: how it answers requests and how it starts.

Merge note (conflict with pull request #13, resolved in favour of the
"backend" code this project has moved to): the imports and the "client" helper
below are our side of that merge. The other side still belonged to the older
"app" code, and it guarded ``test_startup_creates_database_file`` with a check
asking whether a module called ``app.db`` existed. That module has not existed
on this side since the move, so the check could only ever have skipped the
test - and keeping it meant keeping the two lines that defined the name it
looked for. Those are gone now, the guard with them, along with the "importlib"
import the guard needed and nothing else does. The test runs for real here.
"""

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from backend.config import get_settings
from backend.main import create_app


class Body(BaseModel):
    n: int


@pytest.fixture
def settings_env(tmp_path, monkeypatch):
    """Give every test a clean, isolated starting point.

    A brand-new empty folder is created for the single test about to run, the
    app is told to keep its database in a file inside that folder, and anything
    the app remembered from an earlier test is thrown away. No test can then
    read, overwrite or quietly depend on another test's leftovers. The new
    folder is handed to the test to use, and the remembered settings are
    cleared once more after the test finishes.
    """
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("API_KEY", "test-key")
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def client(settings_env):
    """Build the whole application and hand it over ready to be poked at.

    The "settings_env" helper is asked for here even though this function never
    reads it directly. Naming it is what tells the test runner to prepare a
    clean folder and throw away remembered settings first; leaving the name out
    would run the app against whatever an earlier test happened to leave behind.

    A complete copy of the app is created with its static-file part switched
    off, so the built-in website cannot get in the way of the tests, and one
    extra made-up address is added for the tests to send bad data to. The app is
    then started up for real before each test runs and shut down again
    afterwards, so every test gets a working application to talk to without
    needing a real server or a real browser.

    The connection handed over is the same kind an outside program would use,
    which is what makes these checks meaningful.
    """
    app = create_app(mount_static=False)

    @app.post("/_test/validate")
    def validate(body: Body):
        """A made-up address that only exists while the tests are running.

        It accepts a single number called "n" and hands it straight back with
        no questions asked. Sending it something that is not a number is how the
        tests below deliberately provoke the app into rejecting a request, so
        that the rejection itself can be inspected.
        """
        return body

    with TestClient(app) as c:
        yield c


def test_docs_are_served(client):
    """Check that the app's own instruction page opens successfully.

    Every address the app understands is written down on an automatically
    generated page at "/docs". If that page will not load it almost always
    means the app did not start properly, so this doubles as a quick "is the app
    alive at all?" check before the more specific tests are trusted.
    """
    assert client.get("/docs").status_code == 200


def test_unknown_api_path_returns_json_error(client):
    """Check that asking for an address that does not exist still gets a useful answer.

    Someone who types in a made-up address should get a proper reply saying
    "not found", not a blank screen or a raw internal error dump. The reply must
    also carry a short label, "http_404", so that whatever called the app can
    tell this particular kind of failure apart from any other and react to it in
    the right way.
    """
    r = client.get("/api/does-not-exist")
    assert r.status_code == 404
    assert r.json()["error"] == "http_404"


def test_validation_error_has_standard_shape(client):
    """Check that sending nonsense produces the same complaint every time.

    The request below deliberately sends the words "not a number" where a
    number was expected. The app has to refuse it, and the refusal has to look
    the same each time: the label "validation_error" at the top, and beneath it
    a list describing which part of the request was wrong. That list must name
    the offending field, "n", so whoever sent the request can find and fix it
    without guessing.
    """
    r = client.post("/_test/validate", json={"n": "not a number"})
    assert r.status_code == 422
    body = r.json()
    assert body["error"] == "validation_error"
    assert body["detail"][0]["loc"][-1] == "n"


def test_startup_creates_database_file(settings_env):
    """Check that the app creates its own database the first time it runs.

    On a fresh machine there is no database yet - the app is expected to create
    the file, and the tables inside it, by itself when it starts. This test
    starts the app against an empty folder and then confirms two things: the
    database file is now sitting there, and the app kept a working connection to
    it that it can use for the rest of its life.
    """
    app = create_app(mount_static=False)
    with TestClient(app):
        assert (settings_env / "test.db").exists()
        assert app.state.db is not None
