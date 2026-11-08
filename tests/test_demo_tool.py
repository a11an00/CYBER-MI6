"""tools/send_demo_events.py: the data it makes is valid, each attack trips exactly its rule,
normal traffic trips nothing, and the real HTTP client works against a real server."""

import random
import socket
import threading
import time

import pytest
import uvicorn

from app import storage
from app.models import EventIn
from tests.conftest import API_KEY, ingest_headers
from tools import send_demo_events as demo


def post(api, events):
    r = api.post("/api/events", json={"events": events}, headers=ingest_headers())
    assert r.status_code == 201, r.text


# ---- the data -------------------------------------------------------------
@pytest.mark.parametrize(
    "build",
    [lambda rng: demo.normal_events(rng, 30), *demo.ATTACKS.values()],
    ids=["normal", *demo.ATTACKS],
)
def test_every_generated_event_is_valid_for_the_api(build):
    for event in build(random.Random(1)):
        EventIn(**event)  # raises if the API would reject it


@pytest.mark.parametrize("scenario", list(demo.ATTACKS))
def test_each_attack_raises_exactly_its_own_rule(api, scenario):
    post(api, demo.ATTACKS[scenario](random.Random(7)))
    rules = {a.rule for a in storage.list_alerts(api.app_ref.state.db)}
    assert rules == {demo.EXPECTED_RULE[scenario]}


def test_normal_traffic_raises_nothing_even_in_volume(api):
    rng = random.Random(3)
    for _ in range(5):
        post(api, demo.normal_events(rng, 100))
    assert storage.list_alerts(api.app_ref.state.db) == []
    assert storage.count_events(api.app_ref.state.db) == 500


def test_seed_makes_scenarios_repeatable():
    strip = lambda evs: [{k: v for k, v in e.items() if k != "timestamp"} for e in evs]  # noqa: E731
    assert strip(demo.port_scan_events(random.Random(5))) == strip(demo.port_scan_events(random.Random(5)))


def test_attacker_address_is_a_documentation_range():
    import ipaddress

    assert ipaddress.ip_address(demo.ATTACKER_IP) in ipaddress.ip_network("203.0.113.0/24")


# ---- API key lookup -------------------------------------------------------
def test_api_key_precedence_flag_then_env_then_dotenv(tmp_path):
    (tmp_path / ".env").write_text("OTHER=1\nAPI_KEY='from-dotenv'\n")
    assert demo.find_api_key("flag", {"API_KEY": "env"}, [tmp_path]) == "flag"
    assert demo.find_api_key(None, {"API_KEY": "env"}, [tmp_path]) == "env"
    assert demo.find_api_key(None, {}, [tmp_path]) == "from-dotenv"
    assert demo.find_api_key(None, {}, [tmp_path / "nowhere"]) is None


# ---- sending, against a real server ----------------------------------------
@pytest.fixture
def server(app_env):
    from backend.main import create_app

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    app = create_app(mount_static=False)
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    assert srv.started, "test server did not start"
    yield f"http://127.0.0.1:{port}", app
    srv.should_exit = True
    thread.join(timeout=5)


def test_full_demo_over_real_http_raises_all_four_alerts(server, capsys):
    url, app = server
    code = demo.main(["--url", url, "--api-key", API_KEY, "--scenario", "all",
                      "--rate", "3", "--duration", "1", "--pause", "0", "--seed", "1"])
    assert code == 0
    assert {a.rule for a in storage.list_alerts(app.state.db)} == set(demo.ATTACKS)
    assert "Expect alerts for: port_scan, dns_anomaly, auth_failures, web_paths" in capsys.readouterr().out


def test_wrong_key_exits_nonzero_with_a_useful_message(server, capsys):
    url, _ = server
    assert demo.main(["--url", url, "--api-key", "wrong", "--scenario", "port_scan"]) == 1
    assert "rejected the API key" in capsys.readouterr().err


def test_unreachable_server_exits_nonzero_with_a_useful_message(capsys):
    assert demo.main(["--url", "http://127.0.0.1:9", "--api-key", "k", "--scenario", "dns_anomaly"]) == 1
    assert "Cannot reach" in capsys.readouterr().err


def test_no_key_anywhere_exits_2(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(demo, "find_api_key", lambda explicit, *a, **k: explicit)
    assert demo.main(["--scenario", "normal"]) == 2


def test_rate_limited_batches_are_retried(monkeypatch):
    import urllib.error

    calls = []

    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"accepted": 2}'

    def fake_urlopen(request, timeout):
        calls.append(1)
        if len(calls) == 1:
            raise urllib.error.HTTPError(request.full_url, 429, "slow down", {"Retry-After": "2"}, __import__("io").BytesIO(b"{}"))
        return Resp()

    slept = []
    monkeypatch.setattr(demo.urllib.request, "urlopen", fake_urlopen)
    assert demo.send_batch("http://x", "k", [{}, {}], sleep=slept.append) == 2
    assert slept == [2] and len(calls) == 2


def test_dry_run_sends_nothing_and_needs_no_key(capsys, monkeypatch):
    monkeypatch.setattr(demo, "send_batch", lambda *a, **k: pytest.fail("dry run must not send"))
    assert demo.main(["--dry-run", "--scenario", "web_paths", "--seed", "1"]) == 0
    assert "/.env" in capsys.readouterr().out


@pytest.mark.parametrize("bad", [["--batch", "0"], ["--batch", "101"], ["--rate", "0"], ["--duration", "-1"]])
def test_bad_options_are_rejected(bad):
    with pytest.raises(SystemExit) as exit_info:
        demo.main(["--dry-run", *bad])
    assert exit_info.value.code == 2
