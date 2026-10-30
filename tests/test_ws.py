import asyncio
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes import ws as ws_module
from app.routes.ws import ConnectionManager, broadcast_event, router


def wait_until(condition, timeout: float = 2.0) -> bool:
    """Server-side cleanup runs on another thread, so poll briefly instead of asserting at once."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.01)
    return condition()


@pytest.fixture(autouse=True)
def clean_global_manager():
    ws_module.manager._connections.clear()
    yield
    ws_module.manager._connections.clear()


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)

    # Test-only route: lets a test trigger a broadcast from the server side.
    @app.post("/_test/broadcast")
    async def test_broadcast(message: dict):
        await broadcast_event(message)
        return {"ok": True}

    # The `with` block keeps one event loop alive for every request and socket,
    # so the connection manager sees them all on the same loop.
    with TestClient(app) as test_client:
        yield test_client


def test_connect_and_disconnect_update_count(client):
    with client.websocket_connect("/ws"):
        assert wait_until(lambda: ws_module.manager.count == 1)
    assert wait_until(lambda: ws_module.manager.count == 0)


def test_broadcast_reaches_every_client(client):
    with client.websocket_connect("/ws") as a, client.websocket_connect("/ws") as b:
        assert wait_until(lambda: ws_module.manager.count == 2)
        client.post("/_test/broadcast", json={"n": 1})
        assert a.receive_json() == {"kind": "event", "data": {"n": 1}}
        assert b.receive_json() == {"kind": "event", "data": {"n": 1}}


def test_survives_50_connect_broadcast_disconnect_cycles(client):
    for i in range(50):
        with client.websocket_connect("/ws") as ws:
            client.post("/_test/broadcast", json={"n": i})
            assert ws.receive_json()["data"] == {"n": i}
    assert wait_until(lambda: ws_module.manager.count == 0)


class FakeSocket:
    """Stands in for a WebSocket so we can make sends fail or hang."""

    def __init__(self, mode: str = "ok"):
        self.mode = mode
        self.sent: list[dict] = []

    async def send_json(self, message: dict) -> None:
        if self.mode == "broken":
            raise RuntimeError("connection reset")
        if self.mode == "slow":
            await asyncio.sleep(10)
        self.sent.append(message)


def test_broken_client_is_dropped_and_others_still_receive():
    manager = ConnectionManager()
    good, broken = FakeSocket(), FakeSocket("broken")
    manager._connections.update({good, broken})

    asyncio.run(manager.broadcast({"kind": "event", "data": {}}))

    assert good.sent == [{"kind": "event", "data": {}}]
    assert manager.count == 1


def test_slow_client_times_out_and_is_dropped(monkeypatch):
    monkeypatch.setattr(ws_module, "SEND_TIMEOUT_SECONDS", 0.05)
    manager = ConnectionManager()
    fast, slow = FakeSocket(), FakeSocket("slow")
    manager._connections.update({fast, slow})

    asyncio.run(manager.broadcast({"kind": "alert", "data": {}}))

    assert len(fast.sent) == 1
    assert manager.count == 1


def test_broadcast_with_no_clients_does_nothing():
    manager = ConnectionManager()
    asyncio.run(manager.broadcast({"kind": "event", "data": {}}))
    assert manager.count == 0