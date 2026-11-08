import asyncio
import logging

from collections.abc import Awaitable, Callable

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from backend.auth import authenticate_websocket

log = logging.getLogger(__name__)
router = APIRouter()

# One slow browser must not hold up the others.
SEND_TIMEOUT_SECONDS = 2.0


class ConnectionManager:
    """Tracks live WebSocket clients.

    No lock is needed: every method runs on the event loop thread, and nothing
    awaits while the set is being changed.
    """

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()

    @property
    def count(self) -> int:
        return len(self._connections)

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.add(ws)

    def register(self, ws: WebSocket) -> None:
        """Start sending broadcasts to an already accepted (and authenticated) socket."""
        self._connections.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.discard(ws)

    async def broadcast(self, message: dict) -> None:
        targets = list(self._connections)  # snapshot: the set can change while we await
        results = await asyncio.gather(*(self._send(ws, message) for ws in targets))
        dead = [ws for ws, ok in zip(targets, results) if not ok]
        for ws in dead:
            self._connections.discard(ws)
        if dead:
            log.info("Dropped %d dead WebSocket connection(s)", len(dead))

    @staticmethod
    async def _send(ws: WebSocket, message: dict) -> bool:
        try:
            await asyncio.wait_for(ws.send_json(message), SEND_TIMEOUT_SECONDS)
            return True
        except Exception:  # closed, broken, or too slow
            return False


manager = ConnectionManager()


async def broadcast_event(event: dict) -> None:
    await manager.broadcast({"kind": "event", "data": event})


async def broadcast_alert(alert: dict) -> None:
    await manager.broadcast({"kind": "alert", "data": alert})


Authenticator = Callable[[WebSocket], Awaitable[bool]]


def get_ws_authenticator() -> Authenticator:
    """A dependency so tests can swap the login check out (app.dependency_overrides)."""
    return authenticate_websocket


@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket, authenticate: Authenticator = Depends(get_ws_authenticator)) -> None:
    await ws.accept()
    # Not in the manager yet, so an unauthenticated socket never receives a broadcast.
    if not await authenticate(ws):
        return
    manager.register(ws)
    try:
        # Clients don't send data. Waiting here is how we notice a disconnect.
        while True:
            message = await ws.receive()
            if message["type"] == "websocket.disconnect":
                break
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(ws)
