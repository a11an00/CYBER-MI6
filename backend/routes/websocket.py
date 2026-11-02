import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

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


@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await manager.connect(ws)
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
