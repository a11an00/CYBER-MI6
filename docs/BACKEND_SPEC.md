# CYBER-MI6 — Backend Specification

## API endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/api/events` | Ingest and validate an event (or a small batch). Requires the ingestion API key |
| GET | `/api/events` | Recent events with filters: `type`, `src_ip`, `from`, `to`, `limit` |
| GET | `/api/alerts` | Alerts with filters: `severity`, `status`, `rule`, `limit` |
| GET | `/api/alerts/{id}` | Alert detail with evidence events |
| PATCH | `/api/alerts/{id}` | Change status (`new`, `investigating`, `resolved`, `false_positive`) |
| GET | `/api/stats` | Counts for the dashboard (events, alerts by severity, top source IPs) |
| WS | `/ws` | Live stream of new events and alerts |
| GET | `/docs` | Auto-generated OpenAPI documentation (the API contract) |

### Example ingestion request

```http
POST /api/events
X-API-Key: <value from .env>
Content-Type: application/json

{
  "type": "network_connection",
  "timestamp": "2026-10-19T09:15:02Z",
  "source": "laptop-sensor-1",
  "src_ip": "192.168.1.25",
  "dst_ip": "192.168.1.1",
  "dst_port": 445,
  "protocol": "tcp"
}
```

---

## Sensor: Scapy collector (`collectors/scapy_collector.py`)

- Sniffs on a chosen interface using Scapy with a BPF filter.
- Reports **initial TCP SYN** packets (SYN set, ACK not set) as `network_connection` events: source IP, destination IP, destination port.
- Reports **DNS query names** as `dns_query` events.
- Never stores or sends payloads.
- Batches events and sends them to the API with retry and backoff; if the API is down, keeps a small bounded buffer and drops the oldest.
- Command-line options: `--iface`, `--api-url`, `--api-key`, `--source-name`, `--list-ifaces`.
- **Windows:** install Npcap (WinPcap API-compatible mode) and run the terminal as Administrator.
- **Linux:** install libpcap and run with `sudo`, or grant `CAP_NET_RAW` to the Python binary.
- Sees only traffic the chosen computer/interface can observe. See `docs/SENSOR_SETUP.md`.

## Optional Zeek forwarder (`sensor/`)

Reads Zeek JSON `conn.log` and `dns.log` and converts them into the same event format. Build this only after the Scapy sensor works.

---

## Tools and examples

- **`tools/send_demo_events.py`** *(to be built by Member 4)*: sends synthetic events (normal traffic plus scenarios: port scan, long DNS label, repeated login failures, suspicious paths) so the whole system can be tested safely without real traffic. Options: `--scenario port_scan`, `--rate`, etc.
- **`examples/webapp_event_reporting.py`** *(to be built by Member 4)*: a small helper that a team-owned web app imports to report `auth_failure` and `http_request` events to the API (non-blocking, with timeouts so the app never slows down if CYBER-MI6 is down).

---

## Configuration (`.env`)

| Variable | Purpose |
|---|---|
| `API_KEY` | Key required by sensors and apps sending events |
| `DATABASE_PATH` | SQLite file location (default `data/cybermi6.db`) |
| `EVENT_RETENTION_DAYS` | How long events are kept |
| `PORT_SCAN_PORTS`, `PORT_SCAN_WINDOW_SECONDS` | Port scan thresholds |
| `DNS_MAX_LABEL_LENGTH`, `DNS_MIN_ENTROPY` | DNS anomaly thresholds |
| `AUTH_FAIL_COUNT`, `AUTH_FAIL_WINDOW_SECONDS` | Authentication failure thresholds |
| `ALERT_COOLDOWN_SECONDS` | Deduplication window |
| `ALLOWED_ORIGINS` | CORS origins if the dashboard is hosted separately |

Never commit `.env`.
