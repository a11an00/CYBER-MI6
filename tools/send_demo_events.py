#!/usr/bin/env python3
"""Send synthetic events to a running CYBER-MI6 so the whole system can be demonstrated safely.

Standard library only, so it runs unchanged on Linux, macOS and Windows with any Python 3.10+.

    python tools/send_demo_events.py                        # the full demo: all four detections
    python tools/send_demo_events.py --scenario port_scan   # one attack
    python tools/send_demo_events.py --scenario normal --rate 5 --duration 30
    python tools/send_demo_events.py --dry-run --scenario web_paths   # print, send nothing

Scenarios: normal, port_scan, dns_anomaly, auth_failures, web_paths, all.
Attacks come from 203.0.113.50 (a documentation-only address, never routable); nothing here
touches the network except one HTTP POST per batch to the URL you give.

The API key is taken from --api-key, else the API_KEY environment variable, else the API_KEY
line of a .env file in the current or repository directory. It is never printed.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SOURCE = "demo-generator"
ATTACKER_IP = "203.0.113.50"  # TEST-NET-3 (RFC 5737): reserved for documentation
VICTIM_IP = "10.0.0.5"
INTERNAL_IPS = [f"10.0.1.{i}" for i in range(10, 30)]
COMMON_PORTS = [22, 53, 80, 443, 8080]
BENIGN_DOMAINS = ["www.example.com", "mail.example.org", "cdn.example.net", "api.example.com", "updates.example.org"]
BENIGN_PATHS = ["/", "/index.html", "/about", "/static/app.css", "/api/items", "/login"]
SCENARIOS = ("normal", "port_scan", "dns_anomaly", "auth_failures", "web_paths")
MAX_BATCH = 100  # the API's default INGEST_MAX_BATCH
DEFAULT_URL = "http://localhost:8000"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# Event builders. Each returns plain dicts shaped like app/models.py:EventIn.
# --------------------------------------------------------------------------
def normal_events(rng: random.Random, n: int) -> list[dict]:
    """Ordinary traffic that must NOT raise alerts: few ports per host, short DNS names, 200s."""
    events = []
    for _ in range(n):
        kind = rng.choice(["connection", "dns", "http"])
        ip = rng.choice(INTERNAL_IPS)
        if kind == "connection":
            events.append({"type": "network_connection", "timestamp": now(), "source": SOURCE, "src_ip": ip,
                           "dst_ip": VICTIM_IP, "dst_port": rng.choice(COMMON_PORTS), "protocol": "tcp"})
        elif kind == "dns":
            events.append({"type": "dns_query", "timestamp": now(), "source": SOURCE, "src_ip": ip,
                           "dns_name": rng.choice(BENIGN_DOMAINS)})
        else:
            events.append({"type": "http_request", "timestamp": now(), "source": SOURCE, "src_ip": ip,
                           "http_method": "GET", "http_path": rng.choice(BENIGN_PATHS), "http_status": 200})
    return events


def port_scan_events(rng: random.Random, ip: str = ATTACKER_IP) -> list[dict]:
    """One host probing 30 different ports on one target within a few seconds."""
    ports = rng.sample(range(1, 1025), 30)
    return [{"type": "network_connection", "timestamp": now(), "source": SOURCE, "src_ip": ip,
             "dst_ip": VICTIM_IP, "dst_port": p, "protocol": "tcp"} for p in ports]


def dns_anomaly_events(rng: random.Random, ip: str = ATTACKER_IP) -> list[dict]:
    """A very long, random-looking label: the shape of DNS tunnelling or a generated domain."""
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    label = "".join(rng.choice(alphabet) for _ in range(52))
    return [{"type": "dns_query", "timestamp": now(), "source": SOURCE, "src_ip": ip,
             "dns_name": f"{label}.example.com"}]


def auth_failure_events(rng: random.Random, ip: str = ATTACKER_IP) -> list[dict]:
    """Eight failed logins for the same account in a row (password guessing)."""
    return [{"type": "auth_failure", "timestamp": now(), "source": SOURCE, "src_ip": ip, "username": "admin"}
            for _ in range(8)]


def web_path_events(rng: random.Random, ip: str = ATTACKER_IP) -> list[dict]:
    """A scanner walking through paths that only attackers request."""
    paths = ["/../../etc/passwd", "/.env", "/wp-login.php", "/phpmyadmin/", "/search?q=1' or 1=1--"]
    return [{"type": "http_request", "timestamp": now(), "source": SOURCE, "src_ip": ip, "http_method": "GET",
             "http_path": p, "http_status": 404} for p in paths]


ATTACKS = {
    "port_scan": port_scan_events,
    "dns_anomaly": dns_anomaly_events,
    "auth_failures": auth_failure_events,
    "web_paths": web_path_events,
}
EXPECTED_RULE = {name: name for name in ATTACKS}  # scenario name == the rule it should trigger


# --------------------------------------------------------------------------
# Sending
# --------------------------------------------------------------------------
class SendError(Exception):
    """Something went wrong sending; the message is meant to be shown to the person running this."""


def find_api_key(
    explicit: str | None,
    env: dict[str, str] | None = None,
    search: list[Path] | None = None,
) -> str | None:
    if explicit:
        return explicit
    env = os.environ if env is None else env
    if env.get("API_KEY"):
        return env["API_KEY"]
    for folder in search if search is not None else [Path.cwd(), Path(__file__).resolve().parent.parent]:
        dotenv = folder / ".env"
        if dotenv.is_file():
            for line in dotenv.read_text(encoding="utf-8").splitlines():
                key, sep, value = line.partition("=")
                if sep and key.strip() == "API_KEY" and value.strip().strip("'\""):
                    return value.strip().strip("'\"")
    return None


def send_batch(url: str, api_key: str, events: list[dict], *, retries: int = 3, sleep=time.sleep) -> int:
    """POST up to MAX_BATCH events. Returns how many the server accepted."""
    body = json.dumps({"events": events}).encode()
    request = urllib.request.Request(
        url.rstrip("/") + "/api/events", data=body, method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
    )
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return int(json.load(response)["accepted"])
        except urllib.error.HTTPError as err:
            detail = err.read().decode(errors="replace")[:300]
            if err.code == 429 and attempt < retries:
                sleep(min(int(err.headers.get("Retry-After", "5")), 30))
                continue
            if err.code == 401:
                raise SendError(
                    "The server rejected the API key (401). Check API_KEY against the server's .env."
                ) from None
            if err.code == 503:
                raise SendError(
                    "The server has no API_KEY configured, so ingestion is disabled (503)."
                ) from None
            raise SendError(f"The server answered {err.code}: {detail}") from None
        except urllib.error.URLError as err:
            raise SendError(f"Cannot reach {url} ({err.reason}). Is the backend running?") from None
    raise SendError("Still rate limited after several retries (429).")


def send_all(url: str, api_key: str, events: list[dict], batch: int) -> int:
    sent = 0
    for i in range(0, len(events), batch):
        sent += send_batch(url, api_key, events[i:i + batch])
    return sent


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------
def run_normal(rng, emit, rate: float, duration: float, sleep=time.sleep) -> int:
    """``rate`` events per second for ``duration`` seconds, in one-second ticks."""
    total = 0
    for _ in range(max(1, int(duration))):
        total += emit(normal_events(rng, max(1, round(rate))))
        sleep(1)
    return total


def run_demo(rng, emit, *, rate: float, duration: float, pause: float, log=print, sleep=time.sleep) -> int:
    """Normal traffic, then each attack in turn with calm traffic in between."""
    total = 0
    log("Normal traffic (should raise nothing)...")
    total += run_normal(rng, emit, rate, min(duration, 3), sleep)
    for name, build in ATTACKS.items():
        log(f"Attack: {name}")
        total += emit(build(rng))
        sleep(pause)
        total += run_normal(rng, emit, rate, 1, sleep)
    return total


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Send synthetic events to CYBER-MI6.")
    parser.add_argument("--url", default=os.environ.get("CYBER_MI6_URL", DEFAULT_URL),
                        help=f"API base URL (default {DEFAULT_URL})")
    parser.add_argument("--api-key", help="ingestion API key (default: $API_KEY or the .env file)")
    parser.add_argument("--scenario", choices=(*SCENARIOS, "all"), default="all")
    parser.add_argument("--rate", type=float, default=5, help="normal traffic, events per second (default 5)")
    parser.add_argument("--duration", type=float, default=10,
                        help="seconds of normal traffic for --scenario normal (default 10)")
    parser.add_argument("--pause", type=float, default=3,
                        help="seconds between attacks in the full demo (default 3)")
    parser.add_argument("--batch", type=int, default=50, help=f"events per request, max {MAX_BATCH} (default 50)")
    parser.add_argument("--seed", type=int, help="make the generated data repeatable")
    parser.add_argument("--dry-run", action="store_true", help="print the events as JSON instead of sending them")
    args = parser.parse_args(argv)
    if not 1 <= args.batch <= MAX_BATCH:
        parser.error(f"--batch must be between 1 and {MAX_BATCH}")
    if args.rate <= 0 or args.duration <= 0 or args.pause < 0:
        parser.error("--rate and --duration must be positive and --pause cannot be negative")

    rng = random.Random(args.seed)
    if args.dry_run:
        events = (normal_events(rng, 5) if args.scenario == "normal"
                  else [e for build in ATTACKS.values() for e in build(rng)] if args.scenario == "all"
                  else ATTACKS[args.scenario](rng))
        print(json.dumps({"events": events}, indent=2))
        return 0

    api_key = find_api_key(args.api_key)
    if not api_key:
        print("No API key found. Pass --api-key, set API_KEY, or put API_KEY=... in .env.", file=sys.stderr)
        return 2

    def emit(events: list[dict]) -> int:
        return send_all(args.url, api_key, events, args.batch)

    try:
        if args.scenario == "all":
            total = run_demo(rng, emit, rate=args.rate, duration=args.duration, pause=args.pause)
        elif args.scenario == "normal":
            total = run_normal(rng, emit, args.rate, args.duration)
        else:
            total = emit(ATTACKS[args.scenario](rng))
    except SendError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
        return 130
    print(f"Done: {total} events accepted by {args.url}")
    if args.scenario in ("all", *ATTACKS):
        print("Expect alerts for: " + ", ".join(ATTACKS if args.scenario == "all" else [args.scenario]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
