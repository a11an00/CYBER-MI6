# Future changes

Things that work today but are deliberately simple, or are known gaps. Each row says what the
code does now, why it may matter, and what to change. Add a row when you take a shortcut; delete
it when it is fixed.

## Not built yet

| Item | Notes |
|---|---|
| **Setup script** (macOS, Windows, Linux) | Installs dependencies, creates `.env` with generated secrets, runs the first-admin command. |
| **Scapy network sensor** (`collectors/scapy_collector.py`, `docs/SENSOR_SETUP.md`) | Waits until after the demo generator (built). Needs root or Npcap and a real network to test. |
| **Web-app event helper and test web app** (`examples/`) | Described in `docs/BACKEND_SPEC.md`; the only source of real `auth_failure` and `http_request` events. |
| **CI** (GitHub Actions: ruff + pytest + `svelte-check`) | None exists. The suite runs in about 30 seconds. The browser check (`tests/e2e_browser/run.py`) could join it once a Chrome is available on the runner. |
| **Linting** | `ruff.toml` exists (`ruff check .`, rules E, W, F, B). New code is clean. 22 findings remain in older files (whitespace, unused imports, a few long lines, one `zip()` without `strict=`; most are auto-fixable with `ruff --fix`) and were left alone to keep other people's diffs small. Fix them, then add `ruff check .` to CI. |

## Decided to defer

| Item | Now | Change when |
|---|---|---|
| **Blocklist enforcement** | The list is built and **record only**: `/api/blocklist` stores addresses and the dashboard shows them, but nothing refuses traffic from them, and listed addresses can still send events. | Decide what enforcing means first (reject ingestion from the address? a firewall rule on the sensor host? an alert annotation?). Options differ a lot in risk: blocking by source IP at ingestion is easy but sources are often spoofable or shared (NAT). |
| **Alert status transitions** | `PATCH /api/alerts/{id}` allows any status to any other (e.g. `resolved` back to `new`). | You want a workflow. Put the allowed moves next to `AlertStatus` in `models.py` and check them inside the same transaction as the update (`storage.update_alert_status`), so two analysts cannot race. |

## Security hardening

| Item | Now | Suggested change |
|---|---|---|
| **Rate limits behind a reverse proxy** | Both limiters (ingest, login) key on `request.client.host`. Behind a proxy that is one shared address, so one noisy client throttles everyone, and an attacker's failed logins lock everyone out of login. | When deploying behind a proxy, read the real address from a trusted `X-Forwarded-For` (uvicorn `--proxy-headers` with `--forwarded-allow-ips`). |
| **Ingest limit counts requests, not events** | 300 requests/minute, but one request may carry 500 events (150,000 events/minute). | Count events (`allow` with a cost), or lower `INGEST_MAX_BATCH`. |
| **Rate limiter memory** | Idle IP entries are never removed (existing known issue, `ratelimit.py`). | Periodic cleanup of idle keys if this is ever internet-facing. |
| **Tokens cannot be revoked one by one** | A JWT lives `JWT_EXPIRE_MINUTES` (60). Disabling the user or changing their role takes effect at once (checked in the database on every request), but a *password change* does not invalidate tokens already issued. | Add `password_changed_at` to `users` and reject tokens issued before it. |
| **WebSocket is authorised once** | The token is checked when the socket connects. A socket opened with a token stays open after that token expires or the user is disabled. | Close each socket at its token's `exp`, and drop sockets when a user is disabled. |
| **Token storage in the browser** | The frontend keeps the JWT in `localStorage`, readable by any script that runs in the page (XSS). | Move to an `HttpOnly` `Secure` `SameSite=Strict` cookie plus CSRF protection. Bigger change on both sides. |
| **Logout is client-side only** | `auth.logout()` forgets the token; the token stays valid until it expires. | Same fix as "tokens cannot be revoked" (a revocation list or `password_changed_at`-style cutoff). |
| **Brute-force protection is per IP only** | 10 login attempts/minute/IP. A distributed attack on one account is not slowed down. | Per-username backoff or temporary lockout. |
| **TLS** | The app speaks plain HTTP, so passwords and tokens cross the network in clear text. | Always run behind HTTPS in any real deployment. |
| **Password policy** | Length only (12 to 128 characters). | Check against a breached-password list if this matters. |

## Missing features the frontend already hints at

| Item | Now |
|---|---|
| **Change own password / profile** | `frontend/src/views/UserProfileSettings.svelte` is an empty file and no `PATCH /api/users/me` exists. Admins can reset anyone's password; users cannot change their own. |
| **"Recover Access" link** | Login links to `#/forgot-password`, which has no view or endpoint. The CLI `python -m app.manage reset-password <user>` is the recovery path for now. |
| **Who changed an alert** | Alerts store no actor. Add `updated_by` and an audit table if you need to answer "who marked this false positive?". |
| **Live update on status change** | `PATCH /api/alerts/{id}` does not broadcast, so other open dashboards see the change only on their next refresh. |
| **Login attempts as events** | Failed logins go only to the server log. They could be fed into the detection engine as `auth_failure` events so CYBER-MI6 monitors itself. |

## Performance and structure

| Item | Now | Suggested change |
|---|---|---|
| **Detection runs inside the ingest request** | `POST /api/events` stores, runs all rules, then responds (in a worker thread). A 500-event batch runs 4 rules x 500 events. | Measure first (`tests/test_perf.py` is a start). If slow, store and respond, then detect in a background task. |
| **`username` filter** | `storage.list_events` can filter by username; `GET /api/events` does not expose it. | Add the query parameter if the UI needs it. |
| **Stale docs** | `docs/apilayer.md` describes the old `app/` layout and says the routes are "Not started". | Rewrite during the `app/` cleanup. |
