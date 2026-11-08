"""CYBER-MI6 data models: the contract everything else imports.

Rules enforced here (so every other module can trust what it receives):
  * metadata only - payload-like / credential-like fields are rejected, not stored
  * all strings are length-capped and free of control characters
  * ``type``, severities and statuses come from fixed lists
  * ``http_path`` is stored with the query string and fragment removed
  * timestamps are always timezone-aware UTC

``EventIn`` is what sensors/apps POST. ``Event`` is the stored version (adds id,
received_at). ``AlertIn`` is what the detection engine produces; ``Alert`` is the
stored version. ``AlertUpdate`` is the body of PATCH /api/alerts/{id}.
"""

import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal, get_args

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

# --------------------------------------------------------------------------
# Allowed values
# --------------------------------------------------------------------------
EventType = Literal["network_connection", "dns_query", "auth_failure", "http_request"]
Severity = Literal["low", "medium", "high", "critical"]
AlertStatus = Literal["new", "investigating", "resolved", "false_positive"]

EVENT_TYPES: tuple[str, ...] = get_args(EventType)
SEVERITIES: tuple[str, ...] = get_args(Severity)
ALERT_STATUSES: tuple[str, ...] = get_args(AlertStatus)
OPEN_STATUSES: tuple[str, ...] = ("new", "investigating")
SEVERITY_RANK: dict[str, int] = {s: i for i, s in enumerate(SEVERITIES)}

# --------------------------------------------------------------------------
# Limits (single place to tune)
# --------------------------------------------------------------------------
MAX_BATCH_SIZE = 500  # events per POST /api/events batch (route should enforce)
MAX_SOURCE_LEN = 64
MAX_USERNAME_LEN = 128
MAX_DNS_NAME_LEN = 253
MAX_HTTP_PATH_LEN = 2048
MAX_USER_AGENT_LEN = 512
MAX_DETAILS_KEYS = 20
MAX_DETAILS_KEY_LEN = 64
MAX_DETAILS_VALUE_LEN = 256
MAX_TITLE_LEN = 200
MAX_EVIDENCE_IDS = 200  # stored per alert; extra ids are counted but not stored
MAX_EXPLANATION_BYTES = 4096
MAX_FUTURE_SKEW = timedelta(minutes=10)  # tolerate small sensor clock drift

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_SOURCE_RE = re.compile(r"^[A-Za-z0-9._:\-]+$")
_RULE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_METHOD_RE = re.compile(r"^[A-Za-z]{3,10}$")

# Field names that look like payloads or credentials. Normalised (lowercase, only
# letters/digits) and matched as substrings, so "Set-Cookie", "user_password" and
# "request_body" are all caught.
_FORBIDDEN_STEMS = (
    "password", "passwd", "passphrase", "secret", "token", "cookie", "apikey",
    "authorization", "credential", "csrf", "bearer", "session",
    "payload", "body", "packet", "pcap", "hexdump", "formdata", "postdata",
)  # fmt: skip
_FORBIDDEN_EXACT = frozenset({"pwd", "pass", "raw", "data", "content", "text", "bytes"})


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _looks_like_payload_field(name: str) -> bool:
    norm = re.sub(r"[^a-z0-9]", "", name.lower())
    return norm in _FORBIDDEN_EXACT or any(stem in norm for stem in _FORBIDDEN_STEMS)


# Annotated string types ----------------------------------------------------
Source = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_SOURCE_LEN)]
Username = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_USERNAME_LEN)]
UserAgent = Annotated[str, StringConstraints(strip_whitespace=True, max_length=MAX_USER_AGENT_LEN)]
HttpPath = Annotated[str, StringConstraints(min_length=1, max_length=MAX_HTTP_PATH_LEN)]
DnsName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_DNS_NAME_LEN)]
Port = Annotated[int, Field(ge=1, le=65535)]

# Which type-specific fields each event type requires / may use. Common fields
# (type, timestamp, source, src_ip, user_agent, details) are allowed on every type.
_TYPE_REQUIRED: dict[str, frozenset[str]] = {
    "network_connection": frozenset({"dst_ip", "dst_port"}),
    "dns_query": frozenset({"dns_name"}),
    "auth_failure": frozenset({"username"}),
    "http_request": frozenset({"http_method", "http_path"}),
}
_TYPE_OPTIONAL: dict[str, frozenset[str]] = {
    "network_connection": frozenset({"protocol"}),
    "dns_query": frozenset(),
    "auth_failure": frozenset(),
    "http_request": frozenset({"http_status"}),
}
_TYPE_SPECIFIC_FIELDS = frozenset(
    {"dst_ip", "dst_port", "protocol", "dns_name", "username", "http_method", "http_path", "http_status"}
)


def _check_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as exc:
        raise ValueError(f"not a valid IP address: {value!r}") from exc


# --------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------
class EventIn(BaseModel):
    """An event as sent by a sensor or application."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    type: EventType
    timestamp: datetime = Field(default_factory=utcnow)
    source: Source
    src_ip: str

    dst_ip: str | None = None
    dst_port: Port | None = None
    protocol: Literal["tcp", "udp"] | None = None
    dns_name: DnsName | None = None
    username: Username | None = None
    http_method: str | None = None
    http_path: HttpPath | None = None
    http_status: Annotated[int, Field(ge=100, le=599)] | None = None
    user_agent: UserAgent | None = None
    details: dict[str, str | int | float | bool | None] | None = None

    # -- reject payload / credential fields with a clear message -------------
    @model_validator(mode="before")
    @classmethod
    def _reject_payload_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        declared = set(cls.model_fields)
        for key in data:
            if key not in declared and isinstance(key, str) and _looks_like_payload_field(key):
                raise ValueError(
                    f"field {key!r} looks like payload or credential data; "
                    "CYBER-MI6 accepts metadata only"
                )
        return data

    # -- per-field normalisation ---------------------------------------------
    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _valid_ip(cls, v: str | None) -> str | None:
        return None if v is None else _check_ip(v)

    @field_validator("timestamp")
    @classmethod
    def _utc_timestamp(cls, v: datetime) -> datetime:
        if v.tzinfo is None:  # naive timestamps are assumed to already be UTC
            v = v.replace(tzinfo=timezone.utc)
        v = v.astimezone(timezone.utc)
        if v > utcnow() + MAX_FUTURE_SKEW:
            raise ValueError("timestamp is more than 10 minutes in the future")
        return v

    @field_validator("dns_name")
    @classmethod
    def _normalise_dns(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.lower().rstrip(".")
        if not v:
            raise ValueError("dns_name is empty")
        if re.search(r"\s", v):
            raise ValueError("dns_name must not contain whitespace")
        if ".." in v or v.startswith("."):
            raise ValueError("dns_name has an empty label")
        return v

    @field_validator("http_method")
    @classmethod
    def _normalise_method(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not _METHOD_RE.match(v):
            raise ValueError("http_method must be 3-10 letters")
        return v.upper()

    @field_validator("http_path", mode="before")
    @classmethod
    def _redact_query_string(cls, v: Any) -> Any:
        """Drop ?query and #fragment (they can carry tokens or credentials)."""
        if isinstance(v, str):
            for sep in ("?", "#"):
                i = v.find(sep)
                if i != -1:
                    v = v[:i]
            v = v.strip()
            if v and not v.startswith("/"):
                raise ValueError("http_path must start with '/'")
        return v

    @field_validator("source", "username", "dns_name", "http_path", "user_agent", "protocol")
    @classmethod
    def _no_control_chars(cls, v: str | None) -> str | None:
        if v is not None and _CONTROL_CHARS.search(v):
            raise ValueError("control characters are not allowed")
        return v

    @field_validator("source")
    @classmethod
    def _source_charset(cls, v: str) -> str:
        if not _SOURCE_RE.match(v):
            raise ValueError("source may only contain letters, digits and . _ : -")
        return v

    @field_validator("details")
    @classmethod
    def _validate_details(cls, v: dict | None) -> dict | None:
        if v is None:
            return None
        if len(v) > MAX_DETAILS_KEYS:
            raise ValueError(f"details may have at most {MAX_DETAILS_KEYS} keys")
        for key, val in v.items():
            if len(key) > MAX_DETAILS_KEY_LEN or _CONTROL_CHARS.search(key):
                raise ValueError(f"invalid details key: {key[:30]!r}")
            if _looks_like_payload_field(key):
                raise ValueError(
                    f"details key {key!r} looks like payload or credential data; metadata only"
                )
            if isinstance(val, str):
                if len(val) > MAX_DETAILS_VALUE_LEN:
                    raise ValueError(f"details value for {key!r} is longer than {MAX_DETAILS_VALUE_LEN}")
                if _CONTROL_CHARS.search(val):
                    raise ValueError(f"details value for {key!r} has control characters")
        return v

    # -- type-specific required / allowed fields -----------------------------
    @model_validator(mode="after")
    def _check_type_fields(self) -> "EventIn":
        required = _TYPE_REQUIRED[self.type]
        allowed = required | _TYPE_OPTIONAL[self.type]
        missing = sorted(f for f in required if getattr(self, f) is None)
        if missing:
            raise ValueError(f"{self.type} events require: {', '.join(missing)}")
        unexpected = sorted(
            f for f in _TYPE_SPECIFIC_FIELDS - allowed if getattr(self, f) is not None
        )
        if unexpected:
            raise ValueError(f"{self.type} events must not include: {', '.join(unexpected)}")
        if self.type == "network_connection" and self.protocol is None:
            self.protocol = "tcp"
        return self


class Event(EventIn):
    """A stored event."""

    id: int
    received_at: datetime


class EventBatch(BaseModel):
    """Optional wrapper for batch ingestion: {"events": [...]}."""

    model_config = ConfigDict(extra="forbid")
    events: list[EventIn] = Field(min_length=1, max_length=MAX_BATCH_SIZE)


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------
class AlertIn(BaseModel):
    """What the detection engine hands to storage."""

    model_config = ConfigDict(extra="forbid")

    rule: str
    severity: Severity
    title: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_TITLE_LEN)]
    src_ip: str | None = None
    evidence_event_ids: list[Annotated[int, Field(ge=1)]] = Field(default_factory=list, max_length=5000)
    explanation: dict[str, Any] = Field(default_factory=dict)

    @field_validator("rule")
    @classmethod
    def _rule_name(cls, v: str) -> str:
        if not _RULE_RE.match(v):
            raise ValueError("rule must be lowercase letters, digits and underscores, starting with a letter")
        return v

    @field_validator("title")
    @classmethod
    def _title_clean(cls, v: str) -> str:
        if _CONTROL_CHARS.search(v):
            raise ValueError("control characters are not allowed")
        return v

    @field_validator("src_ip")
    @classmethod
    def _valid_ip(cls, v: str | None) -> str | None:
        return None if v is None else _check_ip(v)

    @field_validator("explanation")
    @classmethod
    def _explanation_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        try:
            size = len(json.dumps(v).encode())
        except (TypeError, ValueError) as exc:
            raise ValueError("explanation must be JSON-serialisable") from exc
        if size > MAX_EXPLANATION_BYTES:
            raise ValueError(f"explanation is larger than {MAX_EXPLANATION_BYTES} bytes")
        return v


class Alert(AlertIn):
    """A stored alert. ``count`` = number of triggering events seen so far."""

    id: int
    created_at: datetime
    updated_at: datetime
    status: AlertStatus = "new"
    count: int = 1


class AlertDetail(Alert):
    """Response of GET /api/alerts/{id}: the alert plus its evidence events.

    Events already removed by retention are silently absent, so ``evidence`` can be
    shorter than ``evidence_event_ids``.
    """

    evidence: list[Event] = Field(default_factory=list)


class AlertUpdate(BaseModel):
    """Body of PATCH /api/alerts/{id}."""

    model_config = ConfigDict(extra="forbid")
    status: AlertStatus


# --------------------------------------------------------------------------
# Stats (response of GET /api/stats)
# --------------------------------------------------------------------------
class TopSource(BaseModel):
    src_ip: str
    count: int


class Stats(BaseModel):
    events_today: int
    events_total: int
    alerts_total: int
    open_alerts: int
    alerts_by_severity: dict[str, int]
    alerts_by_status: dict[str, int]
    top_source_ips: list[TopSource]


# --------------------------------------------------------------------------
# Users and login (dashboard accounts; sensors use the API key instead)
# --------------------------------------------------------------------------
Role = Literal["admin", "analyst"]
UserStatus = Literal["active", "disabled"]
ROLES: tuple[str, ...] = get_args(Role)

MIN_PASSWORD_LEN = 12
MAX_PASSWORD_LEN = 128  # argon2 handles long inputs, but unbounded input is a cheap DoS lever

# Permissions are DERIVED from the role on the server and never read from a request body.
_ANALYST_PERMISSIONS = ("alerts:read", "alerts:update", "events:read", "stats:read")
ROLE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "analyst": _ANALYST_PERMISSIONS,
    "admin": _ANALYST_PERMISSIONS + ("users:manage",),
}

Username = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._@-]+$"),
]
NewPassword = Annotated[str, StringConstraints(min_length=MIN_PASSWORD_LEN, max_length=MAX_PASSWORD_LEN)]


class LoginRequest(BaseModel):
    """Body of POST /api/token. No length minimum here: login must never reveal the password policy."""

    model_config = ConfigDict(extra="forbid")
    username: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    password: Annotated[str, StringConstraints(min_length=1, max_length=1024)]


class UserProfile(BaseModel):
    """What the dashboard sees of a user. Field names match frontend/src/types/auth.ts
    (note ``lastLogin`` is camelCase on the wire)."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    username: str
    role: Role
    permissions: list[str]
    status: UserStatus
    last_login: datetime | None = Field(default=None, serialization_alias="lastLogin")


class AuthResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    user: UserProfile


class UserCreate(BaseModel):
    """POST /api/users. Unknown fields (the dashboard also sends ``permissions``) are ignored."""

    model_config = ConfigDict(extra="ignore")
    username: Username
    password: NewPassword
    role: Role = "analyst"
    status: UserStatus = "active"


class UserUpdate(BaseModel):
    """PATCH /api/users/{id}. Every field optional. Unknown fields (``id``, ``permissions``,
    ``lastLogin`` ...) are ignored, so a client cannot grant itself permissions."""

    model_config = ConfigDict(extra="ignore")
    username: Username | None = None
    password: NewPassword | None = None
    role: Role | None = None
    status: UserStatus | None = None


class UserStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: UserStatus


# --------------------------------------------------------------------------
# Blocklist (record only: nothing enforces it yet)
# --------------------------------------------------------------------------
def canonical_ip(value: str) -> str:
    """Validate an IPv4/IPv6 address and return its canonical text form."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise ValueError(f"not a valid IP address: {value!r}") from None


class BlockRequest(BaseModel):
    """POST /api/blocklist."""

    model_config = ConfigDict(extra="forbid")
    ip: str
    alert_id: int | None = Field(default=None, ge=1)
    reason: Annotated[str, StringConstraints(strip_whitespace=True, max_length=200)] | None = None

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        return canonical_ip(value)


class BlockedIp(BaseModel):
    """Mirrors BlockedIp in frontend/src/lib/types.ts (``blocked_by`` is an addition)."""

    ip: str
    alert_id: int | None = None
    reason: str | None = None
    blocked_at: datetime
    blocked_by: str
