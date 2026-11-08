import pytest
from pydantic import ValidationError

from app.models import AlertIn, AlertUpdate, EventBatch, EventIn, MAX_BATCH_SIZE

BASE = {"type": "network_connection", "timestamp": "2026-10-19T09:15:02Z", "source": "laptop-sensor-1",
        "src_ip": "192.168.1.25", "dst_ip": "192.168.1.1", "dst_port": 445, "protocol": "tcp"}


def make(**over):
    d = {**BASE, **over}
    return EventIn(**{k: v for k, v in d.items() if v is not ...})


def test_handbook_example_is_valid():
    ev = EventIn(**BASE)
    assert ev.timestamp.tzinfo is not None and ev.dst_port == 445


def test_naive_timestamp_assumed_utc_and_converted():
    assert make(timestamp="2026-10-19T09:15:02").timestamp.utcoffset().total_seconds() == 0
    assert make(timestamp="2026-10-19T12:15:02+03:00").timestamp.hour == 9


def test_far_future_timestamp_rejected():
    with pytest.raises(ValidationError, match="future"):
        make(timestamp="2999-01-01T00:00:00Z")


@pytest.mark.parametrize("field,value", [
    ("type", "ping"), ("src_ip", "999.1.1.1"), ("dst_ip", "not-an-ip"), ("dst_port", 0),
    ("dst_port", 70000), ("protocol", "icmp"), ("source", ""), ("source", "bad name!"),
    ("source", "x" * 65),
])
def test_bad_values_rejected(field, value):
    with pytest.raises(ValidationError):
        make(**{field: value})


def test_missing_required_common_fields():
    with pytest.raises(ValidationError):
        make(source=...)
    with pytest.raises(ValidationError):
        make(src_ip=...)


def test_ip_is_normalised():
    assert make(src_ip="2001:0db8:0000:0000:0000:0000:0000:0001").src_ip == "2001:db8::1"


def test_type_specific_required_fields():
    with pytest.raises(ValidationError, match="dst_port"):
        make(dst_port=...)
    with pytest.raises(ValidationError, match="dns_name"):
        EventIn(type="dns_query", source="s", src_ip="1.2.3.4")
    with pytest.raises(ValidationError, match="username"):
        EventIn(type="auth_failure", source="s", src_ip="1.2.3.4")
    with pytest.raises(ValidationError, match="http_method"):
        EventIn(type="http_request", source="s", src_ip="1.2.3.4", http_path="/")


def test_irrelevant_type_fields_rejected():
    with pytest.raises(ValidationError, match="must not include"):
        EventIn(type="dns_query", source="s", src_ip="1.2.3.4", dns_name="a.com", dst_port=53)


def test_protocol_defaults_to_tcp_for_connections():
    assert make(protocol=...).protocol == "tcp"


def test_dns_name_normalised_and_checked():
    ev = EventIn(type="dns_query", source="s", src_ip="1.2.3.4", dns_name="WWW.Example.COM.")
    assert ev.dns_name == "www.example.com"
    for bad in ("a..b.com", ".a.com", "x" * 254, "a b.com", "."):
        with pytest.raises(ValidationError):
            EventIn(type="dns_query", source="s", src_ip="1.2.3.4", dns_name=bad)


def test_long_dns_label_is_accepted_so_the_rule_can_flag_it():
    label = "a" * 90  # longer than the DNS spec's 63: still an event, and exactly what we want to detect
    assert EventIn(type="dns_query", source="s", src_ip="1.2.3.4", dns_name=f"{label}.evil.com")


def test_http_path_query_string_and_fragment_redacted():
    ev = EventIn(type="http_request", source="s", src_ip="1.2.3.4", http_method="post",
                 http_path="/login?token=SECRET&user=a#frag", http_status=401)
    assert ev.http_path == "/login" and ev.http_method == "POST"


def test_http_path_must_start_with_slash_and_be_capped():
    for bad in ("login", "http://evil/x", "/" + "a" * 2048):
        with pytest.raises(ValidationError):
            EventIn(type="http_request", source="s", src_ip="1.2.3.4", http_method="GET", http_path=bad)


def test_http_status_range():
    with pytest.raises(ValidationError):
        EventIn(type="http_request", source="s", src_ip="1.2.3.4", http_method="GET",
                http_path="/", http_status=99)


def test_control_characters_rejected():
    with pytest.raises(ValidationError):
        EventIn(type="auth_failure", source="s", src_ip="1.2.3.4", username="adm\x00in")
    with pytest.raises(ValidationError):
        EventIn(type="http_request", source="s", src_ip="1.2.3.4", http_method="GET", http_path="/a\nb")


def test_user_agent_capped():
    with pytest.raises(ValidationError):
        make(user_agent="x" * 513)


@pytest.mark.parametrize("field", [
    "payload", "body", "request_body", "Set-Cookie", "cookie", "password", "user_password",
    "token", "api_key", "Authorization", "session_id", "packet", "raw", "data", "pcap",
])
def test_payload_like_top_level_fields_rejected_with_clear_message(field):
    with pytest.raises(ValidationError, match="payload or credential"):
        EventIn(**BASE, **{field: "x"})


def test_unknown_harmless_field_rejected_by_extra_forbid():
    with pytest.raises(ValidationError, match="Extra inputs"):
        EventIn(**BASE, colour="blue")


def test_details_rules():
    assert make(details={"iface": "eth0", "ttl": 64, "flag": True}).details["ttl"] == 64
    for bad in (
        {"password": "x"}, {"Request_Body": "x"}, {"k": {"nested": 1}}, {"k": [1, 2]},
        {f"k{i}": 1 for i in range(21)}, {"k": "x" * 257}, {"k" * 65: 1}, {"k": "a\x00b"},
    ):
        with pytest.raises(ValidationError):
            make(details=bad)


def test_batch_size_limits():
    ok = EventIn(**BASE)
    assert len(EventBatch(events=[ok] * MAX_BATCH_SIZE).events) == MAX_BATCH_SIZE
    with pytest.raises(ValidationError):
        EventBatch(events=[ok] * (MAX_BATCH_SIZE + 1))
    with pytest.raises(ValidationError):
        EventBatch(events=[])


# ---- alerts -----------------------------------------------------------------
def test_alert_in_valid_and_rejects_bad_values():
    a = AlertIn(rule="port_scan", severity="high", title="t", src_ip="1.2.3.4",
                evidence_event_ids=[1, 2], explanation={"threshold": 20})
    assert a.rule == "port_scan"
    for kw in ({"rule": "Port Scan"}, {"rule": "1x"}, {"severity": "urgent"}, {"title": ""},
               {"title": "x" * 201}, {"src_ip": "nope"}, {"evidence_event_ids": [0]},
               {"explanation": {"x": object()}}, {"explanation": {"x": "y" * 5000}}):
        base = {"rule": "port_scan", "severity": "low", "title": "t"}
        with pytest.raises(ValidationError):
            AlertIn(**{**base, **kw})


def test_alert_update_only_allows_known_statuses():
    for s in ("new", "investigating", "resolved", "false_positive"):
        assert AlertUpdate(status=s).status == s
    with pytest.raises(ValidationError):
        AlertUpdate(status="closed")
    with pytest.raises(ValidationError):
        AlertUpdate(status="new", severity="low")
