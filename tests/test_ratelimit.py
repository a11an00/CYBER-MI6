from concurrent.futures import ThreadPoolExecutor

from app.ratelimit import SlidingWindowLimiter


class FakeClock:
    """Stands in for time.monotonic so tests never sleep."""

    def __init__(self, start: float = 0.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_allows_up_to_limit_then_blocks():
    limiter = SlidingWindowLimiter(3, 60, clock=FakeClock())
    results = [limiter.allow("1.2.3.4") for _ in range(4)]
    assert results == [True, True, True, False]


def test_allows_again_after_window_passes():
    clock = FakeClock()
    limiter = SlidingWindowLimiter(2, 60, clock=clock)
    assert limiter.allow("ip")
    assert limiter.allow("ip")
    assert not limiter.allow("ip")
    clock.advance(61)
    assert limiter.allow("ip")


def test_keys_are_counted_separately():
    limiter = SlidingWindowLimiter(1, 60, clock=FakeClock())
    assert limiter.allow("a")
    assert not limiter.allow("a")
    assert limiter.allow("b")


def test_old_hits_expire_gradually():
    clock = FakeClock()
    limiter = SlidingWindowLimiter(2, 60, clock=clock)
    limiter.allow("ip")       # t=0
    clock.advance(30)
    limiter.allow("ip")       # t=30
    clock.advance(31)         # t=61: the t=0 hit has expired, the t=30 hit has not
    assert limiter.allow("ip")
    assert not limiter.allow("ip")


def test_concurrent_calls_never_exceed_limit():
    limiter = SlidingWindowLimiter(100, 60, clock=FakeClock())
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: limiter.allow("ip"), range(500)))
    assert results.count(True) == 100


def test_invalid_settings_rejected():
    import pytest

    with pytest.raises(ValueError):
        SlidingWindowLimiter(0, 60)
