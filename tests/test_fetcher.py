from __future__ import annotations

import time

from leakhunt import fetcher


def test_fetch_multiple_preserves_input_order(monkeypatch) -> None:
    delays = {"first": 0.03, "second": 0.01, "third": 0.02}

    def fake_fetch_target(target: str, timeout: int = 10) -> fetcher.FetchResult:
        time.sleep(delays[target])
        return fetcher.FetchResult(source=target, content=f"content:{target}")

    monkeypatch.setattr(fetcher, "fetch_target", fake_fetch_target)

    results = fetcher.fetch_multiple(["first", "second", "third"], threads=3)

    assert [result.source for result in results] == ["first", "second", "third"]
