from __future__ import annotations

import time
import threading

import httpx

from core.fetch import Fetcher
from core.models import Item
from core.sources import BACKENDS
from core.sweep import sweep


def test_source_progress_is_emitted_before_slowest_source_finishes(monkeypatch):
    slow_finished = threading.Event()
    progress_saw_slow_finished = []

    def quick(query, fetcher, hours=72, limit=20):
        return []

    def slow(query, fetcher, hours=72, limit=20):
        time.sleep(0.15)
        slow_finished.set()
        return []

    monkeypatch.setitem(BACKENDS, "quick_progress_test", quick)
    monkeypatch.setitem(BACKENDS, "slow_progress_test", slow)
    fetcher = Fetcher(
        "watchtower-test/0.1", delay=0,
        transport=httpx.MockTransport(lambda request: httpx.Response(404)),
    )
    sweep(
        "target", fetcher,
        backends=["quick_progress_test", "slow_progress_test"],
        fetch_bodies=False,
        progress=lambda event: progress_saw_slow_finished.append(
            slow_finished.is_set()) if event.get("name") == "quick_progress_test" else None,
    )
    fetcher.close()

    assert progress_saw_slow_finished == [False]


def test_source_progress_includes_json_safe_provisional_ratings(monkeypatch):
    def source(query, fetcher, hours=72, limit=20):
        return [Item(
            url="https://news.example/result",
            source="preview_test", source_type="news",
            title="Target fraud investigation", text="Target fraud evidence",
        )]

    monkeypatch.setitem(BACKENDS, "preview_test", source)
    events = []
    fetcher = Fetcher(
        "watchtower-test/0.1", delay=0,
        transport=httpx.MockTransport(lambda request: httpx.Response(404)),
    )
    sweep("target fraud", fetcher, backends=["preview_test"],
          fetch_bodies=False, progress=events.append)
    fetcher.close()

    event = next(event for event in events if event.get("name") == "preview_test")
    preview = event["preview"][0]
    assert preview["source"] == "preview_test"
    assert preview["band"] in {"HIGH", "MED", "LOW", "WEAK"}
    assert isinstance(preview["relevance"], int)


def test_paid_backend_finishes_without_unbounding_other_sources(monkeypatch):
    def paid(query, fetcher, hours=72, limit=20):
        time.sleep(0.05)
        return [Item(
            url="https://social.example/post/1",
            source="paid", source_type="social",
            title="target result", text="target result",
        )]

    def unrelated(query, fetcher, hours=72, limit=20):
        time.sleep(0.20)
        return []

    monkeypatch.setitem(BACKENDS, "paid_test", paid)
    monkeypatch.setitem(BACKENDS, "slow_test", unrelated)
    fetcher = Fetcher(
        "watchtower-test/0.1", delay=0,
        transport=httpx.MockTransport(lambda request: httpx.Response(404)),
    )
    started = time.monotonic()
    result = sweep(
        "target", fetcher,
        backends=["paid_test", "slow_test"],
        fetch_bodies=False,
        budget=0.01,
        protected_backends={"paid_test"},
    )
    elapsed = time.monotonic() - started
    fetcher.close()

    assert [item.url for item in result.items] == ["https://social.example/post/1"]
    assert result.per_source["paid_test"] == 1
    assert result.skipped["slow_test"] == "exceeded the sweep time budget"
    assert elapsed < 0.15
