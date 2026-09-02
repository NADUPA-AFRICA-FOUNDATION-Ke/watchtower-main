from __future__ import annotations

import httpx
import pytest

from core.fetch import Fetcher
from core.sources import (SourceError, SourceSkipped, social_web_index,
                          socialcrawl)


def _fetcher(handler) -> Fetcher:
    return Fetcher("watchtower-test/0.1", delay=0,
                   transport=httpx.MockTransport(handler))


def test_socialcrawl_maps_unified_results(monkeypatch):
    monkeypatch.setenv("SOCIALCRAWL_API_KEY", "sc_test")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-api-key"] == "sc_test"
        assert request.url.params["query"] == "mpesa scam"
        assert request.url.params["lookback_days"] == "7"
        return httpx.Response(200, json={
            "success": True,
            "credits_used": 20,
            "credits_remaining": 80,
            "request_id": "req_1",
            "cached": False,
            "data": {"items": [{
                "id": "123",
                "platform": "tiktok",
                "url": "https://www.tiktok.com/@watch/video/123",
                "text": "Fake M-Pesa promotion",
                "author": {"username": "watch"},
                "engagement": {"likes": 10},
                "computed": {"language": "en"},
                "created_at": "2026-08-20T12:00:00Z",
            }]},
        })

    items = socialcrawl("mpesa scam", _fetcher(handler), hours=168)
    assert len(items) == 1
    assert items[0].source == "socialcrawl:tiktok"
    assert items[0].source_type == "social"
    assert items[0].author == "watch"
    assert items[0].lang == "en"
    assert items[0].raw_meta["credits_used"] == 20
    assert items[0].raw_meta["engagement"] == {"likes": 10}


def test_socialcrawl_requires_key(monkeypatch):
    monkeypatch.delenv("SOCIALCRAWL_API_KEY", raising=False)
    with pytest.raises(SourceSkipped, match="SOCIALCRAWL_API_KEY"):
        socialcrawl("query", _fetcher(lambda request: httpx.Response(500)))


def test_socialcrawl_rejects_bad_payload(monkeypatch):
    monkeypatch.setenv("SOCIALCRAWL_API_KEY", "sc_test")
    fetcher = _fetcher(lambda request: httpx.Response(200, text="not json"))
    with pytest.raises(SourceError, match="not valid JSON"):
        socialcrawl("query", fetcher)


def test_socialcrawl_does_not_retry_a_paid_request(monkeypatch):
    monkeypatch.setenv("SOCIALCRAWL_API_KEY", "sc_test")
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, text="upstream unavailable")

    with pytest.raises(SourceError):
        socialcrawl("query", _fetcher(handler))
    assert calls == 1


def test_socialcrawl_reports_unusable_paid_results(monkeypatch):
    monkeypatch.setenv("SOCIALCRAWL_API_KEY", "sc_test")
    fetcher = _fetcher(lambda request: httpx.Response(200, json={
        "success": True,
        "credits_used": 20,
        "data": {"items": [{"source": "reddit", "title": "missing URL"}]},
    }))
    with pytest.raises(SourceError, match="none had a usable URL"):
        socialcrawl("query", fetcher)


def test_free_social_index_maps_public_platform_results(monkeypatch):
    seen = {}

    def search(query, max_results):
        seen.update(query=query, max_results=max_results)
        return [
            {"title": "M-Pesa scam alert", "url": "https://www.tiktok.com/@watch/1#comments",
             "summary": "Fake M-Pesa offer"},
            {"title": "Duplicate", "url": "http://www.tiktok.com/@watch/1",
             "summary": "same post"},
            {"title": "Unrelated", "url": "https://example.com/page", "summary": ""},
            "malformed row",
        ]

    monkeypatch.setattr("osint_discovery.search_duckduckgo", search)
    items = social_web_index("M-Pesa scam", _fetcher(lambda request: httpx.Response(500)))
    assert len(items) == 1
    assert items[0].source == "social_web_index"
    assert items[0].raw_meta["platform"] == "tiktok.com"
    assert items[0].url == "https://www.tiktok.com/@watch/1"
    assert "OR M-Pesa scam" in seen["query"]
    assert seen["max_results"] == 20


def test_free_social_index_validates_query_and_surfaces_provider_errors(monkeypatch):
    with pytest.raises(SourceError, match="at least 2 characters"):
        social_web_index(" ", _fetcher(lambda request: httpx.Response(500)))

    monkeypatch.setattr(
        "osint_discovery.search_duckduckgo",
        lambda query, max_results: (_ for _ in ()).throw(RuntimeError("rate limited")),
    )
    with pytest.raises(SourceError, match="free social index search failed: rate limited"):
        social_web_index("watch tower", _fetcher(lambda request: httpx.Response(500)))


def test_socialcrawl_surfaces_402_credit_details(monkeypatch):
    monkeypatch.setenv("SOCIALCRAWL_API_KEY", "sc_test")
    fetcher = _fetcher(lambda request: httpx.Response(402, json={
        "success": False,
        "error": {
            "type": "INSUFFICIENT_CREDITS",
            "message": "Your account has 0 credits remaining. This endpoint requires 20 credits.",
            "status": 402,
        },
        "credits_used": 0,
        "credits_remaining": 0,
        "request_id": "req-test",
    }))
    with pytest.raises(SourceError) as caught:
        socialcrawl("query", fetcher)
    message = str(caught.value)
    assert "0 credits remaining" in message
    assert "requires 20 credits" in message
    assert "credits used: 0" in message
