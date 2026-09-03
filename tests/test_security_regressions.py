"""Regression coverage for the security review findings."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import httpcore
import pytest

from core.models import Item
from core.report import markdown
from core.sweep import SweepResult
from watchtower.discovery.safe_fetch import _PinnedNetworkBackend


def test_public_bind_is_authenticated_but_loopback_is_not():
    import web.app as webapp

    assert webapp._is_loopback_bind("127.0.0.1")
    assert webapp._is_loopback_bind("::1")
    assert not webapp._is_loopback_bind("0.0.0.0")
    request = SimpleNamespace(
        scope={"server": ("0.0.0.0", 8000)},
        client=SimpleNamespace(host="192.0.2.10"),
    )
    assert webapp._request_requires_auth(request)


def test_safe_fetch_network_backend_uses_only_pinned_addresses():
    backend = _PinnedNetworkBackend()
    seen = []

    class FakeBackend:
        async def connect_tcp(
            self, host, port, timeout=None, local_address=None, socket_options=None
        ):
            seen.append(host)
            return object()

        async def sleep(self, seconds):
            return None

    backend._backend = FakeBackend()
    backend.pin("Example.test", ["93.184.216.34"])
    asyncio.run(backend.connect_tcp("example.test", 443))
    assert seen == ["93.184.216.34"]
    with pytest.raises(httpcore.ConnectError):
        asyncio.run(backend.connect_tcp("unvalidated.test", 443))


def test_markdown_report_escapes_provider_content_and_unsafe_urls():
    result = SweepResult(query="brand <script>alert(1)</script>")
    result.items.append(Item(
        url="javascript:alert(1)",
        source="source|<script>",
        source_type="news",
        title="] [click me](javascript:alert(2))",
        text="<img src=x onerror=alert(3)>",
        summary="[unsafe](javascript:alert(4))",
    ))
    output = markdown(result)
    assert "<script>" not in output
    assert "<img" not in output
    assert "](javascript:" not in output
    assert "javascript:alert(1)" not in output  # unsafe destination omitted


def test_frontend_external_links_use_scheme_allowlist():
    source = (Path(__file__).parents[1] / "web/static/app.js").read_text()
    assert "function safeHref(value)" in source
    assert source.count("href = safeHref(") >= 5
