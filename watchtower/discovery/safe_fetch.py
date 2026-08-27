from __future__ import annotations

import asyncio
import base64
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin, urlsplit

import httpx


ALLOWED_TYPES = {
    "text/html", "application/xhtml+xml", "text/plain",
    "application/json", "application/xml", "text/xml",
    "image/png", "image/jpeg", "image/gif", "image/x-icon",
    "image/vnd.microsoft.icon", "image/svg+xml",
}


class UnsafeTarget(ValueError):
    pass


@dataclass
class SafeFetchResult:
    requested_url: str
    final_url: str = ""
    status: int = 0
    content_type: str = ""
    body: bytes = b""
    redirect_chain: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    error: str = ""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def _public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    return not any((address.is_private, address.is_loopback, address.is_link_local,
                    address.is_reserved, address.is_multicast, address.is_unspecified))


async def resolve_public(host: str) -> list[str]:
    """Resolve all A/AAAA answers and reject mixed public/private sets."""
    if not host or host.lower() in {"localhost", "localhost.localdomain"}:
        raise UnsafeTarget("localhost is not fetchable")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            answers = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise UnsafeTarget(f"DNS resolution failed: {exc}") from exc
        addresses = sorted({row[4][0] for row in answers})
    else:
        addresses = [str(literal)]
    if not addresses or not all(_public_ip(value) for value in addresses):
        raise UnsafeTarget("target resolves to a non-public address")
    return addresses


class SafeFetcher:
    """Bounded HTTP fetcher that validates every redirect destination."""

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        resolver: Callable = resolve_public,
        max_bytes: int = 2_000_000,
        max_redirects: int = 4,
        timeout: float = 15,
        user_agent: str = "Watchtower/1.0 evidence collector",
        cache=None,
        cache_ttl: int = 21600,
    ):
        self._owns_client = client is None
        self.client = client or httpx.AsyncClient(
            timeout=timeout, follow_redirects=False,
            headers={"User-Agent": user_agent, "Accept": "text/html,text/plain;q=0.8"},
        )
        self.resolver = resolver
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.cache = cache
        self.cache_ttl = cache_ttl

    async def close(self):
        if self._owns_client:
            await self.client.aclose()

    async def fetch(self, url: str) -> SafeFetchResult:
        requested = url
        cached = self.cache.get("safe_page", url) if self.cache else None
        if cached:
            cached["body"] = base64.b64decode(cached.get("body", ""))
            return SafeFetchResult(**cached)
        chain = []
        for hop in range(self.max_redirects + 1):
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"}:
                raise UnsafeTarget("only HTTP(S) URLs are fetchable")
            if parsed.username or parsed.password:
                raise UnsafeTarget("credential-bearing URLs are not fetchable")
            await self.resolver(parsed.hostname or "")
            chain.append(url)
            try:
                async with self.client.stream("GET", url) as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        location = response.headers.get("location")
                        if not location:
                            return SafeFetchResult(requested, url, response.status_code,
                                                   redirect_chain=chain,
                                                   error="redirect missing Location")
                        if hop >= self.max_redirects:
                            return SafeFetchResult(requested, url, response.status_code,
                                                   redirect_chain=chain,
                                                   error="redirect limit exceeded")
                        url = urljoin(url, location)
                        continue
                    ctype = response.headers.get("content-type", "").split(";", 1)[0].lower()
                    if ctype and ctype not in ALLOWED_TYPES:
                        return SafeFetchResult(requested, url, response.status_code, ctype,
                                               redirect_chain=chain,
                                               error=f"unsupported content type: {ctype}")
                    declared = response.headers.get("content-length", "")
                    if declared.isdigit() and int(declared) > self.max_bytes:
                        return SafeFetchResult(requested, url, response.status_code, ctype,
                                               redirect_chain=chain,
                                               error="response exceeds size limit")
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > self.max_bytes:
                            return SafeFetchResult(requested, url, response.status_code, ctype,
                                                   redirect_chain=chain,
                                                   error="response exceeds size limit")
                    headers = {k.lower(): v for k, v in response.headers.items()
                               if k.lower() in {"content-type", "server", "location", "via"}}
                    result = SafeFetchResult(requested, url, response.status_code, ctype,
                                             bytes(body), chain, headers)
                    if self.cache:
                        payload = result.__dict__.copy()
                        payload["body"] = base64.b64encode(result.body).decode()
                        self.cache.put("safe_page", requested, payload, self.cache_ttl)
                    return result
            except httpx.HTTPError as exc:
                return SafeFetchResult(requested, url, redirect_chain=chain,
                                       error=f"{type(exc).__name__}: {exc}")
        return SafeFetchResult(requested, url, redirect_chain=chain,
                               error="redirect limit exceeded")
