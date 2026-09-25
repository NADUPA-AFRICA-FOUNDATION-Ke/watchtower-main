from __future__ import annotations

import asyncio
import base64
import ipaddress
import socket
import time
import urllib.robotparser
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin, urlsplit

import httpx
import httpcore


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
        addresses = sorted({str(row[4][0]) for row in answers})
    else:
        addresses = [str(literal)]
    if not addresses or not all(_public_ip(value) for value in addresses):
        raise UnsafeTarget("target resolves to a non-public address")
    return addresses


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Connect only to addresses validated for the current request.

    httpx normally resolves a hostname inside its transport after the caller's
    validation has completed.  Keeping the validated addresses in this
    network backend removes that DNS-rebinding window while preserving the
    original hostname for HTTPS SNI and certificate verification.
    """

    def __init__(self):
        self._backend = httpcore.AnyIOBackend()
        self._pins: dict[str, tuple[str, ...]] = {}

    def pin(self, host: str, addresses: list[str]) -> None:
        self._pins[host.lower()] = tuple(addresses)

    async def connect_tcp(self, host, port, timeout=None, local_address=None,
                          socket_options=None):
        addresses = self._pins.get(str(host).lower())
        if not addresses:
            raise httpcore.ConnectError("hostname was not pinned after SSRF validation")
        last_error = None
        for address in addresses:
            try:
                return await self._backend.connect_tcp(
                    address, port, timeout, local_address, socket_options
                )
            except Exception as exc:  # try another validated A/AAAA answer
                last_error = exc
        raise httpcore.ConnectError(str(last_error or "all validated addresses failed"))

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise httpcore.ConnectError("unix sockets are not allowed by SafeFetcher")

    async def sleep(self, seconds):
        await self._backend.sleep(seconds)


class _PinnedTransport(httpx.AsyncBaseTransport):
    """httpx transport whose DNS lookups are supplied by SafeFetcher."""

    def __init__(self):
        self.backend = _PinnedNetworkBackend()
        self._transport = httpx.AsyncHTTPTransport(trust_env=False)
        # AsyncHTTPTransport creates a direct AsyncConnectionPool when
        # trust_env=False. Replacing only its backend retains httpx's TLS,
        # HTTP/2 and connection-pool behavior without duplicating internals.
        self._transport._pool._network_backend = self.backend

    def pin(self, host: str, addresses: list[str]) -> None:
        self.backend.pin(host, addresses)

    async def handle_async_request(self, request):
        return await self._transport.handle_async_request(request)

    async def aclose(self):
        await self._transport.aclose()


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
        obey_robots: bool = True,
        delay: float = 0.25,
    ):
        self._owns_client = client is None
        self._pinned_transport = _PinnedTransport() if client is None else None
        self.client = client or httpx.AsyncClient(
            timeout=timeout, follow_redirects=False, trust_env=False,
            transport=self._pinned_transport,
            headers={"User-Agent": user_agent, "Accept": "text/html,text/plain;q=0.8"},
        )
        self.resolver = resolver
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.cache = cache
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self.user_agent = user_agent
        self.obey_robots = obey_robots
        self.delay = delay
        self._robots: dict[str, urllib.robotparser.RobotFileParser] = {}
        self._last_hit: dict[str, float] = {}

    async def close(self):
        if self._owns_client:
            await self.client.aclose()

    async def fetch(self, url: str) -> SafeFetchResult:
        try:
            return await asyncio.wait_for(self._fetch(url), timeout=self.timeout * 2)
        except asyncio.TimeoutError:
            return SafeFetchResult(url, error="total fetch deadline exceeded")

    async def _allowed(self, url: str) -> bool:
        parsed = urlsplit(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in self._robots:
            response = await self._fetch(origin + "/robots.txt", check_robots=False)
            parser = urllib.robotparser.RobotFileParser()
            if response.error or response.status >= 500 or response.status in {401, 403, 429}:
                parser.parse(["User-agent: *", "Disallow: /"])
            elif response.status == 200:
                parser.parse(response.text.splitlines())
            else:
                parser.parse(["User-agent: *", "Allow: /"])
            self._robots[origin] = parser
        return self._robots[origin].can_fetch(self.user_agent, url)

    async def _fetch(self, url: str, check_robots: bool = True) -> SafeFetchResult:
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
            host = parsed.hostname or ""
            addresses = list(await self.resolver(host))
            if not addresses or not all(_public_ip(address) for address in addresses):
                raise UnsafeTarget("target resolves to a non-public address")
            if self._pinned_transport:
                self._pinned_transport.pin(host, addresses)
            if check_robots and self.obey_robots and not await self._allowed(url):
                return SafeFetchResult(requested, url, error="blocked by robots.txt or robots unavailable")
            wait = self.delay - (time.monotonic() - self._last_hit.get(host, 0))
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_hit[host] = time.monotonic()
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
                               if k.lower() in {"content-type", "server", "location", "via", "strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options"}}
                    result = SafeFetchResult(requested, url, response.status_code, ctype,
                                             bytes(body), chain, headers)
                    if self.cache and 200 <= response.status_code < 300:
                        payload = result.__dict__.copy()
                        payload["body"] = base64.b64encode(result.body).decode()
                        self.cache.put("safe_page", requested, payload, self.cache_ttl)
                    return result
            except httpx.HTTPError as exc:
                return SafeFetchResult(requested, url, redirect_chain=chain,
                                       error=f"{type(exc).__name__}: {exc}")
        return SafeFetchResult(requested, url, redirect_chain=chain,
                               error="redirect limit exceeded")


class PublicAPITransport(_PinnedTransport):
    """Validate and pin every public API destination, including redirected requests."""

    async def handle_async_request(self, request):
        if request.url.scheme not in {'http', 'https'} or request.url.userinfo:
            raise UnsafeTarget('invalid public API URL')
        addresses = await asyncio.wait_for(resolve_public(request.url.host), timeout=10)
        self.pin(request.url.host, addresses)
        response = await super().handle_async_request(request)
        response.stream = BoundedStream(response.stream, 4_000_000)
        return response


class BoundedStream(httpx.AsyncByteStream):
    def __init__(self, stream, limit):
        self.stream, self.limit = stream, limit

    async def __aiter__(self):
        size = 0
        async for chunk in self.stream:
            size += len(chunk)
            if size > self.limit:
                raise httpx.ReadError('public API response exceeds size limit')
            yield chunk

    async def aclose(self):
        await self.stream.aclose()
