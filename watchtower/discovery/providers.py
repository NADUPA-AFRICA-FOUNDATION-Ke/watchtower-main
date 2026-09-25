from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

import httpx

from investigation.models import Entity, Evidence, Relationship
from investigation.extraction import extract_entities
from investigation.normalization import normalize_domain, normalize_url

from .base import DiscoveryContext, DiscoveryProvider, ProviderRun, SourceHealth, utcnow
from .cache import ProviderCache
from .safe_fetch import PublicAPITransport, resolve_public


def _brand_entity(context: DiscoveryContext) -> Entity:
    return Entity("brand", context.brand.strip().lower(), context.brand)


def _domain_result(
    provider: DiscoveryProvider,
    context: DiscoveryContext,
    domain: str,
    source_url: str,
    metadata: dict[str, Any] | None = None,
    confidence: float = 0.7,
) -> tuple[Entity, Evidence, Relationship] | None:
    domain = normalize_domain(domain)
    if not domain or domain in context.official_domains:
        return None
    entity = Entity("domain", domain, domain, metadata={"discovered_by": provider.name})
    evidence = Evidence(
        context.investigation_id, entity.id, provider.name, "discovery",
        domain, source_url, metadata or {}, confidence,
    )
    relation = Relationship(
        context.investigation_id, _brand_entity(context).id, entity.id,
        "mentions", confidence, evidence.id,
    )
    return entity, evidence, relation


def _finish(provider: DiscoveryProvider, run: ProviderRun) -> ProviderRun:
    if run.health.results is None:
        run.health.results = len(run.entities)
    run.health.last_attempt = run.health.last_attempt or utcnow()
    if run.health.status == "operational":
        run.health.last_success = utcnow()
    return run


class HttpProvider(DiscoveryProvider):
    def __init__(self, client: httpx.AsyncClient | None = None, cache=None):
        self._client = client
        self._owns_client = client is None
        self.cache = cache or ProviderCache()
        self._request_lock: asyncio.Lock | None = None
        self._last_request = 0.0
        self.min_interval = 0.5

    @property
    def client(self):
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=15, follow_redirects=False, trust_env=False,
                transport=PublicAPITransport(), max_redirects=4,
                headers={"User-Agent": os.environ.get(
                    "WATCHTOWER_USER_AGENT", "Watchtower/1.0 OSINT (contact: "
                    + os.environ.get("WATCHTOWER_CONTACT", "unset") + ")"
                )},
            )
        return self._client

    async def close(self):
        if self._owns_client and self._client is not None:
            await self._client.aclose()

    async def _throttle(self):
        if self._request_lock is None:
            self._request_lock = asyncio.Lock()
        async with self._request_lock:
            wait = self.min_interval - (time.monotonic() - self._last_request)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()

    async def _json(self, method: str, url: str, **kwargs):
        """Fetch JSON with bounded retries for safe/idempotent requests.

        Discovery endpoints are public and occasionally return a transient 5xx
        or 429.  Retry GETs only; POST-backed threat lookups are deliberately
        left to their callers so a paid or stateful request is never replayed.
        """
        attempts = 2 if method.upper() in {"GET", "HEAD"} else 1
        for attempt in range(attempts):
            try:
                await self._throttle()
                response = await self.client.request(method, url, **kwargs)
                if response.status_code in {408, 425, 429, 500, 502, 503, 504} and attempt + 1 < attempts:
                    retry_after = response.headers.get("retry-after", "")
                    try:
                        delay = min(2.0, max(0.1, float(retry_after)))
                    except ValueError:
                        delay = 0.25 * (attempt + 1)
                    await asyncio.sleep(delay)
                    continue
                response.raise_for_status()
                return response.json()
            except (httpx.TimeoutException, httpx.NetworkError):
                if attempt + 1 >= attempts:
                    raise
                await asyncio.sleep(0.25 * (attempt + 1))
        raise RuntimeError("request retry loop exhausted")


class DuckDuckGoProvider(DiscoveryProvider):
    name = "duckduckgo"
    # Default public deployment domains documented by their respective hosts.
    # These are searched explicitly because ordinary brand queries strongly
    # favour established news/official domains and routinely omit small,
    # recently-created impersonation pages.
    HOSTING_GROUPS = (
        ("vercel.app", "netlify.app", "lovable.app"),
        ("pages.dev", "web.app", "firebaseapp.com", "github.io"),
    )

    def __init__(self, cache=None):
        self.cache = cache or ProviderCache()
        self._lock: asyncio.Lock | None = None
        self._last_request = 0.0

    async def _search(self, query, limit):
        import osint_discovery
        # Version the key so empty results cached by the retired
        # ``duckduckgo-search`` package cannot suppress the replacement client.
        key = f"ddgs-v2|{query}|{limit}"
        cached = self.cache.get(self.name, key)
        if cached is not None:
            return cached
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            wait = 1.0 - (time.monotonic() - self._last_request)
            if wait > 0: await asyncio.sleep(wait)
            rows = await asyncio.to_thread(osint_discovery.search_duckduckgo, query, limit)
            self._last_request = time.monotonic()
        # An empty unauthenticated-search response is commonly a transient
        # backend block, not a durable fact. Caching it made investigations
        # return nothing for six hours after one bad response.
        if rows:
            self.cache.put(self.name, key, rows, 21600)
        return rows

    def capabilities(self):
        return ("open_web", "social_web_index")

    async def discover(self, context):
        attempted = utcnow()
        try:
            # Search hosted deployment domains first so a full page of generic
            # news results cannot consume max_results before these candidates
            # are even queried. One grouped query per hosting family keeps the
            # extra latency bounded under the provider's one-request/second
            # throttle.
            hosted = [
                f'"{context.brand}" (' + " OR ".join(
                    f"site:{host}" for host in hosts) + ")"
                for hosts in self.HOSTING_GROUPS
            ]
            hosted_filters = dict(zip(hosted, self.HOSTING_GROUPS))
            brand_terms = {
                re.sub(r"[^a-z0-9]", "", str(term).lower())
                for term in (context.brand, *context.aliases)
                if len(re.sub(r"[^a-z0-9]", "", str(term).lower())) >= 4
            }
            queries = list(dict.fromkeys([
                *hosted,
                f'"{context.brand}" scam OR fraud OR fake',
                f'"{context.brand}" loan WhatsApp',
                context.query,
            ]))
            rows = []
            seen_urls = set()
            for query in queries:
                per_query = (max(3, min(8, (context.max_results + 1) // 2))
                             if query in hosted
                             else max(5, min(context.max_results, 12)))
                for row in await self._search(query, per_query):
                    url = row.get("url", "")
                    if not url or url in seen_urls:
                        continue
                    if query in hosted_filters:
                        row_host = (urlsplit(url).hostname or "").lower()
                        if not any(row_host == suffix or row_host.endswith("." + suffix)
                                   for suffix in hosted_filters[query]):
                            continue
                        searchable = re.sub(
                            r"[^a-z0-9]", "",
                            " ".join((url, row.get("title", ""),
                                      row.get("summary", ""))).lower(),
                        )
                        if brand_terms and not any(term in searchable
                                                   for term in brand_terms):
                            continue
                    seen_urls.add(url)
                    rows.append(row)
                # Always run both hosting families. After that, stop once the
                # requested candidate budget is full.
                if len(rows) >= context.max_results and query not in hosted:
                    break
        except Exception as exc:
            return ProviderRun(SourceHealth(
                self.name, "provider_error", tuple(self.capabilities()),
                last_attempt=attempted, error=f"{type(exc).__name__}: {exc}",
            ))
        run = ProviderRun(SourceHealth(
            self.name, "operational" if rows else "limited",
            tuple(self.capabilities()), last_attempt=attempted,
            detail=("Public index returned no rows; unauthenticated search can "
                    "be transient and this is not clean coverage") if not rows else "",
        ))
        for row in rows[:context.max_results]:
            item = _domain_result(
                self, context, row.get("url", ""), row.get("url", ""),
                {"title": row.get("title", ""), "snippet": row.get("summary", "")},
                0.55,
            )
            if item:
                run.entities.append(item[0]); run.evidence.append(item[1]); run.relationships.append(item[2])
        return _finish(self, run)


class SocialWebIndexProvider(DiscoveryProvider):
    """Discover public social URLs through web indexing; never bypass platform controls."""
    name = "social_web_index"
    SITES = (
        "tiktok.com", "facebook.com", "instagram.com", "t.me",
        "wa.me", "x.com", "youtube.com",
    )

    def __init__(self, search_provider=None):
        self.search_provider = search_provider or DuckDuckGoProvider()

    # These are deliberately phrased as the bait a scammer publishes, rather
    # than generic words such as "loan". They keep the free index focused on
    # the same credential, payment, urgency and Kiswahili signals used by the
    # local scoring lexicon.
    DEFAULT_TERMS = (
        "limit increase", "processing fee", "activation fee",
        "guaranteed approval", "instant", "send your pin", "share your pin",
        "enter your pin", "otp", "namba ya siri", "pin ya mpesa",
        "ongeza fuliza", "lipa kwanza", "tuma pesa", "kwa hii namba",
    )
    FALLBACK_SITES = {"t.me", "facebook.com", "tiktok.com"}

    def capabilities(self):
        return ("social_web_index", "tiktok", "facebook", "instagram",
                "telegram", "whatsapp", "x", "youtube")

    @classmethod
    def _query_terms(cls, context: DiscoveryContext) -> list[str]:
        """Combine configured, sourced terms with a small safe fallback set."""
        terms = [*context.lexicon_terms, *cls.DEFAULT_TERMS]
        out, seen = [], set()
        for raw in terms:
            term = " ".join(str(raw or "").split()).strip().lower()
            if len(term) < 3 or term in seen or '"' in term:
                continue
            seen.add(term)
            out.append(term)
        return out[:16]

    @staticmethod
    def _brand_terms(context: DiscoveryContext) -> list[str]:
        terms = [context.brand, *context.aliases]
        out, seen = [], set()
        for raw in terms:
            term = " ".join(str(raw or "").split()).strip()
            key = term.lower()
            if len(term) < 2 or key in seen or '"' in term:
                continue
            seen.add(key)
            out.append(term)
        return out[:4] or [context.brand]

    @staticmethod
    def _normalise_result_url(raw_url: str, site: str) -> str:
        """Return a safe, stable social URL belonging to the requested site."""
        try:
            parsed = urlsplit(str(raw_url or "").strip())
        except ValueError:
            return ""
        host = (parsed.hostname or "").lower().removeprefix("www.")
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return ""
        if not (host == site or host.endswith("." + site)):
            return ""
        path = parsed.path.rstrip("/") or "/"
        return urlunsplit((parsed.scheme, parsed.netloc.lower(), path,
                           parsed.query, ""))

    async def discover(self, context):
        attempted = utcnow()
        run = ProviderRun(SourceHealth(
            self.name, "web_index_only", tuple(self.capabilities()),
            detail="Public search indexing only; direct platform crawling disabled",
            last_attempt=attempted,
        ))
        try:
            per_site = max(3, min(20, context.max_results // len(self.SITES)))
            brands = " OR ".join(f'"{term}"' for term in self._brand_terms(context))
            signals = " OR ".join(f'"{term}"' for term in self._query_terms(context))
            seen_urls: set[str] = set()
            for site in self.SITES:
                query = f"({brands}) ({signals}) site:{site}"
                rows = await self.search_provider._search(query, per_site)
                # A targeted query is intentionally first. If an index does
                # not support grouped OR expressions, retry this site once with
                # a plain brand query so one parser quirk cannot erase its
                # coverage.
                if not rows and site in self.FALLBACK_SITES:
                    query = f'"{context.brand}" site:{site}'
                    rows = await self.search_provider._search(query, per_site)
                for row in rows or []:
                    if not isinstance(row, dict):
                        continue
                    url = self._normalise_result_url(row.get("url", ""), site)
                    if not url or url in seen_urls:
                        continue
                    seen_urls.add(url)
                    title = " ".join(str(row.get("title") or "").split())[:240]
                    snippet = " ".join(str(
                        row.get("summary") or row.get("snippet") or ""
                    ).split())[:2000]
                    platform = {
                        "t.me": "telegram", "wa.me": "whatsapp",
                        "x.com": "x",
                    }.get(site, site.split(".", 1)[0])
                    post = Entity(
                        "social_post", f"{platform}:{url}", title or url,
                        platform, metadata={
                            "url": url, "title": title, "snippet": snippet,
                            "query": query, "site": site,
                        }, confidence=0.55,
                    )
                    run.entities.append(post)
                    post_ev = Evidence(
                        context.investigation_id, post.id, self.name,
                        "social_index_observation", snippet or title or url, url,
                        {"site": site, "query": query, "title": title,
                         "snippet": snippet, "raw_value": snippet or title or url},
                        0.55,
                    )
                    run.evidence.append(post_ev)
                    run.relationships.append(Relationship(
                        context.investigation_id, _brand_entity(context).id,
                        post.id, "mentions", 0.55, post_ev.id,
                    ))
                    extracted = extract_entities(
                        " ".join((url, title, snippet)), url
                    )
                    entity_values = []
                    for entity in extracted:
                        if entity.entity_type not in {"social_account", "phone_number"}:
                            continue
                        entity_values.append(entity.canonical_value)
                        ev = Evidence(
                            context.investigation_id, entity.id, self.name,
                            "social_index_entity", entity.canonical_value, url,
                            {"site": site, "query": query, "title": title,
                             "snippet": snippet}, 0.55,
                        )
                        run.entities.append(entity)
                        run.evidence.append(ev)
                        run.relationships.append(Relationship(
                            context.investigation_id, post.id, entity.id,
                            "links_to", 0.55, ev.id,
                        ))
                    run.social_findings.append({
                        "url": url, "platform": platform, "source": self.name,
                        "title": title, "snippet": snippet, "query": query,
                        "author": str(row.get("author") or "").strip()[:120],
                        "entities": entity_values,
                    })
            run.health.detail = (
                "Lexicon-targeted public index queries; direct platform crawling disabled"
            )
        except Exception as exc:
            run.health.status = "provider_error"
            run.health.error = f"{type(exc).__name__}: {exc}"
        return _finish(self, run)


class BlueskyPublicProvider(HttpProvider):
    """Unauthenticated Bluesky AppView search for public posts.

    This is intentionally separate from the authenticated monitor connector:
    investigations can use the free public endpoint without storing a handle
    or app password.  A server-side policy change is reported as limited rather
    than turning the whole investigation into a false clean result.
    """
    name = "bluesky_public"

    def capabilities(self):
        return ("social_api", "public_social", "bluesky")

    async def discover(self, context):
        attempted = utcnow()
        run = ProviderRun(SourceHealth(
            self.name, "operational", tuple(self.capabilities()), last_attempt=attempted,
        ))
        query = (context.query or context.brand).strip()[:180]
        if not query:
            return ProviderRun.unavailable(self, "limited", "empty query")
        try:
            cache_key = f"search:{query}:{context.max_results}"
            data = self.cache.get(self.name, cache_key)
            if data is None:
                data = await self._json(
                    "GET", "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts",
                    params={"q": query, "limit": min(100, max(1, context.max_results))},
                    timeout=8,
                )
                self.cache.put(self.name, cache_key, data, 900)
            for post in (data or {}).get("posts", [])[:context.max_results]:
                author = post.get("author") or {}
                handle = str(author.get("handle") or "").strip()
                uri = str(post.get("uri") or "")
                text = str((post.get("record") or {}).get("text") or "")
                source_url = str(post.get("url") or "")
                if not source_url and handle and uri:
                    rkey = uri.rsplit("/", 1)[-1]
                    source_url = f"https://bsky.app/profile/{handle}/post/{rkey}"
                if handle:
                    account = Entity("social_account", f"bluesky:{handle.lower()}",
                                     "@" + handle, "bluesky")
                    run.entities.append(account)
                    ev = Evidence(context.investigation_id, account.id, self.name,
                                  "social_post", text[:500], source_url or None,
                                  {"handle": handle, "uri": uri}, 0.7)
                    run.evidence.append(ev)
                    run.relationships.append(Relationship(
                        context.investigation_id, _brand_entity(context).id,
                        account.id, "mentions", 0.7, ev.id,
                    ))
                post_id = uri or source_url
                if post_id:
                    item = Entity("social_post", f"bluesky:{post_id}",
                                  text[:160] or post_id, "bluesky",
                                  metadata={"author": handle, "url": source_url})
                    run.entities.append(item)
                    ev = Evidence(context.investigation_id, item.id, self.name,
                                  "social_post", text[:1000], source_url or None,
                                  {"author": handle, "uri": uri}, 0.65)
                    run.evidence.append(ev)
                    run.relationships.append(Relationship(
                        context.investigation_id, _brand_entity(context).id,
                        item.id, "mentions", 0.65, ev.id,
                    ))
                for extracted in extract_entities(text, source_url):
                    if extracted.entity_type not in {"domain", "phone_number", "email", "social_account"}:
                        continue
                    run.entities.append(extracted)
                    ev = Evidence(context.investigation_id, extracted.id, self.name,
                                  "social_post_entity", extracted.display_value,
                                  source_url or None, {"author": handle}, 0.65)
                    run.evidence.append(ev)
                    run.relationships.append(Relationship(
                        context.investigation_id, item.id if post_id else _brand_entity(context).id,
                        extracted.id, "links_to", 0.65, ev.id,
                    ))
            run.health.results = len(run.entities)
            if not run.entities:
                run.health.status = "limited"
                run.health.detail = "Public AppView returned no matching posts"
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            run.health.status = "rate_limited" if status == 429 else "limited" if status in {401, 403} else "provider_error"
            run.health.error = f"HTTP {status}"
            run.health.detail = "Public AppView search is unavailable or restricted" if status in {401, 403} else ""
        except Exception as exc:
            run.health.status = "provider_error"
            run.health.error = f"{type(exc).__name__}: {exc}"
        return _finish(self, run)


class MastodonPublicProvider(HttpProvider):
    """Best-effort public Mastodon search on a configurable instance."""
    name = "mastodon_public"

    def capabilities(self):
        return ("social_api", "public_social", "mastodon")

    async def discover(self, context):
        attempted = utcnow()
        run = ProviderRun(SourceHealth(
            self.name, "operational", tuple(self.capabilities()), last_attempt=attempted,
        ))
        host = re.sub(r"[^a-z0-9.-]", "", os.environ.get("MASTODON_PUBLIC_HOST", "mastodon.social").lower()).strip(".")
        query = (context.query or context.brand).strip()[:180]
        if not host or not query:
            return ProviderRun.unavailable(self, "limited", "public Mastodon host or query is empty")
        try:
            cache_key = f"search:{host}:{query}:{context.max_results}"
            data = self.cache.get(self.name, cache_key)
            if data is None:
                data = await self._json(
                    "GET", f"https://{host}/api/v2/search",
                    params={"q": query, "type": "statuses", "limit": min(40, max(1, context.max_results))},
                    timeout=8,
                )
                self.cache.put(self.name, cache_key, data, 900)
            statuses = (data or {}).get("statuses", [])
            for status in statuses[:context.max_results]:
                account_data = status.get("account") or {}
                acct = str(account_data.get("acct") or account_data.get("username") or "").strip()
                status_url = str(status.get("url") or "")
                content = re.sub(r"<[^>]+>", " ", str(status.get("content") or ""))
                content = re.sub(r"\s+", " ", content).strip()
                source_id = str(status.get("id") or status_url)
                if acct:
                    account = Entity("social_account", f"mastodon:{acct.lower()}", "@" + acct, "mastodon")
                    run.entities.append(account)
                    ev = Evidence(context.investigation_id, account.id, self.name,
                                  "social_post", content[:500], status_url or None,
                                  {"account": acct, "instance": host}, 0.65)
                    run.evidence.append(ev)
                    run.relationships.append(Relationship(context.investigation_id,
                        _brand_entity(context).id, account.id, "mentions", 0.65, ev.id))
                post = None
                if source_id:
                    post = Entity("social_post", f"mastodon:{source_id}", content[:160] or source_id,
                                  "mastodon", metadata={"account": acct, "url": status_url, "instance": host})
                    run.entities.append(post)
                    ev = Evidence(context.investigation_id, post.id, self.name,
                                  "social_post", content[:1000], status_url or None,
                                  {"account": acct, "instance": host}, 0.6)
                    run.evidence.append(ev)
                    run.relationships.append(Relationship(context.investigation_id,
                        _brand_entity(context).id, post.id, "mentions", 0.6, ev.id))
                for extracted in extract_entities(content, status_url):
                    if extracted.entity_type not in {"domain", "phone_number", "email", "social_account"}:
                        continue
                    run.entities.append(extracted)
                    ev = Evidence(context.investigation_id, extracted.id, self.name,
                                  "social_post_entity", extracted.display_value,
                                  status_url or None, {"account": acct, "instance": host}, 0.6)
                    run.evidence.append(ev)
                    run.relationships.append(Relationship(context.investigation_id,
                        post.id if post else _brand_entity(context).id, extracted.id,
                        "links_to", 0.6, ev.id))
            run.health.results = len(run.entities)
            if not run.entities:
                run.health.status = "limited"
                run.health.detail = "Public Mastodon instance returned no matching statuses"
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            run.health.status = "rate_limited" if status == 429 else "limited" if status in {401, 403, 404} else "provider_error"
            run.health.error = f"HTTP {status}"
            if status in {401, 403, 404}:
                run.health.detail = "This Mastodon instance does not expose public search"
        except Exception as exc:
            run.health.status = "provider_error"
            run.health.error = f"{type(exc).__name__}: {exc}"
        return _finish(self, run)


class CertificateTransparencyProvider(HttpProvider):
    name = "certificate_transparency"

    def capabilities(self):
        return ("domain_discovery", "certificate", "sibling_domains")

    @staticmethod
    def terms(context: DiscoveryContext) -> list[str]:
        values = {re.sub(r"[^a-z0-9]", "", x.lower()) for x in
                  (context.brand, *context.aliases)}
        base = {x for x in values if len(x) >= 4}
        for value in list(base):
            base.update({value + suffix for suffix in
                         ("loan", "help", "care", "promo", "support")})
        return sorted(base)[:12]

    async def discover(self, context):
        attempted = utcnow()
        run = ProviderRun(SourceHealth(
            self.name, "operational", tuple(self.capabilities()), last_attempt=attempted
        ))
        seen_domains = set()
        try:
            for term in self.terms(context):
                key = f"term:{term}"
                rows = self.cache.get(self.name, key)
                if rows is None:
                    try:
                        rows = await self._json(
                            "GET", "https://crt.sh/",
                            params={"q": f"%{term}%", "output": "json"},
                        )
                    except httpx.HTTPStatusError as exc:
                        # crt.sh uses 404 for a valid query with no matching
                        # identities. That is a searched zero, not a broken
                        # provider, and should not poison the full run status.
                        if exc.response.status_code == 404:
                            rows = []
                        else:
                            raise
                    self.cache.put(self.name, key, rows, 30 * 86400)
                for row in rows[:200]:
                    cert_value = str(row.get("min_cert_id") or row.get("id") or
                                     row.get("serial_number") or "")
                    cert = Entity(
                        "certificate", "crtsh:" + cert_value,
                        cert_value, metadata={
                            "issuer": row.get("issuer_name", ""),
                            "first_seen": row.get("entry_timestamp", ""),
                        },
                    )
                    for raw_name in str(row.get("name_value", "")).splitlines():
                        domain = normalize_domain(raw_name.removeprefix("*."))
                        if not domain or domain in seen_domains:
                            continue
                        if not any(t in domain.replace("-", "") for t in self.terms(context)):
                            continue
                        seen_domains.add(domain)
                        item = _domain_result(
                            self, context, domain, "https://crt.sh/",
                            {"certificate": cert.canonical_value,
                             "wildcard": raw_name.startswith("*.")}, 0.8,
                        )
                        if not item:
                            continue
                        run.entities.extend((item[0], cert))
                        run.evidence.append(item[1]); run.relationships.append(item[2])
                        cert_ev = Evidence(
                            context.investigation_id, cert.id, self.name,
                            "certificate_observation", cert.canonical_value,
                            "https://crt.sh/", cert.metadata, 0.95,
                        )
                        run.evidence.append(cert_ev)
                        run.relationships.append(Relationship(
                            context.investigation_id, item[0].id, cert.id,
                            "uses_certificate", 0.95, cert_ev.id,
                        ))
                        if len(seen_domains) >= context.max_results:
                            return _finish(self, run)
        except httpx.HTTPStatusError as exc:
            run.health.status = "rate_limited" if exc.response.status_code == 429 else "provider_error"
            run.health.error = f"HTTP {exc.response.status_code}"
        except Exception as exc:
            run.health.status = "provider_error"
            run.health.error = f"{type(exc).__name__}: {exc}"
        return _finish(self, run)


class CommonCrawlProvider(HttpProvider):
    name = "common_crawl"

    def capabilities(self):
        return ("historical_urls", "open_web")

    async def discover(self, context):
        attempted = utcnow()
        run = ProviderRun(SourceHealth(
            self.name, "operational", tuple(self.capabilities()), last_attempt=attempted
        ))
        try:
            indexes = self.cache.get(self.name, "indexes")
            if indexes is None:
                indexes = await self._json("GET", "https://index.commoncrawl.org/collinfo.json")
                self.cache.put(self.name, "indexes", indexes, 7 * 86400)
            if not isinstance(indexes, list) or not indexes or not indexes[0].get("cdx-api"):
                raise ValueError("Common Crawl index catalog was empty or malformed")
            endpoint = indexes[0]["cdx-api"]
            terms = CertificateTransparencyProvider.terms(context)[:5]
            seen = set()
            for term in terms:
                key = f"cdx:{endpoint}:{term}:{context.max_results}"
                lines = self.cache.get(self.name, key)
                if lines is None:
                    try:
                        data = await self._json("GET", endpoint, params={
                            "url": f"*.{term}*/*", "output": "json", "filter": "status:200",
                            "collapse": "urlkey", "pageSize": min(100, max(1, context.max_results)),
                        })
                        # _json cannot parse NDJSON as one object. Retry with a
                        # bounded text request when the CDX endpoint responds
                        # with newline-delimited records.
                        lines = data if isinstance(data, list) else [data] if isinstance(data, dict) and data.get("url") else []
                    except (json.JSONDecodeError, ValueError):
                        response = await self.client.get(endpoint, params={
                            "url": f"*.{term}*/*", "output": "json", "filter": "status:200",
                            "collapse": "urlkey", "pageSize": min(100, max(1, context.max_results)),
                        })
                        if response.status_code == 404:
                            lines = []
                        else:
                            response.raise_for_status()
                            lines = []
                            for line in response.text.splitlines()[:1000]:
                                try:
                                    row = json.loads(line)
                                except json.JSONDecodeError:
                                    continue
                                if isinstance(row, dict):
                                    lines.append(row)
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 404:
                            lines = []
                        else:
                            raise
                    self.cache.put(self.name, key, lines, 7 * 86400)
                for row in (lines or [])[:1000]:
                    if not isinstance(row, dict):
                        continue
                    url = row.get("url", "")
                    domain = normalize_domain(url)
                    if not domain or domain in seen:
                        continue
                    seen.add(domain)
                    item = _domain_result(
                        self, context, domain, url,
                        {"timestamp": row.get("timestamp"), "mime": row.get("mime")},
                        0.65,
                    )
                    if item:
                        run.entities.append(item[0]); run.evidence.append(item[1]); run.relationships.append(item[2])
                    if len(seen) >= context.max_results:
                        return _finish(self, run)
        except httpx.HTTPStatusError as exc:
            run.health.status = "rate_limited" if exc.response.status_code == 429 else "provider_error"
            run.health.error = f"HTTP {exc.response.status_code}"
        except Exception as exc:
            run.health.status = "provider_error"; run.health.error = f"{type(exc).__name__}: {exc}"
        return _finish(self, run)


class RDAPProvider(HttpProvider):
    name = "rdap"

    def capabilities(self):
        return ("registration", "registrar", "nameserver")

    async def enrich(self, entity, context):
        if entity.entity_type != "domain":
            return ProviderRun.unavailable(self, "not_applicable", "Requires a domain")
        attempted = utcnow()
        run = ProviderRun(SourceHealth(self.name, "operational", tuple(self.capabilities()), last_attempt=attempted))
        domain = entity.canonical_value
        try:
            data = self.cache.get(self.name, domain)
            if data is None:
                response = await self.client.get(f"https://rdap.org/domain/{quote(domain)}", follow_redirects=True)
                response.raise_for_status(); data = response.json()
                self.cache.put(self.name, domain, data, 7 * 86400)
            registrar = ""
            for record in data.get("entities", []):
                if "registrar" in record.get("roles", []):
                    registrar = record.get("handle", "")
            registration = next((e.get("eventDate") for e in data.get("events", [])
                                 if e.get("eventAction") == "registration"), None)
            entity.metadata["rdap"] = {
                "registrar": registrar, "registration_date": registration,
                "expiry": next((e.get("eventDate") for e in data.get("events", [])
                                if e.get("eventAction") == "expiration"), None),
                "status": data.get("status", []),
            }
            ev = Evidence(context.investigation_id, entity.id, self.name,
                          "rdap_observation", domain, f"https://rdap.org/domain/{domain}",
                          entity.metadata["rdap"], 0.9)
            run.entities.append(entity); run.evidence.append(ev)
            for ns_row in data.get("nameservers", []):
                value = normalize_domain(ns_row.get("ldhName", ""))
                if not value:
                    continue
                ns = Entity("nameserver", value, value)
                run.entities.append(ns)
                run.relationships.append(Relationship(context.investigation_id,
                    entity.id, ns.id, "uses_nameserver", 0.95, ev.id))
            if registrar:
                reg = Entity("registrar", registrar.lower(), registrar)
                run.entities.append(reg)
                run.relationships.append(Relationship(context.investigation_id,
                    entity.id, reg.id, "registered_with", 0.9, ev.id))
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                run.health.status = "operational"; run.health.results = 0
                run.health.detail = "RDAP returned no domain record"
            else:
                run.health.status = "provider_error"
                run.health.error = f"HTTP {exc.response.status_code}"
        except Exception as exc:
            run.health.status = "provider_error"; run.health.error = f"{type(exc).__name__}: {exc}"
        return _finish(self, run)


class DNSProvider(DiscoveryProvider):
    name = "dns"

    def __init__(self, cache=None):
        self.cache = cache or ProviderCache()

    def capabilities(self):
        return ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")

    @staticmethod
    def _lookup(domain: str) -> dict[str, list[str]]:
        records: dict[str, list[str]] = {
            k: [] for k in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")
        }
        try:
            import dns.resolver
            for kind in records:
                try:
                    records[kind] = sorted({str(r).rstrip(".") for r in
                                            dns.resolver.resolve(domain, kind, lifetime=5)})
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    continue
                except Exception as exc:
                    records.setdefault("_errors", []).append(f"{kind}:{type(exc).__name__}")
        except ImportError:
            for family, kind in ((socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")):
                try:
                    records[kind] = sorted({str(x[4][0]) for x in
                                            socket.getaddrinfo(domain, None, family)})
                except socket.gaierror:
                    pass
        return records

    async def enrich(self, entity, context):
        if entity.entity_type != "domain":
            return ProviderRun.unavailable(self, "not_applicable", "Requires a domain")
        attempted = utcnow()
        records: dict[str, list[str]] | None = self.cache.get(
            self.name, entity.canonical_value
        )
        if records is None:
            records = await asyncio.to_thread(self._lookup, entity.canonical_value)
            self.cache.put(self.name, entity.canonical_value, records, 900)
        run = ProviderRun(SourceHealth(self.name, "operational", tuple(self.capabilities()),
                                       last_attempt=attempted,
                                       detail="No records returned" if not any(records.values()) else ""))
        entity.metadata["dns"] = records; run.entities.append(entity)
        if records.get("_errors"):
            run.health.status = "degraded" if any(v for k, v in records.items() if k != "_errors") else "provider_error"
            run.health.error = "dns_lookup_incomplete"
        for kind, values in records.items():
            if kind == "_errors":
                continue
            for value in values:
                typ: Any = "ip_address" if kind in {"A", "AAAA"} else "nameserver" if kind == "NS" else "dns_record"
                target = Entity(typ, value.lower(), value, metadata={"record_type": kind})
                ev = Evidence(context.investigation_id, target.id, self.name,
                              "dns_observation", value, None, {"record_type": kind}, 1.0)
                run.entities.append(target); run.evidence.append(ev)
                run.relationships.append(Relationship(context.investigation_id,
                    entity.id, target.id, "resolves_to" if typ == "ip_address" else "uses_dns_record", 1.0, ev.id))
        return _finish(self, run)


class TLSProvider(DiscoveryProvider):
    name = "tls"

    def capabilities(self):
        return ("live_certificate", "certificate_san")

    @staticmethod
    def _certificate(domain, address):
        context = ssl.create_default_context()
        with socket.create_connection((address, 443), timeout=7) as raw:
            with context.wrap_socket(raw, server_hostname=domain) as wrapped:
                return wrapped.getpeercert(binary_form=True), wrapped.getpeercert()

    async def enrich(self, entity, context):
        if entity.entity_type != "domain":
            return ProviderRun.unavailable(self, "not_applicable", "Requires a domain")
        attempted = utcnow()
        run = ProviderRun(SourceHealth(self.name, "operational", tuple(self.capabilities()), last_attempt=attempted))
        try:
            addresses = await resolve_public(entity.canonical_value)
            der, parsed = await asyncio.to_thread(self._certificate, entity.canonical_value, addresses[0])
            digest = hashlib.sha256(der).hexdigest()
            cert = Entity("certificate", "sha256:" + digest, digest,
                          metadata={"sans": [v for k, v in parsed.get("subjectAltName", []) if k == "DNS"],
                                    "not_before": parsed.get("notBefore"), "not_after": parsed.get("notAfter")})
            ev = Evidence(context.investigation_id, cert.id, self.name,
                          "tls_certificate", digest, None, cert.metadata, 1.0)
            run.entities.extend((entity, cert)); run.evidence.append(ev)
            run.relationships.append(Relationship(context.investigation_id,
                entity.id, cert.id, "uses_certificate", 1.0, ev.id))
        except Exception as exc:
            run.health.status = "unavailable"; run.health.error = f"{type(exc).__name__}: {exc}"
        return _finish(self, run)


class AbuseChProvider(HttpProvider):
    """Free URLhaus and ThreatFox lookups; no account or billing required."""
    name = "abuse_ch"

    def capabilities(self):
        return ("urlhaus", "threatfox")

    async def enrich(self, entity, context):
        if entity.entity_type not in {"domain", "url"}:
            return ProviderRun.unavailable(self, "not_applicable", "Requires URL/domain")
        attempted = utcnow()
        run = ProviderRun(SourceHealth(self.name, "operational", tuple(self.capabilities()), last_attempt=attempted))
        value = entity.canonical_value
        url = value if entity.entity_type == "url" else f"https://{value}/"
        matches = []
        errors = {}
        try:
            response = await self.client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers={"Auth-Key": os.environ.get("ABUSECH_AUTH_KEY", "")})
            response.raise_for_status(); data = response.json()
            if data.get("query_status") == "ok":
                matches.append({"provider": "urlhaus", "data": data})
        except Exception as exc:
            errors["urlhaus"] = f"{type(exc).__name__}: {exc}"
        try:
            response = await self.client.post("https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": normalize_domain(url)}, headers={"Auth-Key": os.environ.get("ABUSECH_AUTH_KEY", "")})
            response.raise_for_status(); data = response.json()
            if data.get("query_status") == "ok" and data.get("data"):
                matches.append({"provider": "threatfox", "data": data["data"]})
        except Exception as exc:
            errors["threatfox"] = f"{type(exc).__name__}: {exc}"
        entity.metadata["threat_intelligence"] = {"matches": matches, "errors": errors}
        ev = Evidence(context.investigation_id, entity.id, self.name,
                      "threat_intelligence", value, None,
                      entity.metadata["threat_intelligence"], 1.0 if matches else 0.5)
        run.entities.append(entity); run.evidence.append(ev)
        if len(errors) == 2:
            run.health.status = "provider_error"; run.health.error = json.dumps(errors)
        return _finish(self, run)


class URLhausProvider(HttpProvider):
    name = "urlhaus"

    def capabilities(self):
        return ("urlhaus", "threat_intelligence")

    async def enrich(self, entity, context):
        if entity.entity_type not in {"domain", "url"}:
            return ProviderRun.unavailable(self, "not_applicable", "Requires URL/domain")
        attempted = utcnow(); value = entity.canonical_value
        url = value if entity.entity_type == "url" else f"https://{value}/"
        run = ProviderRun(SourceHealth(self.name, "operational", tuple(self.capabilities()),
                                       last_attempt=attempted))
        try:
            data = self.cache.get(self.name, url)
            if data is None:
                await self._throttle()
                response = await self.client.post("https://urlhaus-api.abuse.ch/v1/url/",
                                                  data={"url": url}, headers={"Auth-Key": os.environ.get("ABUSECH_AUTH_KEY", "")})
                response.raise_for_status(); data = response.json()
                self.cache.put(self.name, url, data, 21600)
            matches = ([{"provider": self.name, "data": data}]
                       if data.get("query_status") == "ok" else [])
            entity.metadata.setdefault("threat_intelligence", {}).setdefault("matches", []).extend(matches)
            ev = Evidence(context.investigation_id, entity.id, self.name,
                          "threat_intelligence", value, None,
                          {"matched": bool(matches), "response": data}, 1.0 if matches else 0.5)
            run.entities.append(entity); run.evidence.append(ev)
            run.health.results = len(matches)
        except Exception as exc:
            run.health.status = "provider_error"; run.health.error = f"{type(exc).__name__}: {exc}"
        return _finish(self, run)


class ThreatFoxProvider(HttpProvider):
    name = "threatfox"

    def capabilities(self):
        return ("threatfox", "threat_intelligence")

    async def enrich(self, entity, context):
        if entity.entity_type not in {"domain", "url"}:
            return ProviderRun.unavailable(self, "not_applicable", "Requires URL/domain")
        attempted = utcnow(); value = entity.canonical_value
        run = ProviderRun(SourceHealth(self.name, "operational", tuple(self.capabilities()),
                                       last_attempt=attempted))
        try:
            lookup = normalize_domain(value)
            data = self.cache.get(self.name, lookup)
            if data is None:
                await self._throttle()
                response = await self.client.post("https://threatfox-api.abuse.ch/api/v1/",
                    json={"query": "search_ioc", "search_term": lookup}, headers={"Auth-Key": os.environ.get("ABUSECH_AUTH_KEY", "")})
                response.raise_for_status(); data = response.json()
                self.cache.put(self.name, lookup, data, 21600)
            matches = ([{"provider": self.name, "data": data.get("data")}]
                       if data.get("query_status") == "ok" and data.get("data") else [])
            entity.metadata.setdefault("threat_intelligence", {}).setdefault("matches", []).extend(matches)
            ev = Evidence(context.investigation_id, entity.id, self.name,
                          "threat_intelligence", value, None,
                          {"matched": bool(matches), "response": data}, 1.0 if matches else 0.5)
            run.entities.append(entity); run.evidence.append(ev)
            run.health.results = len(matches)
        except Exception as exc:
            run.health.status = "provider_error"; run.health.error = f"{type(exc).__name__}: {exc}"
        return _finish(self, run)


class IPASNProvider(DiscoveryProvider):
    """Free Team Cymru DNS ASN lookup; infrastructure context, never a verdict."""
    name = "ip_asn"

    def capabilities(self):
        return ("asn", "network", "organization", "country")

    @staticmethod
    def _lookup(ip: str):
        try:
            import dns.resolver
            address = __import__("ipaddress").ip_address(ip)
            if address.version == 4:
                query = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
            else:
                query = ".".join(reversed(address.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
            row = str(next(iter(dns.resolver.resolve(query, "TXT", lifetime=5)))).strip('"')
            parts = [part.strip() for part in row.split("|")]
            return {"asn": parts[0], "network": parts[1], "country": parts[2],
                    "registry": parts[3], "allocated": parts[4]}
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}

    async def enrich(self, entity, context):
        if entity.entity_type != "ip_address":
            return ProviderRun.unavailable(self, "not_applicable", "Requires an IP")
        attempted = utcnow(); data = await asyncio.to_thread(self._lookup, entity.canonical_value)
        status = "operational" if data.get("asn") else "unavailable"
        run = ProviderRun(SourceHealth(self.name, status, tuple(self.capabilities()),
                                       last_attempt=attempted, error=data.get("error")))
        entity.metadata["ip_asn"] = data; run.entities.append(entity)
        if data.get("asn"):
            asn = Entity("asn", "asn:" + data["asn"], "AS" + data["asn"], metadata=data)
            ev = Evidence(context.investigation_id, asn.id, self.name, "asn_observation",
                          data["asn"], None, data, 0.9)
            run.entities.append(asn); run.evidence.append(ev)
            run.relationships.append(Relationship(context.investigation_id,
                entity.id, asn.id, "belongs_to", 0.9, ev.id))
        return _finish(self, run)


def default_providers(cache: ProviderCache | None = None, client=None):
    """Compatibility factory driven by the authoritative capability catalogue."""
    from watchtower.registry import REGISTRY
    from .factory import build_providers
    definitions = [s for s in REGISTRY.all()
                   if s.surface == "investigation" and s.default
                   and s.phase != "inspection" and s.is_enabled()]
    return build_providers(definitions, cache, client)
