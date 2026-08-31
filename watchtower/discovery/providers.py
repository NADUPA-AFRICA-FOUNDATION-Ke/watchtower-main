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
from urllib.parse import quote, urlsplit

import httpx

from investigation.models import Entity, Evidence, Relationship
from investigation.extraction import extract_entities
from investigation.normalization import normalize_domain, normalize_url

from .base import DiscoveryContext, DiscoveryProvider, ProviderRun, SourceHealth, utcnow
from .cache import ProviderCache


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
                timeout=15, follow_redirects=False,
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
        await self._throttle()
        response = await self.client.request(method, url, **kwargs)
        response.raise_for_status()
        return response.json()


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

    def capabilities(self):
        return ("social_web_index", "tiktok", "facebook", "instagram",
                "telegram", "whatsapp", "x", "youtube")

    async def discover(self, context):
        attempted = utcnow()
        run = ProviderRun(SourceHealth(
            self.name, "web_index_only", tuple(self.capabilities()),
            detail="Public search indexing only; direct platform crawling disabled",
            last_attempt=attempted,
        ))
        try:
            per_site = max(2, context.max_results // len(self.SITES))
            for site in self.SITES:
                rows = await self.search_provider._search(
                    f'"{context.brand}" site:{site}', per_site,
                )
                for row in rows:
                    for entity in extract_entities(
                        " ".join((row.get("url", ""), row.get("title", ""),
                                  row.get("summary", ""))), row.get("url", "")
                    ):
                        if entity.entity_type not in {"social_account", "phone_number"}:
                            continue
                        ev = Evidence(context.investigation_id, entity.id, self.name,
                                      "social_index_observation", entity.canonical_value,
                                      row.get("url"), {"site": site}, 0.55)
                        run.entities.append(entity); run.evidence.append(ev)
                        run.relationships.append(Relationship(
                            context.investigation_id, _brand_entity(context).id,
                            entity.id, "mentions", 0.55, ev.id,
                        ))
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
            endpoint = indexes[0]["cdx-api"]
            terms = CertificateTransparencyProvider.terms(context)[:5]
            seen = set()
            for term in terms:
                response = await self.client.get(endpoint, params={
                    "url": f"*.{term}*/*", "output": "json", "filter": "status:200",
                    "collapse": "urlkey", "pageSize": context.max_results,
                })
                response.raise_for_status()
                for line in response.text.splitlines():
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
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
                except Exception:
                    continue
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
        for kind, values in records.items():
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
    def _certificate(domain):
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=7) as raw:
            with context.wrap_socket(raw, server_hostname=domain) as wrapped:
                return wrapped.getpeercert(binary_form=True), wrapped.getpeercert()

    async def enrich(self, entity, context):
        if entity.entity_type != "domain":
            return ProviderRun.unavailable(self, "not_applicable", "Requires a domain")
        attempted = utcnow()
        run = ProviderRun(SourceHealth(self.name, "operational", tuple(self.capabilities()), last_attempt=attempted))
        try:
            der, parsed = await asyncio.to_thread(self._certificate, entity.canonical_value)
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
            response = await self.client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url})
            response.raise_for_status(); data = response.json()
            if data.get("query_status") == "ok":
                matches.append({"provider": "urlhaus", "data": data})
        except Exception as exc:
            errors["urlhaus"] = f"{type(exc).__name__}: {exc}"
        try:
            response = await self.client.post("https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": normalize_domain(url)})
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
                                                  data={"url": url})
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
                    json={"query": "search_ioc", "search_term": lookup})
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
    cache = cache or ProviderCache()
    enabled = lambda key: os.environ.get(key, "true").lower() not in {"0", "false", "no", "off"}
    providers: list[DiscoveryProvider] = []
    web_search = DuckDuckGoProvider(cache)
    if enabled("ENABLE_DUCKDUCKGO"): providers.append(web_search)
    if enabled("ENABLE_SOCIAL_WEB_INDEX"): providers.append(SocialWebIndexProvider(web_search))
    if enabled("ENABLE_CT"): providers.append(CertificateTransparencyProvider(client, cache))
    if enabled("ENABLE_COMMONCRAWL"): providers.append(CommonCrawlProvider(client, cache))
    if enabled("ENABLE_RDAP"): providers.append(RDAPProvider(client, cache))
    if enabled("ENABLE_DNS"): providers.append(DNSProvider(cache))
    if enabled("ENABLE_IP_ASN"): providers.append(IPASNProvider())
    if enabled("ENABLE_TLS"): providers.append(TLSProvider())
    if enabled("ENABLE_URLHAUS"): providers.append(URLhausProvider(client, cache))
    if enabled("ENABLE_THREATFOX"): providers.append(ThreatFoxProvider(client, cache))
    return providers
