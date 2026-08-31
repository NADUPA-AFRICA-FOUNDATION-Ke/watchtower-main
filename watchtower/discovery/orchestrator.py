from __future__ import annotations

import asyncio
import logging
from collections import Counter, defaultdict, deque
import hashlib
import time
from dataclasses import asdict
from typing import Any, cast

from investigation.models import Entity, Evidence, Relationship
from investigation.normalization import normalize_domain
from investigation.storage import InvestigationStore

from .base import DiscoveryContext, ProviderRun, utcnow
from .page_analysis import analyze_page
from .providers import DuckDuckGoProvider
from .safe_fetch import SafeFetcher, UnsafeTarget
from .scoring import score_domain

log = logging.getLogger(__name__)


EDGE_BY_TYPE = {
    "ip_address": "resolves_to",
    "certificate": "uses_certificate",
    "nameserver": "uses_nameserver",
    "registrar": "registered_with",
    "phone_number": "contains_phone",
    "email": "contains_email",
    "social_account": "links_to_social",
    "payment_identifier": "contains_payment_identifier",
    "analytics_id": "uses_analytics",
    "html_fingerprint": "uses_html_fingerprint",
    "favicon": "uses_favicon",
    "url": "links_to",
}
SHARED_RELATION = {
    "phone_number": "shares_phone",
    "email": "shares_email",
    "social_account": "shares_social_account",
    "certificate": "shares_certificate",
    "nameserver": "shares_nameserver",
    "payment_identifier": "shares_payment_identifier",
    "analytics_id": "shares_analytics",
    "html_fingerprint": "shares_html_fingerprint",
    "favicon": "shares_favicon",
}


class DiscoveryOrchestrator:
    """Free-first evidence graph pipeline with bounded expansion."""

    def __init__(
        self,
        store: InvestigationStore,
        providers,
        fetcher: SafeFetcher | None = None,
        max_domains: int = 40,
        max_fetches: int = 20,
        max_pivot_depth: int = 2,
        max_global_requests: int = 8,
    ):
        self.store = store
        self.providers = list(providers)
        self.fetcher = fetcher or SafeFetcher()
        self.max_domains = max_domains
        self.max_fetches = max_fetches
        self.max_pivot_depth = max_pivot_depth
        self.max_global_requests = max_global_requests
        self.semaphore: asyncio.Semaphore | None = None

    async def _call(self, method, *args) -> ProviderRun:
        if self.semaphore is None:
            self.semaphore = asyncio.Semaphore(self.max_global_requests)
        provider = getattr(getattr(method, "__self__", None), "name", "provider")
        started = time.monotonic()
        async with self.semaphore:
            try:
                run = await method(*args)
            except Exception as exc:
                owner = getattr(method, "__self__", None)
                run = ProviderRun.unavailable(cast(Any, owner), "provider_error",
                                               f"{type(exc).__name__}: {exc}")
        run.health.duration_ms = round((time.monotonic() - started) * 1000)
        log.info("provider_run", extra={
            "provider": provider, "status": run.health.status,
            "duration_ms": run.health.duration_ms,
            "result_count": run.health.results,
        })
        return run

    @staticmethod
    def _merge_entity(target: Entity, incoming: Entity) -> Entity:
        target.metadata.update(incoming.metadata)
        target.confidence = max(target.confidence, incoming.confidence)
        target.last_seen = max(target.last_seen, incoming.last_seen)
        return target

    async def investigate(self, brand: str, query: str | None, brand_config: dict):
        requested = [p.name for p in self.providers]
        iid = self.store.create(brand, query or brand, requested, {
            "zero_key_mode": True,
            "max_domains": self.max_domains,
            "max_fetches": self.max_fetches,
            "max_pivot_depth": self.max_pivot_depth,
        })
        context = DiscoveryContext(
            iid, brand, query or brand,
            tuple(x.lower() for x in brand_config.get("official_domains", [])),
            tuple(brand_config.get("aliases", [])), self.max_domains,
        )
        brand_entity = Entity("brand", brand.strip().lower(), brand,
                              metadata={"official_domains": list(context.official_domains)})
        entities = {brand_entity.id: brand_entity}
        evidence: dict[str, Evidence] = {}
        relationships: dict[str, Relationship] = {}
        health = []

        def absorb(run: ProviderRun):
            health.append(run.health)
            self.store.record_source_run(iid, run.health)
            for entity in run.entities:
                if entity.id in entities:
                    self._merge_entity(entities[entity.id], entity)
                else:
                    entities[entity.id] = entity
            evidence.update({item.id: item for item in run.evidence})
            relationships.update({item.id: item for item in run.relationships})

        discovery = [p for p in self.providers if set(p.capabilities()) &
                     {"open_web", "domain_discovery", "historical_urls", "social_web_index"}]
        runs = await asyncio.gather(*(self._call(p.discover, context) for p in discovery))
        for provider, run in zip(discovery, runs):
            absorb(run)

        domains = [e for e in entities.values() if e.entity_type == "domain"][:self.max_domains]
        # Only domains returned by discovery (and later reverse pivots) are
        # investigation candidates. Domains extracted from fetched page assets
        # such as fonts, analytics and CDNs remain useful graph evidence but
        # must not flood the candidate list or bypass the requested limit.
        candidate_domain_ids = {domain.id for domain in domains}
        enrichers = [p for p in self.providers if set(p.capabilities()) & {
            "registration", "A", "live_certificate", "urlhaus", "threatfox"
        }]
        tasks = [(provider, domain, self._call(provider.enrich, domain, context))
                 for domain in domains for provider in enrichers]
        enriched = await asyncio.gather(*(task[2] for task in tasks))
        for (provider, _, _), run in zip(tasks, enriched):
            absorb(run)

        ip_enrichers = [p for p in self.providers if "asn" in set(p.capabilities())]
        ips = [e for e in entities.values() if e.entity_type == "ip_address"]
        ip_tasks = [(provider, ip, self._call(provider.enrich, ip, context))
                    for ip in ips for provider in ip_enrichers]
        if ip_tasks:
            ip_runs = await asyncio.gather(*(x[2] for x in ip_tasks))
            for (provider, _, _), run in zip(ip_tasks, ip_runs):
                absorb(run)

        # Safe page observations are strong evidence and drive domain -> entity pivots.
        fetch_count = 0
        pivot_queue: deque[tuple[Entity, int]] = deque()
        visited = set()
        for candidate in entities.values():
            if candidate.entity_type in {"social_account", "phone_number", "email"}:
                pivot_queue.append((candidate, 1))
        for domain in domains:
            if fetch_count >= self.max_fetches:
                break
            url = f"https://{domain.canonical_value}/"
            fetch_count += 1
            try:
                fetched = await self.fetcher.fetch(url)
            except UnsafeTarget as exc:
                domain.metadata["page"] = {"error": str(exc), "safe_fetch": "rejected"}
                continue
            page_meta = {
                "status": fetched.status, "content_type": fetched.content_type,
                "redirect_chain": fetched.redirect_chain, "headers": fetched.headers,
                "error": fetched.error,
            }
            if (fetched.body and not fetched.error and
                    (not fetched.content_type or fetched.content_type in
                     {"text/html", "application/xhtml+xml", "text/plain"})):
                page = analyze_page(fetched.text, fetched.final_url or url)
                page_meta.update({
                    "title": page.title, "description": page.description,
                    "visible_text": page.visible_text[:10000],
                    "headings": page.headings, "forms": page.forms,
                    "credential_fields": page.credential_fields,
                    "analytics_ids": page.analytics_ids,
                    "html_fingerprint": page.html_fingerprint,
                    "simhash": page.simhash,
                })
                for child in page.entities:
                    if child.id == domain.id:
                        continue
                    existing = entities.get(child.id)
                    entities[child.id] = self._merge_entity(existing, child) if existing else child
                    ev = Evidence(iid, child.id, "safe_page", "page_observation",
                                  child.display_value, fetched.final_url or url,
                                  {"raw_value": child.display_value,
                                   "normalized_value": child.canonical_value}, 0.95)
                    evidence[ev.id] = ev
                    rel = Relationship(iid, domain.id, child.id,
                                       EDGE_BY_TYPE.get(child.entity_type, "links_to"),
                                       0.95, ev.id)
                    relationships[rel.id] = rel
                    if child.entity_type in {"social_account", "phone_number", "email"}:
                        pivot_queue.append((child, 1))
                if page.favicon_url and fetch_count < self.max_fetches:
                    fetch_count += 1
                    try:
                        favicon_result = await self.fetcher.fetch(page.favicon_url)
                    except UnsafeTarget:
                        favicon_result = None
                    if favicon_result and favicon_result.body and not favicon_result.error:
                        digest = hashlib.sha256(favicon_result.body).hexdigest()
                        favicon = Entity("favicon", "sha256:" + digest, digest,
                                         metadata={"source_url": page.favicon_url})
                        entities.setdefault(favicon.id, favicon)
                        ev = Evidence(iid, favicon.id, "safe_page", "favicon_hash",
                                      digest, page.favicon_url, {}, 1.0)
                        evidence[ev.id] = ev
                        rel = Relationship(iid, domain.id, favicon.id,
                                           "uses_favicon", 1.0, ev.id)
                        relationships[rel.id] = rel
                for destination in fetched.redirect_chain[1:]:
                    target_host = normalize_domain(destination)
                    if not target_host:
                        continue
                    target = Entity("domain", target_host, target_host)
                    entities.setdefault(target.id, target)
                    ev = Evidence(iid, target.id, "safe_page", "redirect_observation",
                                  destination, url, {}, 1.0)
                    evidence[ev.id] = ev
                    rel = Relationship(iid, domain.id, target.id, "redirects_to", 1.0, ev.id)
                    relationships[rel.id] = rel
            domain.metadata["page"] = page_meta

        # Reverse pivots use public indexing only and never crawl a blocked social platform.
        web_provider = next((p for p in discovery if isinstance(p, DuckDuckGoProvider)), None)
        while pivot_queue and web_provider:
            entity, depth = pivot_queue.popleft()
            key = (entity.id, web_provider.name)
            if key in visited or depth > self.max_pivot_depth:
                continue
            visited.add(key)
            value = entity.canonical_value.split(":", 1)[-1]
            pivot_context = DiscoveryContext(
                iid, brand, f'"{value}" "{brand}"', context.official_domains,
                context.aliases, min(10, self.max_domains), depth,
            )
            run = await self._call(web_provider.discover, pivot_context)
            self.store.record_source_run(iid, run.health)
            for target in run.entities:
                if target.entity_type != "domain" or target.id in entities:
                    continue
                entities[target.id] = target
                candidate_domain_ids.add(target.id)
                ev = Evidence(iid, target.id, web_provider.name,
                              "reverse_pivot", target.canonical_value, None,
                              {"pivot_entity": entity.canonical_value}, 0.6)
                evidence[ev.id] = ev
                rel = Relationship(iid, entity.id, target.id, "links_to_domain", 0.6, ev.id)
                relationships[rel.id] = rel

        # Exact high-value identifier reuse creates derived evidence and domain edges.
        owners: defaultdict[str, set[str]] = defaultdict(set)
        for relation in relationships.values():
            source = entities.get(relation.source_entity_id)
            related = entities.get(relation.target_entity_id)
            if source and related and source.entity_type == "domain" and related.entity_type in SHARED_RELATION:
                owners[related.id].add(source.id)
        for shared_id, domain_ids in owners.items():
            ordered = sorted(domain_ids)
            for index, left in enumerate(ordered):
                for right in ordered[index + 1:]:
                    shared = entities[shared_id]
                    ev = Evidence(iid, shared.id, "correlation", SHARED_RELATION[shared.entity_type],
                                  shared.canonical_value, None,
                                  {"source_entity": left, "related_entity": right}, 1.0)
                    evidence[ev.id] = ev
                    rel = Relationship(iid, left, right, SHARED_RELATION[shared.entity_type], 1.0, ev.id)
                    relationships[rel.id] = rel

        # Near-identical page templates become derived evidence. The threshold
        # is intentionally strict; similarity alone never confirms a campaign.
        page_domains: list[Entity] = [
            e for e in entities.values() if e.entity_type == "domain"
            and e.metadata.get("page", {}).get("simhash") is not None
        ]
        for index, left_domain in enumerate(page_domains):
            for right_domain in page_domains[index + 1:]:
                distance = bin(int(left_domain.metadata["page"]["simhash"]) ^
                               int(right_domain.metadata["page"]["simhash"])).count("1")
                if distance > 3:
                    continue
                similarity = round(1 - distance / 64, 3)
                ev = Evidence(iid, left_domain.id, "correlation", "html_similarity",
                              str(similarity), None,
                              {"related_entity": right_domain.id, "hamming_distance": distance},
                              similarity)
                evidence[ev.id] = ev
                rel = Relationship(iid, left_domain.id, right_domain.id, "shares_html_template",
                                   similarity, ev.id)
                relationships[rel.id] = rel

        self.store.persist(iid, list(entities.values()), list(evidence.values()),
                           list(relationships.values()))
        scored = {}
        for domain in [e for e in entities.values() if e.entity_type == "domain"]:
            related_evidence_ids = {r.evidence_id for r in relationships.values()
                                    if domain.id in {r.source_entity_id, r.target_entity_id}}
            domain_evidence = [e for e in evidence.values() if e.entity_id == domain.id
                               or e.id in related_evidence_ids]
            result = score_domain(domain, domain_evidence, list(relationships.values()),
                                  entities, brand_config)
            scored[domain.id] = result.dict(); self.store.save_score(domain.id, result)

        # Campaigns require exact shared identifiers; a shared cloud IP alone is excluded.
        adjacency = defaultdict(set)
        for relation in relationships.values():
            if relation.relationship_type in set(SHARED_RELATION.values()) - {"shares_ip"}:
                adjacency[relation.source_entity_id].add(relation.target_entity_id)
                adjacency[relation.target_entity_id].add(relation.source_entity_id)
        campaigns = []
        seen = set()
        for node in adjacency:
            if node in seen:
                continue
            stack = [node]; component = set()
            while stack:
                current = stack.pop()
                if current in component: continue
                component.add(current); seen.add(current); stack.extend(adjacency[current] - component)
            if len(component) >= 2:
                risk = max((scored.get(x, {}).get("risk_score", 0) for x in component), default=0)
                campaigns.append(self.store.create_campaign(
                    brand, sorted(component), min(100, 40 + 15 * len(component)),
                    "High" if len(component) >= 3 else "Moderate", risk,
                ))

        successful = sorted({h.provider for h in health if h.status == "operational"})
        limited = [h.dict() for h in health if h.status in {"degraded", "limited", "rate_limited"}]
        failed = [h.dict() for h in health if h.status in {"provider_error", "timeout", "network_error"}]
        unavailable = [h.dict() for h in health if h.status in {"unavailable", "disabled", "missing_credentials"}]
        self.store.finish(iid, successful, limited, failed, unavailable,
                          "Searched all configured and currently accessible sources.")
        counts = Counter(e.entity_type for e in entities.values())
        ranked_candidates = [
            {
                "entity_id": domain.id,
                "domain": domain.canonical_value,
                "url": f"https://{domain.canonical_value}/",
                **scored.get(domain.id, {}),
            }
            for domain in entities.values()
            if domain.entity_type == "domain" and domain.id in candidate_domain_ids
            and scored.get(domain.id, {}).get("risk_score", 0) >= 20
        ]
        ranked_candidates.sort(
            key=lambda item: (item.get("risk_score", 0), item.get("confidence", 0)),
            reverse=True,
        )
        response = {
            "id": iid, "brand": brand, "zero_key_mode": True,
            "counts": dict(counts), "campaigns": campaigns,
            "scores": scored,
            "candidates": ranked_candidates[:self.max_domains],
            "filtered_low_signal": max(0, len(candidate_domain_ids) - len(ranked_candidates)),
            "coverage": {
                "configured": len(requested), "attempted": len({h.provider for h in health}),
                "successful": successful, "limited": limited, "failed": failed,
                "unavailable": unavailable,
                "statement": "Searched all configured and currently accessible sources.",
            },
        }
        await asyncio.gather(*(provider.close() for provider in self.providers),
                             return_exceptions=True)
        close_fetcher = getattr(self.fetcher, "close", None)
        if close_fetcher:
            await close_fetcher()
        return response
