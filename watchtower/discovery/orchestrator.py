from __future__ import annotations

import asyncio
import logging
from collections import Counter, defaultdict, deque
import hashlib
import time
from dataclasses import asdict
from typing import Any, cast

from investigation.models import Entity, EntityType, Evidence, Relationship
from investigation.normalization import normalize_domain
from investigation.storage import InvestigationStore
from investigation.correlation import correlate, SHARED_RELATION

from .base import DiscoveryContext, ProviderRun, utcnow
from .page_analysis import analyze_page
from watchtower.engine.adapters import ProviderAdapter, definition_for
from watchtower.engine.coverage import coverage
from watchtower.engine.planner import InvestigationRequest, Plan
from .base import DiscoveryProvider, SourceHealth
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
        max_external_requests: int = 500,
        plan: Plan | None = None,
        request: InvestigationRequest | None = None,
        seeds: list[dict] | None = None,
    ):
        self.seeds = seeds or []
        self.plan = plan
        self.request = request
        self.store = store
        self.providers = list(providers)
        self.fetcher = fetcher or SafeFetcher()
        self.max_domains = max(1, max_domains)
        self.max_fetches = max(0, max_fetches)
        self.max_pivot_depth = max(0, max_pivot_depth)
        self.max_global_requests = max(1, max_global_requests)
        self.max_external_requests = max(1, max_external_requests)
        self.semaphore: asyncio.Semaphore | None = None
        self._budget_lock: asyncio.Lock | None = None
        self._request_count = 0

    async def _call(self, method, *args) -> ProviderRun:
        if self.semaphore is None:
            self.semaphore = asyncio.Semaphore(self.max_global_requests)
        if self._budget_lock is None:
            self._budget_lock = asyncio.Lock()
        provider = getattr(getattr(method, "__self__", None), "name", "provider")
        started = time.monotonic()
        async with self._budget_lock:
            if self._request_count >= self.max_external_requests:
                owner = getattr(method, "__self__", None)
                run = ProviderRun.unavailable(cast(Any, owner), "limited",
                                               "external request budget exhausted")
                run.health.rate_limit = {"budget": self.max_external_requests}
                run.health.duration_ms = 0
                return run
            self._request_count += 1
        async with self.semaphore:
            try:
                owner = getattr(method, "__self__", None)
                if not isinstance(owner, DiscoveryProvider):
                    raise TypeError("source must implement DiscoveryProvider")
                adapter = ProviderAdapter(owner)
                context = args[-1]
                entity = args[0] if len(args) == 2 else None
                result = await adapter.execute(adapter.definition.capabilities[0], context, entity)
                run = result.data
                run.health.rate_limit["envelope"] = result.envelope()
            except Exception as exc:
                owner = getattr(method, "__self__", None)
                run = ProviderRun.unavailable(cast(Any, owner), "provider_error",
                                               type(exc).__name__)
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

    async def investigate(self, brand, query, brand_config, lexicon_terms=()):
        try:
            return await self._investigate(brand, query, brand_config, lexicon_terms)
        finally:
            for provider in self.providers:
                try:
                    await provider.close()
                except Exception as exc:
                    log.warning("provider_close_failed", extra={"source_id": provider.name, "error_code": type(exc).__name__})
            close_fetcher = getattr(self.fetcher, "close", None)
            if close_fetcher:
                await close_fetcher()

    async def _investigate(
        self,
        brand: str,
        query: str | None,
        brand_config: dict,
        lexicon_terms: tuple[str, ...] = (),
    ):
        requested = list(self.plan.requested) if self.plan else [p.name for p in self.providers]
        if self.max_fetches and "safe_page" not in requested:
            requested.append("safe_page")
        iid = self.store.create(brand, query or brand, requested, {
            "zero_key_mode": all(not definition_for(p).missing_credentials() and definition_for(p).access == "no_key" for p in self.providers),
            "max_domains": self.max_domains,
            "max_fetches": self.max_fetches,
            "max_pivot_depth": self.max_pivot_depth,
            "max_external_requests": self.max_external_requests,
        })
        self.investigation_id = iid
        # An orchestrator instance may be reused by a worker. Budgets are per
        # investigation, while the semaphore is only a concurrency guard.
        self._request_count = 0
        self.semaphore = None
        self._budget_lock = None
        context = DiscoveryContext(
            iid, brand, query or brand,
            tuple(x.lower() for x in brand_config.get("official_domains", [])),
            tuple(brand_config.get("aliases", [])), self.max_domains,
            lexicon_terms=tuple(lexicon_terms),
        )
        brand_entity = Entity("brand", brand.strip().lower(), brand,
                              metadata={"official_domains": list(context.official_domains)})
        entities = {brand_entity.id: brand_entity}
        evidence: dict[str, Evidence] = {}
        relationships: dict[str, Relationship] = {}
        health = []
        if self.plan:
            for name in self.plan.missing_credentials:
                health.append(SourceHealth(name, "auth_missing", (), detail="Required credential not configured"))
            for name in self.plan.unavailable:
                health.append(SourceHealth(name, "disabled", (), detail="Source excluded by preflight"))
            for row in health:
                self.store.record_source_run(iid, row)
        social_findings: dict[str, dict[str, Any]] = {}

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
            for finding in run.social_findings:
                if not isinstance(finding, dict):
                    continue
                url = str(finding.get("url") or "").strip()
                if url:
                    # First observation wins so repeated provider rows cannot
                    # overwrite the original query/snippet provenance.
                    social_findings.setdefault(url, dict(finding))

        discovery = [p for p in self.providers if definition_for(p).phase == "discovery"]
        runs = await asyncio.gather(*(self._call(p.discover, context) for p in discovery))
        for provider, run in zip(discovery, runs):
            absorb(run)

        for seed_row in self.seeds[:self.max_domains]:
            seed = Entity(seed_row["entity_type"], seed_row["canonical_value"], seed_row["display_value"])
            entities[seed.id] = seed
            ev = Evidence(iid, seed.id, "user_input", "investigation_seed", seed.canonical_value,
                          raw_metadata={"prior_entity_id": seed_row["id"], "recheck": True}, confidence=0.0)
            evidence[ev.id] = ev
            if seed.entity_type == "ip_address":
                for provider in self.providers:
                    if "ip_address" in definition_for(provider).input_types:
                        absorb(await self._call(provider.enrich, seed, context))

        if self.request and self.request.entity_type in {"domain", "url", "ip_address"}:
            from investigation.normalization import normalize_url
            kind = self.request.entity_type
            value = self.request.brand
            if kind in {"domain", "url"}:
                value = normalize_domain(value)
                kind = "domain"
            seed = Entity(cast(EntityType, kind), value, value)
            entities[seed.id] = seed
            ev = Evidence(iid, seed.id, "user_input", "investigation_seed", value,
                          normalize_url(self.request.brand) if self.request.entity_type == "url" else None,
                          {"unverified_user_input": True}, 0.0)
            evidence[ev.id] = ev
            if kind == "ip_address":
                for provider in self.providers:
                    if "ip_address" in definition_for(provider).input_types:
                        absorb(await self._call(provider.enrich, seed, context))

        domains = [e for e in entities.values() if e.entity_type == "domain"][:self.max_domains]
        # Only domains returned by discovery (and later reverse pivots) are
        # investigation candidates. Domains extracted from fetched page assets
        # such as fonts, analytics and CDNs remain useful graph evidence but
        # must not flood the candidate list or bypass the requested limit.
        candidate_domain_ids = {domain.id for domain in domains}
        enrichers = [p for p in self.providers if definition_for(p).phase == "enrichment"
                     and "domain" in definition_for(p).input_types]
        ip_enrichers = [p for p in self.providers if definition_for(p).phase == "enrichment"
                        and "ip_address" in definition_for(p).input_types]
        fetch_count = 0
        pivot_queue: deque[tuple[Entity, int]] = deque()
        queued_pivots: set[tuple[str, int]] = set()
        processed_domains: set[str] = set()
        processed_ips: set[str] = set()
        expansion_rounds: list[dict[str, Any]] = []

        def queue_pivot(entity: Entity, depth: int):
            if entity.entity_type not in {"social_account", "phone_number", "email"}:
                return
            key = (entity.id, depth)
            if depth <= self.max_pivot_depth and key not in queued_pivots:
                queued_pivots.add(key)
                pivot_queue.append((entity, depth))

        async def enrich_domain(domain: Entity, depth: int):
            if domain.id in processed_domains:
                return
            processed_domains.add(domain.id)
            domain_context = DiscoveryContext(
                iid, brand, context.query, context.official_domains,
                context.aliases, self.max_domains, depth,
            )
            tasks = [(provider, self._call(provider.enrich, domain, domain_context))
                     for provider in enrichers]
            if tasks:
                for (provider, _), run in zip(tasks, await asyncio.gather(*(x[1] for x in tasks))):
                    run.health.rate_limit = {**run.health.rate_limit, "discovery_round": depth}
                    absorb(run)
            # ASN lookups are driven only by newly observed addresses.
            new_ips = [e for e in entities.values()
                       if e.entity_type == "ip_address" and e.id not in processed_ips]
            for ip in new_ips:
                processed_ips.add(ip.id)
                ip_tasks = [(provider, self._call(provider.enrich, ip, domain_context))
                            for provider in ip_enrichers]
                for (provider, _), run in zip(ip_tasks, await asyncio.gather(*(x[1] for x in ip_tasks))):
                    run.health.rate_limit = {**run.health.rate_limit, "discovery_round": depth}
                    absorb(run)

        async def inspect_domain(domain: Entity, depth: int):
            nonlocal fetch_count
            if domain.metadata.get("page", {}).get("inspected"):
                return
            if fetch_count >= self.max_fetches:
                domain.metadata["page"] = {"error": "page fetch budget exhausted", "inspected": False}
                if "safe_page" in requested:
                    absorb(ProviderRun(SourceHealth("safe_page", "limited", ("web_scrape",), detail="Page fetch budget exhausted")))
                return
            url = f"https://{domain.canonical_value}/"
            fetch_count += 1
            try:
                if self.request and self.request.entity_type == "url" and depth == 0:
                    url = self.request.brand
                fetched = await self.fetcher.fetch(url)
            except UnsafeTarget as exc:
                domain.metadata["page"] = {"error": str(exc), "safe_fetch": "rejected", "inspected": True}
                absorb(ProviderRun(SourceHealth("safe_page", "unavailable", ("web_scrape",),
                                                detail="Target rejected by network safety policy", last_attempt=utcnow())))
                return
            page_health = SourceHealth("safe_page", "operational" if not fetched.error and 200 <= fetched.status < 300 else "provider_error",
                                       ("web_scrape",), last_attempt=utcnow(), results=int(bool(fetched.body)),
                                       error="page_fetch_failed" if fetched.error or fetched.status >= 400 else None)
            absorb(ProviderRun(page_health))
            page_meta = {
                "status": fetched.status, "content_type": fetched.content_type,
                "redirect_chain": fetched.redirect_chain, "headers": fetched.headers,
                "error": fetched.error, "inspected": True, "discovery_round": depth,
            }
            if (fetched.body and not fetched.error and
                    (not fetched.content_type or fetched.content_type in
                     {"text/html", "application/xhtml+xml", "text/plain"})):
                page = analyze_page(fetched.text, fetched.final_url or url)
                page_meta.update({
                    "title": page.title, "description": page.description,
                    "visible_text": page.visible_text[:10000], "headings": page.headings,
                    "forms": page.forms, "credential_fields": page.credential_fields,
                    "analytics_ids": page.analytics_ids, "html_fingerprint": page.html_fingerprint,
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
                                       EDGE_BY_TYPE.get(child.entity_type, "links_to"), 0.95, ev.id)
                    relationships[rel.id] = rel
                    queue_pivot(entities[child.id], depth + 1)
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
                        rel = Relationship(iid, domain.id, favicon.id, "uses_favicon", 1.0, ev.id)
                        relationships[rel.id] = rel
                for destination in fetched.redirect_chain[1:]:
                    target_host = normalize_domain(destination)
                    if not target_host:
                        continue
                    target = Entity("domain", target_host, target_host)
                    existing = entities.get(target.id)
                    entities[target.id] = self._merge_entity(existing, target) if existing else target
                    ev = Evidence(iid, target.id, "safe_page", "redirect_observation",
                                  destination, url, {}, 1.0)
                    evidence[ev.id] = ev
                    rel = Relationship(iid, domain.id, target.id, "redirects_to", 1.0, ev.id)
                    relationships[rel.id] = rel
            domain.metadata["page"] = page_meta
            page_ev = Evidence(iid, domain.id, "safe_page", "page_inspection", url, fetched.final_url or url,
                               dict(page_meta), 1.0 if not fetched.error else 0.0)
            evidence[page_ev.id] = page_ev

        # Initial discovery is followed by enrichment and safe inspection. This
        # makes every discovered URL a first-class source of new search seeds.
        for domain in domains:
            await enrich_domain(domain, 0)
            await inspect_domain(domain, 0)
        for candidate in list(entities.values()):
            queue_pivot(candidate, 1)

        # Reverse pivots use public indexing only. Each new domain is enriched
        # and inspected before its extracted identifiers enter the next round.
        web_provider = next((p for p in discovery if "web_search" in definition_for(p).capabilities), None)
        visited: set[tuple[str, str]] = set()
        while pivot_queue and web_provider:
            entity, depth = pivot_queue.popleft()
            key = (entity.id, web_provider.name)
            if key in visited or depth > self.max_pivot_depth:
                continue
            visited.add(key)
            round_row = next((row for row in expansion_rounds if row["depth"] == depth), None)
            if round_row is None:
                round_row = {"depth": depth, "pivots": 0, "new_domains": 0, "inspected": 0}
                expansion_rounds.append(round_row)
            round_row["pivots"] += 1
            value = entity.canonical_value.split(":", 1)[-1]
            pivot_context = DiscoveryContext(
                iid, brand, f'"{value}" "{brand}"', context.official_domains,
                context.aliases, min(10, self.max_domains), depth,
            )
            run = await self._call(web_provider.discover, pivot_context)
            run.health.rate_limit = {**run.health.rate_limit, "discovery_round": depth,
                                     "pivot_entity": entity.canonical_value}
            new_domain_ids = {item.id for item in run.entities
                              if item.entity_type == "domain" and item.id not in entities}
            absorb(run)
            new_domains = []
            for target in run.entities:
                if target.entity_type != "domain":
                    continue
                if target.id in new_domain_ids:
                    new_domains.append(target)
                    round_row["new_domains"] += 1
                    if len(candidate_domain_ids) < self.max_domains:
                        candidate_domain_ids.add(target.id)
                ev = Evidence(iid, target.id, web_provider.name, "reverse_pivot",
                              target.canonical_value, None,
                              {"pivot_entity": entity.canonical_value, "depth": depth}, 0.6)
                evidence[ev.id] = ev
                rel = Relationship(iid, entity.id, target.id, "links_to_domain", 0.6, ev.id)
                relationships[rel.id] = rel
            for target in new_domains:
                await enrich_domain(target, depth)
                before = fetch_count
                await inspect_domain(target, depth)
                round_row["inspected"] += max(0, fetch_count - before)

        correlate(iid, entities, evidence, relationships)

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
            if relation.relationship_type in set(SHARED_RELATION.values()) - {"shares_ip", "shares_nameserver"}:
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

        collection = coverage(requested, health)
        successful = collection["successful"]
        limited = collection["limited"]
        failed = collection["failed"]
        unavailable = collection["unavailable"] + collection["missing_credentials"] + collection["not_searched"]
        coverage_statement = collection["statement"]
        if self._request_count >= self.max_external_requests:
            termination_reason = "external request budget exhausted"
        elif fetch_count >= self.max_fetches:
            termination_reason = "page fetch budget exhausted"
        elif expansion_rounds and any(row["new_domains"] for row in expansion_rounds):
            termination_reason = "no unvisited pivot entities remain"
        else:
            termination_reason = "no meaningful new entities discovered"
        self.store.finish(iid, successful, limited, failed, unavailable,
                          f"Bounded iterative discovery completed: {termination_reason}. "
                          f"{coverage_statement}")
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
            "id": iid, "brand": brand, "zero_key_mode": all(definition_for(p).access == "no_key" for p in self.providers),
            "counts": dict(counts), "campaigns": campaigns,
            "scores": scored,
            "candidates": ranked_candidates[:self.max_domains],
            "filtered_low_signal": max(0, len(candidate_domain_ids) - len(ranked_candidates)),
            "coverage": collection,
            "preflight": self.plan.public() if self.plan else None,
            "social_findings": list(social_findings.values())[:120],
            "social_pagination": {
                "page": 1,
                "page_size": 10,
                "total": min(len(social_findings), 120),
                "has_next": len(social_findings) > 10,
            },
            "expansion": {
                "rounds": sorted(expansion_rounds, key=lambda row: row["depth"]),
                "pivot_entities": len(visited),
                "domains_discovered": len(candidate_domain_ids),
                "domains_inspected": len(processed_domains),
                "pages_fetched": fetch_count,
                "provider_calls": self._request_count,
                "provider_budget": self.max_external_requests,
                "termination_reason": termination_reason,
            },
        }
        from watchtower.engine.reporting import complete_result
        response = complete_result(response, self.store, self.request)
        self.store.save_snapshot(iid, response)
        return response
