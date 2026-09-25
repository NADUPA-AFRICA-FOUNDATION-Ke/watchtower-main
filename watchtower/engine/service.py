"""Single investigation application service used by every interface."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Callable

from investigation.models import now
from investigation.storage import InvestigationStore
from watchtower.discovery.cache import ProviderCache
from watchtower.discovery.factory import build_providers
from watchtower.discovery.orchestrator import DiscoveryOrchestrator
from watchtower.discovery.safe_fetch import SafeFetcher
from watchtower.registry import CAPABILITIES, REGISTRY
from .health import SourceHealthService
from .limits import OperationLimiter
from .planner import InvestigationRequest, QueryPlanner, MARKETS


class InvestigationService:
    def __init__(self, database: str | Path, cache_path: str | Path,
                 configuration: dict | None = None, brand_config: dict | None = None,
                 lexicon_terms: tuple[str, ...] = (), provider_factory: Callable = build_providers,
                 fetcher_factory: Callable = SafeFetcher):
        self.database, self.cache_path = database, cache_path
        self.configuration = configuration or {}
        self.brand_config = brand_config or {}
        self.lexicon_terms = lexicon_terms
        self.provider_factory, self.fetcher_factory = provider_factory, fetcher_factory
        self.planner = QueryPlanner()

    def preflight(self, request: InvestigationRequest) -> dict:
        return self._plan(request).public()

    def _plan(self, request: InvestigationRequest):
        from datetime import datetime, timezone
        store = InvestigationStore(self.database)
        try:
            rows = store.conn.execute("SELECT source,completed_at,rate_limit_metadata FROM source_runs WHERE status='rate_limited'").fetchall()
            cooldowns = []
            for row in rows:
                retry = json.loads(row['rate_limit_metadata'] or '{}').get('retry_after_seconds', 60)
                if (datetime.now(timezone.utc) - datetime.fromisoformat(row['completed_at'])).total_seconds() < min(3600, max(1, retry)):
                    cooldowns.append(row['source'])
            return self.planner.plan(request, cooldowns=tuple(cooldowns))
        finally:
            store.conn.close()

    def _brand(self, request: InvestigationRequest) -> dict:
        configured = self.brand_config
        terms = [configured.get('name', ''), *configured.get('aliases', []), *configured.get('products', [])]
        matches = [term for term in terms if term and (term.lower() in request.brand.lower() or request.brand.lower() in term.lower())]
        if matches:
            return {**configured, 'aliases': list(dict.fromkeys([*terms, request.brand]))}
        return {'name': request.brand, 'aliases': [request.brand], 'official_domains': [], 'products': []}

    async def investigate(self, request: InvestigationRequest, seeds: list[dict] | None = None) -> dict:
        plan = self._plan(request)
        if not plan.can_proceed:
            raise ValueError('No requested sources can run; inspect preflight coverage')
        store = InvestigationStore(self.database)
        limiter = OperationLimiter(self.database)
        cache = None
        lease = None
        try:
            lease = limiter.acquire()
            cache = ProviderCache(self.cache_path)
            definitions = [REGISTRY.get(name) for name in plan.selected if REGISTRY.get(name).phase != 'inspection']
            providers = self.provider_factory(definitions, cache)
            cfg = self.configuration
            engine = DiscoveryOrchestrator(
                store, providers, self.fetcher_factory(cache=cache), plan=plan, request=request, seeds=seeds,
                max_domains=min(request.limit, int(cfg.get('max_domains', 40))),
                max_fetches=int(cfg.get('max_page_fetches', 20)) if 'safe_page' in plan.selected else 0,
                max_pivot_depth=min(2, int(cfg.get('max_pivot_depth', 2))),
                max_global_requests=min(8, int(cfg.get('max_global_requests', 8))),
                max_external_requests=min(500, int(cfg.get('max_external_requests', 500))),
            )
            result = await asyncio.wait_for(engine.investigate(
                request.brand, request.query or request.brand, self._brand(request), self.lexicon_terms,
            ), timeout=180)
            result['preflight'] = plan.public()
            return result
        except BaseException:
            # Only this connection's newly running investigation is affected.
            # The service creates one run per invocation; no other worker's run is changed.
            if 'engine' in locals() and getattr(engine, 'investigation_id', None):
                store.conn.execute("UPDATE investigations SET status='failed',completed_at=?,budget_note=? WHERE id=? AND status='running'",
                                   (now(), 'Execution interrupted; coverage is incomplete', engine.investigation_id))
                store.conn.commit()
            raise
        finally:
            if cache is not None:
                cache.conn.close()
            if lease:
                limiter.release(lease)
            store.conn.close()

    def get(self, iid: str) -> dict:
        store = InvestigationStore(self.database)
        try:
            result = store.snapshot(iid)
            if result:
                return result
            record = store.get('investigations', iid)
            if not record:
                raise LookupError('Investigation not found')
            # Old investigations remain readable without fabricating missing snapshots.
            return {'id': iid, 'investigation': record, 'graph': store.graph(iid),
                    'evidence': store.evidence_for(iid), 'sources': store.source_runs(iid),
                    'warnings': ['Legacy investigation: immutable snapshot and report unavailable']}
        finally:
            store.conn.close()

    def list_investigations(self, limit: int = 50) -> list[dict]:
        store = InvestigationStore(self.database)
        try:
            return [dict(row) for row in store.conn.execute(
                'SELECT id,brand,query,status,started_at,completed_at,coverage_percentage FROM investigations ORDER BY started_at DESC LIMIT ?',
                (min(100, max(1, limit)),))]
        finally:
            store.conn.close()

    async def recheck(self, iid: str, include: list[str] | None = None) -> dict:
        previous = self.get(iid)
        data = previous.get('request') or {'brand': previous['investigation']['brand']}
        if include is not None:
            data = {**data, 'include': include, 'enrich': True}
        result = await self.investigate(InvestigationRequest.model_validate(data))
        result['previous_investigation_id'] = iid
        return result

    async def enrich(self, iid: str, include: list[str] | None = None) -> dict:
        previous = self.get(iid)
        data = previous.get('request') or {'brand': previous['investigation']['brand']}
        chosen = include if include is not None else [s.id for s in REGISTRY.all()
                  if s.default and s.phase in {'enrichment', 'inspection'}]
        for name in chosen:
            if REGISTRY.get(name).phase not in {'enrichment', 'inspection'}:
                raise ValueError('Enrichment requires enrichment or inspection sources')
        request = InvestigationRequest.model_validate({**data, 'sources': chosen, 'include': None, 'enrich': True})
        seeds = [row for row in previous['graph']['nodes'] if row['entity_type'] in {'domain', 'ip_address'}]
        if not seeds:
            raise ValueError('No enrichable domains or IPs in this investigation')
        result = await self.investigate(request, seeds)
        result['previous_investigation_id'] = iid
        return result

    def discover(self, action: str = 'sources', id: str | None = None, search: str = '') -> dict:
        if action == 'sources':
            return {'sources': [s.public() for s in REGISTRY.all()]}
        if action == 'source':
            return REGISTRY.get(id or '').public()
        if action == 'capabilities':
            terms = search.lower().split()
            return {'capabilities': [c for c in sorted(CAPABILITIES) if not terms or any(t in c for t in terms)],
                    'sources': [s.id for s in REGISTRY.all() if not terms or any(t in ' '.join(s.capabilities) + ' ' + s.description.lower() for t in terms)]}
        if action == 'investigation_types':
            return {'types': ['brand', 'domain', 'url', 'phone_number', 'email', 'username', 'ip_address'], 'markets': sorted(MARKETS)}
        if action == 'evidence_types':
            return {'types': ['discovery', 'investigation_seed', 'page_observation', 'page_inspection', 'dns_observation', 'rdap_observation', 'tls_certificate', 'threat_intelligence', 'social_index_observation', 'derived_correlation']}
        if action == 'coverage':
            return self.get(id or '').get('coverage', {'statement': 'Legacy coverage unavailable'})
        if action in {'health', 'freshness'}:
            store = InvestigationStore(self.database)
            try:
                return {'sources': SourceHealthService(store).sources()}
            finally:
                store.conn.close()
        raise ValueError('Unknown discovery action')
