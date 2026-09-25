"""Wrap existing monitor search functions without copying their API clients."""
from __future__ import annotations
import asyncio
from investigation.models import Entity, Evidence
from investigation.normalization import normalize_domain
from .base import DiscoveryProvider, ProviderRun, SourceHealth
from watchtower.registry import SourceDefinition


class MonitorSourceAdapter(DiscoveryProvider):
    def __init__(self, definition: SourceDefinition):
        self.definition = definition
        self.name = definition.id

    def capabilities(self):
        return self.definition.capabilities

    async def discover(self, context):
        from core.sources import BACKENDS, SourceError, SourceSkipped
        from core.fetch import Fetcher
        import os

        def search():
            fetcher = Fetcher('Mnara/1.0 (' + os.environ.get('WATCHTOWER_CONTACT', 'contact unset') + ')', timeout=10)
            try:
                return BACKENDS[self.name](context.query, fetcher, limit=context.max_results)
            finally:
                fetcher.client.close()

        try:
            rows = await asyncio.to_thread(search)
        except SourceSkipped:
            return ProviderRun.unavailable(self, 'unavailable', 'Source unavailable; inspect credential configuration')
        except SourceError:
            return ProviderRun.unavailable(self, 'provider_error', 'Source request failed')
        run = ProviderRun(SourceHealth(self.name, 'operational', self.definition.capabilities))
        for row in rows:
            host = normalize_domain(row.url)
            if not host:
                continue
            domain = Entity('domain', host, host)
            ev = Evidence(context.investigation_id, domain.id, self.name, 'discovery', row.url, row.url,
                          {'title': row.title, 'snippet': row.text[:10000], 'raw': row.raw_meta}, 0.6,
                          source_published_at=row.published_at or None)
            run.entities.append(domain)
            run.evidence.append(ev)
        run.health.results = len(rows)
        return run
