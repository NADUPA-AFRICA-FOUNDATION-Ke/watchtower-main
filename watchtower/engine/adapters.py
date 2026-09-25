"""Compatibility adapter contract over existing discovery implementations."""
from __future__ import annotations

import asyncio
import logging
import time
import httpx
from dataclasses import asdict, dataclass, field
from typing import Literal

from investigation.models import Entity
from watchtower.discovery.base import DiscoveryContext, DiscoveryProvider, ProviderRun, SourceHealth, utcnow
from watchtower.registry import REGISTRY, SourceDefinition

log = logging.getLogger(__name__)
RunStatus = Literal['success', 'partial', 'unavailable', 'rate_limited', 'auth_missing', 'failed', 'not_searched']
STATUS: dict[str, RunStatus] = {
    'operational': 'success', 'degraded': 'partial', 'limited': 'partial',
    'web_index_only': 'partial', 'rate_limited': 'rate_limited',
    'missing_credentials': 'auth_missing', 'auth_missing': 'auth_missing',
    'unavailable': 'unavailable', 'disabled': 'not_searched', 'not_applicable': 'not_searched',
    'provider_error': 'failed', 'timeout': 'failed', 'network_error': 'failed',
}
LEGACY_CAPABILITIES = {
    'open_web': 'web_search', 'domain_discovery': 'domain_search',
    'historical_urls': 'historical_web', 'social_web_index': 'social_mentions',
    'social_api': 'post_search', 'registration': 'domain_registration',
    'A': 'dns_lookup', 'live_certificate': 'certificate_search',
    'urlhaus': 'threat_reputation', 'threatfox': 'threat_reputation', 'asn': 'asn_lookup',
}


def definition_for(provider: DiscoveryProvider) -> SourceDefinition:
    try:
        return REGISTRY.get(provider.name)
    except ValueError:
        # Explicitly injected compatibility providers (including offline fixtures).
        capabilities = tuple(dict.fromkeys(LEGACY_CAPABILITIES.get(c, c) for c in provider.capabilities()
                                          if c in LEGACY_CAPABILITIES))
        enrichment = bool(set(capabilities) & {'domain_registration', 'dns_lookup', 'asn_lookup', 'threat_reputation'})
        return SourceDefinition(provider.name, provider.name, 'other', 'Injected compatibility adapter',
                                capabilities, f'{type(provider).__module__}:{type(provider).__name__}',
                                phase='enrichment' if enrichment else 'discovery',
                                input_types=('ip_address',) if 'asn_lookup' in capabilities else ('domain',) if enrichment else ('brand',))


@dataclass
class SourceResult:
    source_id: str
    capability: str
    status: RunStatus
    started_at: str
    completed_at: str
    duration_ms: int
    query: str
    entity_id: str | None
    data: ProviderRun
    warnings: list[str] = field(default_factory=list)
    error_code: str | None = None
    retryable: bool = False

    def envelope(self) -> dict[str, object]:
        return {
            'source_id': self.source_id, 'capability': self.capability, 'status': self.status,
            'data': [asdict(e) for e in self.data.entities],
            'evidence_ids': [e.id for e in self.data.evidence], 'warnings': self.warnings,
            'error': {'code': self.error_code, 'message': self.error_code, 'retryable': self.retryable} if self.error_code else None,
            'timing': {'started_at': self.started_at, 'completed_at': self.completed_at, 'duration_ms': self.duration_ms},
            'provenance': {'retrieved_at': self.completed_at, 'query': self.query, 'entity_id': self.entity_id},
        }


class ProviderAdapter:
    def __init__(self, provider: DiscoveryProvider, timeout: float = 45):
        self.provider = provider
        self.definition = definition_for(provider)
        self.id = self.definition.id
        self.timeout = timeout
        if hasattr(provider, 'min_interval'):
            provider.min_interval = max(provider.min_interval, self.definition.window_seconds / self.definition.requests)

    async def health(self) -> SourceHealth:
        missing = self.definition.missing_credentials()
        status = 'disabled' if not self.definition.is_enabled() else 'auth_missing' if missing else 'unknown'
        return SourceHealth(self.id, status, self.definition.capabilities, bool(missing),
                            detail='Missing ' + ', '.join(missing) if missing else 'Verified on execution')

    async def execute(self, capability: str, context: DiscoveryContext, entity: Entity | None = None) -> SourceResult:
        if capability not in self.definition.capabilities:
            raise ValueError('adapter does not support capability')
        started, tick = utcnow(), time.monotonic()
        configured = await self.health()
        if configured.status != 'unknown':
            run = ProviderRun(configured)
        else:
            try:
                call = self.provider.discover(context) if entity is None else self.provider.enrich(entity, context)
                run = await asyncio.wait_for(call, self.timeout)
            except httpx.HTTPStatusError as exc:
                code = exc.response.status_code
                state = 'rate_limited' if code == 429 else 'unavailable' if code in {401, 403, 404} else 'provider_error'
                run = ProviderRun.unavailable(self.provider, state, f'HTTP {code}')
                run.health.error = f'HTTP {code}'
                if code == 429:
                    retry = exc.response.headers.get('retry-after', '60')
                    run.health.rate_limit['retry_after_seconds'] = int(retry) if retry.isdigit() else 60
            except (asyncio.TimeoutError, TimeoutError):
                run = ProviderRun.unavailable(self.provider, 'timeout', 'source deadline exceeded')
                run.health.error = 'timeout'
            except Exception as exc:
                # Exception strings can embed credential-bearing upstream URLs/headers.
                run = ProviderRun.unavailable(self.provider, 'provider_error', type(exc).__name__)
                run.health.error = type(exc).__name__
        status = STATUS.get(run.health.status, 'failed')
        if run.health.error:
            # Normalize HTTP failures from legacy providers without exposing payloads.
            error = run.health.error
            if '429' in error:
                status = 'rate_limited'
            elif '401' in error or '403' in error:
                status = 'unavailable'
            run.health.error = 'rate_limited' if status == 'rate_limited' else 'source_error'
        if status == 'failed' and run.evidence:
            status = 'partial'
        run.health.status = {'success': 'operational', 'partial': 'degraded',
                             'unavailable': 'unavailable', 'rate_limited': 'rate_limited',
                             'auth_missing': 'auth_missing', 'failed': 'provider_error',
                             'not_searched': 'disabled'}[status]
        run.health.last_attempt = started
        run.health.duration_ms = round((time.monotonic() - tick) * 1000)
        result = SourceResult(self.id, capability, status, started, utcnow(), run.health.duration_ms,
                              context.query, entity.id if entity else None, run,
                              [run.health.detail] if run.health.detail else [],
                              run.health.error, status in {'rate_limited', 'failed'})
        log.info('source_run', extra={'investigation_id': context.investigation_id, 'source_id': self.id,
                                     'capability': capability, 'duration_ms': result.duration_ms,
                                     'status': status, 'item_count': len(run.entities), 'error_code': result.error_code})
        return result
