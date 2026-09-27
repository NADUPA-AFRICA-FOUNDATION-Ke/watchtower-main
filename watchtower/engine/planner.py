"""Pure capability planning and preflight; no upstream calls or adapter imports."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from typing import Literal, Mapping, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from watchtower.registry import REGISTRY, SourceDefinition, SourceRegistry

MARKETS = frozenset('GLOBAL KE TZ UG RW BI ET SO SS SD ZA NG GH GB US CA IN AU'.split())
ALIASES = {'kenya': 'KE', 'tanzania': 'TZ', 'uganda': 'UG', 'global': 'GLOBAL'}


class InvestigationRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    brand: str = Field(min_length=2, max_length=100)
    query: str = Field(default='', max_length=300)
    market: str = 'GLOBAL'
    lookback_days: int = Field(default=90, ge=1, le=3650)
    limit: int = Field(default=20, ge=1, le=75)
    sources: Optional[list[str]] = Field(default=None, max_length=40)
    enrich: bool = True
    include: Optional[list[str]] = Field(default=None, max_length=40)
    allow_paid: bool = False
    target_type: Literal['auto', 'brand', 'domain', 'url', 'phone_number', 'email', 'username', 'ip_address'] = 'auto'

    @field_validator('market')
    @classmethod
    def valid_market(cls, value: str) -> str:
        code = ALIASES.get(value.lower(), value.upper())
        if code not in MARKETS:
            raise ValueError('unsupported market; use an advertised market code or GLOBAL')
        return code

    @property
    def entity_type(self) -> str:
        if self.target_type != 'auto':
            return self.target_type
        value = self.brand
        try:
            ipaddress.ip_address(value)
            return 'ip_address'
        except ValueError:
            if value.startswith(('https://', 'http://')):
                return 'url'
            if re.fullmatch(r'\+\d[\d ()-]{6,20}', value):
                return 'phone_number'
            if re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value):
                return 'email'
            if value.startswith('@'):
                return 'username'
            if re.fullmatch(r'[\w-]+(?:\.[\w-]+)+\.?', value):
                return 'domain'
            return 'brand'


@dataclass(frozen=True)
class Plan:
    requested: tuple[str, ...]
    selected: tuple[str, ...]
    capabilities: tuple[str, ...]
    missing_credentials: tuple[str, ...]
    unavailable: tuple[str, ...]
    warnings: tuple[str, ...]
    target_type: str

    @property
    def can_proceed(self) -> bool:
        return bool(self.selected)

    def public(self) -> dict[str, object]:
        return {**asdict(self), 'requested_sources': len(self.requested),
                'available_sources': len(self.selected), 'can_proceed': self.can_proceed}


DISCOVERY_CAPABILITIES = {
    'brand': {'keyword_search', 'web_search', 'certificate_search', 'historical_web', 'social_mentions', 'repository_search'},
    'phone_number': {'phone_search', 'web_search'},
    'email': {'email_search', 'web_search'},
    'username': {'username_lookup', 'web_search'},
}


class QueryPlanner:
    def __init__(self, registry: SourceRegistry = REGISTRY):
        self.registry = registry

    def plan(self, request: InvestigationRequest, env: Mapping[str, str] | None = None, cooldowns: tuple[str, ...] = ()) -> Plan:
        kind = request.entity_type
        discovery = DISCOVERY_CAPABILITIES.get(kind, set())
        requested: list[SourceDefinition] = []
        if request.sources is not None:
            requested = [self.registry.get(name) for name in dict.fromkeys(request.sources)]
        else:
            for source in self.registry.all():
                if source.surface != 'investigation' or not source.default:
                    continue
                if source.phase == 'discovery' and set(source.capabilities) & discovery:
                    requested.append(source)
                elif request.enrich and source.phase in {'enrichment', 'inspection'}:
                    inputs = {kind, 'domain' if kind == 'url' else kind}
                    if kind in DISCOVERY_CAPABILITIES or set(source.input_types) & inputs or kind in {'domain', 'url'} and 'ip_address' in source.input_types:
                        requested.append(source)
        if request.include is not None:
            for name in request.include:
                self.registry.get(name)
            requested = [s for s in requested if s.phase == 'discovery' or s.id in request.include]
        selected, missing, unavailable, warnings = [], [], [], []
        for source in requested:
            if not source.is_enabled(env):
                unavailable.append(source.id)
                warnings.append(f'{source.id}: disabled')
            elif source.markets and request.market not in source.markets:
                unavailable.append(source.id)
                warnings.append(f'{source.id}: market unsupported')
            elif source.access == 'paid' and not request.allow_paid:
                unavailable.append(source.id)
                warnings.append(f'{source.id}: paid access not opted in')
            elif source.id in cooldowns:
                unavailable.append(source.id)
                warnings.append(f'{source.id}: rate limited; waiting before another attempt')
            elif source.missing_credentials(env):
                missing.append(source.id)
                warnings.append(f'{source.id}: missing ' + ', '.join(source.missing_credentials(env)))
            elif not request.enrich and source.phase != 'discovery':
                unavailable.append(source.id)
                warnings.append(f'{source.id}: enrichment disabled')
            else:
                selected.append(source.id)
        warnings.append('Lookback is a scope preference; sources without date filtering may return older observations.')
        return Plan(tuple(s.id for s in requested), tuple(selected),
                    tuple(sorted({c for s in requested for c in s.capabilities})),
                    tuple(missing), tuple(unavailable), tuple(warnings), kind)
