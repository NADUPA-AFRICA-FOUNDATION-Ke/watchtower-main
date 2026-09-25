"""Immutable source metadata. This module never imports or executes adapters."""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Mapping

CAPABILITIES = frozenset('''keyword_search domain_search domain_metadata
 domain_registration dns_lookup certificate_search subdomain_discovery url_discovery
 web_search web_scrape page_text screenshot historical_web repository_search
 username_lookup profile_lookup post_search comment_search channel_search phone_search
 email_search social_mentions threat_reputation ip_lookup asn_lookup redirect_chain
 favicon_hash technology_detection brand_similarity credential_form_detection
 link_extraction entity_extraction'''.split())
CATEGORIES = frozenset('search social domain dns certificate threat_intel code archive web messaging other'.split())
ACCESS_MODES = frozenset(('no_key', 'free_key', 'optional_key', 'paid', 'self_hosted'))


@dataclass(frozen=True)
class SourceDefinition:
    id: str
    name: str
    category: str
    description: str
    capabilities: tuple[str, ...]
    adapter: str
    access: str = 'no_key'
    env_vars: tuple[str, ...] = ()
    enabled: bool = True
    enable_env: str = ''
    default: bool = True
    surface: str = 'investigation'
    evidence_types: tuple[str, ...] = ('discovery',)
    input_types: tuple[str, ...] = ('brand',)
    phase: str = 'discovery'
    requests: int = 1
    window_seconds: float = 1.0
    markets: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    documentation: str = ''

    def __post_init__(self) -> None:
        if not self.id or not self.adapter or ':' not in self.adapter:
            raise ValueError('source id and module:adapter are required')
        if not self.capabilities or set(self.capabilities) - CAPABILITIES:
            raise ValueError(f'invalid capabilities for {self.id}')
        if self.category not in CATEGORIES or self.access not in ACCESS_MODES:
            raise ValueError('invalid category or access mode')
        if self.access in {'free_key', 'paid'} and not self.env_vars:
            raise ValueError('keyed source must declare credential names')
        if self.requests < 1 or self.window_seconds <= 0:
            raise ValueError('invalid rate limit')

    def is_enabled(self, env: Mapping[str, str] | None = None) -> bool:
        env = os.environ if env is None else env
        return self.enabled and env.get(self.enable_env, 'true').lower() not in {'0', 'false', 'no', 'off'}

    def missing_credentials(self, env: Mapping[str, str] | None = None) -> list[str]:
        env = os.environ if env is None else env
        if self.access in {'no_key', 'optional_key', 'self_hosted'}:
            return []
        return [key for key in self.env_vars if not env.get(key, '').strip()]

    def public(self, env: Mapping[str, str] | None = None) -> dict[str, object]:
        result: dict[str, object] = asdict(self)
        missing = self.missing_credentials(env)
        result.update(status='disabled' if not self.is_enabled(env) else 'auth_missing' if missing else 'unknown',
                      missing_environment_variables=missing, requires_key=self.access in {'free_key', 'paid'},
                      paid=self.access == 'paid', optional=True)
        return result


class SourceRegistry:
    def __init__(self, definitions: tuple[SourceDefinition, ...]):
        self._sources: dict[str, SourceDefinition] = {}
        for definition in definitions:
            if definition.id in self._sources:
                raise ValueError(f'duplicate source id: {definition.id}')
            self._sources[definition.id] = definition

    def get(self, source_id: str) -> SourceDefinition:
        if source_id not in self._sources:
            raise ValueError(f'unknown source: {source_id}')
        return self._sources[source_id]

    def all(self) -> tuple[SourceDefinition, ...]:
        return tuple(self._sources.values())

    def for_capability(self, capability: str) -> tuple[SourceDefinition, ...]:
        if capability not in CAPABILITIES:
            raise ValueError(f'unknown capability: {capability}')
        return tuple(s for s in self.all() if capability in s.capabilities)
