"""Adapter construction lives at the boundary, never in the planner."""
from __future__ import annotations

import importlib
from collections.abc import Iterable
from .base import DiscoveryProvider
from .cache import ProviderCache
from .providers import DuckDuckGoProvider, SocialWebIndexProvider, HttpProvider, DNSProvider
from watchtower.registry import SourceDefinition


def build_providers(definitions: Iterable[SourceDefinition], cache=None, client=None) -> list[DiscoveryProvider]:
    cache = cache or ProviderCache()
    search = DuckDuckGoProvider(cache)
    result: list[DiscoveryProvider] = []
    for definition in definitions:
        if definition.surface == 'monitor':
            from .monitor_adapter import MonitorSourceAdapter
            result.append(MonitorSourceAdapter(definition))
            continue
        module, name = definition.adapter.split(':', 1)
        cls = getattr(importlib.import_module(module), name)
        provider: DiscoveryProvider
        if cls is DuckDuckGoProvider:
            provider = search
        elif cls is SocialWebIndexProvider:
            provider = cls(search)
        elif issubclass(cls, HttpProvider):
            provider = cls(client, cache)
        elif cls is DNSProvider:
            provider = cls(cache)
        else:
            provider = cls()
        result.append(provider)
    return result
