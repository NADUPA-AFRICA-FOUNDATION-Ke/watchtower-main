from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from investigation.models import Entity, Evidence, Relationship


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DiscoveryContext:
    investigation_id: str
    brand: str
    query: str
    official_domains: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    max_results: int = 30
    depth: int = 0


@dataclass
class SourceHealth:
    provider: str
    status: str
    capabilities: tuple[str, ...]
    credentials_required: bool = False
    detail: str = ""
    last_attempt: str | None = None
    last_success: str | None = None
    results: int | None = None
    error: str | None = None
    rate_limit: dict[str, Any] = field(default_factory=dict)
    duration_ms: int | None = None

    def dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProviderRun:
    health: SourceHealth
    entities: list[Entity] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)

    @classmethod
    def unavailable(cls, provider: "DiscoveryProvider", status: str, detail: str):
        return cls(SourceHealth(
            provider.name, status, tuple(provider.capabilities()),
            provider.credentials_required, detail=detail, last_attempt=utcnow(),
        ))


class DiscoveryProvider:
    """Common contract for discovery and entity enrichment providers."""

    name = "provider"
    credentials_required = False

    def capabilities(self) -> Iterable[str]:
        return ()

    async def healthcheck(self) -> SourceHealth:
        return SourceHealth(
            self.name, "configured", tuple(self.capabilities()),
            self.credentials_required,
            detail="Availability is verified by each investigation run",
        )

    async def discover(self, context: DiscoveryContext) -> ProviderRun:
        return ProviderRun.unavailable(self, "not_applicable", "Discovery unsupported")

    async def enrich(self, entity: Entity, context: DiscoveryContext) -> ProviderRun:
        return ProviderRun.unavailable(self, "not_applicable", "Enrichment unsupported")

    async def close(self) -> None:
        return None
