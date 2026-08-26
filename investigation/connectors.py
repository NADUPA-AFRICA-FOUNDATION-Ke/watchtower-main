from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

STATUSES = {
    "operational",
    "degraded",
    "limited",
    "missing_credentials",
    "authentication_failed",
    "rate_limited",
    "subscription_limited",
    "network_error",
    "provider_error",
    "timeout",
    "disabled",
    "unavailable",
    "web_index_only",
    "direct_api",
}


@dataclass
class ConnectorHealth:
    configured: bool
    status: str
    mode: str | None = None
    detail: str = ""

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError("invalid connector status")


@dataclass
class DiscoveryResult:
    url: str
    title: str = ""
    text: str = ""
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class DiscoveryConnector(ABC):
    name: str

    @abstractmethod
    def is_configured(self) -> bool: ...
    @abstractmethod
    async def healthcheck(self) -> ConnectorHealth: ...
    @abstractmethod
    async def search(self, query, context) -> list[DiscoveryResult]: ...


class TikTokWebIndexConnector(DiscoveryConnector):
    name = "tiktok"
    TERMS = ("", "loan", "WhatsApp", "promotion", "apply", "APK", "scam")

    def __init__(self, search_connector=None, direct_client=None):
        self.search_connector, self.direct_client = search_connector, direct_client

    def is_configured(self):
        return bool(self.direct_client or self.search_connector)

    async def healthcheck(self):
        if self.direct_client:
            return ConnectorHealth(True, "direct_api", "operational_direct_api")
        if self.search_connector:
            return ConnectorHealth(
                True,
                "web_index_only",
                "operational_web_index_only",
                "Coverage is limited to indexed public pages",
            )
        return ConnectorHealth(False, "unavailable")

    async def search(self, query, context):
        if not self.search_connector:
            return []
        brand = context.get("brand", query)
        results = []
        for term in self.TERMS:
            q = f'site:tiktok.com "{brand}"' + (f' "{term}"' if term else "")
            results.extend(
                await self.search_connector.search(
                    q, {**context, "discovery_mode": "tiktok_web_index"}
                )
            )
        return results


def reverse_queries(entity, brand):
    value = entity.canonical_value.split(":", 1)[-1]
    if entity.entity_type == "social_account":
        return [f'"@{value}"', f'"{value}"', f'"{value}" "{brand}"'] + [
            f'"{value}" site:{p}'
            for p in ("tiktok.com", "instagram.com", "facebook.com")
        ]
    if entity.entity_type == "phone_number":
        digits = value.lstrip("+")
        queries = [f'"{value}"', f'"{digits}"']
        if digits.startswith("254") and len(digits) == 12:
            queries.append(f'"0{digits[3:]}"')
        return queries
    return []
