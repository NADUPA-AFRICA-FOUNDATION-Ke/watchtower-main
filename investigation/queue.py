from __future__ import annotations
import heapq
from dataclasses import dataclass, field


@dataclass(order=True)
class InvestigationTask:
    sort_key: float = field(init=False, repr=False)
    entity_id: str = field(compare=False)
    depth: int = field(compare=False)
    discovered_by: str = field(compare=False)
    parent_entity_id: str | None = field(default=None, compare=False)
    priority: float = field(default=0.5, compare=False)
    pivot_type: str = field(default="expand", compare=False)

    def __post_init__(self):
        self.sort_key = -self.priority


class InvestigationQueue:
    def __init__(self, max_size: int = 500):
        self.max_size, self._heap, self._known = max_size, [], set()

    def push(self, task: InvestigationTask) -> bool:
        key = (task.entity_id, task.discovered_by, task.pivot_type)
        if key in self._known or len(self._heap) >= self.max_size:
            return False
        self._known.add(key)
        heapq.heappush(self._heap, task)
        return True

    def pop(self):
        return heapq.heappop(self._heap)

    def __bool__(self):
        return bool(self._heap)


@dataclass
class Budgets:
    max_depth: int = 3
    max_entities: int = 250
    max_domains: int = 75
    max_social_accounts: int = 75
    max_external_requests: int = 500
    max_queue_size: int = 500
    domain_threshold: float = 0.55
    social_threshold: float = 0.55


def should_expand(entity, task, budgets: Budgets, counts: dict[str, int]) -> bool:
    if (
        task.depth >= budgets.max_depth
        or counts.get("entities", 0) >= budgets.max_entities
    ):
        return False
    relevance = float(entity.metadata.get("brand_relevance", 0))
    if entity.entity_type == "domain":
        return (
            counts.get("domain", 0) < budgets.max_domains
            and relevance >= budgets.domain_threshold
        )
    if entity.entity_type == "social_account":
        return (
            counts.get("social_account", 0) < budgets.max_social_accounts
            and relevance >= budgets.social_threshold
        )
    return False
