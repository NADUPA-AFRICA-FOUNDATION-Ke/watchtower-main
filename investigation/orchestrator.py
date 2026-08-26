from __future__ import annotations
import logging
from collections import Counter, defaultdict
from .correlation import correlation_label, correlation_score
from .extraction import extract_entities
from .models import Entity, Evidence, Relationship
from .normalization import normalize_domain
from .queue import Budgets, InvestigationQueue, InvestigationTask, should_expand

log = logging.getLogger(__name__)


class InvestigationEngine:
    def __init__(self, store, connectors=(), budgets=None, weights=None):
        self.store, self.connectors, self.budgets, self.weights = (
            store,
            list(connectors),
            budgets or Budgets(),
            weights,
        )

    async def investigate(self, brand, query=None):
        requested = [c.name for c in self.connectors]
        iid = self.store.create(
            brand,
            query or brand,
            requested,
            {
                "budgets": self.budgets.__dict__,
                "correlation_weights": self.weights or {},
            },
        )
        log.info("investigation_started", extra={"investigation_id": iid})
        entities = {}
        evidence = []
        relationships = []
        successful = []
        limited = []
        failed = []
        unavailable = []
        queue = InvestigationQueue(self.budgets.max_queue_size)
        counts = Counter()
        processed = set()
        brand_entity = Entity("brand", brand.strip().lower(), brand)
        brand_entity.metadata["brand_relevance"] = 1
        entities[brand_entity.id] = brand_entity
        for connector in self.connectors:
            try:
                health = await connector.healthcheck()
                if health.status in {"unavailable", "missing_credentials", "disabled"}:
                    unavailable.append(
                        {"source": connector.name, "status": health.status}
                    )
                    continue
                if health.status in {"limited", "web_index_only"}:
                    limited.append({"source": connector.name, "status": health.status})
                results = await connector.search(
                    query or brand, {"brand": brand, "investigation_id": iid}
                )
                successful.append(connector.name)
                for result in results:
                    host = normalize_domain(result.url)
                    if not host:
                        continue
                    root = Entity(
                        "domain",
                        host,
                        host,
                        metadata={
                            "brand_relevance": 1.0
                            if brand.lower().replace("-", "") in host.replace("-", "")
                            else 0.6
                        },
                    )
                    entities[root.id] = root
                    counts["entities"] += 1
                    counts["domain"] += 1
                    ev = Evidence(
                        iid,
                        root.id,
                        result.source or connector.name,
                        "discovery",
                        result.url,
                        result.url,
                        {"title": result.title, "metadata": result.metadata},
                        0.7,
                    )
                    evidence.append(ev)
                    rel = Relationship(
                        iid, brand_entity.id, root.id, "mentions", 0.6, ev.id
                    )
                    relationships.append(rel)
                    extracted = extract_entities(
                        " ".join((result.url, result.title, result.text)), result.url
                    )
                    for child in extracted:
                        if child.id == root.id:
                            continue
                        child.metadata.setdefault(
                            "brand_relevance", root.metadata["brand_relevance"]
                        )
                        entities[child.id] = child
                        cev = Evidence(
                            iid,
                            child.id,
                            result.source or connector.name,
                            "page_observation",
                            child.display_value,
                            result.url,
                            {},
                            0.95,
                        )
                        evidence.append(cev)
                        kind = (
                            "promotes"
                            if child.entity_type == "social_account"
                            else "links_to"
                        )
                        relationships.append(
                            Relationship(iid, root.id, child.id, kind, 0.9, cev.id)
                        )
                        counts["entities"] += 1
                        counts[child.entity_type] += 1
                        task = InvestigationTask(
                            child.id,
                            0,
                            connector.name,
                            root.id,
                            float(child.metadata["brand_relevance"]),
                        )
                        if should_expand(child, task, self.budgets, counts):
                            queue.push(task)
            except Exception as exc:
                failed.append(
                    {
                        "source": connector.name,
                        "status": "provider_error",
                        "error": type(exc).__name__,
                    }
                )
                log.warning(
                    "source_failed",
                    extra={"investigation_id": iid, "source": connector.name},
                )
        # Shared exact identifiers create evidence-backed domain-to-domain relationships.
        parents = defaultdict(set)
        for r in relationships:
            if entities.get(r.target_entity_id) and entities[
                r.target_entity_id
            ].entity_type in {"phone_number", "email", "social_account"}:
                parents[r.target_entity_id].add(r.source_entity_id)
        for shared, owners in parents.items():
            owners = list(owners)
            typ = {
                "phone_number": "shares_phone",
                "email": "shares_email",
                "social_account": "shares_social_account",
            }[entities[shared].entity_type]
            for a, b in zip(owners, owners[1:]):
                ev = Evidence(
                    iid,
                    shared,
                    "correlation",
                    typ,
                    entities[shared].canonical_value,
                    None,
                    {"entity_a": a, "entity_b": b},
                    0.96,
                )
                evidence.append(ev)
                relationships.append(Relationship(iid, a, b, typ, 0.96, ev.id))
        # Queue is intentionally bounded and pivot keys are processed once. Connectors may implement entity pivots later without changing persistence.
        while queue:
            task = queue.pop()
            key = (task.entity_id, task.discovered_by, task.pivot_type)
            if key in processed:
                continue
            processed.add(key)
        self.store.persist(iid, list(entities.values()), evidence, relationships)
        self.store.finish(iid, successful, limited, failed, unavailable)
        score = correlation_score(relationships, self.weights)
        campaign = (
            self.store.create_campaign(
                brand, list(entities), score, correlation_label(score), None
            )
            if len(entities) > 1
            else None
        )
        return {
            "id": iid,
            "brand": brand,
            "entities": len(entities),
            "relationships": len(relationships),
            "campaign": campaign,
            "correlation_score": score,
            "correlation_label": correlation_label(score),
            "threat_score": None,
            "coverage": {
                "requested": requested,
                "successful": successful,
                "limited": limited,
                "failed": failed,
                "unavailable": unavailable,
                "disclaimer": "Results cover only the sources successfully queried.",
            },
        }
