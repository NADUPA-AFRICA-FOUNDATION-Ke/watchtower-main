from __future__ import annotations
from collections import defaultdict

DEFAULT_WEIGHTS = {
    "shares_phone": 30,
    "links_to": 25,
    "promotes": 25,
    "shares_social_account": 25,
    "shares_email": 25,
    "shares_certificate": 20,
    "shares_registrant": 20,
    "redirects_to": 20,
    "shares_ip": 10,
    "near_identical_domain": 10,
    "references_company": 10,
    "temporal_overlap": 10,
}


def correlation_score(relationships, weights=None):
    weights = weights or DEFAULT_WEIGHTS
    return min(
        100,
        round(
            sum(
                weights.get(r.relationship_type, 0) * r.confidence
                for r in relationships
            )
        ),
    )


def correlation_label(score):
    return (
        "Very High"
        if score >= 80
        else "High"
        if score >= 60
        else "Moderate"
        if score >= 30
        else "Low"
    )


def clusters(entity_ids, relationships):
    adjacency = defaultdict(set)
    # A shared cloud IP alone is not enough to create a campaign.
    for r in relationships:
        if r.relationship_type == "shares_ip" or r.confidence < 0.5:
            continue
        adjacency[r.source_entity_id].add(r.target_entity_id)
        adjacency[r.target_entity_id].add(r.source_entity_id)
    output, seen = [], set()
    for node in entity_ids:
        if node in seen:
            continue
        stack, group = [node], set()
        while stack:
            cur = stack.pop()
            if cur in group:
                continue
            group.add(cur)
            seen.add(cur)
            stack.extend(adjacency[cur] - group)
        if len(group) > 1:
            output.append(group)
    return output


SHARED_RELATION = {
    "phone_number": "shares_phone",
    "email": "shares_email",
    "social_account": "shares_social_account",
    "certificate": "shares_certificate",
    "nameserver": "shares_nameserver",
    "payment_identifier": "shares_payment_identifier",
    "analytics_id": "shares_analytics",
    "html_fingerprint": "shares_html_fingerprint",
    "favicon": "shares_favicon",
}


def correlate(iid, entities, evidence, relationships):
    """Deterministic identifier joins and explicitly derived template similarity."""
    from .models import Entity, Evidence, Relationship
    # Exact high-value identifier reuse creates derived evidence and domain edges.
    owners: defaultdict[str, set[str]] = defaultdict(set)
    for relation in relationships.values():
        source = entities.get(relation.source_entity_id)
        related = entities.get(relation.target_entity_id)
        if source and related and source.entity_type == "domain" and related.entity_type in SHARED_RELATION:
            owners[related.id].add(source.id)
    for shared_id, domain_ids in owners.items():
        ordered = sorted(domain_ids)
        for index, left in enumerate(ordered):
            for right in ordered[index + 1:]:
                shared = entities[shared_id]
                ev = Evidence(iid, shared.id, "correlation", SHARED_RELATION[shared.entity_type],
                              shared.canonical_value, None,
                              {"source_entity": left, "related_entity": right,
                 "derived": True, "supporting_evidence_ids": sorted({r.evidence_id for r in relationships.values()
                     if r.target_entity_id == shared_id and r.source_entity_id in {left, right}})}, 1.0)
                evidence[ev.id] = ev
                rel = Relationship(iid, left, right, SHARED_RELATION[shared.entity_type], 1.0, ev.id)
                relationships[rel.id] = rel

    # Near-identical page templates become derived evidence. The threshold
    # is intentionally strict; similarity alone never confirms a campaign.
    page_domains: list[Entity] = [
        e for e in entities.values() if e.entity_type == "domain"
        and e.metadata.get("page", {}).get("simhash") is not None
    ]
    for index, left_domain in enumerate(page_domains):
        for right_domain in page_domains[index + 1:]:
            distance = bin(int(left_domain.metadata["page"]["simhash"]) ^
                           int(right_domain.metadata["page"]["simhash"])).count("1")
            if distance > 3:
                continue
            similarity = round(1 - distance / 64, 3)
            ev = Evidence(iid, left_domain.id, "correlation", "html_similarity",
                          str(similarity), None,
                          {"related_entity": right_domain.id, "hamming_distance": distance, "derived": True,
                           "supporting_evidence_ids": [e.id for e in evidence.values() if e.entity_id in {left_domain.id, right_domain.id} and e.evidence_type == "page_inspection"]},
                          similarity)
            evidence[ev.id] = ev
            rel = Relationship(iid, left_domain.id, right_domain.id, "shares_html_template",
                               similarity, ev.id)
            relationships[rel.id] = rel
