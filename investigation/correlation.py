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
