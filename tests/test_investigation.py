import asyncio
import json

import pytest

from investigation.connectors import (
    ConnectorHealth,
    DiscoveryConnector,
    DiscoveryResult,
    TikTokWebIndexConnector,
    reverse_queries,
)
from investigation.correlation import clusters, correlation_label, correlation_score
from investigation.extraction import extract_entities
from investigation.models import Entity, Evidence, Relationship
from investigation.normalization import (
    is_public_host,
    normalize_domain,
    normalize_phone,
    normalize_social,
    normalize_url,
)
from investigation.orchestrator import InvestigationEngine
from investigation.queue import (
    Budgets,
    InvestigationQueue,
    InvestigationTask,
    should_expand,
)
from investigation.storage import InvestigationStore


def test_normalization_and_ssrf_guards():
    assert normalize_domain("https://WWW.Example.com/login") == "example.com"
    assert normalize_url("EXAMPLE.com").startswith("https://example.com/")
    assert normalize_phone("0712 345 678", "KE") == "+254712345678"
    assert normalize_phone("0712 345 678") is None
    assert (
        normalize_phone("https://wa.me/254712345678".split("/")[-1], "KE")
        == "+254712345678"
    )
    assert normalize_social("Twitter", "@Example") == "x:example"
    assert not is_public_host("127.0.0.1")


def test_modular_extraction_and_deduplication():
    text = """See https://www.example.com/login, https://tiktok.com/@MpesaCash247,
    https://t.me/mpesaloanhelp https://wa.me/254712345678 and Help@Example.COM.
    Also +254 712 345 678 and https://files.example.net/app.apk"""
    entities = extract_entities(text)
    values = {(e.entity_type, e.canonical_value) for e in entities}
    assert ("domain", "example.com") in values
    assert ("social_account", "tiktok:mpesacash247") in values
    assert ("social_account", "telegram:mpesaloanhelp") in values
    assert ("phone_number", "+254712345678") in values
    assert ("email", "help@example.com") in values
    assert sum(v == ("phone_number", "+254712345678") for v in values) == 1
    assert any(t == "app" for t, _ in values)


def test_crypto_wallets_are_typed_and_canonicalized():
    entities = extract_entities(
        "BTC 1BoatSLRHtKNngkdXEeobR76b53LETtpyT and ETH "
        "0x52908400098527886E0F7030069857D2E4169EE7"
    )
    values = {(entity.entity_type, entity.canonical_value) for entity in entities}
    assert ("wallet", "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT") in values
    assert ("wallet", "ethereum:0x52908400098527886e0f7030069857d2e4169ee7") in values


def test_relationship_requires_evidence_and_scoring_is_separate():
    with pytest.raises(ValueError):
        Relationship("i", "a", "b", "shares_phone", 0.9, "")
    ev = Evidence("i", "phone", "page", "observation", "+254700000000")
    rel = Relationship("i", "a", "b", "shares_phone", 1, ev.id)
    assert correlation_score([rel]) == 30 and correlation_label(30) == "Moderate"
    assert clusters(["a", "b"], [rel]) == [{"a", "b"}]
    ip = Relationship("i", "a", "b", "shares_ip", 1, ev.id)
    assert clusters(["a", "b"], [ip]) == []


def test_wallet_and_username_reuse_create_evidence_backed_edges():
    from investigation.correlation import correlate
    from investigation.models import Entity
    iid = 'investigation'
    domains = [Entity('domain', f'brand-{idx}.example', f'brand-{idx}.example') for idx in (1, 2)]
    wallet = Entity('wallet', 'ethereum:0xabc', '0xabc', 'ethereum')
    evidence = {}
    relationships = {}
    entities = {entity.id: entity for entity in [*domains, wallet]}
    for domain in domains:
        observation = Evidence(iid, wallet.id, 'safe_page', 'page_observation', wallet.display_value)
        evidence[observation.id] = observation
        edge = Relationship(iid, domain.id, wallet.id, 'contains_payment_identifier', .9, observation.id)
        relationships[edge.id] = edge
    correlate(iid, entities, evidence, relationships)
    derived = [edge for edge in relationships.values() if edge.relationship_type == 'shares_wallet']
    assert len(derived) == 1
    assert derived[0].evidence_id in evidence


def test_shared_asn_is_explained_but_stays_a_low_confidence_infrastructure_link():
    from investigation.correlation import correlate
    from investigation.models import Entity
    iid = 'investigation'
    left = Entity('domain', 'left.example', 'left.example')
    right = Entity('domain', 'right.example', 'right.example')
    ips = [Entity('ip_address', f'203.0.113.{n}', f'203.0.113.{n}') for n in (10, 11)]
    asn = Entity('asn', 'asn:64500', 'AS64500')
    entities = {row.id: row for row in (left, right, *ips, asn)}
    evidence, relationships = {}, {}
    for domain, ip in zip((left, right), ips):
        for source, target, relation_type, value in (
            (domain, ip, 'resolves_to', ip.canonical_value),
            (ip, asn, 'belongs_to', asn.canonical_value),
        ):
            observation = Evidence(iid, target.id, 'fixture', relation_type, value,
                                   raw_metadata={'observed_for': source.canonical_value})
            evidence[observation.id] = observation
            relation = Relationship(iid, source.id, target.id, relation_type, .9, observation.id)
            relationships[relation.id] = relation
    correlate(iid, entities, evidence, relationships)
    edge = next(row for row in relationships.values() if row.relationship_type == 'shares_asn')
    derived = evidence[edge.evidence_id]
    assert edge.confidence == .4
    assert len(derived.raw_metadata['supporting_evidence_ids']) == 4


def test_queue_dedupe_and_recursion_limits():
    q = InvestigationQueue(2)
    task = InvestigationTask("domain:a", 0, "web", priority=0.8)
    assert q.push(task) and not q.push(task)
    e = Entity("domain", "a.test", "a.test", metadata={"brand_relevance": 1})
    assert should_expand(e, task, Budgets(max_depth=1), {"entities": 1, "domain": 1})
    assert not should_expand(
        e,
        InvestigationTask(e.id, 1, "web"),
        Budgets(max_depth=1),
        {"entities": 1, "domain": 1},
    )


class Connector(DiscoveryConnector):
    name = "mock"

    def __init__(self, fail=False):
        self.fail = fail

    def is_configured(self):
        return True

    async def healthcheck(self):
        return ConnectorHealth(True, "operational")

    async def search(self, q, c):
        if self.fail:
            raise TimeoutError()
        return [
            DiscoveryResult(
                "https://mpesa-fastloan.test",
                text="https://tiktok.com/@mpesacash247 https://wa.me/254712345678",
                source=self.name,
            ),
            DiscoveryResult(
                "https://mpesa-credit-now.test",
                text="+254 712 345 678",
                source=self.name,
            ),
        ]


def test_integration_partial_failure_graph_and_verdict(tmp_path):
    store = InvestigationStore(tmp_path / "graph.db")
    result = asyncio.run(
        InvestigationEngine(store, [Connector(), Connector(True)]).investigate("M-PESA")
    )
    assert result["coverage"]["successful"] == ["mock"]
    assert result["coverage"]["failed"]
    graph = store.graph(result["id"])
    types = [n["entity_type"] for n in graph["nodes"]]
    assert (
        types.count("domain") == 2
        and "social_account" in types
        and "phone_number" in types
    )
    assert any(
        e["relationship_type"] == "shares_phone"
        and e["observed_value"] == "+254712345678"
        for e in graph["edges"]
    )
    phone = next(n for n in graph["nodes"] if n["entity_type"] == "phone_number")
    assert store.verdict(phone["id"], "suspicious", "reviewed", "alice")[
        "system_classification_unchanged"
    ]
    store.verdict(phone["id"], "benign", "cleared", "alice")
    row = store.conn.execute(
        "SELECT previous_verdict FROM analyst_verdicts ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row[0] == "suspicious"


def test_tiktok_capability_and_queries():
    class Search:
        async def search(self, q, c):
            return []

    connector = TikTokWebIndexConnector(Search())
    health = asyncio.run(connector.healthcheck())
    assert health.status == "web_index_only"
    entity = Entity("social_account", "tiktok:user", "@user", "tiktok")
    assert '"user" site:tiktok.com' in reverse_queries(entity, "M-PESA")


def test_secret_values_are_not_serialized_by_health_contract():
    health = ConnectorHealth(True, "degraded", detail="configured; verify on query")
    assert "secret" not in json.dumps(health.__dict__).lower()
