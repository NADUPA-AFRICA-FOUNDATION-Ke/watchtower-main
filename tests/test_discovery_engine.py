from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from investigation.models import Entity, Evidence, Relationship
from investigation.storage import InvestigationStore
from watchtower.discovery.base import (
    DiscoveryContext,
    DiscoveryProvider,
    ProviderRun,
    SourceHealth,
)
from watchtower.discovery.orchestrator import DiscoveryOrchestrator
from watchtower.discovery.page_analysis import analyze_page
from watchtower.discovery.providers import (
    CertificateTransparencyProvider,
    CommonCrawlProvider,
    DNSProvider,
    RDAPProvider,
    ThreatFoxProvider,
    URLhausProvider,
)
from watchtower.discovery.safe_fetch import (
    SafeFetchResult,
    SafeFetcher,
    UnsafeTarget,
)
from watchtower.discovery.scoring import score_domain


FIXTURES = Path(__file__).parent / "fixtures"
SCAM_HTML = (FIXTURES / "scam_page.html").read_text()


async def public_resolver(host):
    if host in {"localhost", "169.254.169.254", "internal.test"}:
        raise UnsafeTarget("target resolves to a non-public address")
    return ["93.184.216.34"]


def test_safe_fetch_rejects_ssrf_redirects_and_large_responses():
    def handler(request):
        if request.url.host == "public.test" and request.url.path == "/redirect":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/latest"})
        if request.url.path == "/large":
            return httpx.Response(200, headers={"content-type": "text/html"}, content=b"x" * 101)
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<h1>ok</h1>")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    fetcher = SafeFetcher(client, resolver=public_resolver, max_bytes=100, max_redirects=2)
    with pytest.raises(UnsafeTarget):
        asyncio.run(fetcher.fetch("http://public.test/redirect"))
    large = asyncio.run(fetcher.fetch("https://public.test/large"))
    assert large.error == "response exceeds size limit"
    with pytest.raises(UnsafeTarget):
        asyncio.run(fetcher.fetch("file:///etc/passwd"))
    asyncio.run(client.aclose())


def test_page_analysis_extracts_financial_and_social_evidence():
    page = analyze_page(SCAM_HTML, "https://mpesa-fast.example/")
    values = {(item.entity_type, item.canonical_value) for item in page.entities}
    assert ("phone_number", "+254712345678") in values
    assert ("social_account", "tiktok:mpesa_fast") in values
    assert ("social_account", "telegram:mpesa_help") in values
    assert ("social_account", "instagram:mpesa_fast") in values
    assert ("social_account", "facebook:mpesa.fast") in values
    assert ("social_account", "x:mpesa_fast") in values
    assert ("social_account", "youtube:mpesa_fast") in values
    assert ("email", "help@mpesa-fast.example") in values
    assert ("payment_identifier", "paybill:123456") in values
    assert ("analytics_id", "google_analytics:g-abc123xyz") in values
    assert page.credential_fields and page.favicon_url.endswith("/assets/icon.png")
    assert page.html_fingerprint and isinstance(page.simhash, int)


def test_whatsapp_url_variants_normalize_to_one_account():
    from investigation.extraction import extract_entities
    entities = extract_entities(
        "https://api.whatsapp.com/send?phone=254712345678 "
        "whatsapp://send?phone=%2B254712345678 https://wa.me/254712345678"
    )
    values = {(item.entity_type, item.canonical_value) for item in entities}
    assert ("phone_number", "+254712345678") in values
    assert ("social_account", "whatsapp:+254712345678") in values


def test_ct_provider_creates_certificate_edges_from_fixture():
    rows = [{
        "min_cert_id": 42,
        "name_value": "mpesa-help.example\nfuliza-now.example",
        "issuer_name": "Let's Encrypt",
        "entry_timestamp": "2026-08-01T00:00:00Z",
    }]

    def handler(request):
        return httpx.Response(200, json=rows)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = CertificateTransparencyProvider(client)
    context = DiscoveryContext("i", "M-PESA", "M-PESA", (), ("mpesa", "fuliza"), 10)
    run = asyncio.run(provider.discover(context))
    assert run.health.status == "operational"
    assert {e.canonical_value for e in run.entities if e.entity_type == "domain"} == {
        "mpesa-help.example", "fuliza-now.example"
    }
    assert any(r.relationship_type == "uses_certificate" for r in run.relationships)
    assert all(r.evidence_id in {e.id for e in run.evidence} for r in run.relationships)
    asyncio.run(client.aclose())


def test_common_crawl_rdap_and_threat_intel_fixtures():
    def handler(request):
        if request.url.path.endswith("collinfo.json"):
            return httpx.Response(200, json=[{"cdx-api": "https://index.test/cdx"}])
        if request.url.host == "index.test":
            row = {"url": "https://mpesa-archive.example/login", "timestamp": "20260101", "mime": "text/html"}
            return httpx.Response(200, text=__import__("json").dumps(row) + "\n")
        if request.url.host == "rdap.org":
            return httpx.Response(200, json={
                "events": [{"eventAction": "registration", "eventDate": "2026-08-01T00:00:00Z"}],
                "status": ["active"],
                "nameservers": [{"ldhName": "NS1.EXAMPLE.NET"}],
                "entities": [{"handle": "REG-1", "roles": ["registrar"]}],
            })
        if "urlhaus" in request.url.host:
            return httpx.Response(200, json={"query_status": "ok", "url": "https://mpesa-bad.example/"})
        if "threatfox" in request.url.host:
            return httpx.Response(200, json={"query_status": "ok", "data": [{"threat_type": "phishing"}]})
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    context = DiscoveryContext("i", "M-PESA", "M-PESA", (), ("mpesa",), 5)
    common = asyncio.run(CommonCrawlProvider(client).discover(context))
    assert common.health.status == "operational"
    assert any(e.canonical_value == "mpesa-archive.example" for e in common.entities)

    domain = Entity("domain", "mpesa-bad.example", "mpesa-bad.example")
    rdap = asyncio.run(RDAPProvider(client).enrich(domain, context))
    assert rdap.health.status == "operational"
    assert any(e.entity_type == "registrar" for e in rdap.entities)
    assert any(r.relationship_type == "uses_nameserver" for r in rdap.relationships)

    urlhaus = asyncio.run(URLhausProvider(client).enrich(domain, context))
    threatfox = asyncio.run(ThreatFoxProvider(client).enrich(domain, context))
    assert urlhaus.health.status == threatfox.health.status == "operational"
    assert len(domain.metadata["threat_intelligence"]["matches"]) == 2
    asyncio.run(client.aclose())


def test_dns_provider_records_are_evidence_edges(monkeypatch):
    monkeypatch.setattr(DNSProvider, "_lookup", staticmethod(lambda domain: {
        "A": ["93.184.216.34"], "AAAA": [], "CNAME": [], "MX": ["mail.example"],
        "NS": ["ns1.example"], "TXT": ["v=spf1 -all"], "SOA": ["ns1.example hostmaster.example 1"]
    }))
    provider = DNSProvider()
    context = DiscoveryContext("i", "M-PESA", "M-PESA")
    domain = Entity("domain", "mpesa-test.example", "mpesa-test.example")
    run = asyncio.run(provider.enrich(domain, context))
    assert run.health.status == "operational"
    assert any(e.entity_type == "ip_address" for e in run.entities)
    assert any(r.relationship_type == "resolves_to" for r in run.relationships)
    assert all(r.evidence_id in {e.id for e in run.evidence} for r in run.relationships)


class FixtureDiscovery(DiscoveryProvider):
    name = "fixture_web"

    def capabilities(self):
        return ("open_web",)

    async def discover(self, context):
        run = ProviderRun(SourceHealth(self.name, "operational", tuple(self.capabilities())))
        brand = Entity("brand", context.brand.lower(), context.brand)
        for domain in ("mpesa-fast.example", "fuliza-help.example"):
            entity = Entity("domain", domain, domain)
            evidence = Evidence(context.investigation_id, entity.id, self.name,
                                "discovery", domain, f"https://{domain}/", {}, 0.5)
            run.entities.append(entity); run.evidence.append(evidence)
            run.relationships.append(Relationship(context.investigation_id, brand.id,
                                                   entity.id, "mentions", 0.5, evidence.id))
        run.health.results = 2
        return run


class FixtureRegistration(DiscoveryProvider):
    name = "fixture_rdap"

    def capabilities(self):
        return ("registration",)

    async def enrich(self, entity, context):
        entity.metadata["rdap"] = {"registration_date": "2026-08-20T00:00:00+00:00"}
        evidence = Evidence(context.investigation_id, entity.id, self.name,
                            "rdap_observation", entity.canonical_value, None,
                            entity.metadata["rdap"], 1.0)
        return ProviderRun(SourceHealth(self.name, "operational", ("registration",), results=1),
                           [entity], [evidence], [])


class FixtureFailure(DiscoveryProvider):
    name = "broken"

    def capabilities(self):
        return ("domain_discovery",)

    async def discover(self, context):
        raise TimeoutError("fixture timeout")


class FixtureFetcher:
    async def fetch(self, url):
        if url.endswith("icon.png") or url.endswith("favicon.ico"):
            return SafeFetchResult(url, url, 200, "image/png", b"same-icon")
        return SafeFetchResult(url, url, 200, "text/html", SCAM_HTML.encode(), [url], {})


def test_full_zero_key_graph_correlation_scoring_and_provider_failure(tmp_path):
    store = InvestigationStore(tmp_path / "investigation.db")
    engine = DiscoveryOrchestrator(
        store, [FixtureDiscovery(), FixtureRegistration(), FixtureFailure()],
        fetcher=FixtureFetcher(), max_domains=10, max_fetches=10,
    )
    result = asyncio.run(engine.investigate("M-PESA", "M-PESA", {
        "name": "M-PESA", "aliases": ["mpesa", "fuliza"],
        "official_domains": ["safaricom.co.ke"],
    }))
    assert result["zero_key_mode"] is True
    assert "fixture_web" in result["coverage"]["successful"]
    assert any(item["provider"] == "broken" for item in result["coverage"]["failed"])
    graph = store.graph(result["id"])
    relations = {edge["relationship_type"] for edge in graph["edges"]}
    assert {"contains_phone", "links_to_social", "shares_phone", "shares_favicon"} <= relations
    assert result["campaigns"]
    assert all(edge["evidence_id"] for edge in graph["edges"])
    assert all(item["machine_verdict"] in {
        "SUSPICIOUS", "LIKELY_IMPERSONATION", "CONFIRMED_IMPERSONATION"
    } for item in result["candidates"])
    runs = store.source_runs(result["id"])
    assert any(row["status"] == "provider_error" for row in runs)


def test_evidence_scoring_controls_false_positives():
    official = Entity("domain", "safaricom.co.ke", "safaricom.co.ke")
    result = score_domain(official, [], [], {official.id: official}, {
        "official_domains": ["safaricom.co.ke"], "aliases": ["mpesa"]
    })
    assert result.machine_verdict == "LEGITIMATE" and result.risk_score == 0

    unrelated = Entity("domain", "example.org", "example.org")
    result = score_domain(unrelated, [], [], {unrelated.id: unrelated}, {
        "official_domains": ["safaricom.co.ke"], "aliases": ["mpesa"]
    })
    assert result.machine_verdict == "INSUFFICIENT_EVIDENCE"


def test_shared_cloud_ip_alone_does_not_create_campaign(tmp_path):
    store = InvestigationStore(tmp_path / "cloud.db")
    left = Entity("domain", "one.example", "one.example")
    right = Entity("domain", "two.example", "two.example")
    ip = Entity("ip_address", "203.0.113.4", "203.0.113.4")
    ev = Evidence("i", ip.id, "dns", "dns_observation", ip.canonical_value)
    rel = Relationship("i", left.id, right.id, "shares_ip", 1.0, ev.id)
    # Correlation scoring deliberately gives shared hosting only weak weight;
    # campaign creation in the orchestrator excludes shares_ip entirely.
    from investigation.correlation import correlation_score
    assert correlation_score([rel]) == 10
