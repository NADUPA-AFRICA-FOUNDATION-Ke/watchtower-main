"""Full AcmePay fixture: real planner/service/storage, entirely offline adapters."""
import asyncio
import hashlib
import json
from pathlib import Path
from fastapi.testclient import TestClient
from investigation.models import Entity, Evidence, Relationship
from investigation.storage import InvestigationStore
from watchtower.discovery.base import DiscoveryProvider, ProviderRun, SourceHealth
from watchtower.discovery.safe_fetch import SafeFetchResult
from watchtower.engine.planner import InvestigationRequest
from watchtower.engine.service import InvestigationService
from watchtower.engine.reporting import report_html


class AcmeProvider(DiscoveryProvider):
    def __init__(self, name):
        self.name = name

    def capabilities(self):
        return ('open_web',) if self.name == 'duckduckgo' else ('registration',)

    async def discover(self, context):
        run = ProviderRun(SourceHealth(self.name, 'operational', ()))
        for value in ('acmepay-login.example', 'acmepay-help.example'):
            domain = Entity('domain', value, value)
            ev = Evidence(context.investigation_id, domain.id, self.name, 'discovery', value,
                          'https://' + value, {'title': 'AcmePay login'})
            run.entities.append(domain)
            run.evidence.append(ev)
        return run

    async def enrich(self, entity, context):
        if self.name == 'dns':
            raise TimeoutError('offline simulated source outage')
        entity.metadata['rdap'] = {'registration_date': '2026-09-20T00:00:00Z'}
        ev = Evidence(context.investigation_id, entity.id, self.name, 'rdap_observation', entity.canonical_value,
                      raw_metadata=entity.metadata['rdap'])
        return ProviderRun(SourceHealth(self.name, 'operational', ()), [entity], [ev])


class AcmeFetcher:
    def __init__(self, **kwargs):
        pass

    async def fetch(self, url):
        body = b'<html><title>AcmePay support</title><p>Pay processing fee to +254712345678. support@acme-help.example</p><form><input name="password" type="password"></form></html>'
        return SafeFetchResult(url, url, 200, 'text/html', body, [url])

    async def close(self):
        pass


def make_service(tmp_path):
    return InvestigationService(tmp_path / 'investigations.db', tmp_path / 'cache.db',
        {'max_page_fetches': 4, 'max_pivot_depth': 0},
        provider_factory=lambda definitions, cache: [AcmeProvider(d.id) for d in definitions],
        fetcher_factory=AcmeFetcher)


def test_acmepay_pipeline_and_immutable_snapshot(tmp_path, monkeypatch):
    monkeypatch.delenv('ABUSECH_AUTH_KEY', raising=False)
    service = make_service(tmp_path)
    request = InvestigationRequest(brand='AcmePay', sources=['duckduckgo', 'rdap', 'dns', 'safe_page', 'urlhaus'])
    result = asyncio.run(service.investigate(request))
    assert result['preflight']['missing_credentials'] == ('urlhaus',)
    assert result['campaigns']
    assert result['coverage']['full_source_coverage'] == '3/5'
    assert result['coverage']['failed'][0]['provider'] == 'dns'
    assert any(row['entity_type'] == 'phone_number' for row in result['entities'])
    assert any(edge['relationship_type'] == 'shares_phone' for edge in result['relationships'])
    evidence_ids = {e['id'] for e in result['evidence']}
    assert all(r['evidence_id'] in evidence_ids for r in result['relationships'])
    assert all(ev['content_hash'] and ev['retrieved_at'] for ev in result['evidence'])
    for score in result['scores'].values():
        for factor in score['factors']:
            assert factor['evidence_ids'] and set(factor['evidence_ids']) <= evidence_ids
    for ev in result['evidence']:
        if ev['raw_metadata'].get('derived'):
            assert set(ev['raw_metadata']['supporting_evidence_ids']) <= evidence_ids
    assert result['timeline'] and result['report']['limitations']
    assert 'Evidence' in report_html(result)
    stored = service.get(result['id'])
    assert stored['graph'] == result['graph']
    store = InvestigationStore(service.database)
    store.conn.execute("UPDATE entities SET metadata='{}'")
    store.conn.commit()
    assert store.graph(result['id']) == result['graph']
    store.conn.close()


def test_api_preflight_self_discovery_and_validation(tmp_path, monkeypatch):
    import web.app as app_module
    service = make_service(tmp_path)
    monkeypatch.setattr(app_module, 'investigation_service', lambda: service)
    # Existing router factory captures the original function, which resolves config
    # at request time. Point the production path helper at the same isolated DB.
    monkeypatch.setattr(app_module, 'DATA_DIR', tmp_path)
    with TestClient(app_module.app) as client:
        assert client.post('/api/investigations/preflight', json={'brand': 'AcmePay', 'market': 'invalid'}).status_code == 422
        sources = client.get('/api/mnara/discover?action=sources').json()['sources']
        assert any(row['id'] == 'dns' for row in sources)
        assert client.get('/api/mnara/discover?action=source&id=missing').status_code == 400
        response = client.post('/api/investigations', json={'brand': 'AcmePay', 'sources': ['duckduckgo', 'rdap', 'safe_page']})
        assert response.status_code == 200, response.text
        iid = response.json()['id']
        assert client.get(f'/api/investigations/{iid}/evidence').json()['evidence']
        assert client.get(f'/api/investigations/{iid}/report?format=html').status_code == 200
        assert client.get('/api/investigations/missing/evidence').status_code == 404
