import asyncio
import pytest
from pydantic import ValidationError
from test_engine_e2e import make_service
from watchtower.engine.monitoring import MonitorRequest, MonitorService, compare
from watchtower.engine.planner import InvestigationRequest


def test_monitor_intervals_leases_and_failure_visibility(tmp_path):
    service = make_service(tmp_path)
    monitors = MonitorService(service)
    request = InvestigationRequest(brand='AcmePay', sources=['duckduckgo', 'rdap', 'safe_page'])
    with pytest.raises(ValidationError):
        MonitorRequest(investigation=request, interval_seconds=1)
    row = monitors.create(MonitorRequest(investigation=request, interval_seconds=3600))
    assert asyncio.run(monitors.run_due()) == []
    with monitors.connect() as conn:
        conn.execute('UPDATE investigation_monitors SET next_run=0')
    first = asyncio.run(monitors.run_due())
    assert len(first) == 1 and first[0]['changes'][0]['event'] == 'baseline_recorded'
    assert asyncio.run(monitors.run_due()) == []
    monitors.set_enabled(row['id'], False)
    assert monitors.list_monitors()[0]['enabled'] == 0


def test_enrichment_uses_same_service_without_discovery(tmp_path):
    service = make_service(tmp_path)
    result = asyncio.run(service.investigate(InvestigationRequest(brand='AcmePay', sources=['duckduckgo'])))
    hydrated = asyncio.run(service.enrich(result['id'], ['rdap', 'safe_page']))
    assert hydrated['id'] != result['id']
    assert 'duckduckgo' not in hydrated['coverage']['requested']
    assert hydrated['evidence'] and hydrated['candidates']


def test_mcp_schema_and_shared_service(tmp_path):
    pytest.importorskip('mcp')
    from watchtower.mcp_server import create_mcp
    service = make_service(tmp_path)
    mcp = create_mcp(lambda: service)
    tools = asyncio.run(mcp.list_tools())
    assert {t.name for t in tools} == {'mnara_discover', 'mnara_hunt', 'mnara_enrich', 'mnara_correlate',
        'mnara_investigate', 'mnara_evidence', 'mnara_sources', 'mnara_coverage', 'mnara_monitor'}
    result = asyncio.run(mcp.call_tool('mnara_discover', {'action': 'sources'}))
    assert 'dns' in str(result)
