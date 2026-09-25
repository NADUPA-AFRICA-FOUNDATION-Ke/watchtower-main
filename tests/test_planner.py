from dataclasses import replace
import pytest
from pydantic import ValidationError
from watchtower.engine.planner import InvestigationRequest, QueryPlanner
from watchtower.registry import REGISTRY, SourceRegistry
from watchtower.engine.coverage import coverage
from watchtower.discovery.base import SourceHealth


def test_plan_free_first_and_credentials_visible():
    plan = QueryPlanner().plan(InvestigationRequest(brand='AcmePay'), {})
    assert 'dns' in plan.selected
    assert 'urlhaus' in plan.missing_credentials
    assert 'threatfox' in plan.missing_credentials
    assert 'socialcrawl' not in plan.selected
    assert plan.can_proceed
    disabled = QueryPlanner().plan(InvestigationRequest(brand='AcmePay', sources=['dns']), {'ENABLE_DNS': 'false'})
    assert not disabled.can_proceed
    assert disabled.unavailable == ('dns',)


def test_domain_and_phone_plans_do_not_blast_every_source():
    planner = QueryPlanner()
    domain = planner.plan(InvestigationRequest(brand='acmepay.example'), {})
    assert domain.target_type == 'domain'
    assert 'duckduckgo' not in domain.selected and 'rdap' in domain.selected
    phone = planner.plan(InvestigationRequest(brand='+254700000000', enrich=False), {})
    assert 'certificate_transparency' not in phone.selected
    assert 'social_web_index' in phone.selected


def test_market_filter_and_validation():
    source = replace(REGISTRY.get('dns'), markets=('KE',))
    planner = QueryPlanner(SourceRegistry((source,)))
    assert planner.plan(InvestigationRequest(brand='example.test', market='Kenya'), {}).can_proceed
    assert not planner.plan(InvestigationRequest(brand='example.test', market='US'), {}).can_proceed
    with pytest.raises(ValidationError):
        InvestigationRequest(brand='AcmePay', market='imaginary')
    with pytest.raises(ValidationError):
        InvestigationRequest(brand='AcmePay', lookback_days=-1)
    with pytest.raises(ValueError, match='unknown source'):
        QueryPlanner().plan(InvestigationRequest(brand='AcmePay', sources=['imaginary']))


def test_coverage_requires_all_operations_to_succeed():
    result = coverage(['dns', 'rdap', 'urlhaus', 'tls'], [
        SourceHealth('dns', 'operational', ()), SourceHealth('dns', 'timeout', ()),
        SourceHealth('rdap', 'operational', (), results=0),
        SourceHealth('urlhaus', 'auth_missing', ()),
    ])
    assert result['successful'] == ['rdap']  # confirmed no result is a successful call
    assert result['partial'][0]['provider'] == 'dns'
    assert result['missing_credentials'][0]['provider'] == 'urlhaus'
    assert result['not_searched'][0]['provider'] == 'tls'
    assert result['full_source_coverage'] == '1/4'
    assert result['coverage_percentage'] == 25
