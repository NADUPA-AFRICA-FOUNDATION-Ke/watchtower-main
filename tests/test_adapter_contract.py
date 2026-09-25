import asyncio
import httpx
import pytest
from watchtower.discovery.base import DiscoveryContext, DiscoveryProvider, ProviderRun, SourceHealth
from watchtower.engine.adapters import ProviderAdapter


class Fixture(DiscoveryProvider):
    name = 'fixture'

    def __init__(self, status='operational', error=None):
        self.status, self.error = status, error

    def capabilities(self):
        return ('open_web',)

    async def discover(self, context):
        if self.status == 'raise':
            raise RuntimeError('sensitive-token-do-not-log')
        if self.status == 'hang':
            await asyncio.sleep(10)
        return ProviderRun(SourceHealth(self.name, self.status, (), error=self.error))


@pytest.mark.parametrize('status,error,expected', [
    ('operational', None, 'success'), ('limited', None, 'partial'),
    ('provider_error', 'HTTP 429 token=secret', 'rate_limited'),
    ('provider_error', 'HTTP 403', 'unavailable'),
    ('provider_error', 'HTTP 404', 'failed'),
    ('provider_error', 'HTTP 500', 'failed'),
    ('raise', None, 'failed'), ('hang', None, 'failed'),
])
def test_envelope_preserves_failure_semantics_and_redacts(status, error, expected):
    result = asyncio.run(ProviderAdapter(Fixture(status, error), timeout=0.01).execute(
        'web_search', DiscoveryContext('i', 'AcmePay', 'AcmePay')))
    assert result.status == expected
    assert result.duration_ms >= 0
    assert 'sensitive-token' not in str(result.envelope())
    assert 'token=secret' not in str(result.envelope())


def test_missing_credentials_does_not_call_provider(monkeypatch):
    from watchtower.discovery.providers import URLhausProvider
    monkeypatch.delenv('ABUSECH_AUTH_KEY', raising=False)
    adapter = ProviderAdapter(URLhausProvider())
    result = asyncio.run(adapter.execute('threat_reputation', DiscoveryContext('i', 'AcmePay', 'AcmePay')))
    assert result.status == 'auth_missing'


def test_tls_rejects_private_address_before_connect(monkeypatch):
    from investigation.models import Entity
    from watchtower.discovery.providers import TLSProvider
    def fail(*args):
        pytest.fail('socket must not open')
    monkeypatch.setattr(TLSProvider, '_certificate', fail)
    result = asyncio.run(TLSProvider().enrich(Entity('domain', '127.0.0.1', 'local'), DiscoveryContext('i', 'a', 'a')))
    assert result.health.status == 'unavailable'


def test_robots_denial_prevents_page_request():
    from watchtower.discovery.safe_fetch import SafeFetcher
    calls = []
    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, headers={'content-type': 'text/plain'}, text='User-agent: *\nDisallow: /private')
    async def resolver(host):
        return ['93.184.216.34']
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await SafeFetcher(client, resolver=resolver, delay=0).fetch('https://public.test/private')
    result = asyncio.run(run())
    assert 'robots' in result.error
    assert calls == ['/robots.txt']
