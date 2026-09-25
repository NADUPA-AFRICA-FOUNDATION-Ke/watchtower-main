"""One catalogue for investigation and compatibility monitor sources."""
from .models import SourceDefinition, SourceRegistry

P = 'watchtower.discovery.providers:'


def source(id: str, cls: str, category: str, capabilities: str, *,
           phase: str = 'discovery', inputs: str = 'brand', enable: str = '',
           access: str = 'no_key', keys: tuple[str, ...] = (), default: bool = True,
           description: str = '') -> SourceDefinition:
    return SourceDefinition(id, id.replace('_', ' ').title(), category,
                            description or f'Public {category} observations; availability verified per run',
                            tuple(capabilities.split()), P + cls, access, keys,
                            enable_env=enable, default=default, phase=phase,
                            input_types=tuple(inputs.split()), evidence_types={
                                'rdap': ('rdap_observation',), 'dns': ('dns_observation',),
                                'tls': ('tls_certificate',), 'ip_asn': ('asn_observation',),
                                'urlhaus': ('threat_intelligence',), 'threatfox': ('threat_intelligence',),
                                'social_web_index': ('social_index_observation',),
                            }.get(id, ('discovery',)))


DISCOVERY = (
    source('duckduckgo', 'DuckDuckGoProvider', 'search', 'web_search keyword_search url_discovery', enable='ENABLE_DUCKDUCKGO'),
    source('social_web_index', 'SocialWebIndexProvider', 'social', 'social_mentions post_search username_lookup phone_search email_search', enable='ENABLE_SOCIAL_WEB_INDEX',
           description='Indexed public social links; does not search private or authenticated platform content'),
    source('certificate_transparency', 'CertificateTransparencyProvider', 'certificate', 'certificate_search subdomain_discovery domain_search', enable='ENABLE_CT'),
    source('common_crawl', 'CommonCrawlProvider', 'archive', 'historical_web url_discovery', enable='ENABLE_COMMONCRAWL'),
    source('rdap', 'RDAPProvider', 'domain', 'domain_metadata domain_registration', phase='enrichment', inputs='domain', enable='ENABLE_RDAP'),
    source('dns', 'DNSProvider', 'dns', 'dns_lookup', phase='enrichment', inputs='domain', enable='ENABLE_DNS'),
    source('tls', 'TLSProvider', 'certificate', 'certificate_search', phase='enrichment', inputs='domain', enable='ENABLE_TLS'),
    source('ip_asn', 'IPASNProvider', 'domain', 'ip_lookup asn_lookup', phase='enrichment', inputs='ip_address', enable='ENABLE_IP_ASN'),
    source('urlhaus', 'URLhausProvider', 'threat_intel', 'threat_reputation', phase='enrichment', inputs='domain url', access='free_key', keys=('ABUSECH_AUTH_KEY',), enable='ENABLE_URLHAUS'),
    source('threatfox', 'ThreatFoxProvider', 'threat_intel', 'threat_reputation', phase='enrichment', inputs='domain url', access='free_key', keys=('ABUSECH_AUTH_KEY',), enable='ENABLE_THREATFOX'),
    source('bluesky_public', 'BlueskyPublicProvider', 'social', 'post_search social_mentions', default=False),
    source('mastodon_public', 'MastodonPublicProvider', 'social', 'post_search social_mentions', default=False),
)

# Names remain stable for stored CLI jobs. Metadata is no longer copied in web routes.
MONITOR_ROWS = (
    ('gdelt', 'gdelt', 'search', 'no_key', (), True),
    ('google_news', 'google_news', 'search', 'no_key', (), True),
    ('wikipedia', 'wikipedia', 'other', 'no_key', (), True),
    ('hackernews', 'hackernews', 'social', 'no_key', (), True),
    ('gleif', 'gleif', 'other', 'no_key', (), True),
    ('sec_edgar', 'sec_edgar', 'other', 'no_key', (), True),
    ('opensanctions', 'opensanctions', 'other', 'free_key', ('OPENSANCTIONS_API_KEY',), True),
    ('opencorporates', 'opencorporates', 'other', 'paid', ('OPENCORPORATES_API_KEY',), True),
    ('reddit', 'reddit', 'social', 'free_key', ('REDDIT_CLIENT_ID', 'REDDIT_CLIENT_SECRET'), True),
    ('x', 'x_twitter', 'social', 'paid', ('X_BEARER_TOKEN',), True),
    ('socialcrawl', 'socialcrawl', 'social', 'paid', ('SOCIALCRAWL_API_KEY',), False),
    ('web_search', 'web_search', 'search', 'paid', ('BRAVE_API_KEY',), False),
    ('mastodon', 'mastodon', 'social', 'no_key', (), False),
    ('bluesky', 'bluesky', 'social', 'no_key', (), False),
)
MONITOR = tuple(SourceDefinition(
    id, id.replace('_', ' ').title(), category, 'Existing monitor search adapter',
    ('keyword_search',), 'core.sources:' + function, access, keys,
    default=default, surface='monitor',
) for id, function, category, access, keys, default in MONITOR_ROWS)
SAFE_PAGE = SourceDefinition(
    'safe_page', 'Public page inspection', 'web', 'Robots-aware bounded public page inspection',
    ('web_scrape', 'page_text', 'redirect_chain', 'favicon_hash', 'credential_form_detection', 'link_extraction'),
    'watchtower.discovery.safe_fetch:SafeFetcher', input_types=('domain', 'url'), phase='inspection',
)
OPEN_SOURCES = (
    SourceDefinition('github_public', 'GitHub public repositories', 'code', 'Public repository search, not authenticated code search',
                     ('repository_search',), 'watchtower.discovery.open_sources:GitHubPublicProvider',
                     default=False, requests=1, window_seconds=6),
    SourceDefinition('wayback', 'Internet Archive', 'archive', 'Historical public URL captures',
                     ('historical_web', 'url_discovery'), 'watchtower.discovery.open_sources:WaybackProvider',
                     default=False, input_types=('domain',), phase='enrichment'),
)
REGISTRY = SourceRegistry((*DISCOVERY, *MONITOR, SAFE_PAGE, *OPEN_SOURCES))
