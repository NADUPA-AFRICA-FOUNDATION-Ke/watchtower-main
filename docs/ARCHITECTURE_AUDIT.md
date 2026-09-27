# Mnara incremental architecture audit — 2026-09-25

This is the implementation map, recorded before architectural edits. Existing
uncommitted UI resilience fixes are preserved. No deployment is part of this migration.

## Actual call paths

- FastAPI `web/app.py` serves vanilla HTML/CSS/JS; no frontend build step.
- Monitor: JS EventSource -> `/api/sweep` -> `core.sweep.sweep` ->
  `core.sources.BACKENDS` -> synchronous `Fetcher` -> `Item` -> keyword / optional
  Gemini or Anthropic enrichment -> SQLite FTS archive and HTML/Markdown report.
  SourceSkipped and SourceError reach SSE separately from zero results.
- Investigate: JS POST `/api/investigations` -> default_providers ->
  DiscoveryOrchestrator -> discover -> domain enrichment -> safe page inspection ->
  bounded reverse pivots -> exact correlation -> score_domain -> SQLite graph.
  Existing ProviderRun contains Entity/Evidence/Relationship objects. Keep these.
- Quick score -> scamscan.score_finding (offline). Live URL scan -> SafeFetcher
  through the web route. Hunt -> scamscan.hunt -> paid model search -> separate
  scamscan.db. Preserve its config, scoring and review queue.
- `investigation.InvestigationEngine` is an older connector pipeline, imported
  by its compatibility API and tests only. Do not add new production callers.
- `/api/discover` and `/api/discover_async` expose older discovery pipelines;
  keep compatibility until service-backed replacements have tests.
- `enrichment/engine.py` has no production caller, duplicates provider logic and
  includes placeholders. Deprecate for new use; do not route new work into it.

## Source behavior traced

| Source / entry | Request and normalization | Failure / credentials / bounds | Consumer / storage |
| --- | --- | --- | --- |
| DuckDuckGoProvider | ddgs through osint_discovery; rows -> domain evidence | empty marked limited, exceptions provider_error; no key; serialized searches, TTL | investigation graph/cache |
| SocialWebIndexProvider | indexed public platform links -> social posts/accounts | restricted to public indexes, partial status; no direct platform auth bypass | investigation/social UI |
| CT | crt.sh JSON -> domains/certificates | HTTP and malformed responses; no key; throttle/cache | graph |
| Common Crawl | index selection + NDJSON -> domains | HTTP errors, 404 empty, cache/throttle | graph |
| RDAP | rdap.org -> registration metadata, nameservers, registrar | 404 no record; other errors; redirects need safe handling | graph/cache |
| DNS | dnspython A/AAAA/CNAME/MX/NS/TXT/SOA -> entities | currently swallows query failures (gap); per-query timeout/cache | graph |
| TLS | socket:443 -> certificate digest/SAN | currently connects without pinned public IP (gap) | graph |
| IP ASN | Team Cymru DNS -> ASN entity | lookup error -> unavailable | graph |
| URLhaus / ThreatFox | POST -> reputation evidence | currently incorrectly no-key; Auth-Key required; errors flattened | graph/cache |
| Bluesky/Mastodon public providers | public search JSON -> social entities | instance dependent, opt-in; not defaults | retained providers |
| core.sources news/reference | GDELT JSON, Google RSS, Wikipedia, HN, SEC, GLEIF -> Item | SourceError / SourceSkipped; Fetcher retries and host throttle | monitor/archive |
| core.sources social/keyed | indexed social, Reddit OAuth pair, X bearer, SocialCrawl, OpenSanctions, OpenCorporates | explicit credential requirements; paid optional | monitor/archive |
| legacy Brave/Bluesky/Mastodon | retained explicit monitor backends | retired from defaults; compatibility only | CLI jobs |
| scheduled adapters | RSS, GDELT, webpages, Reddit -> Item | isolate per feed; robots, retention, seen URL dedupe | run.py collect/enrich/alert |

## Persistence and boundaries

SQLite databases: watchtower.db (FTS), scamscan.db, investigations.db (entities,
evidence, relationships, scores, campaigns, source_runs, verdicts), provider-cache.db
(TTL). Investigation graph currently joins mutable global entity metadata, so old
investigations may show later scores. Evidence lacks a content hash and distinct
retrieval/publication timestamps. Correlations cite derived evidence but not always
its supporting observations. Coverage counts any success even with failed sibling
calls. Page fetches are missing from source coverage. Fix incrementally.

Authentication is HTTP Basic with constant-time comparison; public binds fail closed
without WATCHTOWER_PASSWORD. Hosted ephemeral storage disables durable review actions.
Environment/config: config.yaml, config.json, .env.example; optional AI keys.
CI runs pytest + fatal flake8 + compileall on Python 3.10. No typecheck/MCP exists.
Docker Python 3.11, Railway and Vercel configs coexist. User identifies Render service
srv-daat15ijnfac73fdt6bg; no authenticated host access available in this session.
CLI scheduled collection exists; no investigation-aware durable scheduler/worker.

## Decisions

KEEP: existing entities/evidence/SQLite, safe fetcher, deterministic scoring,
monitor/scamscan public interfaces, provider extraction, report escaping.
REFACTOR: metadata into one registry; capability planning; source statuses/coverage;
service lifecycle; evidence-backed scores; immutable investigation snapshots.
WRAP: existing DiscoveryProvider and core source functions behind common contract.
DEPRECATE: old connector orchestrator and experimental discovery for new callers.
REMOVE: no working path until a tested replacement exists.

Dependency order: registry -> adapter contract/planner/preflight -> provider wrapping
and accurate coverage -> evidence/enrichment/correlation -> shared service/API/MCP ->
reports/rechecks/monitors -> investigation UI -> adversarial and end-to-end checks.

## Re-audit after initial implementation

The first implementation did not satisfy several stated interactions. A second
pass found and corrected these concrete gaps: domain and URL seeds did not plan
discovery providers; email, phone and username requests were labeled as brands
and never created typed seed evidence; the campaign Evidence button referenced
an undefined function; HTML reports omitted infrastructure/social/campaign
context; wallet addresses were not extracted; campaign detail routing was
shadowed by an older handler; and same-ASN relationships lost their underlying
IP evidence. Those now have implementation and focused regression coverage.
Campaign details preserve the legacy response fields while exposing supporting
links; ASNs remain explicitly low-confidence infrastructure context. The
connection panel now has an interactive, keyboard-operable SVG view alongside
its evidence table. Phone, email, username, domain, URL and IP seeds are
canonicalized and retained as typed evidence.

The remaining target items are still partial and should not be represented as
done:

| Requirement | Current boundary |
| --- | --- |
| Live source health probes | Health combines declared config and last persisted run. No scheduled active health probes yet; untested sources correctly remain `unknown`. |
| Source catalog completeness | Existing and implemented adapters are registered, but the long-tail capability names (screenshots, page technology detection, phone/email OSINT outside public indexing, credential-form reputation, etc.) do not all have adapters. |
| Correlation and campaign analysis | Deterministic exact-identifier relations and conservative components exist. Several requested signals (analytics IDs, favicon/page-template similarity, wallet reuse) are not all wired into campaign scoring. |
| Monitoring operations | SQLite records and a bounded due-work command exist, but this Render service has no separately provisioned scheduled worker. Rechecks therefore require an external scheduler. |
| Storage and retention | Investigation evidence/snapshots are SQLite-backed. There is no retention policy, evidence blob store, or production Postgres migration. Render persistence depends on the service's configured disk/data directory. |
| Graph interaction | The UI supports filtering, selecting, and expanding visible nodes in a bounded SVG/list view. It is a small-graph view, not a layout engine for large investigations. |
| Report coverage | Structured evidence, coverage, source limitations, timeline, infrastructure, social links, and campaign context are included. Analyst verdict capture and report export formats beyond JSON/HTML remain in the legacy workflow. |
| CI/type checks | Repository CI currently gates syntax, fatal flake8 rules, and pytest. A scoped mypy check passes for the new engine modules; the whole repository is not mypy-clean. |
| Deployment | Source was pushed to `main`; the Render deployment status could not be read without Render credentials. |
