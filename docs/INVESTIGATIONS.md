# Mnara investigations

Mnara's investigation engine lives alongside the existing monitoring and scam
scanning workflows. The Python web API and optional MCP server share the same
`InvestigationService`, planner, source registry, adapters, and storage.

## Investigation workflow

An `InvestigationRequest` is validated, preflighted against enabled sources and
credentials, planned by capability, and executed with bounded concurrency. Each
adapter returns a status envelope; one source failure does not abort collection.
Results are normalized into entities and evidence with source provenance and a
content hash. Deterministic correlations, evidence-linked scoring, campaign
grouping, source coverage, and a report are persisted as an investigation
snapshot. Recheck and enrichment use the same service path.

The registry is the source catalogue: `watchtower/registry/catalog.py`. Add an
adapter and metadata entry there rather than adding provider-name branches to
the planner. Optional integrations with credentials remain unavailable until
their configured key is present. The application starts and investigates
without paid API keys.

## HTTP API

- `POST /api/investigations/preflight` — validate and preview sources.
- `POST /api/investigations` — create an investigation.
- `GET /api/investigations` — list stored investigations.
- `GET /api/investigations/{id}/snapshot` — retrieve the persisted report view.
- `GET /api/investigations/{id}/entities`, `/evidence`, `/coverage`, `/timeline`,
  `/graph`, and `/report` — retrieve investigation components.
- `POST /api/investigations/{id}/enrich` and `/recheck` — run bounded follow-up
  collection.
- `GET /api/mnara/discover` — inspect source and capability metadata.
- `GET /api/sources/health` — inspect source configuration and last health state.
- `/api/monitors` — create and manage scheduled investigation checks.

These routes use the application's existing authentication middleware.

## MCP and monitoring worker

MCP is optional so it does not add a runtime dependency to the web application.
Install `requirements-mcp.txt`, then run `python -m watchtower.mcp_server` for a
stdio server. The MCP tools call the same investigation service as HTTP.

Scheduled monitor records are durable, but checks only run when a worker is
scheduled. Run `python -m watchtower.engine.monitoring` as a recurring worker
(at least hourly); do not run overlapping unbounded pollers. A hosted scheduler
can invoke that command. Configure `ABUSECH_AUTH_KEY` to enable the free-key
URLhaus and ThreatFox feeds; without it they are reported as requiring a key.

## Coverage and confidence

Coverage is collection completeness, not threat risk. The investigation records
requested, attempted, successful, partial, failed, unavailable, rate-limited,
and credential-missing sources. A successful search with no findings remains
distinct from a source that was not searched or could not run. Risk factors and
relationships link to evidence IDs; reports preserve retrieved and source
publication dates separately. Source health is `unknown` until a check or run
provides an observation, and the UI labels it as unverified.
