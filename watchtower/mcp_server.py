"""Local stdio MCP interface. No business logic or network listener lives here.

Run with Python >=3.10 and requirements-mcp.txt installed:
    python -m watchtower.mcp_server
"""
from __future__ import annotations
from typing import Callable, Optional
from mcp.server.fastmcp import FastMCP
from watchtower.engine.runtime import create_service
from watchtower.engine.planner import InvestigationRequest
from watchtower.engine.monitoring import MonitorRequest, MonitorService


def create_mcp(factory: Callable = create_service) -> FastMCP:
    mcp = FastMCP('Mnara', instructions='Evidence-first public-source investigations. Coverage is not risk. Never infer ownership or criminality from similarity alone.')

    @mcp.tool()
    def mnara_discover(action: str = 'sources', id: Optional[str] = None, search: str = '') -> dict:
        """Describe sources, capabilities, source, investigation_types, evidence_types, coverage, health or freshness."""
        return factory().discover(action, id, search)

    @mcp.tool()
    async def mnara_investigate(request: InvestigationRequest) -> dict:
        """Run a bounded investigation and return evidence, coverage, graph and report."""
        return await factory().investigate(request)

    @mcp.tool()
    async def mnara_hunt(request: InvestigationRequest) -> dict:
        """Capability-planned discovery; paid sources require explicit allow_paid."""
        return await factory().investigate(request)

    @mcp.tool()
    async def mnara_enrich(investigation_id: str, include: Optional[list[str]] = None) -> dict:
        """Hydrate discovered entities into a new immutable investigation snapshot."""
        return await factory().enrich(investigation_id, include)

    @mcp.tool()
    def mnara_correlate(investigation_id: str) -> dict:
        """Read persisted, evidence-backed correlations; never invent relationships."""
        result = factory().get(investigation_id)
        return {'relationships': result['graph']['edges'], 'campaigns': result.get('campaigns', [])}

    @mcp.tool()
    def mnara_evidence(investigation_id: str) -> dict:
        """Read immutable source observations with retrieval times and content hashes."""
        return {'evidence': factory().get(investigation_id)['evidence']}

    @mcp.tool()
    def mnara_sources() -> dict:
        """List source capabilities, access requirements and observed health."""
        return factory().discover('health')

    @mcp.tool()
    def mnara_coverage(investigation_id: str) -> dict:
        """Explain searched, unsearched, failed and credential-gated coverage."""
        return factory().discover('coverage', investigation_id)

    @mcp.tool()
    def mnara_monitor(request: MonitorRequest) -> dict:
        """Create a durable schedule; requires an explicitly configured monitor worker."""
        return MonitorService(factory()).create(request)

    return mcp


if __name__ == '__main__':
    create_mcp().run(transport='stdio')
