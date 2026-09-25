"""HTTP translation only; all workflows use InvestigationService."""
from __future__ import annotations
import asyncio
from typing import Callable, Optional
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field
from watchtower.engine.limits import BusyError
from watchtower.engine.planner import InvestigationRequest
from watchtower.engine.reporting import report_html


class EnrichmentRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    include: Optional[list[str]] = Field(default=None, max_length=40)


def router_for(factory: Callable) -> APIRouter:
    router = APIRouter()

    def get(iid):
        try:
            return factory().get(iid)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc

    @router.post('/api/investigations/preflight')
    def preflight(payload: InvestigationRequest):
        try:
            return factory().preflight(payload)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @router.get('/api/investigations')
    def list_investigations(limit: int = Query(50, ge=1, le=100)):
        return {'investigations': factory().list_investigations(limit)}

    @router.get('/api/investigations/{iid}/snapshot')
    def snapshot(iid: str):
        return get(iid)

    @router.get('/api/campaigns')
    def campaigns():
        from investigation.storage import InvestigationStore
        store = InvestigationStore(factory().database)
        try:
            return {'campaigns': [dict(row) for row in store.conn.execute(
                'SELECT * FROM campaigns ORDER BY created_at DESC LIMIT 100')]}
        finally:
            store.conn.close()

    @router.get('/api/investigations/{iid}/entities')
    def entities(iid: str):
        return {'entities': get(iid)['graph']['nodes']}

    @router.get('/api/investigations/{iid}/evidence')
    def evidence(iid: str):
        return {'evidence': get(iid)['evidence']}

    @router.get('/api/investigations/{iid}/coverage')
    def coverage(iid: str):
        return get(iid).get('coverage', {'statement': 'Coverage unavailable for legacy investigation'})

    @router.get('/api/investigations/{iid}/timeline')
    def timeline(iid: str):
        return {'timeline': get(iid).get('timeline', [])}

    @router.get('/api/investigations/{iid}/report')
    def report(iid: str, format: str = Query('json', pattern='^(json|html)$')):
        result = get(iid)
        if 'report' not in result:
            raise HTTPException(409, 'Recheck this legacy investigation to produce a report')
        if format == 'html':
            return HTMLResponse(report_html(result))
        return result['report']

    @router.post('/api/investigations/{iid}/recheck')
    async def recheck(iid: str):
        get(iid)
        try:
            return await factory().recheck(iid)
        except BusyError as exc:
            raise HTTPException(429, str(exc), headers={'Retry-After': '60'}) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except asyncio.TimeoutError as exc:
            raise HTTPException(504, 'Investigation deadline exceeded; check source runs') from exc

    @router.post('/api/investigations/{iid}/enrich')
    async def enrich(iid: str, payload: EnrichmentRequest):
        get(iid)
        try:
            return await factory().enrich(iid, payload.include)
        except BusyError as exc:
            raise HTTPException(429, str(exc), headers={'Retry-After': '60'}) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        except asyncio.TimeoutError as exc:
            raise HTTPException(504, 'Enrichment deadline exceeded') from exc

    @router.get('/api/sources/health')
    def health():
        return factory().discover('health')

    @router.get('/api/mnara/discover')
    def discover(action: str = 'sources', id: Optional[str] = None, search: str = Query('', max_length=100)):
        try:
            return factory().discover(action, id, search)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    return router
