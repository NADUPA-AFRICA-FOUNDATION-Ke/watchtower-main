from typing import Callable
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict
from watchtower.engine.monitoring import MonitorRequest, MonitorService


class MonitorState(BaseModel):
    model_config = ConfigDict(extra='forbid')
    enabled: bool


def router_for(factory: Callable) -> APIRouter:
    router = APIRouter()

    @router.get('/api/monitors')
    def list_monitors():
        return {'monitors': MonitorService(factory()).list_monitors()}

    @router.post('/api/monitors')
    def create_monitor(payload: MonitorRequest):
        try:
            return MonitorService(factory()).create(payload)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @router.patch('/api/monitors/{id}')
    def update_monitor(id: str, payload: MonitorState):
        try:
            MonitorService(factory()).set_enabled(id, payload.enabled)
            return {'id': id, 'enabled': payload.enabled}
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc

    return router
