"""Durable, bounded investigation rechecks. Run explicitly from a worker/cron."""
from __future__ import annotations
import json
import sqlite3
import time
import uuid
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field
from .planner import InvestigationRequest
from .service import InvestigationService


class MonitorRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    investigation: InvestigationRequest
    interval_seconds: int = Field(default=86400, ge=3600, le=2592000)


class MonitorService:
    def __init__(self, service: InvestigationService):
        self.service = service
        with self.connect() as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS investigation_monitors(
                id TEXT PRIMARY KEY, request TEXT NOT NULL, interval_seconds INTEGER NOT NULL,
                enabled INTEGER NOT NULL, next_run REAL NOT NULL, lease_until REAL,
                last_investigation_id TEXT, last_error TEXT, changes TEXT)''')

    def connect(self):
        conn = sqlite3.connect(str(self.service.database), timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def create(self, request: MonitorRequest) -> dict:
        preflight = self.service.preflight(request.investigation)
        if not preflight['can_proceed']:
            raise ValueError('Monitor has no executable sources')
        id = str(uuid.uuid4())
        with self.connect() as conn:
            conn.execute('INSERT INTO investigation_monitors VALUES(?,?,?,?,?,?,?,?,?)',
                         (id, request.investigation.model_dump_json(), request.interval_seconds,
                          1, time.time() + request.interval_seconds, 0, None, None, '[]'))
        return next(row for row in self.list_monitors() if row['id'] == id)

    def list_monitors(self) -> list[dict]:
        with self.connect() as conn:
            rows = [dict(row) for row in conn.execute('SELECT * FROM investigation_monitors ORDER BY next_run LIMIT 100')]
        for row in rows:
            row['request'] = json.loads(row['request'])
            row['changes'] = json.loads(row['changes'] or '[]')
        return rows

    def set_enabled(self, id: str, enabled: bool) -> None:
        with self.connect() as conn:
            cursor = conn.execute('UPDATE investigation_monitors SET enabled=? WHERE id=?', (int(enabled), id))
            if not cursor.rowcount:
                raise LookupError('Monitor not found')

    async def run_due(self, limit: int = 5) -> list[dict]:
        results = []
        for _ in range(min(5, max(0, limit))):
            with self.connect() as conn:
                conn.execute('BEGIN IMMEDIATE')
                row = conn.execute('''SELECT * FROM investigation_monitors WHERE enabled=1 AND next_run<=?
                    AND COALESCE(lease_until,0)<? ORDER BY next_run LIMIT 1''', (time.time(), time.time())).fetchone()
                if row is None:
                    break
                conn.execute('UPDATE investigation_monitors SET lease_until=? WHERE id=?', (time.time() + 240, row['id']))
            try:
                result = await self.service.investigate(InvestigationRequest.model_validate_json(row['request']))
                previous = self.service.get(row['last_investigation_id']) if row['last_investigation_id'] else None
                changes = compare(previous, result)
                with self.connect() as conn:
                    conn.execute('''UPDATE investigation_monitors SET last_investigation_id=?,last_error=NULL,
                        changes=?,next_run=?,lease_until=0 WHERE id=?''',
                        (result['id'], json.dumps(changes), time.time() + row['interval_seconds'], row['id']))
                results.append({'monitor_id': row['id'], 'investigation_id': result['id'], 'changes': changes})
            except Exception as exc:
                with self.connect() as conn:
                    conn.execute('UPDATE investigation_monitors SET last_error=?,next_run=?,lease_until=0 WHERE id=?',
                                 (type(exc).__name__, time.time() + row['interval_seconds'], row['id']))
                results.append({'monitor_id': row['id'], 'error': type(exc).__name__})
        return results


def compare(previous: Optional[dict], current: dict) -> list[dict]:
    if not previous:
        return [{'event': 'baseline_recorded', 'investigation_id': current['id']}]
    old = {row['id']: row for row in previous['entities']}
    changes = []
    for row in current['entities']:
        if row['id'] not in old:
            changes.append({'event': 'new_entity', 'entity_id': row['id'], 'entity_type': row['entity_type']})
        else:
            prior = old[row['id']]['metadata']
            metadata = row['metadata']
            if metadata.get('risk', {}).get('risk_score', 0) > prior.get('risk', {}).get('risk_score', 0):
                changes.append({'event': 'risk_increased', 'entity_id': row['id']})
            for field in ('dns', 'rdap', 'threat_intelligence'):
                if field in metadata and field in prior and metadata[field] != prior[field]:
                    changes.append({'event': field + '_changed', 'entity_id': row['id']})
            if metadata.get('page', {}).get('redirect_chain') != prior.get('page', {}).get('redirect_chain'):
                changes.append({'event': 'redirect_chain_changed', 'entity_id': row['id']})
    return changes


def main() -> None:
    import asyncio
    from .runtime import create_service
    print(json.dumps(asyncio.run(MonitorService(create_service()).run_due()), indent=2))


if __name__ == '__main__':
    main()
