"""Health combines configuration with persisted observations, never guessed uptime."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from investigation.storage import InvestigationStore
from watchtower.registry import REGISTRY


class SourceHealthService:
    def __init__(self, store: InvestigationStore):
        self.store = store

    def sources(self) -> list[dict]:
        rows = self.store.conn.execute('''SELECT s.* FROM source_runs s JOIN
            (SELECT source,MAX(id) id FROM source_runs GROUP BY source) latest ON s.id=latest.id''').fetchall()
        latest = {row['source']: dict(row) for row in rows}
        result = []
        for source in REGISTRY.all():
            value = source.public()
            row = latest.get(source.id)
            if value['status'] == 'unknown' and row:
                value['status'] = {
                    'operational': 'operational', 'provider_error': 'degraded',
                    'network_error': 'degraded', 'timeout': 'degraded',
                    'limited': 'degraded', 'web_index_only': 'degraded',
                    'missing_credentials': 'auth_missing',
                }.get(row['status'], row['status'])
                value['last_checked'] = row['completed_at']
                value['latency_ms'] = json.loads(row['rate_limit_metadata'] or '{}').get('duration_ms')
                value['error'] = row['error_code']
                checked = datetime.fromisoformat(row['completed_at'])
                value['stale'] = (datetime.now(timezone.utc) - checked).total_seconds() > 3600
            else:
                value.update(last_checked=None, latency_ms=None, error=None, stale=True)
            result.append(value)
        return result
