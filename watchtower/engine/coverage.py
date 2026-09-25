"""Collection coverage is independent of evidence confidence and threat risk."""
from __future__ import annotations
from collections import defaultdict
from typing import Iterable
from watchtower.discovery.base import SourceHealth
from .adapters import STATUS


def coverage(requested: Iterable[str], health: Iterable[SourceHealth]) -> dict:
    requested = list(dict.fromkeys(requested))
    runs: dict[str, list[SourceHealth]] = defaultdict(list)
    for row in health:
        runs[row.provider].append(row)
    groups: dict[str, list] = {k: [] for k in ('successful', 'partial', 'failed', 'unavailable', 'missing_credentials', 'rate_limited', 'not_searched')}
    attempted = []
    for name in requested:
        rows = runs.get(name, [])
        states = {STATUS.get(row.status, 'failed') for row in rows}
        if states - {'not_searched', 'auth_missing'}:
            attempted.append(name)
        if states == {'success'}:
            groups['successful'].append(name)
            continue
        if not states or states == {'not_searched'}:
            bucket = 'not_searched'
        elif 'auth_missing' in states:
            bucket = 'missing_credentials'
        elif 'rate_limited' in states:
            bucket = 'rate_limited'
        elif 'success' in states or 'partial' in states:
            bucket = 'partial'
        elif 'failed' in states:
            bucket = 'failed'
        else:
            bucket = 'unavailable'
        groups[bucket].append({'provider': name, 'status': bucket,
                               'detail': rows[-1].detail if rows else 'No applicable entity or source not executed'})
    total, full = len(requested), len(groups['successful'])
    return {'requested': requested, 'configured': total, 'attempted': len(attempted),
            'attempted_sources': attempted, **groups,
            'limited': groups['partial'] + groups['rate_limited'],
            'full_source_coverage': f'{full}/{total}',
            'coverage_percentage': round(100 * full / total, 1) if total else 0,
            'statement': f'{full}/{total} full-source coverage. ' +
            ('All requested source operations completed; this does not imply exhaustive internet coverage.'
             if total and full == total else 'Partial coverage: unsearched or incomplete sources remain.')}
