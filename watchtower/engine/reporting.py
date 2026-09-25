"""Deterministic analyst reports. Source claims remain evidence-linked observations."""
from __future__ import annotations

import json
from html import escape
from investigation.storage import InvestigationStore
from .planner import InvestigationRequest


def complete_result(result: dict, store: InvestigationStore, request: InvestigationRequest | None) -> dict:
    iid = result['id']
    evidence = store.evidence_for(iid)
    graph = store.graph(iid)
    timeline = []
    for ev in evidence:
        timeline.append({'event': 'evidence_retrieved', 'date': ev.get('retrieved_at') or ev['observed_at'],
                         'date_type': 'mnara_retrieval', 'evidence_id': ev['id'], 'source': ev['source']})
        if ev.get('source_published_at'):
            timeline.append({'event': 'source_published', 'date': ev['source_published_at'],
                             'date_type': 'source_publication', 'evidence_id': ev['id'], 'source': ev['source']})
        metadata = ev['raw_metadata']
        for field, event in [('registration_date', 'domain_registered'), ('not_before', 'certificate_issued')]:
            if metadata.get(field):
                timeline.append({'event': event, 'date': metadata[field], 'date_type': 'source_observation',
                                 'evidence_id': ev['id'], 'source': ev['source']})
    timeline.sort(key=lambda row: (str(row['date']), row['evidence_id']))
    warnings = [result['coverage']['statement']]
    if request:
        warnings.append('Lookback is not enforced by every source; check publication and retrieval dates.')
    observations = [ev for ev in evidence if ev['source'] != 'correlation']
    report = {
        'title': f"Investigation: {result['brand']}",
        'executive_summary': f"{len(result['candidates'])} candidates warrant review. Similarity and shared infrastructure do not establish ownership or criminality.",
        'scope': request.model_dump() if request else {'brand': result['brand']},
        'coverage': result['coverage'], 'key_findings': result['candidates'],
        'evidence_table': [{'id': ev['id'], 'source': ev['source'], 'type': ev['evidence_type'],
                            'value': ev['observed_value'], 'url': ev['source_url'],
                            'retrieved_at': ev.get('retrieved_at'), 'content_hash': ev.get('content_hash')}
                           for ev in observations],
        'campaigns': result['campaigns'], 'timeline': timeline,
        'limitations': warnings,
        'confidence_explanation': 'Evidence confidence, deterministic risk factors and collection coverage are separate measures. None establishes attribution.',
        'follow_up': ['Review each cited observation and contradictory evidence.',
                      'Recheck failed sources before interpreting missing findings as absence.',
                      'Confirm suspected impersonation with the affected organization.'],
    }
    row = store.get('investigations', iid)
    return {**result, 'investigation': row, 'request': request.model_dump() if request else None,
            'graph': graph, 'entities': graph['nodes'], 'relationships': graph['edges'],
            'evidence': evidence, 'sources': store.source_runs(iid),
            'scoring': result['scores'], 'timeline': timeline, 'warnings': warnings, 'report': report}


def report_html(result: dict) -> str:
    report = result['report']
    sections = [('Executive summary', report['executive_summary']),
                ('Scope', json.dumps(report['scope'], ensure_ascii=False)),
                ('Coverage', report['coverage']['statement']),
                ('Confidence', report['confidence_explanation'])]
    body = ''.join(f'<section><h2>{escape(title)}</h2><p>{escape(text)}</p></section>' for title, text in sections)
    rows = ''.join('<tr>' + ''.join(f'<td>{escape(str(row.get(key) or ""))}</td>'
                                  for key in ('id', 'source', 'type', 'value', 'retrieved_at')) + '</tr>'
                   for row in report['evidence_table'])
    findings = ''.join(f'<li>{escape(str(row["domain"]))}: {row["risk_score"]}/100 — {escape(str(row["machine_verdict"]))}</li>'
                       for row in report['key_findings'])
    limitations = ''.join(f'<li>{escape(text)}</li>' for text in report['limitations'])
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
            f'<title>{escape(report["title"])}</title><style>body{{font:16px/1.6 system-ui;max-width:1100px;margin:2rem auto;padding:1rem}}'
            'td,th{border-bottom:1px solid #aaa;padding:.5rem;text-align:left;overflow-wrap:anywhere}table{width:100%;table-layout:fixed}</style>'
            f'<h1>{escape(report["title"])}</h1>{body}<h2>Findings</h2><ul>{findings}</ul>'
            f'<h2>Evidence</h2><table><thead><tr><th>ID</th><th>Source</th><th>Type</th><th>Observation</th><th>Retrieved</th></tr></thead><tbody>{rows}</tbody></table>'
            f'<h2>Source limitations</h2><ul>{limitations}</ul></html>')
