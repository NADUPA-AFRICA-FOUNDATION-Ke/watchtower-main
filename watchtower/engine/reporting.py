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
    limitations = []
    for category in ('partial', 'failed', 'unavailable', 'missing_credentials', 'rate_limited', 'not_searched'):
        for row in result['coverage'].get(category, []):
            limitations.append({
                'source': row.get('provider'), 'status': category,
                'detail': row.get('detail', ''),
            })
    observations = [ev for ev in evidence if ev['source'] != 'correlation']
    entity_types = {node['id']: node['entity_type'] for node in graph['nodes']}
    infrastructure_types = {'ip_address', 'asn', 'certificate', 'nameserver', 'registrar', 'dns_record'}
    infrastructure = [node for node in graph['nodes'] if node['entity_type'] in infrastructure_types]
    social_types = {'social_account', 'social_post', 'messaging_account', 'username', 'phone_number', 'email'}
    social_relationships = [edge for edge in graph['edges']
                            if entity_types.get(edge['source_entity_id']) in social_types
                            or entity_types.get(edge['target_entity_id']) in social_types]
    campaign_entity_ids = {entity_id for campaign in result['campaigns']
                           for entity_id in campaign.get('entity_ids', [])}
    campaign_relationships = [edge for edge in graph['edges']
                              if edge['source_entity_id'] in campaign_entity_ids
                              and edge['target_entity_id'] in campaign_entity_ids]
    candidates = result['candidates']
    subject = request.brand if request else result['brand']
    if candidates:
        summary = f"{len(candidates)} domain candidate(s) warrant analyst review."
    else:
        summary = (f"Investigation of {subject} collected {len(observations)} observation(s); "
                   "no domain candidate met the current reporting threshold.")
    summary += ' Similarity and shared infrastructure do not establish ownership or criminality.'
    report = {
        'title': f"Investigation: {result['brand']}",
        'executive_summary': summary,
        'scope': request.model_dump() if request else {'brand': result['brand']},
        'coverage': result['coverage'], 'key_findings': candidates,
        'high_risk_entities': [candidate for candidate in candidates if candidate.get('risk_score', 0) >= 60],
        'evidence_table': [{'id': ev['id'], 'source': ev['source'], 'type': ev['evidence_type'],
                            'value': ev['observed_value'], 'url': ev['source_url'],
                            'retrieved_at': ev.get('retrieved_at'), 'content_hash': ev.get('content_hash')}
                           for ev in observations],
        'infrastructure': infrastructure, 'social_relationships': social_relationships,
        'campaigns': result['campaigns'], 'campaign_relationships': campaign_relationships,
        'timeline': timeline, 'source_limitations': limitations, 'limitations': warnings,
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
    source_limitations = ''.join(
        f'<li>{escape(str(row["source"]))}: {escape(str(row["status"]))} — {escape(str(row["detail"]))}</li>'
        for row in report['source_limitations']) or '<li>No source limitations were reported.</li>'
    infrastructure = ''.join(
        f'<li>{escape(str(row["entity_type"]))}: {escape(str(row["display_value"]))}</li>'
        for row in report['infrastructure']) or '<li>No infrastructure entities observed.</li>'
    social = ''.join(
        f'<li>{escape(str(row["relationship_type"]))}: {escape(str(row["source_entity_id"]))} → {escape(str(row["target_entity_id"]))}; evidence {escape(str(row["evidence_id"]))}</li>'
        for row in report['social_relationships']) or '<li>No social relationships observed.</li>'
    campaigns = ''.join(
        f'<li>{escape(str(row.get("public_id", row.get("id", ""))))}: {escape(str(row.get("correlation_label", "unrated")))} correlation</li>'
        for row in report['campaigns']) or '<li>No evidence-backed campaign cluster was formed.</li>'
    timeline = ''.join(
        f'<li>{escape(str(row["date"]))} ({escape(str(row["date_type"]))}): {escape(str(row["event"]))}; evidence {escape(str(row["evidence_id"]))}</li>'
        for row in report['timeline'])
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
            f'<title>{escape(report["title"])}</title><style>body{{font:16px/1.6 system-ui;max-width:1100px;margin:2rem auto;padding:1rem}}'
            'td,th{border-bottom:1px solid #aaa;padding:.5rem;text-align:left;overflow-wrap:anywhere}table{width:100%;table-layout:fixed}</style>'
            f'<h1>{escape(report["title"])}</h1>{body}<h2>Findings</h2><ul>{findings}</ul>'
            f'<h2>Infrastructure</h2><ul>{infrastructure}</ul><h2>Social relationships</h2><ul>{social}</ul>'
            f'<h2>Campaign relationships</h2><ul>{campaigns}</ul><h2>Timeline</h2><ul>{timeline}</ul>'
            f'<h2>Evidence</h2><table><thead><tr><th>ID</th><th>Source</th><th>Type</th><th>Observation</th><th>Retrieved</th></tr></thead><tbody>{rows}</tbody></table>'
            f'<h2>Source limitations</h2><ul>{limitations}{source_limitations}</ul></html>')
