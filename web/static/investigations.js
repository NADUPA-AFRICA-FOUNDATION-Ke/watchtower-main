/* Investigation records share the existing navigation and rendering primitives. */
(() => {
  const record = $('#investigation-record');

  async function request(url, options) {
    const response = await fetch(url, options);
    const data = await response.json();
    if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Request failed. Check the input and retry.');
    return data;
  }
  const post = (url, body) => request(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  function button(label, action) {
    const node = el('button', 'secondary-button', label);
    node.type = 'button';
    node.onclick = async () => {
      node.disabled = true;
      try { await action(); } catch (error) { showError(node.parentElement, error); }
      finally { node.disabled = false; }
    };
    return node;
  }
  function showError(box, error) {
    const message = el('p', 'errs', error.message || 'Could not reach the server.');
    message.setAttribute('role', 'alert');
    box.append(message);
  }
  function table(headers, rows) {
    const wrap = el('div', 'evidence-table-wrap');
    wrap.tabIndex = 0;
    wrap.setAttribute('role', 'region');
    wrap.setAttribute('aria-label', headers.join(', '));
    const result = el('table', 'evidence-table');
    const head = el('thead'), tr = el('tr'), body = el('tbody');
    headers.forEach(value => { const th = el('th', null, value); th.scope = 'col'; tr.append(th); });
    head.append(tr);
    rows.forEach(row => {
      const tr = el('tr');
      row.forEach(value => { const td = el('td'); td.append(value instanceof Node ? value : document.createTextNode(String(value ?? '—'))); tr.append(td); });
      body.append(tr);
    });
    result.append(head, body); wrap.append(result);
    return wrap;
  }
  function section(title, open = false) {
    const box = el('details', 'record-section');
    box.open = open;
    box.append(el('summary', null, title));
    return box;
  }
  function inputRequest() {
    return {
      brand: $('#discover-brand').value.trim(), query: $('#discover-query').value.trim(),
      limit: Number($('#discover-limit').value), market: $('#investigation-market').value,
      lookback_days: Number($('#investigation-lookback').value), enrich: $('#investigation-enrich').checked,
    };
  }
  window.mnaraPreflight = async () => {
    const payload = inputRequest();
    const plan = await post('/api/investigations/preflight', payload);
    const out = $('#investigation-preflight-result');
    out.replaceChildren(el('p', null, `${plan.available_sources}/${plan.requested_sources} sources available for this plan.`));
    const warnings = el('ul', 'hint');
    (plan.warnings || []).forEach(warning => warnings.append(el('li', null, warning)));
    out.append(warnings);
    return plan.can_proceed ? payload : null;
  };
  $('#investigation-preflight').onclick = async () => {
    const control = $('#investigation-preflight');
    control.disabled = true;
    try { await window.mnaraPreflight(); } catch (error) { showError($('#investigation-preflight-result'), error); }
    finally { control.disabled = false; }
  };

  function evidenceDetail(evidence, container) {
    container.replaceChildren(el('h3', null, evidence.evidence_type || evidence.type),
      el('p', null, evidence.observed_value || evidence.value),
      el('p', 'hint', `Evidence ${evidence.id} · Source ${evidence.source}`),
      el('p', 'hint', `Retrieved ${evidence.retrieved_at || 'not recorded'} · Published ${evidence.source_published_at || 'not supplied'}`),
      el('p', 'hint', `Integrity SHA-256: ${evidence.content_hash || 'legacy record'}`));
    if (evidence.source_url) { const link = el('a', null, 'Open source'); link.href = safeHref(evidence.source_url); link.target = '_blank'; link.rel = 'noopener noreferrer'; container.append(link); }
    const raw = section('Raw source observation');
    raw.append(el('pre', null, JSON.stringify(evidence.raw_metadata, null, 2)));
    container.append(raw);
  }

  function graphView(graph, evidence) {
    const box = section('Connections', true), filters = el('div', 'graph-filters');
    const types = el('select'), relations = el('select'), confidence = el('input');
    types.id = 'graph-entity-filter'; relations.id = 'graph-relation-filter'; confidence.id = 'graph-confidence-filter';
    confidence.type = 'range'; confidence.min = 0; confidence.max = 1; confidence.step = .1; confidence.value = 0;
    [[types, 'Entity type'], [relations, 'Relationship type'], [confidence, 'Minimum confidence']].forEach(([control, label]) => { const field = el('label', null, label); field.htmlFor = control.id; field.append(control); filters.append(field); });
    [['All entity types', types, [...new Set(graph.nodes.map(n => n.entity_type))]], ['All relationships', relations, [...new Set(graph.edges.map(e => e.relationship_type))]]].forEach(([label, control, options]) => {
      const all = el('option', null, label); all.value = ''; control.append(all);
      options.sort().forEach(value => { const option = el('option', null, value); option.value = value; control.append(option); });
    });
    const nodes = el('div', 'graph-node-list'), edges = el('div'), detail = el('div', 'record-detail'), status = el('p', 'hint');
    let limit = 40;
    const more = button('Show more nodes', () => { limit += 40; draw(); });
    function inspect(node) {
      detail.replaceChildren(el('h3', null, node.display_value), el('p', 'hint', `${node.entity_type} · ${node.id}`));
      const nearby = graph.edges.filter(edge => edge.source_entity_id === node.id || edge.target_entity_id === node.id);
      const relatedIds = new Set(nearby.flatMap(edge => [edge.source_entity_id, edge.target_entity_id]));
      const related = el('div', 'graph-node-list');
      graph.nodes.filter(n => n.id !== node.id && relatedIds.has(n.id)).slice(0, 30).forEach(n => related.append(button(n.display_value, () => inspect(n))));
      detail.append(el('p', null, `${nearby.length} connected observations`), related);
      const evidenceBox = el('div');
      evidence.filter(ev => ev.entity_id === node.id || nearby.some(edge => edge.evidence_id === ev.id)).slice(0, 30).forEach(ev => detail.append(button(`${ev.source}: ${ev.evidence_type}`, () => evidenceDetail(ev, evidenceBox))));
      detail.append(evidenceBox);
    }
    function draw() {
      const filteredEdges = graph.edges.filter(edge => (!relations.value || edge.relationship_type === relations.value) && edge.confidence >= Number(confidence.value));
      const ids = new Set(filteredEdges.flatMap(edge => [edge.source_entity_id, edge.target_entity_id]));
      const filteredNodes = graph.nodes.filter(node => (!types.value || node.entity_type === types.value) && (!relations.value || ids.has(node.id)) && node.confidence >= Number(confidence.value));
      nodes.replaceChildren(...filteredNodes.slice(0, limit).map(node => button(`${node.entity_type}: ${node.display_value}`, () => inspect(node))));
      const names = new Map(graph.nodes.map(node => [node.id, node.display_value]));
      const visible = new Set(filteredNodes.slice(0, limit).map(node => node.id));
      const rows = filteredEdges.filter(edge => visible.has(edge.source_entity_id) || visible.has(edge.target_entity_id)).slice(0, 50);
      edges.replaceChildren(table(['From', 'Relationship', 'To', 'Evidence'], rows.map(edge => [names.get(edge.source_entity_id), edge.relationship_type, names.get(edge.target_entity_id), button(edge.evidence_id, () => { const ev = evidence.find(ev => ev.id === edge.evidence_id); if (ev) evidenceDetail(ev, detail); })])));
      status.textContent = `${Math.min(limit, filteredNodes.length)} of ${filteredNodes.length} matching nodes · minimum confidence ${confidence.value}. Select a node to expand its connections.`;
      more.hidden = limit >= filteredNodes.length;
    }
    [types, relations, confidence].forEach(control => control.onchange = () => { limit = 40; draw(); });
    box.append(filters, status, nodes, more, edges, detail); draw(); return box;
  }

  window.mnaraShowInvestigation = data => {
    record.hidden = false;
    record.replaceChildren(el('h2', null, `${data.brand} · Investigation record`),
      el('p', 'hint', `${data.id} · ${data.coverage?.full_source_coverage || 'Unknown'} full-source coverage`));
    const actions = el('div', 'record-actions');
    actions.append(button('Recheck', async () => { const updated = await post(`/api/investigations/${data.id}/recheck`, {}); window.mnaraShowInvestigation(updated); }),
      button('Enrich entities', async () => { const updated = await post(`/api/investigations/${data.id}/enrich`, {}); window.mnaraShowInvestigation(updated); }),
      button('Monitor daily', async () => { await post('/api/monitors', { investigation: data.request || { brand: data.brand }, interval_seconds: 86400 }); actions.append(el('p', 'hint', 'Daily monitor saved. It runs when the monitor worker is enabled.')); }));
    ['json', 'html'].forEach(format => { const link = el('a', null, `Open ${format.toUpperCase()} report`); link.href = `/api/investigations/${data.id}/report?format=${format}`; link.target = '_blank'; link.rel = 'noopener'; actions.append(link); });
    record.append(actions);
    const overview = section('Overview and risk factors', true);
    overview.append(el('p', null, data.report?.executive_summary || 'Review observations before drawing conclusions.'), el('p', 'hint', data.coverage?.statement));
    (data.candidates || []).slice(0, 20).forEach(candidate => {
      const finding = section(`${candidate.domain} · Risk ${candidate.risk_score}/100`);
      finding.append(el('p', 'hint', `Evidence confidence ${candidate.confidence}. Coverage is reported separately.`));
      finding.append(table(['Factor', 'Points', 'Evidence IDs'], (candidate.factors || []).map(f => [f.factor, f.score, f.evidence_ids.join(', ')])));
      overview.append(finding);
    });
    record.append(overview);
    const evidence = data.evidence || [];
    const graph = data.graph || { nodes: [], edges: [] };
    record.append(graphView(graph, evidence));
    const observations = section(`Evidence · ${evidence.length} observations`), detail = el('div', 'record-detail');
    observations.append(table(['Source', 'Observation', 'Retrieved', 'Inspect'], evidence.slice(0, 100).map(ev => [ev.source, ev.observed_value, ev.retrieved_at, button('Evidence', () => evidenceDetail(ev, detail))])), detail);
    if (evidence.length > 100) observations.append(el('p', 'hint', 'Showing the first 100 observations. The JSON report contains the full evidence table.'));
    const timeline = section('Timeline');
    timeline.append(table(['Date', 'Date meaning', 'Event', 'Evidence'], (data.timeline || []).slice(0, 100).map(row => [row.date, row.date_type, row.event, row.evidence_id])));
    const infrastructure = section('Infrastructure');
    infrastructure.append(table(['Entity', 'Type', 'Confidence'], graph.nodes.filter(n => ['ip_address', 'asn', 'certificate', 'nameserver', 'registrar'].includes(n.entity_type)).slice(0, 100).map(n => [n.display_value, n.entity_type, n.confidence])));
    const runs = section('Source runs');
    runs.append(table(['Source', 'Status', 'Results', 'Error'], (data.sources || []).slice(0, 150).map(row => [row.source, row.status, row.results_returned, row.error_code])));
    record.append(observations, timeline, infrastructure, runs);
  };

  async function openRecord(id) {
    const data = await request(`/api/investigations/${id}/snapshot`);
    document.querySelector('.tab[data-view="discover"]').click();
    ['summary', 'coverage', 'expansion', 'campaigns', 'graph', 'social', 'results'].forEach(panel => $(`#discover-${panel}`).replaceChildren());
    window.mnaraShowInvestigation(data);
    $('#discover-brand').value = data.brand || data.investigation.brand;
    record.scrollIntoView({ block: 'start' });
  }
  async function loadView(view) {
    const out = $(`#${view}-content`);
    if (!out) return;
    out.replaceChildren(el('p', 'hint', 'Loading…'));
    try {
      if (['cases', 'reports'].includes(view)) {
        const data = await request('/api/investigations');
        out.replaceChildren(button('New investigation', () => document.querySelector('.tab[data-view="discover"]').click()));
        if (!data.investigations.length) out.append(el('p', 'hint', 'No investigations yet. Start with a brand or public domain.'));
        else out.append(table(['Subject', 'Started', 'Status', 'Coverage', 'Open'], data.investigations.map(row => [row.brand, row.started_at, row.status, `${row.coverage_percentage ?? 0}%`, button('Open record', () => openRecord(row.id))])));
      } else if (['sources', 'health'].includes(view)) {
        const data = await request('/api/sources/health'); const catalogue = data.sources;
        out.replaceChildren(table(['Source', 'Access', 'Status', 'Capabilities', 'Last checked'], catalogue.map(row => [row.name, row.access, `${row.status}${row.stale ? ' · stale/unverified' : ''}`, row.capabilities.join(', '), row.last_checked || 'Not checked'])));
        out.append(el('p', 'hint', 'Missing credentials are optional. No source is treated as searched solely because it is configured.'));
      } else if (view === 'monitors') {
        const data = await request('/api/monitors');
        out.replaceChildren(el('p', 'hint', 'Create a daily monitor from an investigation record. Schedules require a running monitor worker.'));
        out.append(table(['Subject', 'Interval', 'State', 'Last result', 'Action'], data.monitors.map(row => [row.request.brand, `${row.interval_seconds / 3600} hours`, row.enabled ? 'Scheduled' : 'Paused', row.last_error || (row.last_investigation_id ? 'Completed' : 'Not run'), button(row.enabled ? 'Pause' : 'Resume', async () => { await request(`/api/monitors/${row.id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: !row.enabled }) }); await loadView('monitors'); })])));
      } else if (view === 'campaigns') {
        const data = await request('/api/campaigns');
        out.replaceChildren(table(['Campaign', 'Brand', 'Correlation', 'Risk', 'Inspect'], data.campaigns.map(row => [row.public_id, row.brand, row.correlation_label, row.threat_score, button('Evidence', () => openCampaignDetail(row.id))])));
        if (!data.campaigns.length) out.append(el('p', 'hint', 'No campaign links yet. A shared brand name alone does not create a campaign.'));
      } else if (view === 'settings') {
        out.replaceChildren(el('h2', null, 'Investigation defaults'), el('p', null, 'Free public sources are preferred. Paid sources require explicit API opt-in. Enrichment can be disabled before a run.'),
          el('p', null, 'Source credentials and storage are configured on the server. Secret values are never shown here.'),
          button('Inspect source availability', () => document.querySelector('.tab[data-view="sources"]').click()));
      }
    } catch (error) { out.replaceChildren(); showError(out, error); out.append(button('Retry', () => loadView(view))); }
  }
  window.addEventListener('mnara:view', event => loadView(event.detail));
  if (!location.hash) document.querySelector('.tab[data-view="cases"]').click();
  else loadView(location.hash.slice(1));
})();
