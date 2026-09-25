const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync('web/static/app.js', 'utf8');
function section(start, end) {
  return source.slice(source.indexOf(start), source.indexOf(end, source.indexOf(start)));
}

test('theme initializes and toggles when browser storage is blocked', () => {
  const root = { dataset: {} };
  let toggle;
  const button = { setAttribute() {}, addEventListener(name, handler) { toggle = handler; } };
  vm.runInNewContext(section('const THEME_KEY', '/* ------------------------------------------------------------ bootstrap */'), {
    document: { documentElement: root }, $: () => button,
    window: { get localStorage() { throw new Error('Storage blocked'); } },
  });
  assert.equal(root.dataset.theme, 'light');
  toggle();
  assert.equal(root.dataset.theme, 'terminal');
});

test('unknown URL fragments never become CSS selectors', () => {
  let queried = false;
  vm.runInNewContext(section('function openHashView()', 'window.addEventListener("hashchange"') + '\nopenHashView();', {
    location: { hash: '#"]broken' }, VIEWS: ['sweep', 'archive'],
    document: { querySelector() { queried = true; throw new Error('Invalid selector'); } },
  });
  assert.equal(queried, false);
});

test('failed source handshake provides an actionable status and disables monitoring', async () => {
  const nodes = new Map();
  const $ = key => {
    if (!nodes.has(key)) nodes.set(key, { replaceChildren(...children) { this.children = children; } });
    return nodes.get(key);
  };
  await vm.runInNewContext(section('async function init()', 'async function refreshSystemHealth') + '\ninit();', {
    $, fetch: async () => ({ ok: false }), el: (tag, cls, text) => ({ text }),
  });
  assert.equal($('#go').disabled, true);
  assert.match($('#system-status-summary').textContent, /reload/);
});

test('mouse selection moves the radio group keyboard entry point', () => {
  const buttons = [24, 72].map(h => ({ dataset: { h }, tabIndex: h === 72 ? 0 : -1,
    classList: { add() {}, remove() {} }, setAttribute() {} }));
  const group = { querySelectorAll: () => buttons };
  vm.runInNewContext(section('$("#window").onclick', 'function radioKeys'), {
    $: () => group, saveMonitorPrefs() {},
  });
  group.onclick({ target: { closest: () => buttons[0] } });
  assert.deepEqual(buttons.map(button => button.tabIndex), [0, -1]);
});

test('investigation findings survive graph failure and stale panels are cleared', async () => {
  const nodes = new Map();
  const $ = key => {
    if (!nodes.has(key)) nodes.set(key, {
      value: key === '#discover-brand' ? 'Example' : '', children: ['stale'],
      replaceChildren(...children) { this.children = children; },
      append(...children) { this.children.push(...children); },
    });
    return nodes.get(key);
  };
  const candidate = { risk_score: 50 };
  const context = {
    $, el: (tag, cls, text) => ({ text, addEventListener() {} }),
    fetch: async () => ({ ok: true, json: async () => ({ id: 'run-1', candidates: [candidate] }) }),
    renderInvestigationCoverage() {}, renderInvestigationExpansion() {}, renderCampaigns() {},
    renderInvestigationSocial() {}, investigationCard: item => item,
    renderInvestigationGraph: async () => { throw new Error('Network unavailable'); },
  };
  vm.runInNewContext(section('$("#discover-form").onsubmit', 'function renderInvestigationSocial'), context);
  await $('#discover-form').onsubmit({ preventDefault() {} });
  assert.deepEqual($('#discover-results').children, [candidate]);
  for (const panel of ['coverage', 'expansion', 'campaigns']) {
    assert.deepEqual($(`#discover-${panel}`).children, []);
  }
  assert.match($('#discover-graph').children[0].text, /unavailable/);
  assert.equal($('#discover-go').disabled, false);
  assert.equal($('#discover-go').textContent, 'Discover');
});
