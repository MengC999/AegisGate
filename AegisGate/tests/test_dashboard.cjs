const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function createHarness(api = async () => ({})) {
  const nodes = new Map();
  function element() {
    const classes = new Set();
    return {
      textContent: '', value: '', children: [], dataset: {}, style: {}, hidden: false,
      classList: { add: name => classes.add(name), remove: name => classes.delete(name), contains: name => classes.has(name), toggle: (name, enabled) => enabled ? classes.add(name) : classes.delete(name) },
      setAttribute(name, value) { this[name] = value; },
      removeAttribute(name) { delete this[name]; },
      addEventListener() {},
      append(...children) { this.children.push(...children); },
      appendChild(child) { this.children.push(child); },
      replaceChildren(...children) { this.children = children; },
    };
  }
  const byId = id => { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); };
  byId('homeTrendRange').value = '7';
  const charts = new Map();
  class Chart {
    constructor(node, config) { this.config = config; charts.set(node, this); }
    destroy() { this.destroyed = true; }
    resize() {}
  }
  const context = vm.createContext({
    Chart, api, byId, console, URLSearchParams, URL, requestAnimationFrame: fn => fn(),
    matchMedia: () => ({ matches: true }),
    window: { Chart, innerWidth: 1440, addEventListener() {} },
    document: { body: element(), querySelectorAll: () => [], querySelector: element, createElement: element, addEventListener() {} },
    state: { view: 'detect', enterpriseResource: 'dashboard', health: { status: 'ok' }, stats: { total_requests: 7, violation_requests: 2 } },
    enterpriseResourceMeta: {}, enterpriseStatusNames: {}, enterpriseSeverityNames: { critical: '严重', high: '高', medium: '中', low: '低', info: '信息' },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/operations-navigation.js'), 'utf8'), context);
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/dashboard.js'), 'utf8'), context);
  return { context, byId, charts };
}

const fixture = {
  counts: { assets: 5, online_assets: 4, open_alerts: 3, open_vulnerabilities: 2, overdue_vulnerabilities: 1 },
  alert_severity: { critical: 2, medium: 4 },
  vulnerability_status: { closed: 2, fixing: 2 },
  remediation_completion_rate: 50,
  trends: { alerts: Array.from({ length: 14 }, (_, i) => ({ date: `2026-09-${String(i + 1).padStart(2, '0')}`, total: i, high_risk: i % 3 })) },
  data_mode: 'runtime_with_demo_seed',
};

test('dashboard respects backend percentage units and real severity counts', () => {
  const { context, byId, charts } = createHarness();
  context.renderHomeDashboard(fixture);
  assert.equal(byId('homeCompletionRate').textContent, '50%');
  assert.equal(byId('homeAlertTotal').textContent, '6');
  assert.equal(byId('homeAssets').textContent, '5');
  assert.deepEqual(Array.from(charts.get(byId('homeCompletionChart')).config.data.datasets[0].data), [2, 2]);
  assert.match(byId('homeDataSource').textContent, /演示数据/);
});

test('date range uses the selected number of actual daily points', () => {
  const { context, byId, charts } = createHarness();
  vm.runInContext('homeDashboard = fixture;', Object.assign(context, { fixture }));
  context.drawHomeTrend();
  assert.equal(charts.get(byId('homeTrendChart')).config.data.labels.length, 7);
  assert.equal(charts.get(byId('homeTrendChart')).config.data.labels[0], '09-08');
  byId('homeTrendRange').value = '14';
  context.drawHomeTrend();
  assert.equal(charts.get(byId('homeTrendChart')).config.data.labels.length, 14);
});

test('empty datasets display zero counts without fabricated chart tooltips', () => {
  const { context, byId, charts } = createHarness();
  context.renderHomeDashboard({ counts: {}, remediation_completion_rate: 100 });
  assert.equal(byId('homeAlertTotal').textContent, '0');
  assert.equal(byId('homeCompletionRate').textContent, '100%');
  assert.equal(charts.get(byId('homeRiskChart')).config.options.plugins.tooltip.enabled, false);
  assert.equal(charts.get(byId('homeCompletionChart')).config.options.plugins.tooltip.enabled, false);
});

test('failed refresh clears stale metrics while independent todo data stays available', async () => {
  const { context, byId, charts } = createHarness(async url => {
    if (url.includes('/todos')) return { total: 0, items: [] };
    throw new Error('HTTP 503');
  });
  context.renderHomeDashboard(fixture);
  const priorChart = charts.get(byId('homeRiskChart'));
  await context.loadHomeDashboard();
  assert.equal(byId('homeAssets').textContent, '--');
  assert.equal(byId('homeCompletionRate').textContent, '--');
  assert.equal(byId('homeTodoCount').textContent, '0');
  assert.equal(byId('homeError').hidden, false);
  assert.match(byId('homeErrorText').textContent, /503/);
  assert.equal(priorChart.destroyed, true);
});
