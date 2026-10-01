const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const navigation = fs.readFileSync(path.join(__dirname, '../web/operations-navigation.js'), 'utf8');
const application = fs.readFileSync(path.join(__dirname, '../web/app.js'), 'utf8');

function routes() {
  const context = vm.createContext({});
  vm.runInContext(navigation, context);
  return context;
}

test('every existing enterprise resource has exactly one destination page', () => {
  const context = routes();
  vm.runInContext(application.slice(application.indexOf('const enterpriseResourceMeta ='), application.indexOf('function opsDisplayValue')), context);
  const resources = vm.runInContext('Object.keys(enterpriseResourceMeta)', context);
  const assigned = vm.runInContext('Object.values(operationsPages).flatMap(page => page.resources.map(([key]) => key))', context);
  assert.equal(assigned.length, new Set(assigned).size);
  for (const resource of [...resources, 'settings', 'dashboard']) {
    assert.ok(context.operationsPageForResource(resource), `missing page for ${resource}`);
  }
});

test('old bookmarks open the matching new page and retain the selected module', () => {
  const context = routes();
  for (const [resource, view] of [['assets', 'ops-assets'], ['incidents', 'ops-response'], ['scan-tasks', 'ops-risks'], ['roles', 'ops-access'], ['settings', 'ops-settings']]) {
    assert.equal(context.resolveOperationsRoute('ops', resource).view, view);
    assert.equal(context.resolveOperationsRoute('ops', resource).resource, resource);
  }
});

test('unrelated or unknown modules fall back to the page default without crossing data stores', () => {
  const context = routes();
  assert.equal(context.resolveOperationsRoute('ops-assets', 'alerts').resource, 'assets');
  assert.equal(context.resolveOperationsRoute('ops-history', 'alerts').view, 'ops-history');
  assert.equal(context.resolveOperationsRoute('ops-history', 'settings').resource, 'overview');
  assert.equal(context.resolveOperationsRoute('ops', 'unknown').resource, 'dashboard');
  assert.equal(context.resolveOperationsRoute('home', 'assets').resource, null);
});

test('a slow previous module cannot overwrite the current table or its loading state', async () => {
  const pending = [];
  const rendered = [];
  const modes = [];
  const nodes = new Map();
  const byId = id => {
    if (!nodes.has(id)) nodes.set(id, { value: '', classList: { add() {}, remove() {} } });
    return nodes.get(id);
  };
  const context = vm.createContext({
    URLSearchParams, byId,
    state: { enterpriseRequestId: 0 }, enterpriseResourceMeta: { assets: {}, alerts: {} },
    populateEnterpriseFilters() {},
    setEnterpriseState(mode) { modes.push(mode); },
    renderEnterpriseTable(resource) { rendered.push(resource); },
    api: () => new Promise((resolve, reject) => pending.push({ resolve, reject })),
  });
  vm.runInContext(application.slice(application.indexOf('async function loadEnterpriseResource('), application.indexOf('async function loadEnterpriseSettings(')), context);
  const old = context.loadEnterpriseResource('assets');
  const current = context.loadEnterpriseResource('alerts');
  pending[1].resolve({ items: [] });
  await current;
  pending[0].resolve({ items: [{ id: 'old' }] });
  await old;
  assert.deepEqual(rendered, ['alerts']);
  assert.deepEqual(modes, ['loading', 'loading', 'ready']);
  const failed = context.loadEnterpriseResource('assets');
  const latest = context.loadEnterpriseResource('alerts');
  pending[3].resolve({ items: [] }); await latest;
  pending[2].reject(new Error('late error')); await failed;
  assert.equal(modes.includes('error'), false);
});
