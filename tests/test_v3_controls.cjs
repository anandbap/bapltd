// Run with: node tests/test_v3_controls.cjs (no packages required).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, '../bap-controlplane/internal/dashboardui/web/v3.html'), 'utf8');
const source = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const section = (start, end) => source.slice(source.indexOf(start), source.indexOf(end, source.indexOf(start)));
const flush = () => new Promise(resolve => setImmediate(resolve));

async function main() {
  const elements = new Map();
  const element = () => ({ hidden: false, textContent: '', children: [], classList: { contains: () => true },
    appendChild(child) { this.children.push(child); }, addEventListener(_, cb) { this.click = cb; } });
  const ctx = vm.createContext({ console, Date, Promise, performance, encodeURIComponent,
    S: { adminActive: true, mode: 'live' }, stories: {}, STREAMS: [], liveRequest: 0, liveInFlight: false,
    $: id => { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); },
    esc: value => String(value), render() {}, openAdminPopover() {}, confirm: () => true,
    document: { createElement: element, addEventListener(_, cb) { ctx.clickSession = cb; } } });
  const fixtures = {
    '/api/v1/sessions': { sessions: [{ session_id: 'claude', app_id: 'claude-code', status: 'active', last_active_at: new Date().toISOString() }] },
    '/api/activity/live': { activities: [{ session_id: 'claude', action_status: 'completed', timestamp: new Date().toISOString() }] }
  };
  ctx.getJSON = async url => fixtures[url] || {};
  vm.runInContext(section('  function loadLive(force)', '  function startLive()'), ctx);
  await ctx.loadLive();
  assert.equal(ctx.S.coverage[0].protect, 'Coverage unknown');
  assert.doesNotMatch(ctx.S.coverage[0].means, /Every action/);
  fixtures['/api/v1/sessions'].sessions[0].reporting_layers = ['discovery'];
  await ctx.loadLive();
  assert.equal(ctx.S.coverage[0].protect, 'Discovered');
  assert.match(ctx.S.coverage[0].means, /Prompt text not reported/);
  fixtures['/api/v1/sessions'].sessions[0].reporting_layers.push('broker');
  await ctx.loadLive();
  assert.equal(ctx.S.coverage[0].protect, 'Evidence received');
  assert.match(ctx.S.coverage[0].means, /discovery, broker/);
  assert.match(ctx.S.coverage[0].actionHtml, /Freeze session/);
  assert.doesNotMatch(ctx.S.coverage[0].surfaceHtml, /data-session-freeze/);
  assert.doesNotMatch(ctx.S.coverage[0].actionHtml, / disabled/);
  fixtures['/api/v1/sessions'].sessions[0].last_active_at = new Date(Date.now()-60000).toISOString();
  await ctx.loadLive();
  assert.equal(ctx.S.coverage[0].report, 'Offline');
  assert.match(ctx.S.coverage[0].actionHtml, / disabled/);
  // A newer action cannot override the authoritative stale heartbeat.
  fixtures['/api/activity/live'].activities[0].timestamp = new Date().toISOString();
  await ctx.loadLive();
  assert.match(ctx.S.coverage[0].actionHtml, / disabled/);
  fixtures['/api/v1/sessions'].sessions[0].last_active_at = new Date().toISOString();
  ctx.S.adminActive = false;
  await ctx.loadLive();
  assert.equal(ctx.S.coverage[0].actionHtml, '');
  ctx.S.adminActive = true;
  fixtures['/api/v1/sessions'].sessions[0].status = 'revoked';
  fixtures['/api/v1/sessions'].sessions[0].close_reason = 'Frozen by administrator';
  await ctx.loadLive();
  assert.match(ctx.S.coverage[0].actionHtml, /Unfreeze session/);
  assert.doesNotMatch(ctx.S.coverage[0].actionHtml, / disabled/);

  // A slow request must finish instead of being invalidated on every poll.
  const originalGetJSON = ctx.getJSON;
  let release;
  ctx.getJSON = url => url === '/api/v1/sessions' ? new Promise(resolve => { release = resolve; }) : originalGetJSON(url);
  const slow = ctx.loadLive();
  const request = ctx.liveRequest;
  await ctx.loadLive();
  assert.equal(ctx.liveRequest, request);
  release(fixtures['/api/v1/sessions']);
  await slow;
  assert.equal(ctx.liveInFlight, false);
  ctx.getJSON = originalGetJSON;

  vm.runInContext(section("  document.addEventListener('click', function (e) {\n    var btn = e.target.closest('[data-session-freeze]');", '  var liveTimer'), ctx);
  let calls = 0;
  ctx.loadLive = () => { calls++; };
  ctx.apiFetch = async () => ({ json: async () => ({ status: 'revoked' }) });
  const attrs = { 'data-session-freeze': 'freeze', 'data-session-id': 'claude' };
  const button = { getAttribute: key => attrs[key], setAttribute: (key, value) => { attrs[key] = value; } };
  button.disabled = true;
  ctx.clickSession({ target: { closest: () => button } });
  await flush();
  assert.equal(calls, 0);
  button.disabled = false;
  ctx.S.adminActive = false;
  ctx.clickSession({ target: { closest: () => button } });
  await flush();
  assert.equal(calls, 0);
  ctx.S.adminActive = true;
  ctx.clickSession({ target: { closest: () => button } });
  await flush();
  assert.equal(attrs['data-session-freeze'], 'unfreeze');
  assert.equal(button.textContent, 'Unfreeze session');
  assert.equal(button.disabled, false);

  ctx.getAdminToken = () => '';
  ctx.authHeaders = h => h;
  ctx.fetch = async () => ({ ok: false, status: 409, text: async () => JSON.stringify({ error: 'Session is not frozen' }) });
  vm.runInContext(section('  function apiFetch(', '  function getJSON('), ctx);
  await assert.rejects(ctx.apiFetch('/test'), /HTTP 409: Session is not frozen/);

  let shown, requests = 0;
  ctx.openList = (title, rows) => { shown = rows.slice(); ctx.$('dTitle').textContent = title; ctx.$('dConvo').children = []; };
  ctx.getJSON = async url => {
    requests++;
    const offset = Number(new URL(url, 'https://local.test').searchParams.get('offset'));
    return { snapshot: 105, total: 105, next_offset: offset + Math.min(100, 105-offset), has_more: offset === 0,
      events: Array.from({ length: Math.min(100, 105-offset) }, (_, i) => ({ event_hash: 'hash-'+(offset+i), decision: i%2 ? 'deny' : 'audit_permitted', full_command: 'action-'+(offset+i), session_id: 'claude' })) };
  };
  vm.runInContext(section('  function openRiskyActions()', '  // Opens a drawer that lists rows'), ctx);
  ctx.openRiskyActions();
  await flush();
  assert.equal(shown.length, 100);
  assert.equal(shown[0].shadow, true);
  assert.equal(shown[1].blocked, true);
  ctx.$('dConvo').children.at(-1).children[0].click();
  await flush();
  assert.equal(shown.length, 105);
  assert.equal(requests, 2);
  assert.equal(new Set(shown.map(row => row.storyId)).size, 105);
  console.log('UI v3 controls: passed');
}
main().catch(err => { console.error(err); process.exitCode = 1; });
