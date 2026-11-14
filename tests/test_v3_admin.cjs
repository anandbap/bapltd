// Run with node tests/test_v3_admin.cjs; no external packages required.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const flush = () => new Promise(resolve => setImmediate(resolve));

async function main() {
  const html = fs.readFileSync(path.join(__dirname, '../bap-controlplane/internal/dashboardui/web/v3.html'), 'utf8');
  assert.match(html, /id="navAdmin"/);
  assert.match(html, /src="\/dashboard\/admin.js"/);
  new vm.Script(html.match(/<script>([\s\S]*?)<\/script>/)[1]);
  const elements = new Map();
  const el = id => {
    if (!elements.has(id)) elements.set(id, {value:'', textContent:'', innerHTML:'', disabled:false, hidden:false, events:{},
      addEventListener(name, fn) { this.events[name] = fn; }});
    return elements.get(id);
  };
  let admin = false, live = true, gets = 0, changed = 0, failDecision = false;
  const calls = [];
  const policy = {version:3, digest:'fixture-digest', policy_cedar:'permit(principal, action, resource);', schema_json:'', kill_switch:true};
  const pending = {escalation_id:'esc-fixture', status:'PENDING', action:'fs:write', resource:'/workspace/report', reason:'<script>unsafe</script>', ephemeral_grant:'MUST_NOT_RENDER', requested_at:'2026-11-13T10:00:00Z'};
  const fixture = {escalations:[pending]};
  const recommendation = {id:'rec-fixture',asset_id:'asset/a',instance_id:'workstation',action:'dev:go:test',status:'pending',command_hint:'<img src=x onerror=alert(1)>',justification:'Run tests',occurrences:2};
  const ctx = vm.createContext({console, Promise, Set, Date, Number, JSON, Error, document:{getElementById:el}, confirm:()=>true});
  ctx.window = ctx;
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../bap-controlplane/internal/dashboardui/web/admin.js'), 'utf8'), ctx);
  const deps = {
    isAdmin:()=>admin, isLive:()=>live, requireAdminLogin() {}, onDecision(){changed++;},
    async getJSON(url) { gets++; return url.includes('recommendations') ? {recommendations:[recommendation]} : url.includes('escalation') ? fixture : policy; },
    async apiFetch(url, options) {
      const body = options.body ? JSON.parse(options.body) : null; calls.push({url, body});
      if (url.includes('/policy/recommendations/')) {
        if (failDecision) throw new Error('HTTP 403: unauthorized');
        recommendation.status = url.endsWith('/approve') ? 'approved' : 'rejected';
        return {json:async()=>({...recommendation})};
      }
      if (options.method === 'DELETE') { recommendation.status='revoked'; return {json:async()=>({approved_effects:{}})}; }
      if (url.endsWith('/resolve')) {
        if (failDecision) throw new Error('HTTP 403: unauthorized');
        pending.status = body.decision === 'approve' ? 'APPROVED' : 'DENIED';
        return {json:async()=>({status:pending.status})};
      }
      if (url.endsWith('/validate')) return {json:async()=>({valid:true,policy_count:1})};
      if (url.endsWith('/simulate')) return {json:async()=>({draft_policy_valid:true,total_evaluated:2,denied_to_allowed:1,allowed_to_denied:0,diff_items:[]})};
      if (url.endsWith('/deploy')) return {json:async()=>({...policy,version:4,policy_cedar:body.policy_cedar})};
      throw new Error('Unexpected URL ' + url);
    }
  };
  ctx.BAPAdmin.init(deps);
  ctx.BAPAdmin.show(); await flush();
  assert.equal(gets, 0, 'Locked admin view must not load private requests');
  assert.equal(el('adminWorkspace').hidden, true);
  await ctx.BAPAdmin.resolve('esc-fixture', 'approve');
  assert.equal(calls.length, 0);

  admin = true; ctx.BAPAdmin.authChanged(); await flush();
  assert.equal(el('adminWorkspace').hidden, false);
  assert.match(el('approvalList').innerHTML, /&lt;script&gt;/);
  assert.doesNotMatch(el('approvalList').innerHTML, /MUST_NOT_RENDER/);
  el('approvalReviewer').value = 'reviewer@example.test'; el('approvalTTL').value = '300';
  failDecision = true;
  await ctx.BAPAdmin.resolve('esc-fixture', 'approve');
  assert.equal(pending.status, 'PENDING');
  assert.equal(changed, 0, 'Do not claim approval before server confirmation');
  assert.match(el('approvalsStatus').textContent, /Decision not confirmed/);
  failDecision = false;
  await ctx.BAPAdmin.resolve('esc-fixture', 'approve');
  assert.equal(changed, 1);
  const decision = calls.find(c=>c.url.endsWith('/resolve')).body;
  assert.equal(decision.escalation_id, 'esc-fixture');
  assert.equal(decision.decision, 'approve');
  assert.equal(decision.reviewer_email, 'reviewer@example.test');
  assert.equal(decision.ttl_seconds, 300);

  assert.match(el('recommendationList').innerHTML, /&lt;img/);
  assert.doesNotMatch(el('recommendationList').innerHTML, /<img/);
  failDecision = true;
  await ctx.BAPAdmin.decideRecommendation('rec-fixture','approve');
  assert.equal(recommendation.status, 'pending');
  assert.match(el('recommendationsStatus').textContent, /Decision not confirmed/);
  failDecision = false;
  el('recommendationNote').value = 'Reviewed local tests';
  await ctx.BAPAdmin.decideRecommendation('rec-fixture','approve');
  assert.equal(recommendation.status, 'approved');
  assert.equal(calls.filter(c=>c.url.endsWith('/rec-fixture/approve')).at(-1).body.note, 'Reviewed local tests');
  await ctx.BAPAdmin.decideRecommendation('rec-fixture','revoke');
  assert.equal(recommendation.status, 'revoked');
  assert.ok(calls.some(c=>c.url.includes('asset_id=asset%2Fa&action=dev%3Ago%3Atest')));

  el('policyScenarios').value = '[]';
  el('policyReason').value = 'Reviewed narrower workspace policy';
  await ctx.BAPAdmin.validate();
  assert.equal(el('policyDeploy').disabled, true, 'Validation alone is insufficient');
  await ctx.BAPAdmin.simulate();
  assert.equal(el('policyDeploy').disabled, false);
  el('policyDraft').value += '\n// edited after review'; el('policyDraft').events.input();
  assert.equal(el('policyDeploy').disabled, true, 'Editing invalidates prior validation and simulation');
  await ctx.BAPAdmin.validate(); await ctx.BAPAdmin.simulate(); await ctx.BAPAdmin.deploy();
  const deploy = calls.find(c=>c.url.endsWith('/deploy')).body;
  assert.equal(deploy.expected_version, 3);
  assert.equal(deploy.kill_switch, true, 'Policy editing must preserve fleet freeze');
  assert.match(el('policyResult').textContent, /version 4 deployed/);

  const beforeDemo = calls.length;
  live = false; ctx.BAPAdmin.authChanged();
  await ctx.BAPAdmin.validate(); await ctx.BAPAdmin.resolve('esc-fixture', 'deny');
  await ctx.BAPAdmin.decideRecommendation('rec-fixture','approve');
  assert.equal(calls.length, beforeDemo, 'Demo mode cannot mutate the live backend');
  assert.equal(el('adminWorkspace').hidden, true);

  // Responses issued under an old admin session cannot repopulate a logged-out view.
  live = true; admin = true;
  let release;
  deps.getJSON = url => url.includes('/current') ? new Promise(resolve=>{release=resolve;}) : Promise.resolve(fixture);
  ctx.BAPAdmin.authChanged(); await flush();
  admin = false; ctx.BAPAdmin.authChanged(); release(policy); await flush();
  assert.equal(el('policyDraft').value, '');
  assert.equal(el('approvalList').innerHTML, '');
  assert.equal(el('recommendationList').innerHTML, '');
  assert.equal(el('adminWorkspace').hidden, true);
  console.log('V3 admin policies and HITL approvals: passed');
}
main().catch(err=>{console.error(err);process.exitCode=1;});
