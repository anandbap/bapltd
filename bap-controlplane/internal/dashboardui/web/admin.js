(function (root) {
  'use strict';
  var deps, visible = false, epoch = 0, bundle = null, validated = '', simulated = '', busy = false;
  var requests = [], deciding = new Set();
  var $ = function (id) { return document.getElementById(id); };
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }
  function authorized() { return !!(deps && deps.isAdmin() && deps.isLive()); }
  function draftKey() { return JSON.stringify([$('policyDraft').value, $('policySchema').value]); }
  function showMessage(id, value) { $(id).textContent = value; }
  function controls() {
    var allow = authorized();
    $('adminLocked').hidden = !!(deps && deps.isAdmin());
    $('adminModeNotice').hidden = !(deps && deps.isAdmin() && !deps.isLive());
    $('adminWorkspace').hidden = !allow;
    ['policyValidate','policySimulate','policyReload','approvalsRefresh'].forEach(function (id) { $(id).disabled = !allow || busy; });
    $('policyDeploy').disabled = !allow || busy || !bundle || validated !== draftKey() || simulated !== draftKey() || !$('policyReason').value.trim();
  }
  function post(url, data) {
    if (!authorized()) return Promise.reject(new Error('Verify your admin token and switch to Live mode.'));
    return deps.apiFetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)}).then(function (r) { return r.json(); });
  }
  function changeDraft() { validated = simulated = ''; showMessage('policyResult', 'Draft changed. Validate and simulate again before deployment.'); controls(); }
  function renderRequests() {
    $('approvalList').innerHTML = requests.map(function (r) {
      var pending = String(r.status).toUpperCase() === 'PENDING';
      var id = String(r.escalation_id || '');
      return '<article class="panel" data-approval-id="' + esc(id) + '"><h3>' + esc(r.action) + ' <span class="chip">' + esc(r.status) + '</span></h3>' +
        '<dl><dt>Resource</dt><dd>' + esc(r.resource) + '</dd><dt>Agent / session</dt><dd>' + esc(r.agent_id) + ' / ' + esc(r.session_id) + '</dd>' +
        '<dt>Reason</dt><dd>' + esc(r.reason) + '</dd><dt>Risk</dt><dd>' + esc(r.risk_rating) + '</dd><dt>Requested</dt><dd>' + esc(r.requested_at) + '</dd>' +
        (r.reviewer_email ? '<dt>Reviewer</dt><dd>' + esc(r.reviewer_email) + '</dd>' : '') +
        (r.expires_at ? '<dt>Grant expires</dt><dd>' + esc(r.expires_at) + '</dd>' : '') + '</dl>' +
        (pending ? '<div class="btns"><button class="btn" data-approval-decision="approve" data-approval-id="' + esc(id) + '"' + (deciding.has(id) ? ' disabled' : '') + '>Approve</button>' +
        '<button class="btn" data-approval-decision="deny" data-approval-id="' + esc(id) + '"' + (deciding.has(id) ? ' disabled' : '') + '>Deny</button></div>' : '') + '</article>';
    }).join('');
  }
  function loadRequests() {
    if (!authorized()) return Promise.resolve();
    var run = epoch;
    showMessage('approvalsStatus', 'Loading requests…');
    return deps.getJSON('/api/v1/escalation/requests').then(function (data) {
      if (run !== epoch || !authorized()) return;
      requests = (data.escalations || []).slice().sort(function (a,b) {
        var pending = Number(b.status === 'PENDING') - Number(a.status === 'PENDING');
        return pending || Date.parse(b.requested_at) - Date.parse(a.requested_at);
      });
      renderRequests();
      var pending = requests.filter(function (r) { return r.status === 'PENDING'; }).length;
      showMessage('approvalsStatus', requests.length ? pending + ' pending · ' + requests.length + ' total requests' : 'No control-plane approval requests.');
    }).catch(function (err) { if (run === epoch) showMessage('approvalsStatus', 'Could not load approvals: ' + err.message); });
  }
  function resolveRequest(id, decision) {
    if (!authorized() || deciding.has(id)) return Promise.resolve();
    var reviewer = $('approvalReviewer').value.trim(), ttl = Number($('approvalTTL').value);
    if (!reviewer || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(reviewer)) {
      showMessage('approvalsStatus', 'Enter your reviewer email before recording a decision.'); return Promise.resolve();
    }
    if (!Number.isInteger(ttl) || ttl < 1 || ttl > 900) { showMessage('approvalsStatus', 'Choose a lifetime from 1 to 900 seconds.'); return Promise.resolve(); }
    if (!requests.some(function (r) { return r.escalation_id === id && r.status === 'PENDING'; })) return Promise.resolve();
    if (!root.confirm((decision === 'approve' ? 'Approve for ' + ttl + ' seconds' : 'Deny') + ' request ' + id + '?')) return Promise.resolve();
    var run = epoch;
    deciding.add(id); renderRequests();
    return post('/api/v1/escalation/resolve', {escalation_id:id, decision:decision, reviewer_email:reviewer, ttl_seconds:ttl}).then(function (data) {
      if (run !== epoch || !authorized()) return;
      if (data.status !== (decision === 'approve' ? 'APPROVED' : 'DENIED')) throw new Error('The server did not confirm this decision.');
      return loadRequests().then(function () {
        if (run !== epoch) return;
        showMessage('approvalsStatus', 'Server recorded ' + data.status.toLowerCase() + ' for ' + id + '.');
        if (deps.onDecision) deps.onDecision();
      });
    }).catch(function (err) { if (run === epoch) showMessage('approvalsStatus', 'Decision not confirmed: ' + err.message + '. Refresh before retrying.'); })
      .finally(function () { deciding.delete(id); if (run === epoch) renderRequests(); });
  }
  function loadPolicy() {
    if (!authorized()) return Promise.resolve();
    if (bundle && ($('policyDraft').value !== bundle.policy_cedar || $('policySchema').value !== (bundle.schema_json || '')) && !root.confirm('Discard the edited policy draft and reload?')) return Promise.resolve();
    var run = epoch;
    return deps.getJSON('/api/v1/policies/cedar/current').then(function (data) {
      if (run !== epoch || !authorized()) return;
      bundle = data; validated = simulated = '';
      $('policyDraft').value = data.policy_cedar || '';
      $('policySchema').value = data.schema_json || '';
      showMessage('policyVersion', 'Version ' + data.version + ' · ' + (data.digest || '') + ' · Fleet freeze: ' + (data.kill_switch ? 'active' : 'off'));
      showMessage('policyResult', 'Current policy loaded. Edit, validate, and simulate before deployment.'); controls();
    }).catch(function (err) { if (run === epoch) showMessage('policyResult', 'Could not load policy: ' + err.message); });
  }
  function validatePolicy() {
    if (!authorized() || busy) return Promise.resolve();
    var run = epoch, key = draftKey();
    validated = simulated = ''; busy = true; controls();
    return post('/api/v1/policies/cedar/validate', {policy_cedar:$('policyDraft').value, schema_json:$('policySchema').value}).then(function (data) {
      if (run !== epoch || key !== draftKey() || !authorized()) return;
      if (data.valid) { validated = key; showMessage('policyResult', 'Valid Cedar policy · ' + data.policy_count + ' rules. Simulate the impact next.'); }
      else showMessage('policyResult', 'Validation failed:\n' + (data.errors || []).map(function (e) { return 'Line ' + e.line + ': ' + e.message; }).join('\n'));
    }).catch(function (err) { if (run === epoch) showMessage('policyResult', 'Validation failed: ' + err.message); })
      .finally(function () { if (run === epoch) { busy = false; controls(); } });
  }
  function simulatePolicy() {
    if (!authorized() || busy) return Promise.resolve();
    var run = epoch, key = draftKey(), scenarios, scenarioText = $('policyScenarios').value;
    simulated = '';
    if (validated !== key) { showMessage('policyResult', 'Validate this draft before simulation.'); controls(); return Promise.resolve(); }
    try { scenarios = JSON.parse($('policyScenarios').value || '[]'); if (!Array.isArray(scenarios)) throw new Error('Expected an array.'); }
    catch (err) { showMessage('policyResult', 'Invalid scenario JSON: ' + err.message); controls(); return Promise.resolve(); }
    busy = true; controls();
    return post('/api/v1/policies/cedar/simulate', {draft_policy:$('policyDraft').value, scenarios:scenarios, include_historical_audit:true, max_historical:50}).then(function (data) {
      if (run !== epoch || key !== draftKey() || scenarioText !== $('policyScenarios').value || !authorized()) return;
      if (!data.draft_policy_valid || !data.total_evaluated) throw new Error('No successful simulation. Add scenarios if the audit history is empty.');
      simulated = key;
      showMessage('policyResult', data.total_evaluated + ' scenarios evaluated · ' + data.denied_to_allowed + ' newly allowed · ' + data.allowed_to_denied + ' newly denied.\n' +
        (data.diff_items || []).filter(function (r) { return r.diff_type !== 'UNCHANGED'; }).map(function (r) { return r.current_decision + ' → ' + r.draft_decision + ': ' + r.command; }).join('\n'));
    }).catch(function (err) { if (run === epoch) showMessage('policyResult', 'Simulation failed: ' + err.message); })
      .finally(function () { if (run === epoch) { busy = false; controls(); } });
  }
  function deployPolicy() {
    controls();
    if ($('policyDeploy').disabled) return Promise.resolve();
    if (!root.confirm('Deploy the reviewed policy to the control plane? Enrolled edges receive it on policy sync.')) return Promise.resolve();
    var run = epoch;
    busy = true; controls();
    return post('/api/v1/policies/cedar/deploy', {policy_cedar:$('policyDraft').value, schema_json:$('policySchema').value,
      kill_switch:bundle.kill_switch, expected_version:bundle.version, reason:$('policyReason').value.trim()}).then(function (data) {
      if (run !== epoch || !authorized()) return;
      bundle = data; validated = simulated = '';
      showMessage('policyVersion', 'Version ' + data.version + ' · ' + data.digest);
      showMessage('policyResult', 'Policy version ' + data.version + ' deployed. Edge rollout completes through policy sync.');
    }).catch(function (err) { if (run === epoch) showMessage('policyResult', 'Deployment not confirmed: ' + err.message); })
      .finally(function () { if (run === epoch) { busy = false; controls(); } });
  }
  function authChanged() {
    if (!deps) return;
    epoch++; bundle = null; requests = []; validated = simulated = ''; busy = false; deciding.clear();
    ['policyDraft','policySchema','policyReason','approvalReviewer'].forEach(function (id) { $(id).value = ''; });
    $('approvalList').innerHTML = ''; showMessage('policyVersion', 'Current policy not loaded.'); showMessage('policyResult', '');
    showMessage('approvalsStatus', 'No requests loaded.'); controls();
    if (visible && authorized()) { loadPolicy(); loadRequests(); }
  }
  root.BAPAdmin = {
    init: function (options) {
      deps = options;
      $('adminUnlock').addEventListener('click', deps.requireAdminLogin);
      $('policyReload').addEventListener('click', loadPolicy);
      $('approvalsRefresh').addEventListener('click', loadRequests);
      $('policyValidate').addEventListener('click', validatePolicy);
      $('policySimulate').addEventListener('click', simulatePolicy);
      $('policyDeploy').addEventListener('click', deployPolicy);
      ['policyDraft','policySchema'].forEach(function (id) { $(id).addEventListener('input', changeDraft); });
      $('policyScenarios').addEventListener('input', function () { simulated = ''; controls(); });
      $('policyReason').addEventListener('input', controls);
      $('approvalList').addEventListener('click', function (event) {
        var button = event.target.closest('[data-approval-decision]');
        if (button && !button.disabled) resolveRequest(button.getAttribute('data-approval-id'), button.getAttribute('data-approval-decision'));
      });
      controls();
    },
    show: function () { visible = true; controls(); if (authorized()) { if (!bundle) loadPolicy(); loadRequests(); } },
    hide: function () { visible = false; }, authChanged: authChanged,
    refresh: loadRequests, resolve: resolveRequest, validate: validatePolicy, simulate: simulatePolicy, deploy: deployPolicy
  };
})(window);
