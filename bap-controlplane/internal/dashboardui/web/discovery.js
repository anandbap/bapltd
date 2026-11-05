/* Discovery is an independent, lazy inventory view, never a grant/enrollment UI. */
(function (root) {
  'use strict';
  var api, state = {rows: [], next: '', revision: 0, busy: false, active: false, generation: 0};
  function el(id) { return document.getElementById(id); }
  function text(id, value) { var node = el(id); if (node) node.textContent = value; }
  function allowed() { return Boolean(api && api.isAdmin && api.isAdmin() && (!api.hasAdminToken || api.hasAdminToken()) && api.isLive && api.isLive()); }
  function message(value) { text('discoveryMessage', value); }
  function clear() { state.generation++; state.rows = []; state.next = ''; state.revision = 0; render(); text('discoverySummary', 'Authenticate as admin in Live mode to inspect workstation discovery.'); text('discoveryCoverage','No scan coverage loaded.'); text('discoveryEvidenceBody',''); text('discoveryStorage',''); text('pilotCoverageSummary','Pilot roster not loaded.'); if (el('pilotCoverageRows')) el('pilotCoverageRows').replaceChildren(); el('discoveryDrawer').close(); message('No discovery data loaded.'); }
  function pilotCoverage() {
    if (!allowed() || !state.active) return Promise.resolve();
    var generation = state.generation;
    return api.getJSON('/api/v1/pilot/coverage').then(function (report) {
      if (!allowed() || generation !== state.generation) return;
      var box = el('pilotCoverageRows'); if (!box) return; box.replaceChildren();
      text('pilotCoverageSummary', report.fresh_workstations + '/' + report.expected_workstations + ' expected workstations have fresh check-ins; ' + report.expected_people + ' expected people. As of ' + report.as_of + '. Current snapshot; history is not durable.');
      (report.rows || []).forEach(function (row) { var p = document.createElement('p'); p.textContent = row.person_id + ' / ' + row.team + ' / ' + row.instance_id + ': ' + row.state + (row.last_checkin ? ' / last check-in ' + row.last_checkin : ''); box.appendChild(p); });
    }).catch(function () {
      if (!allowed() || generation !== state.generation) return;
      if (el('pilotCoverageRows')) el('pilotCoverageRows').replaceChildren();
      text('pilotCoverageSummary','Pilot coverage unavailable or roster not configured. Expected denominator unknown.');
    });
  }
  function summary() {
    if (!allowed()) { clear(); return Promise.resolve(); }
    var generation = state.generation;
    return api.getJSON('/api/v1/discovery/shadow-it/summary').then(function (s) {
      if (!allowed() || generation !== state.generation) return;
      text('discoverySummary', s.open_findings + ' open observations · ' + s.fresh_workstations + '/' + s.expected_workstations + ' workstations with fresh complete scans · ' + s.partial_workstations + ' partial · ' + s.stale_workstations + ' stale · ' + s.not_scanned_workstations + ' not scanned');
      text('discoveryStorage', 'Storage: ' + s.storage + '. Fleet coverage covers reported scopes only. Configuration and process presence do not prove execution or enforcement.');
    }).catch(function () { text('discoverySummary', 'Discovery summary unavailable. Retained data may be stale.'); });
  }
  function render() {
    var body = el('discoveryRows'); if (!body) return; body.replaceChildren();
    state.rows.forEach(function (a) {
      var tr = document.createElement('tr');
      [a.name, a.instance_id, a.kind, a.evidence, a.state, a.disposition || 'open', a.last_seen].forEach(function (v) { var td = document.createElement('td'); td.textContent = v || 'Unknown'; tr.appendChild(td); });
      var td = document.createElement('td'), button = document.createElement('button'); button.type = 'button'; button.className = 'link'; button.textContent = 'Evidence'; button.addEventListener('click', function () { evidence(a); }); td.appendChild(button); tr.appendChild(td); body.appendChild(tr);
    });
    el('discoveryMore').disabled = !state.next || state.busy;
    text('discoveryCount', state.rows.length + ' observations loaded');
  }
  function load(more) {
    if (!allowed()) { clear(); return Promise.resolve(); }
    if (state.busy) { if (!more) state.reloadPending = true; return Promise.resolve(); }
    state.busy = true; var generation = state.generation;
    if (!more) { state.next = ''; state.revision = 0; }
    var query = new URLSearchParams({limit: '50'});
    ['instance_id','kind','state'].forEach(function (key) { var value = el('discoveryFilter_' + key).value.trim(); if (value) query.set(key, value); });
    if (more && state.next) { query.set('cursor', state.next); query.set('revision', String(state.revision)); }
    message('Loading discovery evidence…');
    return api.getJSON('/api/v1/discovery/shadow-it/findings?' + query.toString()).then(function (page) {
      if (!allowed() || generation !== state.generation) return;
      var raw = more ? state.rows.concat(page.findings || []) : (page.findings || []);
      var seen = {};
      var deduped = [];
      raw.forEach(function (row) {
        var k = (row.instance_id || '') + '::' + (row.kind || '') + '::' + (row.name || '');
        if (!seen[k]) {
          seen[k] = true;
          deduped.push(row);
        }
      });
      state.rows = deduped; state.next = page.next_cursor || ''; state.revision = page.revision;
      message(page.total === 0 ? 'No observations match this filter. Check scan coverage before treating this as clean.' : 'Latest inventory snapshot. Presence and invocation are separate evidence.');
      render();
    }).catch(function (error) {
      if (generation !== state.generation) return;
      state.next = ''; message(String(error.message).indexOf('409') >= 0 ? 'Inventory changed. Refresh to start a new snapshot.' : 'Discovery unavailable. Showing previously loaded evidence; it may be stale.');
    }).finally(function () { state.busy = false; render(); if (state.reloadPending) {state.reloadPending = false; load(false);} });
  }
  function post(path, value) {
    if (!allowed()) {
      return Promise.reject(new Error('Access Denied: Administrative credential required. Action blocked.'));
    }
    return api.apiFetch('/api/v1/discovery/shadow-it/' + path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(value)}).then(function (r) {return r.json();});
  }
  function rescan() {
    if (!allowed()) {
      message('Access Denied: Administrative credential required. Enter a verified admin token to trigger a scan.');
      if (api && api.requireAdminLogin) api.requireAdminLogin();
      return;
    }
    var instance = el('discoveryFilter_instance_id').value.trim();
    if (!instance && !root.confirm('Queue a metadata discovery scan for every enrolled workstation?')) return;
    post('scan/trigger', instance ? {scope: 'selected', instances: [instance]} : {scope: 'fleet'}).then(function () {message('Scan requested. Offline workstations will receive it on a later authenticated heartbeat. Completion is pending.');}).catch(function (error) {message('Rescan request failed: ' + error.message);});
  }
  function evidence(a) {
    text('discoveryEvidenceTitle', a.name);
    text('discoveryEvidenceBody', JSON.stringify({workstation: a.instance_id, owner: a.owner, kind: a.kind, evidence: a.evidence, first_seen: a.first_seen, last_seen: a.last_seen, pid: a.pid, process_birth: a.birth, operation_id: a.operation_id, outcome: a.outcome, mediation: a.mediation, approval: a.approval, disposition: a.disposition || 'open', reason: a.reason, exception_expires: a.expires_at}, null, 2));
    el('discoveryAcknowledge').onclick = function () { disposition(a, 'acknowledged'); };
    el('discoveryException').onclick = function () { disposition(a, 'exception'); };
    el('discoveryReopen').onclick = function () { disposition(a, 'open'); };
    el('discoveryDrawer').showModal();
  }
  function disposition(a, value) {
    if (!allowed()) {
      message('Access Denied: Administrative credential required to record review decisions.');
      if (api && api.requireAdminLogin) api.requireAdminLogin();
      return;
    }
    var reason = root.prompt('Reason (metadata only; do not enter secrets):'); if (!reason || !reason.trim()) return;
    var request = {id: a.id, state: value, reason: reason.trim()};
    if (value === 'exception') { var days = Number(root.prompt('Exception duration in days (1–30):', '7')); if (!Number.isFinite(days) || days < 1 || days > 30) return; request.expires_at = new Date(Date.now() + days * 86400000).toISOString(); }
    post('disposition', request).then(function () {el('discoveryDrawer').close(); summary(); return load(false);}).catch(function (error) {message('Disposition failed: ' + error.message);});
  }
  function coverage() {
    if (!allowed()) return Promise.resolve();
    var generation = state.generation;
    return api.getJSON('/api/v1/discovery/shadow-it/reports?limit=100').then(function (result) {
      if (!allowed() || generation !== state.generation) return;
      var box = el('discoveryCoverage'); box.replaceChildren();
      (result.reports || []).forEach(function (report) {var p = document.createElement('p'); p.textContent = report.instance_id + ' · ' + report.status + ' · completed ' + report.completed_at + ' · ' + (report.scopes || []).map(function (scope) {return scope.id + ': ' + scope.status;}).join(', '); box.appendChild(p);});
      if (!result.count) box.textContent = 'No workstation scans received. This does not mean the fleet is clean.';
    }).catch(function () {text('discoveryCoverage', 'Scan coverage unavailable.');});
  }
  root.BAPDiscovery = {
    init: function (options) { api = options; el('discoveryRefresh').onclick = function () {summary(); coverage(); pilotCoverage(); load(false);}; el('discoveryMore').onclick = function () {load(true);}; el('discoveryRescan').onclick = rescan; el('discoveryClose').onclick = function () {el('discoveryDrawer').close();}; ['instance_id','kind','state'].forEach(function (key) {el('discoveryFilter_' + key).addEventListener('change', function () {state.generation++; load(false);});}); summary(); root.setInterval(function () {summary(); pilotCoverage();}, 30000); },
    authChanged: function () { if (!api) return; state.generation++; if (!allowed()) clear(); else {summary(); if (state.active) {load(false); coverage(); pilotCoverage();}} },
    show: function (instance) {state.active = true; if (instance !== undefined) el('discoveryFilter_instance_id').value = instance; summary(); load(false); coverage(); pilotCoverage();},
    hide: function () {state.active = false;},
    refresh: function () {return load(false);}
  };
})(window);
