import React, { useState, useEffect } from 'react';

const API = '/api/v1';

export default function GatewayPEPView({ adminToken, onNotify }) {
  const [pepStatus, setPepStatus] = useState(null);
  const [edgeEvents, setEdgeEvents] = useState([]);
  const [activeTab, setActiveTab] = useState('routes'); // 'routes' | 'tester' | 'audit'
  const [loading, setLoading] = useState(false);

  // Simulation test state
  const [simScenario, setSimScenario] = useState('rogue_no_grant');
  const [simulating, setSimulating] = useState(false);
  const [simResult, setSimResult] = useState(null);

  useEffect(() => {
    fetchPEPStatus();
    fetchEdgeAudit();
  }, []);

  async function fetchPEPStatus() {
    setLoading(true);
    try {
      const res = await fetch(`${API}/pep/status`);
      if (res.ok) {
        const data = await res.json();
        setPepStatus(data);
      }
    } catch (err) {
      console.error('Failed to load Gateway PEP status', err);
    } finally {
      setLoading(false);
    }
  }

  async function fetchEdgeAudit() {
    try {
      const res = await fetch(`${API}/telemetry`);
      if (res.ok) {
        const data = await res.json();
        setEdgeEvents(data.edge_events || []);
      }
    } catch (err) {
      console.error('Failed to load edge audit events', err);
    }
  }

  async function runSimulation(scenarioKey) {
    const scenario = scenarioKey || simScenario;
    setSimulating(true);
    setSimResult(null);
    try {
      const res = await fetch(`${API}/pep/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario }),
      });
      if (res.ok) {
        const result = await res.json();
        setSimResult(result);
        await fetchEdgeAudit();
        if (onNotify) {
          onNotify(`Gateway PEP test completed: ${result.scenario} -> HTTP ${result.http_status || (result.call_1_result ? '200 & 403' : '200')}`);
        }
      }
    } catch (err) {
      console.error('Simulation error', err);
      if (onNotify) onNotify('Simulation execution error');
    } finally {
      setSimulating(false);
    }
  }

  return (
    <div className="gateway-pep-container">
      {/* PEP Overview Header */}
      <section className="pep-header">
        <div className="pep-header-left">
          <p className="eyebrow">Resource-Side Zero-Trust Policy Enforcement Point</p>
          <h2>BAP Gateway PEP & Anti-Replay Guard</h2>
          <p>
            Enforces Cedar security invariants at the resource perimeter. Authoritatively derives
            operations from HTTP requests, blocks client header spoofing, and synchronously burns single-use grants.
          </p>
        </div>

        <div className="pep-header-badges">
          <div className="pep-status-badge online">
            <i className="status-dot" />
            <span>PEP Status: <b>{pepStatus?.status || 'OPERATIONAL'}</b></span>
          </div>
          <div className="pep-status-badge anti-spoof">
            <span className="badge-icon">🛡️</span>
            <span>Anti-Spoofing: <b>ENFORCED (BAP-411)</b></span>
          </div>
          <div className="pep-status-badge burn">
            <span className="badge-icon">🔥</span>
            <span>Single-Use Burn: <b>SYNCHRONOUS (BAP-412)</b></span>
          </div>
        </div>
      </section>

      {/* Visual Architectural Data Flow */}
      <section className="pep-architecture-flow">
        <div className="arch-node agent">
          <div className="node-icon">🤖</div>
          <strong>Untrusted AI Agent</strong>
          <span>Claude / Cursor / Copilot</span>
          <small>Potential Prompt Injection</small>
        </div>

        <div className="arch-connector">
          <span className="connector-label">HTTP Request + Bearer Grant</span>
          <div className="connector-line">
            <div className="connector-arrow">▶</div>
          </div>
        </div>

        <div className="arch-node pep active">
          <div className="node-icon">🛡️</div>
          <strong>BAP Gateway PEP</strong>
          <span>Reverse Proxy / Envoy ext_authz</span>
          <small>Authoritative Derivation & Burn</small>
        </div>

        <div className="arch-connector">
          <span className="connector-label">Verified Governed Request</span>
          <div className="connector-line green">
            <div className="connector-arrow green">▶</div>
          </div>
        </div>

        <div className="arch-node backend">
          <div className="node-icon">🏦</div>
          <strong>Protected Microservices</strong>
          <span>Financial Records / Banking API</span>
          <small>Zero Standing Credentials</small>
        </div>
      </section>

      {/* Navigation Sub-Tabs */}
      <div className="pep-subtabs">
        <button
          className={`subtab-btn ${activeTab === 'routes' ? 'active' : ''}`}
          onClick={() => setActiveTab('routes')}
        >
          Protected Route Matrix ({pepStatus?.protected_routes?.length || 2})
        </button>
        <button
          className={`subtab-btn ${activeTab === 'tester' ? 'active' : ''}`}
          onClick={() => setActiveTab('tester')}
        >
          ⚡ Live PEP Anti-Spoofing & Replay Sandbox
        </button>
        <button
          className={`subtab-btn ${activeTab === 'audit' ? 'active' : ''}`}
          onClick={() => setActiveTab('audit')}
        >
          Edge PEP Audit Stream ({edgeEvents.length})
        </button>
      </div>

      {/* TAB 1: Protected Routes Matrix */}
      {activeTab === 'routes' && (
        <section className="pep-routes-panel">
          <div className="panel-intro">
            <h3>Authoritative Operation Derivation Matrix (Invariant BAP-411)</h3>
            <p>
              The PEP ignores all caller-provided hints (like <code>X-Agent-Action</code>).
              Operations are strictly derived from the HTTP method and URI path before evaluating BAP Grants.
            </p>
          </div>

          <div className="routes-table-wrapper">
            <table className="pep-routes-table">
              <thead>
                <tr>
                  <th>Target Resource Path</th>
                  <th>HTTP Method</th>
                  <th>Authoritative Derived Action</th>
                  <th>Guardrail Enforcement</th>
                  <th>Token Burn Policy</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {(pepStatus?.protected_routes || [
                  {
                    path: '/api/v1/financial-records',
                    methods: ['GET', 'POST'],
                    derived_actions: { GET: 'financial.records.read', POST: 'financial.records.write' },
                    auth_requirement: 'Ephemeral BAP Grant Bearer',
                    max_uses: 1,
                    burn_on_use: true,
                    status: 'PROTECTED',
                  },
                  {
                    path: '/api/v1/core-banking/*',
                    methods: ['GET', 'POST'],
                    derived_actions: { GET: 'core_banking.read', POST: 'core_banking.transfer' },
                    auth_requirement: 'Ephemeral BAP Grant Bearer + Cedar Review',
                    max_uses: 1,
                    burn_on_use: true,
                    status: 'PROTECTED',
                  },
                ]).map((route, i) => (
                  <React.Fragment key={i}>
                    {route.methods.map((method) => (
                      <tr key={`${route.path}-${method}`}>
                        <td className="route-path"><code>{route.path}</code></td>
                        <td><span className={`method-pill ${method.toLowerCase()}`}>{method}</span></td>
                        <td className="derived-action">
                          <code>{route.derived_actions?.[method] || `${method}:${route.path}`}</code>
                        </td>
                        <td><span className="auth-req">{route.auth_requirement}</span></td>
                        <td>
                          <span className="burn-pill">🔥 Single-Use (max_uses={route.max_uses})</span>
                        </td>
                        <td><span className="protected-tag">ACTIVE PEP GUARD</span></td>
                      </tr>
                    ))}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* TAB 2: Interactive Sandbox & Anti-Spoofing Tester */}
      {activeTab === 'tester' && (
        <section className="pep-tester-panel">
          <div className="tester-grid">
            {/* Scenarios Selection */}
            <div className="tester-scenarios-card">
              <h3>Choose Test Attack Scenario</h3>
              <p>Execute real-time adversary simulations against the BAP Gateway PEP:</p>

              <div className="scenario-options">
                <label
                  className={`scenario-option ${simScenario === 'rogue_no_grant' ? 'selected' : ''}`}
                  onClick={() => setSimScenario('rogue_no_grant')}
                >
                  <input
                    type="radio"
                    name="scenario"
                    checked={simScenario === 'rogue_no_grant'}
                    onChange={() => setSimScenario('rogue_no_grant')}
                  />
                  <div className="scenario-details">
                    <strong>1. Rogue Access Attempt (No BAP Grant)</strong>
                    <p>Agent calls protected financial microservice directly without acquiring a BAP grant token.</p>
                    <span className="expected-result">Expected: <code>HTTP 401 Unauthorized (AccessDenied)</code></span>
                  </div>
                </label>

                <label
                  className={`scenario-option ${simScenario === 'header_spoofing' ? 'selected' : ''}`}
                  onClick={() => setSimScenario('header_spoofing')}
                >
                  <input
                    type="radio"
                    name="scenario"
                    checked={simScenario === 'header_spoofing'}
                    onChange={() => setSimScenario('header_spoofing')}
                  />
                  <div className="scenario-details">
                    <strong>2. Client Header Spoofing Attack</strong>
                    <p>Agent attempts to perform a <code>POST</code> write while injecting <code>X-Agent-Action: harmless.read</code>.</p>
                    <span className="expected-result">Expected: <code>PEP derives 'financial.records.write', rejects spoofing</code></span>
                  </div>
                </label>

                <label
                  className={`scenario-option ${simScenario === 'ephemeral_burn' ? 'selected' : ''}`}
                  onClick={() => setSimScenario('ephemeral_burn')}
                >
                  <input
                    type="radio"
                    name="scenario"
                    checked={simScenario === 'ephemeral_burn'}
                    onChange={() => setSimScenario('ephemeral_burn')}
                  />
                  <div className="scenario-details">
                    <strong>3. Single-Use Grant Burning & Anti-Replay Defense</strong>
                    <p>Mints 1-time grant (<code>max_uses=1</code>), presents on Call 1, then attempts immediate Replay on Call 2.</p>
                    <span className="expected-result">Expected: <code>Call 1: 200 OK | Call 2: 403 Forbidden (Burned)</code></span>
                  </div>
                </label>
              </div>

              <button
                className="btn-primary run-sim-btn"
                onClick={() => runSimulation()}
                disabled={simulating}
              >
                {simulating ? 'Evaluating Against PEP Perimeter…' : '⚡ Execute Real-Time PEP Verification'}
              </button>
            </div>

            {/* Results Console */}
            <div className="tester-console-card">
              <div className="console-head">
                <h3>Gateway PEP Inspection Console</h3>
                {simResult && <span className="status-chip success">EVALUATION COMPLETE</span>}
              </div>

              <div className="console-body">
                {simResult ? (
                  <div className="sim-result-details">
                    {simResult.scenario === 'rogue_no_grant' && (
                      <div className="result-block rogue">
                        <div className="result-status-row">
                          <span className="http-badge status-401">HTTP {simResult.http_status} UNAUTHORIZED</span>
                          <span className="decision-badge deny">DECISION: {simResult.pep_decision}</span>
                        </div>
                        <h4 className="result-headline">{simResult.message}</h4>
                        <div className="security-proof-box">
                          <strong>🛡️ Security Invariant Proof:</strong>
                          <p>{simResult.security_proof}</p>
                        </div>
                        <pre className="json-dump">{JSON.stringify(simResult, null, 2)}</pre>
                      </div>
                    )}

                    {simResult.scenario === 'header_spoofing' && (
                      <div className="result-block spoofing">
                        <div className="result-status-row">
                          <span className="http-badge status-401">HTTP 401 UNAUTHORIZED</span>
                          <span className="decision-badge deny">HEADER SPOOF BLOCKED</span>
                        </div>
                        <h4 className="result-headline">Client Header Spoofing Neutralized</h4>
                        <div className="security-proof-box">
                          <strong>🛡️ Anti-Spoofing Proof:</strong>
                          <p>
                            Client supplied: <code>{simResult.client_header}</code><br/>
                            PEP authoritatively derived: <code>{simResult.pep_derivation}</code>
                          </p>
                          <p>{simResult.security_proof}</p>
                        </div>
                        <pre className="json-dump">{JSON.stringify(simResult, null, 2)}</pre>
                      </div>
                    )}

                    {simResult.scenario === 'ephemeral_burn' && (
                      <div className="result-block burn">
                        <h4 className="result-headline">Atomic Single-Use Ephemeral Grant Burning</h4>
                        <div className="burn-flow">
                          <div className="burn-step allow">
                            <div className="burn-step-top">
                              <span className="http-badge status-200">CALL 1: HTTP 200 OK</span>
                              <span className="decision-badge allow">ALLOW</span>
                            </div>
                            <p>{simResult.call_1_result?.message}</p>
                            <small>🔥 {simResult.call_1_result?.burn_action}</small>
                          </div>

                          <div className="burn-divider">▼ IMMEDIATE REPLAY ATTACK ▼</div>

                          <div className="burn-step deny">
                            <div className="burn-step-top">
                              <span className="http-badge status-403">CALL 2: HTTP 403 FORBIDDEN</span>
                              <span className="decision-badge deny">DENY</span>
                            </div>
                            <p>{simResult.call_2_replay?.message}</p>
                            <small>🛡️ {simResult.call_2_replay?.anti_replay}</small>
                          </div>
                        </div>
                        <pre className="json-dump">{JSON.stringify(simResult, null, 2)}</pre>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="console-placeholder">
                    <span className="console-icon">🛡️</span>
                    <h4>Awaiting PEP Simulation Trigger</h4>
                    <p>Select a scenario on the left and click "Execute Real-Time PEP Verification" to inspect the live decision envelope.</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>
      )}

      {/* TAB 3: Edge Audit Stream */}
      {activeTab === 'audit' && (
        <section className="pep-audit-panel">
          <div className="panel-intro">
            <h3>Live Gateway PEP Edge Audit Stream</h3>
            <p>Every authorization rejection, token burn, and permitted execution logged authoritatively at the resource perimeter:</p>
          </div>

          <div className="audit-events-list">
            {edgeEvents.slice(-15).reverse().map((ev, idx) => {
              const isDeny = ev.decision === 'deny' || (ev.reason && ev.reason.includes('BLOCKED'));
              return (
                <div key={idx} className={`audit-event-card ${isDeny ? 'deny' : 'allow'}`}>
                  <div className="event-top">
                    <span className={`event-decision-pill ${isDeny ? 'deny' : 'allow'}`}>
                      {isDeny ? 'DENIED / BLOCKED' : 'PERMITTED'}
                    </span>
                    <span className="event-path"><code>{ev.executable || ev.full_command || 'Gateway PEP'}</code></span>
                    <span className="event-time">
                      {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'Live'}
                    </span>
                  </div>
                  <p className="event-reason">{ev.reason || ev.full_command || 'Gateway authorization event'}</p>
                </div>
              );
            })}

            {edgeEvents.length === 0 && (
              <div className="empty-audit">
                <p>No recent edge events captured. Run a test in the Sandbox tab above to populate live audit telemetry.</p>
              </div>
            )}
          </div>
        </section>
      )}
    </div>
  );
}
