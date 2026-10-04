import React, { useState, useEffect } from 'react';

const API = '/api/v1';

export default function ShadowITView({ adminToken, onNotify }) {
  const [findings, setFindings] = useState([]);
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [filter, setFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [lastScanTime, setLastScanTime] = useState(null);

  useEffect(() => {
    fetchFindings();
    fetchReports();
  }, []);

  async function fetchFindings() {
    setLoading(true);
    try {
      const res = await fetch(`${API}/discovery/shadow-it/findings`);
      if (res.ok) {
        const data = await res.json();
        setFindings(data.findings || []);
      }
    } catch (err) {
      console.error('Failed to load shadow IT findings', err);
    } finally {
      setLoading(false);
    }
  }

  async function fetchReports() {
    try {
      const res = await fetch(`${API}/discovery/shadow-it/reports`);
      if (res.ok) {
        const data = await res.json();
        setReports(data.reports || []);
      }
    } catch (err) {
      console.error('Failed to load shadow IT reports', err);
    }
  }

  async function triggerScan() {
    setScanning(true);
    try {
      const res = await fetch(`${API}/discovery/shadow-it/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (res.ok) {
        const report = await res.json();
        setLastScanTime(new Date());
        await fetchFindings();
        await fetchReports();
        if (onNotify) {
          onNotify(`Discovery scan completed: ${report.total_findings} shadow assets identified (${report.critical_count} critical)`);
        }
      }
    } catch (err) {
      console.error('Scan failed', err);
      if (onNotify) onNotify('Scan execution error');
    } finally {
      setScanning(false);
    }
  }

  // Filter & Search
  const filteredFindings = findings.filter((f) => {
    if (filter === 'CRITICAL' && f.risk_level !== 'CRITICAL') return false;
    if (filter === 'HIGH' && f.risk_level !== 'HIGH') return false;
    if (filter === 'MCP' && f.type !== 'UNMANAGED_LOCAL_MCP_SERVER') return false;
    if (filter === 'ENV_VAR' && f.type !== 'UNMANAGED_ENV_VARIABLE') return false;
    if (filter === 'ENV_FILE' && f.type !== 'UNPROTECTED_ENV_FILE') return false;

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchName = (f.name || '').toLowerCase().includes(q);
      const matchTarget = (f.target || '').toLowerCase().includes(q);
      const matchDetails = (f.details || '').toLowerCase().includes(q);
      const matchRemediation = (f.remediation || '').toLowerCase().includes(q);
      return matchName || matchTarget || matchDetails || matchRemediation;
    }
    return true;
  });

  const criticalCount = findings.filter((f) => f.risk_level === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.risk_level === 'HIGH').length;
  const mcpCount = findings.filter((f) => f.type === 'UNMANAGED_LOCAL_MCP_SERVER').length;
  const envVarCount = findings.filter((f) => f.type === 'UNMANAGED_ENV_VARIABLE').length;
  const envFileCount = findings.filter((f) => f.type === 'UNPROTECTED_ENV_FILE').length;

  return (
    <div className="shadow-it-container">
      {/* Top Header */}
      <section className="shadow-header">
        <div className="shadow-header-left">
          <p className="eyebrow">Enterprise Attack Surface Management</p>
          <h2>Shadow IT & Unmanaged Asset Discovery</h2>
          <p>
            Continuous scanning for rogue local MCP servers, leaked standing credentials,
            and unprotected secrets bypassing BAP's Zero Standing Privilege invariant.
          </p>
        </div>
        <div className="shadow-header-right">
          <button
            className={`btn-primary shadow-scan-btn ${scanning ? 'loading' : ''}`}
            onClick={triggerScan}
            disabled={scanning}
          >
            <span className="scan-icon">{scanning ? '⟳' : '⚡'}</span>
            {scanning ? 'Scanning Workstation & Configs…' : 'Trigger Discovery Scan'}
          </button>
          {lastScanTime && (
            <span className="last-scan-time">
              Last scan: {lastScanTime.toLocaleTimeString()}
            </span>
          )}
        </div>
      </section>

      {/* KPI Metric Cards */}
      <section className="shadow-kpi-grid">
        <div className="shadow-kpi-card total">
          <span className="kpi-label">Total Shadow Assets</span>
          <strong className="kpi-value">{findings.length}</strong>
          <small className="kpi-sub">Across workstation & fleet</small>
        </div>
        <div className="shadow-kpi-card critical">
          <span className="kpi-label">Critical Standing Keys</span>
          <strong className="kpi-value warn">{criticalCount}</strong>
          <small className="kpi-sub">AWS, OpenAI, DB credentials</small>
        </div>
        <div className="shadow-kpi-card mcp">
          <span className="kpi-label">Unmanaged MCP Servers</span>
          <strong className="kpi-value info">{mcpCount}</strong>
          <small className="kpi-sub">Claude Desktop, Cursor, stdio</small>
        </div>
        <div className="shadow-kpi-card files">
          <span className="kpi-label">Unprotected .env Files</span>
          <strong className="kpi-value">{envFileCount}</strong>
          <small className="kpi-sub">Plaintext config on disk</small>
        </div>
      </section>

      {/* Search & Filter Toolbar */}
      <section className="shadow-toolbar">
        <div className="shadow-search-box">
          <span className="search-icon">🔍</span>
          <input
            type="text"
            placeholder="Search shadow assets, secrets, MCP tools, paths…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
          {searchQuery && (
            <button className="clear-search" onClick={() => setSearchQuery('')}>×</button>
          )}
        </div>

        <div className="shadow-filter-pills">
          <button
            className={`filter-pill ${filter === 'ALL' ? 'active' : ''}`}
            onClick={() => setFilter('ALL')}
          >
            All Findings ({findings.length})
          </button>
          <button
            className={`filter-pill critical ${filter === 'CRITICAL' ? 'active' : ''}`}
            onClick={() => setFilter('CRITICAL')}
          >
            Critical ({criticalCount})
          </button>
          <button
            className={`filter-pill high ${filter === 'HIGH' ? 'active' : ''}`}
            onClick={() => setFilter('HIGH')}
          >
            High Risk ({highCount})
          </button>
          <button
            className={`filter-pill mcp ${filter === 'MCP' ? 'active' : ''}`}
            onClick={() => setFilter('MCP')}
          >
            Local MCP Servers ({mcpCount})
          </button>
          <button
            className={`filter-pill env ${filter === 'ENV_VAR' ? 'active' : ''}`}
            onClick={() => setFilter('ENV_VAR')}
          >
            Env Credentials ({envVarCount})
          </button>
          <button
            className={`filter-pill files ${filter === 'ENV_FILE' ? 'active' : ''}`}
            onClick={() => setFilter('ENV_FILE')}
          >
            .env Files ({envFileCount})
          </button>
        </div>
      </section>

      {/* Findings Catalog & Inspector Grid */}
      <section className="shadow-findings-grid">
        <div className="shadow-findings-list">
          {filteredFindings.map((finding) => {
            const isSelected = selectedFinding?.id === finding.id;
            const isCritical = finding.risk_level === 'CRITICAL';
            const isMCP = finding.type === 'UNMANAGED_LOCAL_MCP_SERVER';
            const isEnv = finding.type === 'UNMANAGED_ENV_VARIABLE';

            return (
              <div
                key={finding.id}
                className={`finding-card risk-${finding.risk_level.toLowerCase()} ${isSelected ? 'selected' : ''}`}
                onClick={() => setSelectedFinding(finding)}
              >
                <div className="finding-header">
                  <div className="finding-type-chip">
                    <span className="chip-icon">
                      {isMCP ? '⚙️' : isEnv ? '🔑' : '📄'}
                    </span>
                    <span className="chip-text">
                      {isMCP ? 'LOCAL MCP SERVER' : isEnv ? 'STANDING CREDENTIAL' : 'UNPROTECTED SECRETS FILE'}
                    </span>
                  </div>
                  <span className={`risk-badge badge-${finding.risk_level.toLowerCase()}`}>
                    <i className="badge-dot" />
                    {finding.risk_level} ({(finding.risk_score * 100).toFixed(0)}%)
                  </span>
                </div>

                <h4 className="finding-title">{finding.name}</h4>
                <div className="finding-target" title={finding.target}>
                  <code>{finding.target}</code>
                </div>

                <p className="finding-details">{finding.details}</p>

                <div className="finding-remediation-box">
                  <span className="remediation-title">🛡️ BAP Remediation Guidance:</span>
                  <p>{finding.remediation}</p>
                </div>

                {finding.metadata && Object.keys(finding.metadata).length > 0 && (
                  <div className="finding-meta-row">
                    {finding.metadata.server_name && (
                      <span className="meta-tag">Server: <b>{finding.metadata.server_name}</b></span>
                    )}
                    {finding.metadata.command && (
                      <span className="meta-tag">Command: <code>{finding.metadata.command}</code></span>
                    )}
                    {finding.metadata.category && (
                      <span className="meta-tag">Category: <b>{finding.metadata.category}</b></span>
                    )}
                    {finding.metadata.value_mask && (
                      <span className="meta-tag">Masked: <code>{finding.metadata.value_mask}</code></span>
                    )}
                  </div>
                )}
              </div>
            );
          })}

          {filteredFindings.length === 0 && (
            <div className="empty-findings-state">
              <span className="empty-icon">🛡️</span>
              <h3>No Shadow Assets in Current View</h3>
              <p>
                {findings.length === 0
                  ? 'Click "Trigger Discovery Scan" above to scan local MCP configs and environment credentials.'
                  : 'No findings match the selected filter criteria.'}
              </p>
            </div>
          )}
        </div>

        {/* Audit & Scan History Drawer */}
        <aside className="shadow-history-panel">
          <div className="history-head">
            <h3>Discovery Scan History</h3>
            <span className="report-badge">{reports.length} Runs</span>
          </div>

          <div className="history-list">
            {reports.slice(-6).reverse().map((rep) => (
              <div key={rep.scan_id} className="history-item">
                <div className="history-item-top">
                  <strong className="scan-id">{rep.scan_id}</strong>
                  <span className="history-time">
                    {new Date(rep.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>
                <div className="history-stats">
                  <span className="stat-crit">{rep.critical_count} Critical</span>
                  <span className="stat-mcp">{rep.unmanaged_mcp_count} MCP</span>
                  <span className="stat-env">{rep.unmanaged_env_var_count} Env</span>
                </div>
                <p className="history-summary">{rep.summary}</p>
              </div>
            ))}

            {reports.length === 0 && (
              <div className="empty-history">
                <p>No previous scans recorded in this session.</p>
              </div>
            )}
          </div>

          <div className="zero-trust-principle-card">
            <h4>💡 BAP Zero-Trust Invariant</h4>
            <p>
              <strong>Zero Standing Privilege:</strong> Standing API keys, unmanaged MCP servers,
              and local credentials allow LLM agents to execute lateral actions without policy evaluation.
              Wrap MCP tools with <code>bapedge mcp</code> and proxy all microservice calls through the BAP Gateway PEP.
            </p>
          </div>
        </aside>
      </section>
    </div>
  );
}
