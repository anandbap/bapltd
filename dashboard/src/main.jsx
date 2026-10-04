import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { elapsed, presence } from './presence.js';
import PolicyStudio from './PolicyStudio.jsx';
import ShadowITView from './ShadowITView.jsx';
import GatewayPEPView from './GatewayPEPView.jsx';
import EndpointHardeningView from './EndpointHardeningView.jsx';
import './style.css';

const API = '/api/v1';
const PAGE_SIZE = 25;
const PRIVILEGED_SESSION_MS = 60_000;
const PROTECTED = '[Protected: Leadership Authentication Required]';
const RISK_ORDER = { CRITICAL: 4, ELEVATED: 3, HEALTHY: 2, STOPPED: 1, REVOKED: 0 };

const Icon = ({ name, size = 16 }) => {
  const paths = {
    shield: <><path d="M12 3 5 6v5c0 4.5 2.8 8.1 7 10 4.2-1.9 7-5.5 7-10V6l-7-3Z"/><path d="m9.5 12 1.6 1.6 3.7-4"/></>,
    search: <><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></>,
    pulse: <path d="M3 12h4l2-6 4 12 2-6h6"/>,
    alert: <><path d="M12 3 2.7 20h18.6L12 3Z"/><path d="M12 9v4m0 3h.01"/></>,
    lock: <><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></>,
    unlock: <><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M9 10V7a4 4 0 0 1 7.5-2"/></>,
    stop: <rect x="5" y="5" width="14" height="14" rx="2"/>,
    ban: <><circle cx="12" cy="12" r="9"/><path d="m6 6 12 12"/></>,
    play: <path d="m8 5 11 7-11 7V5Z"/>,
    reset: <><path d="M4 10a8 8 0 1 1 2 7"/><path d="M4 4v6h6"/></>,
    trash: <><path d="M4 7h16M9 7V4h6v3m3 0-1 14H7L6 7"/><path d="M10 11v6m4-6v6"/></>,
    chevron: <path d="m9 18 6-6-6-6"/>,
    command: <><path d="M9 6v12m6-12v12M6 9h12M6 15h12"/></>,
    check: <path d="m5 12 4 4L19 6"/>,
  };
  return <svg className="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
};

function actionLabel(command = '', executable = '') {
  const value = command.toLowerCase();
  if (!command) return 'Waiting for next tool call';
  if (value.includes('user_prompt_submitted')) return 'Received operator prompt';
  if (value.includes('git log')) return 'Reading repository history';
  if (value.includes('git status')) return 'Inspecting working tree';
  if (value.includes('pytest')) return 'Running verification suite';
  if (value.includes('financial-records')) return 'Blocked credential exfiltration';
  if (value.includes('.env')) return 'Blocked secret access attempt';
  if (value.includes('stop_session')) return 'Session terminated by admin';
  if (value.includes('revoke_access')) return 'Authority revoked by admin';
  const clean = command.replace(/\s+/g, ' ').trim();
  return clean.length > 48 ? `${clean.slice(0, 48)}…` : clean || executable || 'Tool action';
}

function intentLabel(value = 'UNKNOWN') {
  return value.toLowerCase().split('_').map((word) => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
}

function riskFor(agent) {
  if (agent.status === 'revoked') return 'REVOKED';
  if (agent.status === 'stopped' || agent.status === 'closed') return 'STOPPED';
  if (agent.isHighRisk || agent.promptRiskLevel === 'CRITICAL' || agent.deniedCount >= 2 || agent.hasTamper) return 'CRITICAL';
  if (agent.promptRiskLevel === 'ELEVATED' || agent.deniedCount === 1) return 'ELEVATED';
  return 'HEALTHY';
}

function protectedValue(value) {
  return typeof value === 'string' && value.startsWith('[Protected:');
}

function normalizeFleet(data, sensitive, now, localStatus) {
  const source = sensitive || data || {};
  const sessions = source.sessions || [];
  const agents = source.agents || [];
  const events = source.central_events || [];
  const revokedSessions = source.revoked_sessions || [];
  const revokedUsers = source.revoked_users || [];
  const fleet = new Map();

  agents.forEach((agent, index) => {
	const rawId = agent.instance_id || agent.agent_id;
	const id = protectedValue(rawId) ? `${agent.app_id || 'agent'}:registered:${index}` : rawId;
    const currentPresence = presence(agent, now);
    fleet.set(id, {
      id, instanceId: id, agentId: agent.agent_id, sessionId: '', appId: agent.app_id || 'agent',
      name: agent.agent_name || agent.app_id || id,
      owner: agent.owner_email || agent.owner_id || 'Governed operator',
      hostname: agent.hostname || 'unreported-host',
      spiffeId: agent.spiffe_id || `spiffe://bap.internal/app/${agent.app_id}/instance/${id}`,
      status: agent.status || currentPresence.status, lastSeen: currentPresence.age,
      prompt: agent.user_prompt || '', events: [], allowedCount: 0, deniedCount: 0, totalEvents: 0,
      primaryIntent: agent.intent?.primary || 'UNKNOWN', secondaryIntents: agent.intent?.secondary || [],
      intentTags: agent.intent?.tags || [], intentConfidence: agent.intent?.confidence || 0,
      intentSource: agent.intent?.source || 'unavailable', promptCaptured: Boolean(agent.intent?.prompt_captured),
    });
  });

  sessions.forEach((session, index) => {
    const existing = fleet.get(session.instance_id) || fleet.get(session.session_id) ||
      (protectedValue(session.session_id)
        ? [...fleet.values()].find((agent) => agent.appId === session.app_id && !agent.sessionId)
        : null);
	// A restarted workload can share an instance with a closed historical
	// session. The live session owns the fleet tile; history stays in totals.
	if (existing?.sessionId && existing.status === 'active' && session.status !== 'active') return;
	const rawId = session.session_id;
	const id = existing?.id || (protectedValue(rawId) ? `${session.app_id || 'agent'}:session:${index}` : rawId);
    const currentPresence = presence(session, now);
    const revoked = session.status === 'revoked' || revokedSessions.includes(session.session_id) || revokedUsers.includes(session.user_id) || revokedUsers.includes(session.user_email);
    const status = localStatus[session.session_id] || (revoked ? 'revoked' : session.status || currentPresence.status);
    const next = existing || { id, events: [], allowedCount: 0, deniedCount: 0 };
    const mission = session.intent || {};
    // Public telemetry protects stable identifiers. In that mode the session
    // record is still independently rendered, while privileged mode merges it
    // with its registered workload by exact instance identity.
    fleet.set(id, {
      ...next, sessionId: session.session_id, instanceId: session.instance_id || next.instanceId || session.session_id,
      agentId: next.agentId || session.session_id, appId: session.app_id || next.appId || 'agent',
      name: session.agent_name || session.role || next.name || session.app_id || 'Agent',
      owner: session.user_email || session.user_id || next.owner || 'Governed operator',
      hostname: session.hostname || next.hostname || 'unreported-host',
      spiffeId: session.spiffe_id || next.spiffeId || `spiffe://bap.internal/app/${session.app_id}/instance/${id}`,
      status, lastSeen: currentPresence.age, prompt: session.user_prompt || next.prompt || '', clientPid: session.client_pid,
      primaryIntent: mission.primary || next.primaryIntent || 'UNKNOWN',
      secondaryIntents: mission.secondary || next.secondaryIntents || [], intentTags: mission.tags || next.intentTags || [],
      intentConfidence: mission.confidence || next.intentConfidence || 0, intentSource: mission.source || next.intentSource || 'unavailable',
      promptCaptured: mission.prompt_captured ?? next.promptCaptured ?? Boolean(session.user_prompt),
      allowedCount: session.allowed_count || next.allowedCount || 0,
      deniedCount: session.denied_count || next.deniedCount || 0,
      totalEvents: session.total_events || next.totalEvents || 0,
      promptRiskScore: session.prompt_risk_score || mission.prompt_risk_score || 0,
      promptRiskLevel: session.prompt_risk_level || mission.prompt_risk_level || 'LOW',
      injectionSignals: session.injection_signals || mission.injection_signals || [],
      isHighRisk: session.is_high_risk || mission.is_high_risk || false,
    });
  });

  events.forEach((event) => {
    const target = [...fleet.values()].find((agent) => agent.sessionId === event.session_id || agent.instanceId === event.session_id || agent.id === event.session_id);
    if (!target) return;
    target.events.push(event);
    target.totalEvents = Math.max(target.totalEvents || 0, target.events.length);
    if (!target.sessionId) {
      if (event.decision === 'allow') target.allowedCount += 1;
      if (event.decision === 'deny') target.deniedCount += 1;
    }
    if (!target.prompt && event.user_prompt && event.user_prompt !== PROTECTED) target.prompt = event.user_prompt;
    if ((!target.primaryIntent || target.primaryIntent === 'UNKNOWN') && event.primary_intent) {
      target.primaryIntent = event.primary_intent;
      target.secondaryIntents = event.secondary_intents || [];
      target.intentTags = event.intent_tags || [];
      target.intentConfidence = event.intent_confidence || 0;
    }
  });

  return [...fleet.values()].map((agent) => {
    const sortedEvents = [...agent.events].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
    const latest = sortedEvents[0];
    const normalized = { ...agent, primaryIntent: agent.primaryIntent || 'UNKNOWN', secondaryIntents: agent.secondaryIntents || [], intentTags: agent.intentTags || [], events: sortedEvents, latest, currentAction: actionLabel(latest?.full_command, latest?.executable), hasTamper: sortedEvents.some((event) => (event.reason || '').toLowerCase().includes('tamper')) };
    return { ...normalized, risk: riskFor(normalized) };
  });
}

function App() {
  const [data, setData] = useState(null);
  const [sensitive, setSensitive] = useState(null);
  const [adminToken, setAdminToken] = useState('');
  const [privilegedUntil, setPrivilegedUntil] = useState(0);
  const [runtime, setRuntime] = useState({ environment: 'production', demo_mode: false });
  const [now, setNow] = useState(Date.now());
  const [connected, setConnected] = useState(false);
  const [lastRefresh, setLastRefresh] = useState(0);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('HEALTHY');
  const [intentWindow, setIntentWindow] = useState('live');
  const [sortMode, setSortMode] = useState('RISK');
  const [activeView, setActiveView] = useState('fleet');
  const [page, setPage] = useState(0);
  const [selectedId, setSelectedId] = useState('');
  const [expandedEvent, setExpandedEvent] = useState('');
  const [notice, setNotice] = useState('');
  const [pending, setPending] = useState(false);
  const [modal, setModal] = useState(null);
  const [tokenInput, setTokenInput] = useState('');
  const [localStatus, setLocalStatus] = useState({});
  const modalRef = useRef(null);
  const tokenRef = useRef(null);

  useEffect(() => {
    fetch('/dashboard-config', { credentials: 'omit', cache: 'no-store' })
      .then((response) => response.ok ? response.json() : Promise.reject(new Error(`HTTP ${response.status}`)))
      .then((config) => setRuntime({ environment: config.environment || 'production', demo_mode: Boolean(config.demo_mode) }))
      .catch(() => setRuntime({ environment: 'production', demo_mode: false }));
  }, []);

  const refresh = async (token = adminToken) => {
    try {
      const headers = token ? { Authorization: `Bearer ${token}` } : {};
      const response = await fetch(`${API}${token ? '/admin/inspector/data' : '/inspector/data'}`, { headers, cache: 'no-store' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const payload = await response.json();
      setData(payload);
      if (token && payload.admin_authorized) setSensitive(payload);
      setConnected(true); setLastRefresh(Date.now());
      return payload;
    } catch { setConnected(false); return null; }
  };

  useEffect(() => {
    let alive = true;
    const poll = async () => { if (alive) await refresh(); };
    poll();
    const interval = setInterval(poll, 2000);
    const clock = setInterval(() => setNow(Date.now()), 1000);
    return () => { alive = false; clearInterval(interval); clearInterval(clock); };
  }, [adminToken]);
  useEffect(() => { if (modal && modalRef.current && !modalRef.current.open) { modalRef.current.showModal(); setTimeout(() => tokenRef.current?.focus(), 0); } }, [modal]);
  useEffect(() => { setPage(0); }, [query, filter, sortMode]);
  useEffect(() => {
    if (adminToken && privilegedUntil && now >= privilegedUntil) {
      setAdminToken(''); setSensitive(null); setPrivilegedUntil(0);
      setNotice('Privileged session expired. Protected telemetry is locked.');
    }
  }, [adminToken, now, privilegedUntil]);

  const fleet = useMemo(() => normalizeFleet(data, sensitive, now, localStatus), [data, sensitive, now, localStatus]);
  const incidents = useMemo(() => fleet.filter((a) => ['CRITICAL', 'ELEVATED'].includes(a.risk)).sort((a, b) => RISK_ORDER[b.risk] - RISK_ORDER[a.risk] || a.lastSeen - b.lastSeen), [fleet]);
  const filteredFleet = useMemo(() => {
    const q = query.trim().toLowerCase();
    const values = fleet.filter((agent) => {
      if (filter === 'RISK' && !['CRITICAL', 'ELEVATED'].includes(agent.risk)) return false;
      if (filter === 'HEALTHY' && agent.risk !== 'HEALTHY') return false;
      if (filter === 'STOPPED' && !['STOPPED', 'REVOKED'].includes(agent.risk)) return false;
      return !q || [agent.name, agent.owner, agent.appId, agent.hostname, agent.id, agent.currentAction, agent.primaryIntent, ...(agent.secondaryIntents || []), ...(agent.intentTags || [])].some((value) => (value || '').toLowerCase().includes(q));
    });
    return values.sort((a, b) => sortMode === 'RECENT' ? a.lastSeen - b.lastSeen : RISK_ORDER[b.risk] - RISK_ORDER[a.risk] || a.lastSeen - b.lastSeen);
  }, [fleet, filter, query, sortMode]);
  const pageCount = Math.max(1, Math.ceil(filteredFleet.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const visibleFleet = filteredFleet.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);
  const selected = fleet.find((agent) => agent.id === selectedId) || incidents[0] || visibleFleet[0] || null;
  const activeCount = fleet.filter((agent) => agent.status === 'active').length;
  const currentActions = fleet.filter((agent) => agent.status === 'active' && agent.latest).length;
  const intentMix = useMemo(() => {
    const counts = new Map();
    const windowData = (sensitive || data)?.intent_windows?.[intentWindow];
    const serverCounts = windowData?.counts || (sensitive || data)?.intent_counts;
    if (serverCounts && typeof serverCounts === 'object') {
      Object.entries(serverCounts).forEach(([intent, count]) => {
        if (typeof count === 'number' && count > 0) {
          counts.set(intent, count);
        }
      });
    }

    if (counts.size === 0) {
      const events = (sensitive || data)?.central_events || [];
      events.forEach((ev) => {
        const intent = ev.primary_intent || ev.primaryIntent;
        if (intent && (ev.decision === 'intent' || ev.executable === 'user_prompt')) {
          counts.set(intent, (counts.get(intent) || 0) + 1);
        }
      });
      if (counts.size === 0) {
        fleet.forEach((agent) => {
          if (agent.primaryIntent && agent.primaryIntent !== 'UNKNOWN') {
            counts.set(agent.primaryIntent, (counts.get(agent.primaryIntent) || 0) + 1);
          }
        });
      }
    }

    return [...counts.entries()]
      .map(([intent, count]) => ({ intent, count }))
      .sort((a, b) => b.count - a.count || a.intent.localeCompare(b.intent));
  }, [data, sensitive, fleet, intentWindow]);

  const totalPrompts = useMemo(() => {
    const windowData = (sensitive || data)?.intent_windows?.[intentWindow];
    const serverTotal = windowData?.total ?? (sensitive || data)?.total_prompts;
    if (typeof serverTotal === 'number' && serverTotal >= 0) return serverTotal;
    return intentMix.reduce((acc, item) => acc + item.count, 0);
  }, [data, sensitive, intentMix, intentWindow]);
  const eventHistory = (sensitive || data)?.central_events || [];
  const allowedHistory = eventHistory.filter((event) => event.decision === 'allow').length;
  const deniedHistory = eventHistory.filter((event) => event.decision === 'deny').length;
  const killSwitch = Boolean(data?.kill_switch);

  function closeModal() { modalRef.current?.close(); setModal(null); setTokenInput(''); }
  async function authenticatedFetch(path, token, body) {
    const response = await fetch(`${API}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: body === undefined ? undefined : JSON.stringify(body) });
    if (!response.ok) { const detail = await response.json().catch(() => ({})); throw new Error(detail.error || detail.message || `HTTP ${response.status}`); }
    return response.json().catch(() => ({}));
  }

  async function runAction(event) {
    event?.preventDefault();
    if (!modal || pending) return;
    const token = adminToken || tokenInput;
    if (!token) return;
    setPending(true);
    try {
      if (modal.type === 'REVEAL') {
        const response = await fetch(`${API}/admin/inspector/data`, { headers: { Authorization: `Bearer ${token}` }, cache: 'no-store' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        setSensitive(await response.json());
      } else if (modal.type === 'START') {
        await authenticatedFetch('/demo/fleet-scale', token, { count: 25 }); await authenticatedFetch('/demo/exec-safe', token, {});
      } else if (modal.type === 'INCIDENT') {
        await Promise.all([0, 1, 2].map(() => authenticatedFetch('/demo/exec-attack', token, {})));
      } else if (modal.type === 'RESET') {
        await authenticatedFetch('/sessions/reset', token, {}); await authenticatedFetch('/control/kill-switch', token, { enabled: false }); await authenticatedFetch('/demo/fleet-scale', token, { count: 25 });
      } else if (modal.type === 'CLEANUP') {
        await authenticatedFetch('/sessions/reset', token, {}); await authenticatedFetch('/control/kill-switch', token, { enabled: false });
      } else if (modal.type === 'FREEZE') {
        await authenticatedFetch('/control/kill-switch', token, { enabled: !killSwitch });
      } else if (['STOP', 'REVOKE', 'RESTORE'].includes(modal.type)) {
        const target = modal.agent.sessionId || modal.agent.agentId || modal.agent.id;
        if (modal.type === 'STOP') setLocalStatus((prev) => ({ ...prev, [target]: 'stopping' }));
        await authenticatedFetch('/control/agent/kill', token, { target, action: modal.type.toLowerCase(), user_id: modal.agent.owner });
        setLocalStatus((prev) => ({ ...prev, [target]: modal.type === 'STOP' ? 'closed' : modal.type === 'REVOKE' ? 'revoked' : 'active' }));
      }
      setAdminToken(token); setPrivilegedUntil(Date.now() + PRIVILEGED_SESSION_MS); setNotice(modal.success); closeModal(); await refresh(token);
    } catch (error) { setNotice(`Action failed: ${error.message}`); }
    finally { setPending(false); }
  }

  const openAction = (type, overrides = {}) => {
    const configs = {
      REVEAL: { title: 'Start privileged session', detail: 'Unlock operator identity and prompt telemetry for 60 seconds. The credential remains only in memory.', confirm: 'Unlock telemetry', success: 'Privileged telemetry session active for 60 seconds.' },
      START: { title: 'Start 25-agent demo', detail: 'Reset and seed the control plane with 25 active governed agents and live execution telemetry.', confirm: 'Start demo', success: '25-agent fleet demo started.' },
      INCIDENT: { title: 'Trigger controlled incident', detail: 'Emit three denied exfiltration attempts through the control plane and promote the workload into the incident queue.', confirm: 'Trigger incident', success: 'Critical incident injected into control-plane telemetry.' },
      RESET: { title: 'Reset demo scenario', detail: 'Clear session state, lift Global Freeze, and recreate a clean 25-agent fleet.', confirm: 'Reset scenario', success: 'Demo reset to a clean 25-agent fleet.' },
      CLEANUP: { title: 'Clean up demo', detail: 'Close demo sessions and return fleet governance to its normal unfrozen state.', confirm: 'Clean up', success: 'Demo sessions cleaned up.' },
      FREEZE: { title: killSwitch ? 'Release Global Freeze' : 'Activate Global Freeze', detail: killSwitch ? 'Return permitted agents to normal governed execution.' : 'Immediately block execution across the entire fleet.', confirm: killSwitch ? 'Release fleet' : 'Freeze entire fleet', success: killSwitch ? 'Global Freeze released.' : 'Global Freeze active. Entire fleet stopped.' },
    };
    setModal({ type, ...configs[type], ...overrides });
  };

  return <div className={`app-shell ${killSwitch ? 'is-frozen' : ''}`}>
    <header className="topbar">
      <div className="brand-lockup"><span className="brand-mark"><Icon name="shield" size={19}/></span><div><strong>BAP</strong><span>Fleet Command</span></div></div>
      <div className="environment"><span>{runtime.environment.toUpperCase()}</span><b>{runtime.demo_mode ? 'Isolated demonstration control plane' : 'Enterprise control plane'}</b></div>
      <nav className="view-switcher" role="tablist" aria-label="Command Views">
        <button
          role="tab"
          aria-selected={activeView === 'fleet'}
          className={`view-tab ${activeView === 'fleet' ? 'active' : ''}`}
          onClick={() => setActiveView('fleet')}
        >
          <Icon name="shield" size={14}/> Fleet Operations
        </button>
        <button
          role="tab"
          aria-selected={activeView === 'policies'}
          className={`view-tab ${activeView === 'policies' ? 'active' : ''}`}
          onClick={() => setActiveView('policies')}
        >
          <Icon name="command" size={14}/> Cedar Policy Studio
        </button>
        <button
          role="tab"
          aria-selected={activeView === 'shadow_it'}
          className={`view-tab ${activeView === 'shadow_it' ? 'active' : ''}`}
          onClick={() => setActiveView('shadow_it')}
        >
          <Icon name="search" size={14}/> Shadow IT Discovery
        </button>
        <button
          role="tab"
          aria-selected={activeView === 'pep'}
          className={`view-tab ${activeView === 'pep' ? 'active' : ''}`}
          onClick={() => setActiveView('pep')}
        >
          <Icon name="lock" size={14}/> Gateway PEP Guard
        </button>
        <button
          role="tab"
          aria-selected={activeView === 'endpoint'}
          className={`view-tab ${activeView === 'endpoint' ? 'active' : ''}`}
          onClick={() => setActiveView('endpoint')}
        >
          <Icon name="shield" size={14}/> Endpoint Hardening
        </button>
      </nav>
      <div className="topbar-actions">
        <div className={`connection ${connected ? 'online' : ''}`}><i/>{connected ? 'Live telemetry' : 'Reconnecting'}<small>{lastRefresh ? elapsed(now - lastRefresh) : 'waiting'}</small></div>
        <button className={sensitive ? 'session-active' : 'quiet'} onClick={() => sensitive ? (setSensitive(null), setAdminToken(''), setPrivilegedUntil(0)) : openAction('REVEAL')}><Icon name={sensitive ? 'unlock' : 'lock'}/>{sensitive ? `Privileged · ${Math.max(0, Math.ceil((privilegedUntil - now) / 1000))}s` : 'Unlock prompts'}</button>
        <button className={`freeze-button ${killSwitch ? 'release' : ''}`} onClick={() => openAction('FREEZE')}><Icon name={killSwitch ? 'play' : 'stop'}/>{killSwitch ? 'Release Freeze' : 'Global Freeze'}</button>
      </div>
    </header>
    {killSwitch && <div className="freeze-ribbon"><Icon name="alert"/><strong>GLOBAL FREEZE ACTIVE</strong><span>All execution is blocked at the control plane. Telemetry remains online.</span></div>}
    {notice && <div className="toast" role="status"><Icon name="check"/><span>{notice}</span><button aria-label="Dismiss notification" onClick={() => setNotice('')}>×</button></div>}

    <main>
      {activeView === 'policies' && (
        <PolicyStudio adminToken={adminToken} onNotify={(msg) => setNotice(msg)}/>
      )}
      {activeView === 'shadow_it' && (
        <ShadowITView adminToken={adminToken} onNotify={(msg) => setNotice(msg)}/>
      )}
      {activeView === 'pep' && (
        <GatewayPEPView adminToken={adminToken} onNotify={(msg) => setNotice(msg)}/>
      )}
      {activeView === 'endpoint' && (
        <EndpointHardeningView adminToken={adminToken} onNotify={(msg) => setNotice(msg)}/>
      )}
      {activeView === 'fleet' && (
        <>
          <section className="overview" aria-labelledby="agent-operations-heading">
        <div className="overview-title"><p className="eyebrow">Autonomous operations</p><h1 id="agent-operations-heading">Agent operations</h1><p>Live command and containment across the enterprise fleet</p></div>
        <div className="metric current"><span>Operating now</span><strong>{activeCount}</strong><small><i/> {currentActions} executing actions</small></div>
        <div className="metric"><span>Incident queue</span><strong className={incidents.length ? 'warn' : ''}>{incidents.length}</strong><small>{incidents.filter((agent) => agent.risk === 'CRITICAL').length} critical · {incidents.filter((agent) => agent.risk === 'ELEVATED').length} elevated</small></div>
        <div className="metric history"><span>Historical decisions</span><strong>{eventHistory.length}</strong><small><b>{allowedHistory} allowed</b> · {deniedHistory} denied</small></div>
        <div className="metric history"><span>Audit integrity</span><strong className="compact">{data?.chain_status === 'valid' ? 'Verified' : data?.chain_status === 'corrupted' ? 'At risk' : 'Unverified'}</strong><small>{data?.policy_version || 'Policy status unavailable'} · tamper-evident chain</small></div>
      </section>

      <section className="intent-overview" aria-label="Live mission intent mix">
        <div className="intent-meta">
          <p className="eyebrow">Declared work</p>
          <div className="intent-title-row">
            <strong>Mission mix</strong>
            <div className="time-pills" role="tablist" aria-label="Select timeframe">
              {[
                { id: 'live', label: 'Live' },
                { id: 'day', label: 'Day' },
                { id: 'week', label: 'Week' },
                { id: 'month', label: 'Month' },
              ].map((w) => (
                <button
                  key={w.id}
                  type="button"
                  role="tab"
                  aria-selected={intentWindow === w.id}
                  className={intentWindow === w.id ? 'active' : ''}
                  onClick={() => setIntentWindow(w.id)}
                >
                  {w.label}
                </button>
              ))}
            </div>
          </div>
          <span>Classified at BAP Edge · {totalPrompts} declared mission{totalPrompts === 1 ? '' : 's'}</span>
        </div>
        <div className="intent-mix">
          {intentMix.map(({ intent, count }) => (
            <span key={intent} className={`${intent === 'UNKNOWN' ? 'unknown' : ''} active`}>
              <b>{count}</b>{intentLabel(intent)}
            </span>
          ))}
          {!intentMix.length && <span className="empty"><b>0</b>No prompt missions recorded</span>}
        </div>
      </section>

      <section className="workspace">
        <div className="fleet-panel">
          <div className="panel-toolbar">
            <div><p className="eyebrow">Live topology</p><h2>Fleet matrix <span>{filteredFleet.length} agents</span></h2></div>
            <div className="fleet-tools">
              <label className="search"><Icon name="search"/><input aria-label="Search fleet" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search agent, owner, action…"/></label>
              <div className="segments" aria-label="Filter fleet">{['HEALTHY', 'RISK', 'STOPPED', 'ALL'].map((item) => <button key={item} className={filter === item ? 'active' : ''} onClick={() => setFilter(item)}>{item === 'HEALTHY' ? 'Live (Healthy)' : item === 'RISK' ? 'At risk' : item === 'STOPPED' ? 'Stopped' : 'All'}</button>)}</div>
              <select aria-label="Sort fleet" value={sortMode} onChange={(event) => setSortMode(event.target.value)}><option value="RISK">Risk first</option><option value="RECENT">Most recent</option></select>
              <div className="pager"><button aria-label="Previous fleet page" disabled={safePage === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>‹</button><span>{safePage + 1} / {pageCount}</span><button aria-label="Next fleet page" disabled={safePage >= pageCount - 1} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>›</button></div>
            </div>
          </div>
          <div className="fleet-grid" aria-label="Active agent fleet">
            {visibleFleet.map((agent) => {
              const stopped = ['closed', 'stopped', 'revoked'].includes(agent.status);
              return <button key={agent.id} className={`agent-tile risk-${agent.risk.toLowerCase()} ${selected?.id === agent.id ? 'selected' : ''}`} onClick={() => setSelectedId(agent.id)} aria-label={agent.name}>
                <span className="tile-top"><i className={`state-dot ${stopped ? 'stopped' : killSwitch ? 'frozen' : ''}`}/><b>{agent.name}</b><em>{agent.risk}</em></span>
                <span className="tile-owner">{agent.owner}</span>
                <span className={`tile-intent ${agent.primaryIntent === 'UNKNOWN' ? 'unknown' : ''}`}>{intentLabel(agent.primaryIntent)}</span>
                <span className="tile-action"><Icon name={stopped ? 'stop' : 'pulse'} size={13}/><span>{killSwitch && !stopped ? 'Execution frozen globally' : agent.currentAction}</span></span>
                <span className="tile-foot"><small>{agent.appId}</small><small>{stopped ? agent.status : elapsed(agent.lastSeen)}</small></span>
              </button>;
            })}
            {!visibleFleet.length && <div className="empty-fleet"><Icon name="search" size={22}/><strong>No agents match this view</strong><span>{runtime.demo_mode ? 'Change filters or start the demo fleet.' : 'Change filters or wait for governed agents to connect.'}</span></div>}
          </div>
        </div>

        <aside className="incident-panel" aria-label="Incident panel">
          <div className="incident-head"><div><p className="eyebrow">Auto-promoted</p><h2>Incident queue</h2></div><span>{incidents.length}</span></div>
          <div className="incident-list">
            {incidents.map((agent, index) => <button key={agent.id} className={selected?.id === agent.id ? 'active' : ''} onClick={() => setSelectedId(agent.id)}>
              <span className="incident-rank">{String(index + 1).padStart(2, '0')}</span><span className="incident-copy"><b>{agent.name}</b><small>{agent.currentAction}</small><em>{agent.deniedCount} denied · {elapsed(agent.lastSeen)}</em></span><span className={`risk-label ${agent.risk.toLowerCase()}`}>{agent.risk}</span><Icon name="chevron" size={14}/>
            </button>)}
            {!incidents.length && <div className="clear-state"><span><Icon name="shield" size={23}/></span><strong>No active incidents</strong><p>Elevated and critical agents will be promoted here automatically across all {fleet.length || 0} agents.</p></div>}
          </div>
        </aside>
      </section>

      <section className="detail-dock">
        <div className="timeline-panel">
          <div className="detail-heading"><div><p className="eyebrow">Prompt → policy → action</p><h2>{selected ? selected.name : 'Select an agent'} <span className={`risk-label ${selected?.risk?.toLowerCase() || ''}`}>{selected?.risk || 'NO SELECTION'}</span></h2></div>{selected && <div className="identity"><span>{selected.hostname}</span><code>{selected.sessionId || selected.id}</code></div>}</div>
          {selected ? <>
            <div className="prompt-strip"><span><Icon name={sensitive ? 'unlock' : 'lock'}/>{sensitive ? 'Operator prompt' : 'Prompt protected'}</span><p>{sensitive ? (selected.prompt || (selected.promptCaptured ? 'No prompt received.' : 'Raw prompt capture disabled by endpoint policy.')) : 'Unlock a privileged demo session to reveal prompt telemetry.'}</p><div className="mission-classification"><b>{intentLabel(selected.primaryIntent)}</b>{selected.secondaryIntents.map((intent) => <em key={intent}>+ {intentLabel(intent)}</em>)}<small>{Math.round((selected.intentConfidence || 0) * 100)}% · {selected.intentSource}</small></div></div>
            <div className="timeline" aria-label="Prompt-to-action timeline">
              <div className="timeline-event intent"><i/><span className="event-icon"><Icon name="command"/></span><div><b>{intentLabel(selected.primaryIntent)}</b><small>{selected.secondaryIntents.length ? `Also: ${selected.secondaryIntents.map(intentLabel).join(', ')}` : selected.owner}</small></div></div>
              {selected.events.slice(0, 4).reverse().map((event, index) => { const key = event.event_id || `${event.timestamp}-${index}`; return <button key={key} className={`timeline-event ${event.decision}`} onClick={() => setExpandedEvent(expandedEvent === key ? '' : key)}><i/><span className="event-icon"><Icon name={event.decision === 'deny' ? 'ban' : 'check'}/></span><div><b>{actionLabel(event.full_command, event.executable)}</b><small>{event.executable || 'control-plane'} · {event.decision || 'observed'} · {event.duration_ms || 1} ms</small>{expandedEvent === key && <code className="event-command">{event.full_command || event.reason}</code>}</div></button>; })}
              {selected.status === 'revoked' && <div className="timeline-event deny"><i/><span className="event-icon"><Icon name="ban"/></span><div><b>Execution authority revoked</b><small>Restart and future execution blocked</small></div></div>}
            </div>
          </> : <div className="detail-empty">Select any fleet tile to inspect its prompt-to-action timeline.</div>}
        </div>

        <aside className="control-panel">
          <div className="control-head"><div><p className="eyebrow">Closed-loop response</p><h2>Session control</h2></div><span className="zero-trust"><Icon name="shield" size={13}/> Enforced</span></div>
          {selected ? <>
            <div className="control-actions"><button disabled={pending || ['closed', 'stopped', 'revoked'].includes(selected.status)} onClick={() => openAction('STOP', { agent: selected, title: `Stop ${selected.name}`, detail: 'Terminate this session. The rest of the fleet will continue operating.', confirm: 'Stop session', success: `${selected.name} visibly stopped; remaining fleet is operating.` })}><Icon name="stop"/>Stop</button>{selected.status === 'revoked' ? <button className="restore" disabled={pending} onClick={() => openAction('RESTORE', { agent: selected, title: `Restore ${selected.name}`, detail: 'Permit this operator to start new governed sessions.', confirm: 'Restore authority', success: `${selected.name} authority restored.` })}><Icon name="play"/>Restore</button> : <button className="revoke" disabled={pending} onClick={() => openAction('REVOKE', { agent: selected, title: `Revoke ${selected.name}`, detail: 'Terminate this session and block restart and all future execution.', confirm: 'Revoke authority', success: `${selected.name} revoked; restart and future execution blocked.` })}><Icon name="ban"/>Revoke</button>}</div>
            <dl className="session-facts"><div><dt>Status</dt><dd><i className={`state-dot ${selected.status !== 'active' ? 'stopped' : ''}`}/>{selected.status}</dd></div><div><dt>Current activity</dt><dd>{selected.currentAction}</dd></div><div><dt>Session totals</dt><dd>{selected.allowedCount} allow · {selected.deniedCount} deny</dd></div><div><dt>Identity</dt><dd title={selected.spiffeId}>{selected.spiffeId.replace('spiffe://bap.internal/', '')}</dd></div></dl>
          </> : <div className="detail-empty">No session selected.</div>}
        </aside>
      </section>

      {runtime.demo_mode && <section className="demo-bar"><div><span className="demo-kicker">DEMO CONTROL</span><p>Deterministic orchestration backed by control-plane telemetry</p></div><div className="demo-actions"><button onClick={() => openAction('START')}><Icon name="play"/>Start Demo</button><button className="incident-trigger" onClick={() => openAction('INCIDENT')}><Icon name="alert"/>Trigger Incident</button><button onClick={() => openAction('RESET')}><Icon name="reset"/>Reset</button><button onClick={() => openAction('CLEANUP')}><Icon name="trash"/>Cleanup</button></div></section>}
        </>
      )}
    </main>

    <dialog ref={modalRef} className="action-dialog" onClose={() => setModal(null)}><form onSubmit={runAction}><div className={`dialog-icon ${['FREEZE', 'REVOKE', 'INCIDENT'].includes(modal?.type) ? 'danger' : ''}`}><Icon name={['FREEZE', 'STOP'].includes(modal?.type) ? 'stop' : modal?.type === 'REVOKE' ? 'ban' : modal?.type === 'INCIDENT' ? 'alert' : 'shield'} size={21}/></div><p className="eyebrow">Administrative confirmation</p><h2>{modal?.title}</h2><p>{modal?.detail}</p>{!adminToken && <label>Admin credential<input ref={tokenRef} aria-label="Admin credential" type="password" autoComplete="off" value={tokenInput} onChange={(event) => setTokenInput(event.target.value)} placeholder="Enter control-plane token" required/></label>}<div className="dialog-actions"><button type="button" onClick={closeModal}>Cancel</button><button className={['FREEZE', 'STOP', 'REVOKE', 'INCIDENT', 'CLEANUP'].includes(modal?.type) ? 'danger' : 'primary'} type="submit" disabled={pending || (!adminToken && !tokenInput)}>{pending ? 'Working…' : modal?.confirm || 'Confirm action'}</button></div></form></dialog>
  </div>;
}

createRoot(document.getElementById('root')).render(<App/>);
