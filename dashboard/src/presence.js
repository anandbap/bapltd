export const STALE_MS = 30_000;
export const OFFLINE_MS = 30_000;

export function presence(agent, now) {
  const last = Date.parse(agent.last_active_at || agent.last_heartbeat_at || agent.enrolled_at || agent.created_at || agent.started_at);
  const age = Number.isFinite(last) ? Math.max(0, now - last) : Infinity;
  if (agent.status === 'revoked') return { status: 'revoked', age, visible: true };
  if (agent.status === 'stopped' || agent.status === 'closed') {
    return { status: agent.status, age, visible: age < 300_000 };
  }
  if (['deregistered', 'inactive', 'offline'].includes(agent.status) || age >= OFFLINE_MS) {
    return { status: 'offline', age, visible: false };
  }
  return { status: agent.status || 'active', age, visible: true };
}

export function elapsed(ms) {
  if (!Number.isFinite(ms)) return 'Not reported';
  if (ms < 1000) return 'Just now';
  if (ms < 60_000) return `${Math.floor(ms / 1000)}s ago`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
  return `${Math.floor(ms / 3_600_000)}h ago`;
}
