import React, { useState, useEffect } from 'react';

const API = '/api/v1';

export default function EndpointHardeningView({ adminToken, onNotify }) {
  const [targetOS, setTargetOS] = useState('windows');
  const [layersData, setLayersData] = useState(null);
  const [activeSubTab, setActiveSubTab] = useState('layers'); // 'layers' | 'mdm' | 'stepup' | 'offline'
  const [loading, setLoading] = useState(false);

  // MDM state
  const [mdmPlatform, setMdmPlatform] = useState('windows');
  const [mdmProfile, setMdmProfile] = useState(null);

  // Step-Up state
  const [stepUpOp, setStepUpOp] = useState('database.schema_migration');
  const [stepUpRisk, setStepUpRisk] = useState(0.85);
  const [challenge, setChallenge] = useState(null);
  const [stepUpToken, setStepUpToken] = useState(null);
  const [stepUpError, setStepUpError] = useState(null);
  const [stepUpLoading, setStepUpLoading] = useState(false);

  // Offline Classifier state
  const [offlineCmd, setOfflineCmd] = useState('cargo test --all');
  const [offlineResult, setOfflineResult] = useState(null);

  useEffect(() => {
    fetchLayers(targetOS);
    fetchMDMProfile(mdmPlatform);
  }, []);

  async function fetchLayers(osName) {
    setLoading(true);
    try {
      const res = await fetch(`${API}/endpoint/layers?os=${osName}`);
      if (res.ok) {
        const data = await res.json();
        setLayersData(data);
      }
    } catch (err) {
      console.error('Failed to load endpoint layers', err);
    } finally {
      setLoading(false);
    }
  }

  async function fetchMDMProfile(platform) {
    try {
      const res = await fetch(`${API}/endpoint/mdm/profile?platform=${platform}`);
      if (res.ok) {
        const data = await res.json();
        setMdmProfile(data);
      }
    } catch (err) {
      console.error('Failed to load MDM profile', err);
    }
  }

  async function initiateStepUp() {
    setStepUpLoading(true);
    setChallenge(null);
    setStepUpToken(null);
    setStepUpError(null);
    try {
      const res = await fetch(`${API}/endpoint/stepup/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agent_id: 'agent-claude-developer',
          operation: stepUpOp,
          risk_score: parseFloat(stepUpRisk),
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setChallenge(data);
        if (onNotify) onNotify(`Biometric Step-Up Challenge created: ${data.challenge_id}`);
      } else {
        const err = await res.json();
        setStepUpError(err.error || 'Failed to create challenge');
      }
    } catch (err) {
      setStepUpError(err.message);
    } finally {
      setStepUpLoading(false);
    }
  }

  async function verifyStepUp() {
    if (!challenge) return;
    setStepUpLoading(true);
    setStepUpError(null);
    try {
      const res = await fetch(`${API}/endpoint/stepup/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challenge_id: challenge.challenge_id,
          method: challenge.required_auth,
          biometric_signature: `sig-${challenge.required_auth.toLowerCase()}-verified`,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setStepUpToken(data);
        if (onNotify) onNotify(`Biometric Step-Up Verified! Token minted: ${data.token_id}`);
      } else {
        const err = await res.json();
        setStepUpError(err.error || 'Biometric verification rejected');
      }
    } catch (err) {
      setStepUpError(err.message);
    } finally {
      setStepUpLoading(false);
    }
  }

  async function classifyOffline() {
    try {
      const res = await fetch(`${API}/endpoint/offline/classify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ operation: offlineCmd }),
      });
      if (res.ok) {
        const data = await res.json();
        setOfflineResult(data);
      }
    } catch (err) {
      console.error('Failed to classify capability', err);
    }
  }

  return (
    <div className="endpoint-hardening-container" style={{ padding: '1rem', maxWidth: '1400px', margin: '0 auto' }}>
      {/* Subnav */}
      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '0.75rem' }}>
        {[
          { id: 'layers', label: '3-Layer Architecture', icon: '🛡️' },
          { id: 'mdm', label: 'MDM Configuration Packaging', icon: '📦' },
          { id: 'stepup', label: 'Biometric Step-Up Sandbox', icon: '👆' },
          { id: 'offline', label: 'Scoped Offline Degradation', icon: '✈️' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveSubTab(tab.id)}
            style={{
              padding: '0.5rem 1rem',
              borderRadius: '6px',
              border: activeSubTab === tab.id ? '1px solid #3b82f6' : '1px solid transparent',
              background: activeSubTab === tab.id ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
              color: activeSubTab === tab.id ? '#60a5fa' : '#94a3b8',
              fontWeight: activeSubTab === tab.id ? '600' : '400',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
            }}
          >
            <span>{tab.icon}</span>
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Subtab 1: 3-Layer Architecture */}
      {activeSubTab === 'layers' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: '600', color: '#f8fafc', margin: 0 }}>
                Defense-in-Depth: 3-Tier Layered Enforcement
              </h2>
              <p style={{ color: '#94a3b8', fontSize: '0.875rem', margin: '0.25rem 0 0 0' }}>
                Cooperative user-space hooks backed by hard OS execution control and network egress pinning.
              </p>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              {['windows', 'darwin', 'linux'].map((os) => (
                <button
                  key={os}
                  onClick={() => { setTargetOS(os); fetchLayers(os); }}
                  style={{
                    padding: '0.35rem 0.75rem',
                    borderRadius: '4px',
                    fontSize: '0.75rem',
                    textTransform: 'uppercase',
                    border: targetOS === os ? '1px solid #10b981' : '1px solid rgba(255,255,255,0.1)',
                    background: targetOS === os ? 'rgba(16, 185, 129, 0.15)' : '#1e293b',
                    color: targetOS === os ? '#34d399' : '#94a3b8',
                    cursor: 'pointer',
                  }}
                >
                  {os === 'darwin' ? 'macOS' : os}
                </button>
              ))}
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))', gap: '1rem' }}>
            {(layersData?.layers || []).map((layer) => (
              <div
                key={layer.layer_id}
                style={{
                  background: '#0f172a',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  borderRadius: '8px',
                  padding: '1.25rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.75rem', fontWeight: '700', color: '#38bdf8', letterSpacing: '0.05em' }}>
                    {layer.layer_id.split('_')[1]}
                  </span>
                  <span
                    style={{
                      fontSize: '0.7rem',
                      padding: '0.2rem 0.5rem',
                      borderRadius: '999px',
                      background: layer.enforcing ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                      color: layer.enforcing ? '#34d399' : '#f87171',
                      fontWeight: '600',
                    }}
                  >
                    {layer.enforcing ? 'HARD ENFORCING' : 'COOPERATIVE'}
                  </span>
                </div>
                <h3 style={{ fontSize: '1rem', fontWeight: '600', color: '#f1f5f9', margin: 0 }}>
                  {layer.name}
                </h3>
                <p style={{ color: '#94a3b8', fontSize: '0.8rem', lineHeight: '1.4', margin: 0 }}>
                  {layer.description}
                </p>
                <div style={{ marginTop: 'auto', paddingTop: '0.5rem', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                  <span style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', fontWeight: '600' }}>
                    Active OS Primitives:
                  </span>
                  <ul style={{ margin: '0.25rem 0 0 0', paddingLeft: '1.2rem', color: '#cbd5e1', fontSize: '0.75rem' }}>
                    {layer.primitives.map((prim, idx) => (
                      <li key={idx} style={{ marginBottom: '0.2rem' }}>{prim}</li>
                    ))}
                  </ul>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Subtab 2: MDM Configuration Packaging */}
      {activeSubTab === 'mdm' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: '600', color: '#f8fafc', margin: 0 }}>
                Enterprise MDM Profiles & Immutable Settings
              </h2>
              <p style={{ color: '#94a3b8', fontSize: '0.875rem', margin: '0.25rem 0 0 0' }}>
                Deploy user-immutable <code style={{ color: '#38bdf8' }}>managed-settings.json</code> locking <code style={{ color: '#f43f5e' }}>--dangerously-skip-permissions: false</code>.
              </p>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                onClick={() => { setMdmPlatform('windows'); fetchMDMProfile('windows'); }}
                style={{
                  padding: '0.35rem 0.75rem',
                  borderRadius: '4px',
                  fontSize: '0.75rem',
                  border: mdmPlatform === 'windows' ? '1px solid #3b82f6' : '1px solid rgba(255,255,255,0.1)',
                  background: mdmPlatform === 'windows' ? 'rgba(59, 130, 246, 0.2)' : '#1e293b',
                  color: mdmPlatform === 'windows' ? '#60a5fa' : '#94a3b8',
                  cursor: 'pointer',
                }}
              >
                Microsoft Intune (Windows)
              </button>
              <button
                onClick={() => { setMdmPlatform('macos'); fetchMDMProfile('macos'); }}
                style={{
                  padding: '0.35rem 0.75rem',
                  borderRadius: '4px',
                  fontSize: '0.75rem',
                  border: mdmPlatform === 'macos' ? '1px solid #3b82f6' : '1px solid rgba(255,255,255,0.1)',
                  background: mdmPlatform === 'macos' ? 'rgba(59, 130, 246, 0.2)' : '#1e293b',
                  color: mdmPlatform === 'macos' ? '#60a5fa' : '#94a3b8',
                  cursor: 'pointer',
                }}
              >
                Jamf Pro (macOS)
              </button>
            </div>
          </div>

          <div style={{ background: '#090d16', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)', padding: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem', color: '#64748b', fontSize: '0.75rem' }}>
              <span>Payload: {mdmProfile?.management_tool}</span>
              <span>Schema: {mdmProfile?.payload_type}</span>
            </div>
            <pre style={{ margin: 0, color: '#38bdf8', fontSize: '0.8rem', overflowX: 'auto', maxHeight: '420px' }}>
              {JSON.stringify(mdmProfile, null, 2)}
            </pre>
          </div>
        </div>
      )}

      {/* Subtab 3: Biometric Step-Up Sandbox */}
      {activeSubTab === 'stepup' && (
        <div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: '600', color: '#f8fafc', margin: '0 0 0.5rem 0' }}>
            Interactive Biometric Step-Up Approvals (Windows Hello / Touch ID / FIDO2)
          </h2>
          <p style={{ color: '#94a3b8', fontSize: '0.875rem', margin: '0 0 1.25rem 0' }}>
            High-risk operations require explicit human biometric sign-off rather than ambient agent authority or blanket denials.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
            <div style={{ background: '#0f172a', padding: '1.25rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
              <h3 style={{ fontSize: '0.95rem', color: '#f1f5f9', margin: '0 0 1rem 0' }}>1. Request Elevation Challenge</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <div>
                  <label style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Protected High-Risk Action</label>
                  <select
                    value={stepUpOp}
                    onChange={(e) => setStepUpOp(e.target.value)}
                    style={{ width: '100%', padding: '0.5rem', background: '#1e293b', border: '1px solid #334155', borderRadius: '4px', color: '#f8fafc' }}
                  >
                    <option value="database.schema_migration">database.schema_migration (Risk: 0.85)</option>
                    <option value="core_banking.transfer">core_banking.transfer (Risk: 0.95 - FIDO2 Required)</option>
                    <option value="production_secret.read">production_secret.read (Risk: 0.90)</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Risk Tier / Score</label>
                  <input
                    type="number"
                    step="0.05"
                    value={stepUpRisk}
                    onChange={(e) => setStepUpRisk(e.target.value)}
                    style={{ width: '100%', padding: '0.5rem', background: '#1e293b', border: '1px solid #334155', borderRadius: '4px', color: '#f8fafc' }}
                  />
                </div>
                <button
                  onClick={initiateStepUp}
                  disabled={stepUpLoading}
                  style={{
                    padding: '0.6rem',
                    background: '#2563eb',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    fontWeight: '600',
                    cursor: 'pointer',
                    marginTop: '0.5rem',
                  }}
                >
                  {stepUpLoading ? 'Generating Challenge...' : 'Initiate Biometric Challenge'}
                </button>
              </div>

              {challenge && (
                <div style={{ marginTop: '1rem', padding: '0.75rem', background: '#090d16', borderRadius: '6px', border: '1px solid rgba(59,130,246,0.3)' }}>
                  <div style={{ color: '#60a5fa', fontSize: '0.8rem', fontWeight: '600' }}>Challenge Created</div>
                  <div style={{ color: '#cbd5e1', fontSize: '0.75rem', marginTop: '0.25rem' }}>ID: {challenge.challenge_id}</div>
                  <div style={{ color: '#fbbf24', fontSize: '0.75rem' }}>Required Authenticator: {challenge.RequiredAuth || challenge.required_auth}</div>
                  <div style={{ color: '#64748b', fontSize: '0.7rem' }}>Nonce: {challenge.nonce}</div>
                </div>
              )}
            </div>

            <div style={{ background: '#0f172a', padding: '1.25rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
              <h3 style={{ fontSize: '0.95rem', color: '#f1f5f9', margin: '0 0 1rem 0' }}>2. Simulate Biometric Verification</h3>
              <p style={{ color: '#94a3b8', fontSize: '0.8rem', margin: '0 0 1rem 0' }}>
                Simulates the operator touching a YubiKey or passing Windows Hello fingerprint prompt on the laptop.
              </p>
              <button
                onClick={verifyStepUp}
                disabled={!challenge || stepUpLoading || stepUpToken}
                style={{
                  width: '100%',
                  padding: '0.6rem',
                  background: challenge && !stepUpToken ? '#059669' : '#334155',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  fontWeight: '600',
                  cursor: challenge && !stepUpToken ? 'pointer' : 'not-allowed',
                }}
              >
                Touch Biometric Authenticator
              </button>

              {stepUpToken && (
                <div style={{ marginTop: '1rem', padding: '0.75rem', background: '#064e3b', borderRadius: '6px', border: '1px solid #10b981' }}>
                  <div style={{ color: '#34d399', fontSize: '0.8rem', fontWeight: '600' }}>✓ Biometric Step-Up Authorized!</div>
                  <div style={{ color: '#ecfdf5', fontSize: '0.75rem', marginTop: '0.25rem' }}>Token ID: {stepUpToken.token_id}</div>
                  <div style={{ color: '#a7f3d0', fontSize: '0.75rem' }}>Method: {stepUpToken.method}</div>
                  <div style={{ color: '#6ee7b7', fontSize: '0.7rem', wordBreak: 'break-all' }}>Signature: {stepUpToken.signature}</div>
                </div>
              )}
              {stepUpError && (
                <div style={{ marginTop: '1rem', padding: '0.75rem', background: '#7f1d1d', borderRadius: '6px', border: '1px solid #ef4444', color: '#fca5a5', fontSize: '0.75rem' }}>
                  {stepUpError}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Subtab 4: Scoped Offline Degradation */}
      {activeSubTab === 'offline' && (
        <div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: '600', color: '#f8fafc', margin: '0 0 0.5rem 0' }}>
            Scoped Offline Capability Classification
          </h2>
          <p style={{ color: '#94a3b8', fontSize: '0.875rem', margin: '0 0 1.25rem 0' }}>
            Prevents EDR lockout on airplanes by allowing Tier 1 local builds and unit tests offline while strictly failing closed on Tier 2 enterprise egress.
          </p>

          <div style={{ background: '#0f172a', padding: '1.25rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
              <input
                type="text"
                value={offlineCmd}
                onChange={(e) => setOfflineCmd(e.target.value)}
                placeholder="Enter command or API route (e.g. pytest tests/ or POST /api/v1/transfer)"
                style={{ flex: 1, padding: '0.6rem', background: '#1e293b', border: '1px solid #334155', borderRadius: '4px', color: '#f8fafc' }}
              />
              <button
                onClick={classifyOffline}
                style={{ padding: '0.6rem 1.25rem', background: '#3b82f6', color: 'white', border: 'none', borderRadius: '4px', fontWeight: '600', cursor: 'pointer' }}
              >
                Evaluate Offline Policy
              </button>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
              {[
                'cargo test --all',
                'pytest tests/unit',
                'git status',
                'POST /api/v1/core-banking/transfer',
                'aws s3 cp s3://confidential-data ./',
              ].map((sample) => (
                <button
                  key={sample}
                  onClick={() => { setOfflineCmd(sample); }}
                  style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem', background: '#1e293b', border: '1px solid #334155', borderRadius: '4px', color: '#94a3b8', cursor: 'pointer' }}
                >
                  {sample}
                </button>
              ))}
            </div>

            {offlineResult && (
              <div
                style={{
                  padding: '1rem',
                  borderRadius: '6px',
                  background: offlineResult.allowed_offline ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                  border: offlineResult.allowed_offline ? '1px solid #10b981' : '1px solid #ef4444',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <strong style={{ color: offlineResult.allowed_offline ? '#34d399' : '#f87171', fontSize: '0.9rem' }}>
                    {offlineResult.tier === 'TIER_1_SAFE_LOCAL_DEV' ? '✓ TIER 1: SAFE LOCAL DEVELOPMENT' : '🛑 TIER 2: PROTECTED CLOUD EGRESS'}
                  </strong>
                  <span
                    style={{
                      fontSize: '0.75rem',
                      padding: '0.2rem 0.5rem',
                      borderRadius: '4px',
                      background: offlineResult.allowed_offline ? '#064e3b' : '#7f1d1d',
                      color: offlineResult.allowed_offline ? '#a7f3d0' : '#fca5a5',
                    }}
                  >
                    {offlineResult.allowed_offline ? 'ALLOWED OFFLINE (CACHED CEDAR)' : 'FAIL-CLOSED OFFLINE (NO EGRESS)'}
                  </span>
                </div>
                <p style={{ color: '#cbd5e1', fontSize: '0.85rem', margin: 0 }}>
                  {offlineResult.explanation}
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
