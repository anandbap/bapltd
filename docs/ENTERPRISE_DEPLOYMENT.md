# BAP Enterprise Deployment & Fleet Management Guide

This guide describes how enterprise security, IT engineering, and SecOps teams can deploy and manage the **Bounded Authority Plane (BAP)** across thousands of developer endpoints using Microsoft Intune, Jamf Pro, Group Policy (GPO), or Ansible.

---

## 1. Architectural Overview

```mermaid
flowchart TD
    subgraph Central Plane [Central Control Plane (Render / AWS / Kubernetes)]
        CP["bapcontrolplane<br/>(Cluster / Cloud)"]
        DB[("Audit Ledger & SQLite WAL")]
        RADAR["Live Workload Radar<br/>(Real-Time Agent Visibility)"]
        CP --- DB
        CP --- RADAR
    end

    subgraph Fleet [Enterprise Developer Endpoints]
        M1["Developer Laptop 1 (Windows)<br/>Claude Code + Antigravity"]
        M2["Developer Laptop 2 (macOS)<br/>VS Code Copilot"]
        M3["CI/CD Runner (Linux)<br/>Python Autonomous Agents"]
    end

    M1 -->|"mTLS / HTTPS (Telemetry & Sync)"| CP
    M2 -->|"mTLS / HTTPS (Telemetry & Sync)"| CP
    M3 -->|"mTLS / HTTPS (Telemetry & Sync)"| CP
```

### Key Enterprise Security Capabilities
1. **Zero-Trust Cedar Authorization**: Enforces strict invariants (no credential harvesting, no data exfiltration, workspace boundary isolation) directly on endpoints.
2. **Offline Resilience & Local Cache**: If remote network connectivity is lost, edge daemons operate in fail-secure cached mode without interrupting development.
3. **Cryptographic Merkle Audit Chain**: Every execution decision produces an unforgeable receipt anchored in a tamper-evident audit ledger.
4. **OIDC & SPIFFE Identity Mesh**: Binds developer Entra ID / Okta identity to ephemeral agent instance SPIFFE IDs.

---

## 2. Silent & Headless Deployment

The BAP Universal Installer supports unattended, silent installation for MDM and automated rollouts.

### Windows (Microsoft Intune / SCCM / PowerShell)
Deploy as a user-context or system-context script:

```powershell
# Silent User-Mode Deployment (No Admin Required)
python scripts/bap_install.py `
    --non-interactive `
    --server "https://bap-controlplane.onrender.com" `
    --workspace "$env:USERPROFILE\source\repos"
```

To deploy as an auto-starting background Windows Service:
```powershell
# System-Wide Service Deployment (Elevated Admin)
python scripts/bap_install.py --system --server "https://bap-controlplane.onrender.com"
```

### macOS (Jamf Pro / Munki)
Run via Jamf policy in user context:

```bash
#!/bin/bash
export BAP_SERVER_URL="https://bap-controlplane.onrender.com"
python3 scripts/bap_install.py --non-interactive --server "$BAP_SERVER_URL"
```

### Linux (Ansible / Puppet / Cloud-Init)
```yaml
- name: Deploy BAP Zero-Trust to Developer Workstations
  hosts: developers
  tasks:
    - name: Install BAP Python package
      pip:
        name: bap-ltd
        state: latest

    - name: Run BAP silent installer
      command: bap install --non-interactive --server https://bap-controlplane.onrender.com
      environment:
        HOME: "{{ ansible_env.HOME }}"
```

---

## 3. Enterprise Control Plane Configuration

For enterprise self-hosting (AWS ECS, EKS, Azure Container Apps, or bare metal):

### Configuration File (`bap-config.json`)
```json
{
  "controlplane_url": "https://bap.enterprise.corp",
  "trust_domain": "bap.enterprise.corp",
  "enforcement_mode": "enforce",
  "offline_cache_ttl_hours": 168,
  "heartbeat_interval_sec": 10,
  "audit_forwarding": {
    "enabled": true,
    "format": "jsonl",
    "siem_syslog_host": "siem.enterprise.corp:514"
  }
}
```

### Identity Provider Federation (Entra ID / Okta)
Enable OIDC Device Code flow on the control plane:
```bash
bapcontrolplane start \
  --port 8443 \
  --mode prod \
  --oidc-provider entra \
  --oidc-client-id "00000000-0000-0000-0000-000000000000" \
  --oidc-tenant-id "contoso.onmicrosoft.com" \
  --allow-remote-admin
```

---

## 4. SIEM / SOAR & Compliance Integration

All agent telemetry streams to the central audit store and can be ingested directly into:
- **Splunk / Datadog / Microsoft Sentinel**: Stream `/api/v1/audit/events` via HTTP Event Collector (HEC) or syslog.
- **SOC 2 & FedRAMP Audits**: Verify cryptographic chain integrity at any time via:
  ```bash
  curl -sSL https://bap-controlplane.onrender.com/api/v1/control/chain/verify
  ```
  Returns signed JSON with Merkle head hash and compliance status (`SOC2_FEDRAMP_ISO27001_COMPLIANT`).
