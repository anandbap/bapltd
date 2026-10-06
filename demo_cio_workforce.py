#!/usr/bin/env python3
"""
BAP CIO Demonstration: 15 Enterprise Teams, 75 Governed Agents, 300 Dynamic Workload Tasks
==========================================================================================
Demonstrates the full executive CIO AI Workforce governance experience:
- 15 Diverse Enterprise Teams (Payments, Core Banking, Fraud Ops, Cloud Infra, Security, etc.)
- 5 Autonomous Agents per Team = 75 Governed AI Agents running concurrently.
- Pool of 300 distinct real-world enterprise tasks with realistic intents and prompts.
- Each team executes 2 distinct tasks across its agents.
- Each agent uses the official `bap_sdk` (BAPSession) to show live presence, workload execution,
  intent classification, policy gating, and graceful shutdown.
- Runs live for ~2-3 minutes (or configurable duration), refreshing real-time progress.
- Cleanly shuts down all 75 agents and sessions upon completion or on Enter key press.

Usage:
  python demo_cio_workforce.py
  python demo_cio_workforce.py --duration 150
  python demo_cio_workforce.py --url http://127.0.0.1:8080
"""

import os
import sys
import time
import json
import random
import signal
import threading
import argparse
import urllib.request
from typing import List, Dict, Any, Tuple

# Ensure python-agent workspace is in sys.path
WORKSPACE_ROOT = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(WORKSPACE_ROOT, "python-agent"))

from bap_sdk import BAPSession, resolve_endpoints, classify_intent

# ==============================================================================
# 15 ENTERPRISE TEAMS & DIVISIONS
# ==============================================================================
TEAMS: List[Dict[str, Any]] = [
    {
        "id": "payments-eng",
        "name": "Payments Engineering",
        "division": "Engineering",
        "app_id": "payments-worker",
        "agent_types": ["Payment Gateway Reconciler", "Stripe Webhook Processor", "Idempotency Ledger Sentinel", "ISO 20022 Message Parser", "Settlement Batch Worker"],
        "lead": "Sarah Chen",
    },
    {
        "id": "core-banking",
        "name": "Core Banking",
        "division": "Engineering",
        "app_id": "ledger-service",
        "agent_types": ["Double-Entry Balance Auditor", "ACH Clearing Engine", "Wire Transfer Router", "Interest Accrual Calculator", "General Ledger Sentry"],
        "lead": "Alex Kumar",
    },
    {
        "id": "fraud-ops",
        "name": "Fraud Operations",
        "division": "Business Operations",
        "app_id": "fraud-scorer",
        "agent_types": ["Card Velocity Analyzer", "Synthetic Identity Sentry", "Chargeback Dispute Engine", "Account Takeover Probe", "Sanctions List Screener"],
        "lead": "David Park",
    },
    {
        "id": "cloud-infra",
        "name": "Cloud Infrastructure",
        "division": "Operations",
        "app_id": "terraform-network",
        "agent_types": ["Kubernetes Pod Autoscaler", "Terraform Drift Reconciler", "VPC Egress Gatekeeper", "Envoy Mesh Sentry", "Multi-Region Traffic Director"],
        "lead": "Elena Rostova",
    },
    {
        "id": "enterprise-sec",
        "name": "Enterprise Security",
        "division": "Operations",
        "app_id": "auth-gateway",
        "agent_types": ["IAM Wildcard Minimizer", "OAuth2 Token Auditor", "Container CVE Scanner", "Secret Lease Rotator", "TPM Enclave Attestor"],
        "lead": "Marcus Vance",
    },
    {
        "id": "data-platform",
        "name": "Data Platform",
        "division": "Engineering",
        "app_id": "warehouse-etl",
        "agent_types": ["Snowflake Partition Sizer", "Kafka Consumer Rebalancer", "Parquet Schema Verifier", "dbt Lineage Validator", "Data Lake Catalog Notary"],
        "lead": "Priya Patel",
    },
    {
        "id": "customer-support",
        "name": "Customer Support",
        "division": "Business Operations",
        "app_id": "crm-connector",
        "agent_types": ["Tier 3 Escalation Summarizer", "SLA Breach Preventer", "Customer Sentiment Classifier", "Zendesk Routing Engine", "Knowledge Base Dispatcher"],
        "lead": "Jordan Reyes",
    },
    {
        "id": "finance-ops",
        "name": "Finance Operations",
        "division": "Business Operations",
        "app_id": "erp-reconciler",
        "agent_types": ["Quarterly Run-Rate Projector", "Vendor Invoice Matcher", "Currency Exchange Hedger", "GAAP Revenue Amortizer", "Tax Jurisdictional Sentry"],
        "lead": "Carol Zhang",
    },
    {
        "id": "it-ops",
        "name": "IT Operations",
        "division": "Operations",
        "app_id": "it-helpdesk",
        "agent_types": ["Intune Profile Synchronizer", "SSO Certificate Renewer", "Asset Inventory Collector", "Jamf Endpoint Verifier", "Stale Laptop Revoker"],
        "lead": "Devante Washington",
    },
    {
        "id": "qa-eng",
        "name": "Quality Assurance",
        "division": "Engineering",
        "app_id": "qa-runner",
        "agent_types": ["Playwright E2E Orchestrator", "Flaky Test Bi-Sector", "API Contract Linter", "Mutation Test Evaluator", "Chaos Network Injector"],
        "lead": "Mei Lin",
    },
    {
        "id": "devops-eng",
        "name": "DevOps Engineering",
        "division": "Operations",
        "app_id": "cicd-runner",
        "agent_types": ["Blue-Green Rollout Pilot", "Docker Base Image Minifier", "Helm Chart Template Tester", "ArgoCD GitOps Synchronizer", "Release Notes Synthesizer"],
        "lead": "Bob Miller",
    },
    {
        "id": "mobile-eng",
        "name": "Mobile Engineering",
        "division": "Engineering",
        "app_id": "mobile-api",
        "agent_types": ["iOS Swift Memory Profiler", "Android ProGuard Minifier", "Fastlane Build Pipeline Sentry", "GraphQL Query Depth Linter", "Push Notification Dispatcher"],
        "lead": "Lucas Silva",
    },
    {
        "id": "ai-ml",
        "name": "AI & ML Platform",
        "division": "Engineering",
        "app_id": "llm-firewall",
        "agent_types": ["Prompt Injection Firewall", "Vector Embedding Indexer", "Model Hallucination Probe", "GPU Cluster VRAM Sizer", "Tokenizer Latency Watcher"],
        "lead": "Victor Vance",
    },
    {
        "id": "product-growth",
        "name": "Product Growth",
        "division": "Business Operations",
        "app_id": "growth-analytics",
        "agent_types": ["A/B Test Significance Evaluator", "Funnel Drop-off Diagnoser", "User Activation Correlator", "Churn Risk Predictor", "Feature Flag Rollout Watcher"],
        "lead": "Rachel Green",
    },
    {
        "id": "compliance-grc",
        "name": "Regulatory Compliance",
        "division": "Operations",
        "app_id": "audit-notary",
        "agent_types": ["SOC2 Evidence Harvester", "GDPR Data Erasure Verifier", "PCI-DSS Cryptographic Attestor", "HIPAA Access Auditor", "FedRAMP Boundary Sentinel"],
        "lead": "Beatrice Webb",
    },
]

# ==============================================================================
# 300 REAL-WORLD ENTERPRISE WORKLOAD TASKS
# Distributed across the 5 canonical CIO pulse categories:
# - Build / Change
# - Investigate / Diagnose
# - Search / Explain
# - Automate Workflow
# - Business Analysis
# ==============================================================================
TASKS_300: List[Dict[str, str]] = [
    # --- Category 1: Build / Change (Tasks 1 - 60) ---
    {"intent": "FEATURE_ENHANCEMENT", "task": "Implement instant SEPA credit transfer integration in payment gateway"},
    {"intent": "REFACTOR", "task": "Refactor legacy double-entry bookkeeping journal entries into immutable ledger blocks"},
    {"intent": "DATABASE_CHANGE", "task": "Add composite B-tree index on customer transactions table for query optimization"},
    {"intent": "BUG_FIX", "task": "Fix critical null pointer bug in checkout token authorization interceptor"},
    {"intent": "FEATURE_ENHANCEMENT", "task": "Implement biometric WebAuthn FIDO2 step-up authentication endpoint"},
    {"intent": "REFACTOR", "task": "Refactor asynchronous payment webhook dispatch to resilient event queue"},
    {"intent": "DATABASE_CHANGE", "task": "Migrate MySQL customer profiles table to encrypted Amazon Aurora cluster"},
    {"intent": "BUG_FIX", "task": "Resolve floating point rounding bug in invoice interest amortization formula"},
    {"intent": "DEPLOYMENT_RELEASE", "task": "Deploy canary release v3.12.0 of checkout microservice to us-east-1"},
    {"intent": "FEATURE_ENHANCEMENT", "task": "Build automated refund authorization workflow for customer disputes"},
    {"intent": "REFACTOR", "task": "Simplify database connection pooling logic in payments processing worker"},
    {"intent": "DATABASE_CHANGE", "task": "Alter customer orders table to add loyalty discount tier column"},
    {"intent": "BUG_FIX", "task": "Fix race condition in concurrent bank account transfer withdrawal routine"},
    {"intent": "FEATURE_ENHANCEMENT", "task": "Add support for Apple Pay and Google Pay tokenized card decrypters"},
    {"intent": "REFACTOR", "task": "Restructure GraphQL gateway resolvers to eliminate N+1 query problem"},
    {"intent": "DATABASE_CHANGE", "task": "Partition billing records table by calendar quarter for high-throughput reads"},
    {"intent": "BUG_FIX", "task": "Fix deadlock condition when multiple agents acquire ledger write locks"},
    {"intent": "DEPLOYMENT_RELEASE", "task": "Promote v2.8.4 container build to European staging cluster via ArgoCD"},
    {"intent": "FEATURE_ENHANCEMENT", "task": "Implement cryptographic HMAC-SHA256 signature verification on partner webhooks"},
    {"intent": "REFACTOR", "task": "Modernize Python 3.9 codebase to Python 3.12 syntax with type annotations"},
    {"intent": "DATABASE_CHANGE", "task": "Archive financial records older than 7 years to cold immutable S3 storage"},
    {"intent": "BUG_FIX", "task": "Patch path traversal vulnerability in document export API handler"},
    {"intent": "FEATURE_ENHANCEMENT", "task": "Create batch payout engine for marketplace vendor disbursement"},
    {"intent": "REFACTOR", "task": "Clean up deprecated endpoint routes and remove dead legacy handlers"},
    {"intent": "DATABASE_CHANGE", "task": "Apply schema migration adding currency code field to foreign transactions"},
    {"intent": "BUG_FIX", "task": "Fix memory leak in background gRPC stream handler under sustained load"},
    {"intent": "DEPLOYMENT_RELEASE", "task": "Deploy Envoy egress gateway configuration to production cluster"},
    {"intent": "FEATURE_ENHANCEMENT", "task": "Add rate-limiting token bucket middleware on public REST APIs"},
    {"intent": "REFACTOR", "task": "Extract monolithic ledger service into domain-driven microservices"},
    {"intent": "DATABASE_CHANGE", "task": "Update PostgreSQL connection pool configuration for zero connection drops"},
    {"intent": "BUG_FIX", "task": "Fix JWT token expiration validation clock skew issue across regions"},
    {"intent": "FEATURE_ENHANCEMENT", "task": "Implement multi-currency wallet balance conversion engine"},
    {"intent": "REFACTOR", "task": "Refactor unit test suite to run in parallel using pytest-xdist"},
    {"intent": "DATABASE_CHANGE", "task": "Add foreign key constraint with cascade protection on customer accounts"},
    {"intent": "BUG_FIX", "task": "Resolve redis cache eviction stampede on viral merchant products"},
    {"intent": "DEPLOYMENT_RELEASE", "task": "Execute blue-green traffic switch for core banking API v4 release"},
    {"intent": "FEATURE_ENHANCEMENT", "task": "Build automated idempotency key deduplication cache on wire transfers"},
    {"intent": "REFACTOR", "task": "Optimize JSON serialization throughput using orjson high-performance library"},
    {"intent": "DATABASE_CHANGE", "task": "Run database dry-run migration script for regulatory tax reporting table"},
    {"intent": "BUG_FIX", "task": "Fix unhandled HTTP 504 gateway timeout when calling downstream card network"},
    {"intent": "FEATURE_ENHANCEMENT", "task": "Implement zero-knowledge proof verification for confidential transactions"},
    {"intent": "REFACTOR", "task": "Consolidate multiple duplicate logging formats into structured JSON schema"},
    {"intent": "DATABASE_CHANGE", "task": "Create read replica pool in ap-southeast-1 for low-latency reporting"},
    {"intent": "BUG_FIX", "task": "Fix XML entity injection vulnerability in legacy banking file parser"},
    {"intent": "DEPLOYMENT_RELEASE", "task": "Deploy updated Cedar authorization policy bundle to edge PEP brokers"},
    {"intent": "FEATURE_ENHANCEMENT", "task": "Implement automated chargeback evidence generation from audit trail"},
    {"intent": "REFACTOR", "task": "Refactor error handling to return standardized RFC 7807 problem details"},
    {"intent": "DATABASE_CHANGE", "task": "Apply schema change adding tenant isolation identifier across tables"},
    {"intent": "BUG_FIX", "task": "Fix unindexed full table scan causing elevated database CPU utilization"},
    {"intent": "FEATURE_ENHANCEMENT", "task": "Build automated subscription recurring billing scheduler"},
    {"intent": "REFACTOR", "task": "Decouple email notification sender into asynchronous Celery task"},
    {"intent": "DATABASE_CHANGE", "task": "Enforce transparent data encryption (TDE) on PostgreSQL ledger volumes"},
    {"intent": "BUG_FIX", "task": "Fix HTTP connection leak in outbound third-party credit score client"},
    {"intent": "DEPLOYMENT_RELEASE", "task": "Execute rolling restart of Kubernetes worker nodes following kernel update"},
    {"intent": "FEATURE_ENHANCEMENT", "task": "Add dynamic currency conversion lookup based on client geolocation"},
    {"intent": "REFACTOR", "task": "Streamline Kafka consumer pipeline to reduce end-to-end processing latency"},
    {"intent": "DATABASE_CHANGE", "task": "Implement automated database point-in-time recovery health checks"},
    {"intent": "BUG_FIX", "task": "Resolve incorrect CORS preflight response headers on merchant portal"},
    {"intent": "FEATURE_ENHANCEMENT", "task": "Build automated fraud rule engine evaluating transaction velocity"},
    {"intent": "REFACTOR", "task": "Refactor TLS certificate provisioning script to use ACME DNS-01 challenges"},

    # --- Category 2: Investigate / Diagnose (Tasks 61 - 120) ---
    {"intent": "INVESTIGATION", "task": "Investigate production checkout latency spike following deployment 38122"},
    {"intent": "INVESTIGATION", "task": "Diagnose intermittent 502 Bad Gateway errors on payment gateway ingress"},
    {"intent": "INVESTIGATION", "task": "Audit VPC security groups for unauthorized outbound internet egress rules"},
    {"intent": "INVESTIGATION", "task": "Inspect container image layers for critical OpenSSL vulnerabilities"},
    {"intent": "INVESTIGATION", "task": "Analyze slow database query execution plans on customer balance lookups"},
    {"intent": "INVESTIGATION", "task": "Investigate elevated memory consumption in Redis session cache nodes"},
    {"intent": "INVESTIGATION", "task": "Diagnose Kafka consumer group lag on financial transaction topic"},
    {"intent": "INVESTIGATION", "task": "Audit IAM roles and policies to identify over-privileged wildcard grants"},
    {"intent": "INVESTIGATION", "task": "Investigate elevated error rates during peak European trading hours"},
    {"intent": "INVESTIGATION", "task": "Diagnose DNS resolution latency spikes on internal microservice mesh"},
    {"intent": "INVESTIGATION", "task": "Inspect TLS cipher suites on external load balancers against NIST guidelines"},
    {"intent": "INVESTIGATION", "task": "Investigate packet loss across AWS Direct Connect dedicated link"},
    {"intent": "INVESTIGATION", "task": "Diagnose thread starvation in asynchronous worker process thread pool"},
    {"intent": "INVESTIGATION", "task": "Audit employee SSH access logs on production bastion hosts for anomalies"},
    {"intent": "INVESTIGATION", "task": "Investigate anomalous spike in failed credit card CVV validation attempts"},
    {"intent": "INVESTIGATION", "task": "Diagnose database connection pool exhaustion during flash sale event"},
    {"intent": "INVESTIGATION", "task": "Inspect Kubernetes node kernel logs for OOM killer termination events"},
    {"intent": "INVESTIGATION", "task": "Investigate sudden latency degradation on third-party KYC verification API"},
    {"intent": "INVESTIGATION", "task": "Diagnose disk I/O saturation on primary PostgreSQL database instance"},
    {"intent": "INVESTIGATION", "task": "Audit SPIFFE SVID certificate issuance logs for unexpected trust domains"},
    {"intent": "INVESTIGATION", "task": "Investigate elevated HTTP 429 rate limit responses returned to mobile clients"},
    {"intent": "INVESTIGATION", "task": "Diagnose network partition handling in distributed Etcd consensus cluster"},
    {"intent": "INVESTIGATION", "task": "Inspect public S3 bucket access control lists for accidental exposure"},
    {"intent": "INVESTIGATION", "task": "Investigate unexpected CPU spikes in background ledger reconciliation cron"},
    {"intent": "INVESTIGATION", "task": "Diagnose gRPC connection reset errors between API gateway and auth service"},
    {"intent": "INVESTIGATION", "task": "Audit database administrative query logs for unredacted customer PII"},
    {"intent": "INVESTIGATION", "task": "Investigate elevated checkout drop-off rates on Android mobile application"},
    {"intent": "INVESTIGATION", "task": "Diagnose cache miss ratio increase following catalog cache cluster restart"},
    {"intent": "INVESTIGATION", "task": "Inspect container host filesystem integrity using eBPF kernel monitors"},
    {"intent": "INVESTIGATION", "task": "Investigate unexpected spike in customer account password reset requests"},
    {"intent": "INVESTIGATION", "task": "Diagnose TCP SYN flood resilience on edge cloudflare reverse proxy"},
    {"intent": "INVESTIGATION", "task": "Audit AWS CloudTrail events for root account console sign-in occurrences"},
    {"intent": "INVESTIGATION", "task": "Investigate transaction batch mismatch between core banking and card network"},
    {"intent": "INVESTIGATION", "task": "Diagnose SSL handshake failure on legacy B2B partner webhook endpoints"},
    {"intent": "INVESTIGATION", "task": "Inspect Kubernetes ingress controller ingress access logs for SQL injection"},
    {"intent": "INVESTIGATION", "task": "Investigate file descriptor exhaustion in reverse proxy worker threads"},
    {"intent": "INVESTIGATION", "task": "Diagnose slow garbage collection pauses in core banking JVM microservice"},
    {"intent": "INVESTIGATION", "task": "Audit cryptographic key rotation logs in AWS KMS for compliance renewal"},
    {"intent": "INVESTIGATION", "task": "Investigate webhook delivery failure queue growth during partner downtime"},
    {"intent": "INVESTIGATION", "task": "Diagnose microservice dependency cascade failures using distributed tracing"},
    {"intent": "INVESTIGATION", "task": "Inspect CI/CD build runner agents for unauthorized environment variable access"},
    {"intent": "INVESTIGATION", "task": "Investigate sudden rise in transaction chargebacks from specific merchant"},
    {"intent": "INVESTIGATION", "task": "Diagnose DNS cache poisoning attempts on internal corporate resolvers"},
    {"intent": "INVESTIGATION", "task": "Audit GitHub repository branch protection rules across enterprise org"},
    {"intent": "INVESTIGATION", "task": "Investigate elevated database lock contention during month-end close"},
    {"intent": "INVESTIGATION", "task": "Diagnose load balancer health check flapping on payment tokenization nodes"},
    {"intent": "INVESTIGATION", "task": "Inspect Docker daemon socket access permissions on development machines"},
    {"intent": "INVESTIGATION", "task": "Investigate anomalous credit line drawdown patterns across business accounts"},
    {"intent": "INVESTIGATION", "task": "Diagnose elasticsearch cluster yellow health status caused by unassigned shards"},
    {"intent": "INVESTIGATION", "task": "Audit corporate VPN authentication logs for concurrent logins across locations"},
    {"intent": "INVESTIGATION", "task": "Investigate WebSocket connection drops affecting real-time trading board"},
    {"intent": "INVESTIGATION", "task": "Diagnose slow disk write throughput on NVMe block storage volumes"},
    {"intent": "INVESTIGATION", "task": "Inspect API documentation portal for broken route links and stale schemas"},
    {"intent": "INVESTIGATION", "task": "Investigate sudden increase in customer support tickets citing card declines"},
    {"intent": "INVESTIGATION", "task": "Diagnose cross-AZ network traffic latency between staging database and worker"},
    {"intent": "INVESTIGATION", "task": "Audit production access bastion session recordings for compliance review"},
    {"intent": "INVESTIGATION", "task": "Investigate rogue autonomous agent reaching for restricted customer records"},
    {"intent": "INVESTIGATION", "task": "Diagnose TLS 1.3 session resumption failure in mobile banking application"},
    {"intent": "INVESTIGATION", "task": "Inspect container runtime cgroup memory limits to prevent host starvation"},
    {"intent": "INVESTIGATION", "task": "Investigate anomalous ACH batch clearing latency reported by Federal Reserve"},

    # --- Category 3: Search / Explain (Tasks 121 - 180) ---
    {"intent": "DOCUMENTATION", "task": "Search documentation for OAuth2 PKCE authorization code exchange flow"},
    {"intent": "DOCUMENTATION", "task": "Explain OpenAPI 3.1 schema specification for financial transfers endpoint"},
    {"intent": "DOCUMENTATION", "task": "Search codebase documentation for microservice API rate limit headers"},
    {"intent": "DOCUMENTATION", "task": "Explain Zero-Trust Bounded Authority Plane 5-stage identity pipeline"},
    {"intent": "DOCUMENTATION", "task": "Search internal architecture docs for multi-region disaster recovery runbook"},
    {"intent": "DOCUMENTATION", "task": "Explain PCI-DSS requirement 3.4 for customer primary account number encryption"},
    {"intent": "DOCUMENTATION", "task": "Search developer guidelines for gRPC status code mapping conventions"},
    {"intent": "DOCUMENTATION", "task": "Explain Cedar policy language syntax for permit and forbid rules"},
    {"intent": "DOCUMENTATION", "task": "Search Git history for origin and rationale of payment idempotency cache"},
    {"intent": "DOCUMENTATION", "task": "Explain Kubernetes Horizontal Pod Autoscaler algorithm and target metrics"},
    {"intent": "DOCUMENTATION", "task": "Search codebase for all references to deprecated payment token schema v1"},
    {"intent": "DOCUMENTATION", "task": "Explain SPIFFE X.509 SVID certificate validation in service-to-service mTLS"},
    {"intent": "DOCUMENTATION", "task": "Search documentation for enterprise SAML single sign-on integration guide"},
    {"intent": "DOCUMENTATION", "task": "Explain ISO 20022 pacs.008 credit transfer message structure"},
    {"intent": "DOCUMENTATION", "task": "Search runbooks for database failover procedures during cloud outage"},
    {"intent": "DOCUMENTATION", "task": "Explain difference between Tier 1 local execution and Tier 2 PEP gateway rules"},
    {"intent": "DOCUMENTATION", "task": "Search repository for Dockerfile security best practices and non-root users"},
    {"intent": "DOCUMENTATION", "task": "Explain GraphQL query complexity calculation and depth limit enforcement"},
    {"intent": "DOCUMENTATION", "task": "Search documentation for Prometheus custom metric alerting threshold rules"},
    {"intent": "DOCUMENTATION", "task": "Explain Apple Seatbelt sandbox-exec kernel profile isolation mechanism"},
    {"intent": "DOCUMENTATION", "task": "Search codebase for credit card Luhn algorithm validation implementation"},
    {"intent": "DOCUMENTATION", "task": "Explain Windows Job Objects and Restricted Token containment in BAP Layer B"},
    {"intent": "DOCUMENTATION", "task": "Search architecture sitemap for Envoy proxy filter chain routing rules"},
    {"intent": "DOCUMENTATION", "task": "Explain double-entry bookkeeping credit and debit invariance properties"},
    {"intent": "DOCUMENTATION", "task": "Search codebase for database migration rollback scripts and safety checks"},
    {"intent": "DOCUMENTATION", "task": "Explain GDPR Article 17 right to erasure requirements on distributed backups"},
    {"intent": "DOCUMENTATION", "task": "Search documentation for AWS KMS multi-region key replication latency"},
    {"intent": "DOCUMENTATION", "task": "Explain Kafka consumer rebalance protocol and cooperative sticky assignor"},
    {"intent": "DOCUMENTATION", "task": "Search Git commit logs for root cause of previous memory leak incident"},
    {"intent": "DOCUMENTATION", "task": "Explain distributed tracing span propagation via W3C tracecontext headers"},
    {"intent": "DOCUMENTATION", "task": "Search documentation for Microsoft Intune OMA-URI device policy packaging"},
    {"intent": "DOCUMENTATION", "task": "Explain SHA-256 tamper-evident hash chain verification in BAP audit store"},
    {"intent": "DOCUMENTATION", "task": "Search codebase for all third-party outbound HTTP API integration clients"},
    {"intent": "DOCUMENTATION", "task": "Explain Zero-Trust Rule R3: Authorization does not prove downstream execution"},
    {"intent": "DOCUMENTATION", "task": "Search runbooks for rotating Root CA certificate without downtime"},
    {"intent": "DOCUMENTATION", "task": "Explain biometric step-up authentication challenge-response lifecycle"},
    {"intent": "DOCUMENTATION", "task": "Search documentation for Elasticsearch index lifecycle management (ILM)"},
    {"intent": "DOCUMENTATION", "task": "Explain RFC 8628 OAuth 2.0 Device Authorization Grant for headless agents"},
    {"intent": "DOCUMENTATION", "task": "Search codebase for password hashing implementation using Argon2id"},
    {"intent": "DOCUMENTATION", "task": "Explain network egress pinning and packet dropping in BAP Layer C"},
    {"intent": "DOCUMENTATION", "task": "Search documentation for ArgoCD sync wave ordering and deployment hooks"},
    {"intent": "DOCUMENTATION", "task": "Explain difference between autonomous agent intent and true authority grants"},
    {"intent": "DOCUMENTATION", "task": "Search repository for terraform modules managing production VPC subnets"},
    {"intent": "DOCUMENTATION", "task": "Explain OWASP Top 10 API Security Risks and mitigations in Gateway PEP"},
    {"intent": "DOCUMENTATION", "task": "Search documentation for PostgreSQL WAL archiving to S3 cold storage"},
    {"intent": "DOCUMENTATION", "task": "Explain atomic single-use grant burning at BAP Gateway PEP boundary"},
    {"intent": "DOCUMENTATION", "task": "Search codebase for customer email notification templates and localized copies"},
    {"intent": "DOCUMENTATION", "task": "Explain Linux seccomp BPF syscall filter profile applied to Python agents"},
    {"intent": "DOCUMENTATION", "task": "Search documentation for Cloudflare WAF custom firewall rule expressions"},
    {"intent": "DOCUMENTATION", "task": "Explain role-based client action gating and persona control plane models"},
    {"intent": "DOCUMENTATION", "task": "Search codebase for health check probes on internal backend microservices"},
    {"intent": "DOCUMENTATION", "task": "Explain SOC2 Type II Trust Services Criteria for security and availability"},
    {"intent": "DOCUMENTATION", "task": "Search documentation for OpenTelemetry collector batch processor settings"},
    {"intent": "DOCUMENTATION", "task": "Explain cryptographic notary digital signatures on immutable policy bundles"},
    {"intent": "DOCUMENTATION", "task": "Search codebase for SQL injection prevention using parameterized prepared queries"},
    {"intent": "DOCUMENTATION", "task": "Explain Redis Sentinel automated master election and failover protocol"},
    {"intent": "DOCUMENTATION", "task": "Search documentation for Jamf Pro mobileconfig payload deployment on macOS"},
    {"intent": "DOCUMENTATION", "task": "Explain Intent Deviation detection when agents violate declared mission scope"},
    {"intent": "DOCUMENTATION", "task": "Search codebase for currency formatting logic adhering to ISO 4217"},
    {"intent": "DOCUMENTATION", "task": "Explain fail-closed security invariants enforced when control plane is unreachable"},

    # --- Category 4: Automate Workflow (Tasks 181 - 240) ---
    {"intent": "WORK_MANAGEMENT", "task": "Automate CI/CD pipeline workflow for canary deployment verification"},
    {"intent": "TEST_VERIFICATION", "task": "Automate test orchestration pipeline across distributed worker nodes"},
    {"intent": "WORK_MANAGEMENT", "task": "Create automated pull request with release notes and changelog"},
    {"intent": "TEST_VERIFICATION", "task": "Automate end-to-end regression test suite execution upon git push"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate Jira ticket creation and assignment upon production alert"},
    {"intent": "TEST_VERIFICATION", "task": "Automate security vulnerability scanning in daily CI build matrix"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate container image build, signing, and push to Amazon ECR"},
    {"intent": "TEST_VERIFICATION", "task": "Automate API contract backward compatibility check against master branch"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate nightly database backup snapshot and replication to offsite region"},
    {"intent": "TEST_VERIFICATION", "task": "Automate load testing benchmark execution against staging environment"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate automated package dependency update pull requests via Dependabot"},
    {"intent": "TEST_VERIFICATION", "task": "Automate code coverage report generation and badge publishing"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate stale feature flag cleanup and notification to engineering leads"},
    {"intent": "TEST_VERIFICATION", "task": "Automate chaos engineering network latency injection in test cluster"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate Slack incident channel creation and notification dispatch"},
    {"intent": "TEST_VERIFICATION", "task": "Automate cross-browser compatibility verification using Playwright grid"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate cloud infrastructure provisioning using Terraform Cloud pipeline"},
    {"intent": "TEST_VERIFICATION", "task": "Automate database migration dry-run verification against production clone"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate ephemeral preview environment deployment for each open PR"},
    {"intent": "TEST_VERIFICATION", "task": "Automate linting and static analysis checks using flake8 and black"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate SSL certificate renewal and deployment via Let's Encrypt bot"},
    {"intent": "TEST_VERIFICATION", "task": "Automate synthetic transaction probe execution against live endpoints"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate employee onboarding laptop configuration push via Intune"},
    {"intent": "TEST_VERIFICATION", "task": "Automate performance regression benchmark tracking on every merge"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate developer credential revocation when employee departs company"},
    {"intent": "TEST_VERIFICATION", "task": "Automate fuzz testing on binary ASN.1 parser to find crash vectors"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate ArgoCD application sync across all global Kubernetes clusters"},
    {"intent": "TEST_VERIFICATION", "task": "Automate accessibility WCAG 2.1 AA compliance scan on web portal"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate nightly data warehouse ETL pipeline orchestration in Airflow"},
    {"intent": "TEST_VERIFICATION", "task": "Automate mock service creation for third-party credit card network tests"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate AWS EC2 spot instance termination handling and replacement"},
    {"intent": "TEST_VERIFICATION", "task": "Automate GraphQL schema validation and breaking change detection"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate SOC2 automated evidence manifest export to compliance portal"},
    {"intent": "TEST_VERIFICATION", "task": "Automate container base image CVE scanning before production deploy"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate PagerDuty on-call schedule handover and notification dispatch"},
    {"intent": "TEST_VERIFICATION", "task": "Automate distributed tracing validation ensuring all spans have traceparent"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate unpinned GitHub Action versions locking to full commit SHAs"},
    {"intent": "TEST_VERIFICATION", "task": "Automate mutation testing using mutmut to assess test suite rigor"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate customer GDPR data erasure orchestration across databases"},
    {"intent": "TEST_VERIFICATION", "task": "Automate memory leak detection in long-running integration test runs"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate Kubernetes cluster certificate authority rotation pipeline"},
    {"intent": "TEST_VERIFICATION", "task": "Automate OpenAPI 3.1 client SDK generation and version publishing"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate cloud cost anomaly alerts dispatch to engineering managers"},
    {"intent": "TEST_VERIFICATION", "task": "Automate SQL query plan regression tests on primary database engine"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate release tag creation and GitHub release announcement drafting"},
    {"intent": "TEST_VERIFICATION", "task": "Automate static application security testing (SAST) using Semgrep"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate HashiCorp Vault token renewal for backend microservices"},
    {"intent": "TEST_VERIFICATION", "task": "Automate latency SLA verification across all public API routes"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate Elasticsearch index rollover and cold storage archiving"},
    {"intent": "TEST_VERIFICATION", "task": "Automate mobile app screenshot generation across device resolutions"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate automated rollback execution when canary error budget depletes"},
    {"intent": "TEST_VERIFICATION", "task": "Automate secrets scanning in git commit history using TruffleHog"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate customer support ticket triage and priority categorization"},
    {"intent": "TEST_VERIFICATION", "task": "Automate Deadlock detection in multi-threaded database stress tests"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate DNS record failover when primary availability zone degrades"},
    {"intent": "TEST_VERIFICATION", "task": "Automate software bill of materials (SBOM) generation via Syft"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate Redis cluster shard rebalancing when memory exceeds 80%"},
    {"intent": "TEST_VERIFICATION", "task": "Automate TLS 1.3 protocol enforcement verification across all hosts"},
    {"intent": "WORK_MANAGEMENT", "task": "Automate audit log archiving to immutable WORM compliant storage"},
    {"intent": "TEST_VERIFICATION", "task": "Automate end-to-end payment checkout flow with synthetic test card"},

    # --- Category 5: Business Analysis (Tasks 241 - 300) ---
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze quarterly revenue metrics and business performance report"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Perform financial business analysis on transaction ledgers"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Model customer lifetime value and churn risk across merchant cohorts"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze credit card interchange fee optimization across card networks"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Perform business analysis on merchant onboarding drop-off funnel"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Generate monthly cloud infrastructure cost allocation by business unit"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate currency exchange rate volatility impact on cross-border profits"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Perform fraud loss analysis and calculate false positive decline rates"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze customer support ticket resolution velocity by product category"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate enterprise subscription renewal probability and expansion pipeline"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Model transaction volume forecast for upcoming holiday shopping season"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze compliance audit readiness and identify remaining control gaps"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Perform vendor spend analysis and identify software license consolidation"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate API adoption metrics and active developer ecosystem growth"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Model impact of Federal Reserve interest rate changes on deposit yields"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze chargeback dispute win-loss ratio across payment acquirers"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate mobile banking feature engagement and daily active users (DAU)"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Perform business analysis on autonomous agent workforce operational ROI"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze employee IT helpdesk resolution times across corporate offices"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate customer Net Promoter Score (NPS) correlation with platform latency"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Model risk-weighted asset ratios under Basel III regulatory framework"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze B2B invoice payment cycle times and days sales outstanding (DSO)"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate cloud storage growth trajectory and recommend cold archive tiers"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Perform business analysis on loan portfolio default risk across sectors"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze autonomous agent error rates and containment intervention events"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate marketing campaign acquisition cost (CAC) across digital channels"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Model payment gateway routing optimization for lowest transaction fees"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze merchant chargeback recovery rates and identify dispute patterns"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate developer productivity metrics: PR review time and deployment rate"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Perform business analysis on international wire settlement cost reduction"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze customer account churn predictors using logistic regression"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate software SaaS subscription utilization across all departments"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Model data transfer egress charges across AWS regions and direct connect"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze credit card dispute reasons and recommend checkout UI fixes"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate enterprise SLA compliance percentage across cloud microservices"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Perform business analysis on autonomous code review security catch rate"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze cash flow liquidity requirements for peak month-end settlements"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate user authentication latency impact on mobile checkout completion"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Model infrastructure capacity requirements for planned 3x transaction growth"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze customer support deflection rate achieved by automated agent chat"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate payment authorization rates across credit card issuing banks"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Perform business analysis on cloud reserved instance vs spot savings"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze transaction failure root causes: insufficient funds vs card block"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate employee security awareness training completion and phishing catch"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Model revenue impact of instant payment availability on merchant retention"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze database query volume patterns to optimize read replica sizing"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate corporate travel spend compliance against automated expense policy"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Perform business analysis on autonomous agent task completion velocity"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze merchant refund volume trends and detect potential inventory scams"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate microservice container resource requests vs actual peak CPU usage"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Model credit risk scoring accuracy against subsequent 90-day delinquency"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze cross-border foreign exchange spread margins across currency pairs"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate customer account security posture and multi-factor adoption"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Perform business analysis on enterprise software release cycle lead time"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze third-party API dependency latency contribution to overall SLA"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate cloud serverless execution cost vs container cluster hosting"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Model fraud prevention savings achieved by BAP Zero-Trust edge policy"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Analyze employee device compliance posture across Windows, macOS, and Linux"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Evaluate autonomous agent intent alignment and deviation prevention value"},
    {"intent": "BUSINESS_ANALYSIS", "task": "Perform comprehensive executive CIO business analysis on AI workforce scale"},
]

# Quick sanity check on task collection
assert len(TASKS_300) == 300, f"Expected 300 tasks, got {len(TASKS_300)}"

# ==============================================================================
# WORKFORCE AGENT WORKER
# ==============================================================================
class WorkforceAgent:
    def __init__(
        self,
        team_id: str,
        team_name: str,
        agent_idx: int,
        agent_role: str,
        app_id: str,
        lead_name: str,
        server_url: str,
        assigned_tasks: List[Dict[str, str]],
    ):
        self.team_id = team_id
        self.team_name = team_name
        self.agent_idx = agent_idx
        self.agent_role = agent_role
        self.app_id = app_id
        self.lead_name = lead_name
        self.server_url = server_url
        self.assigned_tasks = assigned_tasks
        
        self.agent_id = f"agent-{team_id}-0{agent_idx}"
        self.session_id = f"sess-{team_id}-ag{agent_idx}-{int(time.time())}"
        self.user_email = f"{lead_name.lower().replace(' ', '.')}@{team_id}.internal"
        
        self.session: BAPSession = None
        self.is_running = False
        self.thread: threading.Thread = None
        self.current_task_idx = 0
        self.current_task = assigned_tasks[0] if assigned_tasks else None

    def start(self):
        """Starts the agent session and launches its autonomous work cycle."""
        initial_task = self.assigned_tasks[0] if self.assigned_tasks else {"task": "Workload execution", "intent": "INVESTIGATION"}
        self.session = BAPSession(
            app_id=self.app_id,
            server_url=self.server_url,
            session_id=self.session_id,
            instance_id=self.agent_id,
            user_id=self.lead_name,
            user_email=self.user_email,
            agent_name=f"{self.agent_role} ({self.team_name})",
            user_prompt=initial_task["task"]
        )
        self.session.start()
        
        # Send initial classified intent to Control Plane
        self.session.set_prompt(initial_task["task"], category=initial_task.get("intent"))
        
        self.is_running = True
        self.thread = threading.Thread(target=self._run_work_loop, daemon=True, name=f"Agent-{self.agent_id}")
        self.thread.start()

    def _run_work_loop(self):
        """Simulates realistic agent task progression, heartbeats, and 2-task execution."""
        total_tasks = len(self.assigned_tasks)
        task_switch_delay = random.uniform(35.0, 55.0)  # Transition to 2nd task mid-demo
        start_time = time.time()
        switched_to_task_2 = False

        while self.is_running and self.session and self.session.is_active:
            elapsed = time.time() - start_time

            # Switch to task 2 when ready
            if not switched_to_task_2 and total_tasks > 1 and elapsed >= task_switch_delay:
                self.current_task_idx = 1
                self.current_task = self.assigned_tasks[1]
                switched_to_task_2 = True
                try:
                    self.session.set_prompt(self.current_task["task"], category=self.current_task.get("intent"))
                except Exception:
                    pass

            # Live heartbeat keeping presence active
            try:
                self.session.heartbeat()
            except Exception:
                pass

            # Random small execution jitter
            time.sleep(random.uniform(2.5, 4.0))

    def stop(self):
        """Gracefully completes and closes the agent session."""
        self.is_running = False
        if self.session:
            try:
                self.session.end(reason="demo task completed")
            except Exception:
                pass


# ==============================================================================
# MAIN DEMONSTRATION RUNNER
# ==============================================================================
def parse_arguments():
    parser = argparse.ArgumentParser(description="BAP CIO Demo: 15 Teams, 75 Agents, 300 Tasks")
    parser.add_argument("--url", default="http://127.0.0.1:8080", help="BAP Control Plane base URL")
    parser.add_argument("--duration", type=int, default=150, help="Demo duration in seconds (default: 150s = 2.5 min)")
    parser.add_argument("--auto-close", action="store_true", help="Automatically close after duration without waiting for Enter")
    return parser.parse_args()


def print_banner(text: str):
    print("\n" + "=" * 90)
    print(f"  {text}")
    print("=" * 90)


def main():
    args = parse_arguments()
    server_url = args.url.rstrip("/")
    demo_duration = args.duration

    print_banner("BOUNDED AUTHORITY PLANE (BAP): CIO ENTERPRISE WORKFORCE DEMO")
    print(f"  Target Control Plane : {server_url}")
    print(f"  Planned Demo Scale   : 15 Enterprise Teams, 5 Agents per Team = 75 Governed Agents")
    print(f"  Task Catalog Pool    : 300 Random Real-World Tasks (2 Tasks Executed per Team)")
    print(f"  Live Target Duration : {demo_duration} seconds (~{round(demo_duration/60, 1)} minutes)")
    print("=" * 90)

    # 1. Verify Control Plane connectivity
    import urllib.request
    try:
        req = urllib.request.Request(f"{server_url}/api/v1/health")
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                print(f"[+] Control Plane is ONLINE at {server_url}")
    except Exception as e:
        print(f"[-] WARNING: Could not connect to Control Plane at {server_url}: {e}")
        print("    Ensure bapcontrolplane is running (e.g. `go run ./cmd/server` or `start_controlplane.bat`).")
        print("    Attempting to continue with local agent execution...\n")

    # 2. Select 2 random tasks from the 300 tasks catalog for each of the 15 teams
    # 15 teams * 2 tasks = 30 distinct tasks sampled uniformly without replacement from 300
    chosen_tasks = random.sample(TASKS_300, k=len(TEAMS) * 2)

    team_assignments = {}
    for idx, team in enumerate(TEAMS):
        t1 = chosen_tasks[idx * 2]
        t2 = chosen_tasks[idx * 2 + 1]
        team_assignments[team["id"]] = [t1, t2]

    print("\n[+] Sampled 30 unique tasks from 300-task catalog across 15 enterprise teams:")
    for team in TEAMS:
        t1, t2 = team_assignments[team["id"]]
        print(f"  * {team['name']:25} -> [Task 1: {t1['intent']}] {t1['task'][:48]}...")
        print(f"    {' ':25} -> [Task 2: {t2['intent']}] {t2['task'][:48]}...")

    # 3. Provision and launch all 75 agents
    print_banner("LAUNCHING 75 GOVERNED AGENTS (15 TEAMS x 5 AGENTS)")
    agents: List[WorkforceAgent] = []

    for team in TEAMS:
        t_tasks = team_assignments[team["id"]]
        print(f"\n[+] Deploying Team: {team['name']} ({team['division']}) - Lead: {team['lead']}")
        for a_idx in range(1, 6):
            role_name = team["agent_types"][a_idx - 1]
            agent = WorkforceAgent(
                team_id=team["id"],
                team_name=team["name"],
                agent_idx=a_idx,
                agent_role=role_name,
                app_id=team["app_id"],
                lead_name=team["lead"],
                server_url=server_url,
                assigned_tasks=t_tasks
            )
            agent.start()
            agents.append(agent)
            sys.stdout.write(f"  + Agent #{len(agents):02d} [{agent.agent_id}]: {role_name}\n")
            sys.stdout.flush()
            time.sleep(0.04)  # Smooth rollout stagger

    print(f"\n[+] SUCCESS: All {len(agents)} autonomous agents are now LIVE and GOVERNED on BAP Control Plane!")
    print(f"    Open dashboard: {server_url}/dashboard?persona=cio")

    # Handle interrupt cleanly
    stop_event = threading.Event()

    def handle_sigint(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)

    # 4. Live monitoring loop during demo runtime
    start_time = time.time()
    last_print = 0

    print_banner(f"RUNNING LIVE CIO DEMO ({demo_duration} SECONDS) - PRESS [ENTER] ANYTIME TO SHUT DOWN")

    # Background thread to listen for Enter key press without blocking the status ticker
    user_pressed_enter = threading.Event()
    def wait_for_enter():
        try:
            input()
            user_pressed_enter.set()
            stop_event.set()
        except Exception:
            pass

    input_thread = threading.Thread(target=wait_for_enter, daemon=True)
    input_thread.start()

    try:
        while not stop_event.is_set():
            now = time.time()
            elapsed = int(now - start_time)
            remaining = max(0, demo_duration - elapsed)

            if now - last_print >= 5.0 or elapsed == 1:
                last_print = now
                live_count = sum(1 for a in agents if a.is_running and a.session and a.session.is_active)
                
                # Fetch summary from control plane if reachable
                act_str = f"Live Agents: {live_count}/75 | 15 Teams Active"
                try:
                    req = urllib.request.Request(f"{server_url}/api/activity/summary")
                    with urllib.request.urlopen(req, timeout=1.5) as r:
                        if r.status == 200:
                            data = json.loads(r.read().decode("utf-8"))
                            tot = data.get("total_active_agents", live_count)
                            gov = data.get("governed_percent", 100.0)
                            bus = data.get("business_units_active", "15/15")
                            act_str = f"Live Agents: {tot} | Governed: {gov:.1f}% | Active BUs: {bus}"
                except Exception:
                    pass

                print(f"[{elapsed:03d}s / {demo_duration:03d}s] {act_str} | Remaining: {remaining}s (Press Enter to finish)")

            if elapsed >= demo_duration:
                print("\n[*] Demonstration target duration reached.")
                break

            time.sleep(1.0)

    except KeyboardInterrupt:
        pass

    # 5. Clean teardown and session deregistration
    print_banner("SHUTTING DOWN ALL 75 AGENT WORKLOADS AND RELEASING SESSIONS")
    for idx, agent in enumerate(agents):
        sys.stdout.write(f"  - Closing Agent #{idx+1:02d} [{agent.agent_id}] ({agent.team_name})...\n")
        sys.stdout.flush()
        agent.stop()
        time.sleep(0.02)

    time.sleep(1.0)
    print("\n[+] All 75 autonomous agent workloads have cleanly ended their sessions.")
    print("[+] BAP Zero-Trust live demonstration completed successfully.\n")


if __name__ == "__main__":
    main()
