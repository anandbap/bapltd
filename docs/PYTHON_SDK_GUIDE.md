# BAP Python Agent SDK Guide

The **BAP Python Agent SDK** (`bap_sdk`) is a zero-dependency, high-performance client library that embeds Zero-Trust governance, Cedar authorization, and live telemetry observability into custom Python AI agents.

---

## 1. Installation

```bash
pip install bap-ltd
```
Or use the embedded library directly in your repository:
```python
from bap_sdk import BAPSession, BAPHttpClient
```

---

## 2. Quickstart: Governing Agent Shell Actions

Wrap your agent's tool execution functions inside a governed BAP session:

```python
from bap_sdk import BAPSession

# 1. Initialize session with user and agent identity
session = BAPSession(
    app_id="financial-reconciler",
    user_id="alex.developer",
    user_email="alex@enterprise.corp",
    workspace_root="."
)
session.start()

# 2. Transmit prompt context and intent
session.record_prompt(
    prompt="Reconcile Q3 payments and audit ledger entries",
    intent="INVESTIGATION"
)

# 3. Execute governed tool commands
# Cedar policy is evaluated in-process; violations are blocked before execution
result = session.execute("python -m pytest tests/test_reconciliation.py")

if result.allowed:
    print(f"Tool executed successfully: exit {result.exit_code}")
    print(result.output)
else:
    print(f"SECURITY BLOCK: {result.reason}")
    print(f"Suggested alternative: {result.suggestion}")

# 4. End session and sync telemetry
session.end()
```

---

## 3. Decorator-Based Governance

For function calling and tool pipelines in frameworks like **LangChain**, **CrewAI**, or **AutoGen**:

```python
from bap_sdk import governed_action

@governed_action(intent="DATABASE_CHANGE", resource="db://payments")
def migrate_database_schema(migration_file: str):
    """Executes database schema migration under Zero-Trust inspection."""
    import subprocess
    return subprocess.run(["alembic", "upgrade", "head"], capture_output=True, text=True)
```

---

## 4. Key Capabilities & Invariants

1. **Zero External Dependencies**: Pure Python standard library (`urllib`, `ssl`, `json`, `hashlib`, `subprocess`). No heavy frameworks or complex native dependencies.
2. **Automatic Offline Fallback**: If the central control plane is unreachable, the SDK falls back to the local `bapedge` broker and local cached Cedar policies without throwing exceptions or blocking execution.
3. **Intent Heuristics**: Automatically categorizes prompts into canonical enterprise taxonomy (`BUG_FIX`, `REFACTOR`, `INVESTIGATION`, `SECURITY_REMEDIATION`, `DATABASE_CHANGE`, etc.).
4. **Cryptographic Receipts**: Every call returns a signed receipt ID (`rcpt-...`) and request hash for audit tracking.
