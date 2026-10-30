# BAP Python SDK (`bap-sdk`)

Enterprise zero-dependency Python SDK for the **Bounded Authority Plane (BAP)**. Enables AI agents (LangChain, CrewAI, AutoGen, LlamaIndex, custom scripts) to execute OS tools and network actions with cryptographic zero-trust governance, SPIFFE identity binding, and sub-millisecond Cedar policy enforcement.

---

## Key Capabilities

1. **3 Lines of Code Integration**: Wrap any agent workflow in `with BAPSession(app_id="...") as bap:` context manager.
2. **Zero Dependencies**: Pure Python standard library (`urllib`, `subprocess`, `json`). No external pip dependencies, preventing dependency hell or supply chain vulnerabilities.
3. **Dual Identity Binding**: Bridges human developer identity (`apiKeyHelper` token or authenticated OS user) with workload SPIFFE ID (`spiffe://bap.internal/app/{app_id}/instance/{node_id}`).
4. **Sub-Millisecond Policy Enforcement**: Edge broker (`bapedge.exe`) enforces Cedar policies locally with zero network hops for permitted actions.
5. **Real-Time Fleet Observability**: Automatic heartbeat and session registration into the BAP Control Plane (`/api/v1/sessions/start`, `/api/v1/agents`), rendering live agent chips and active radar beacons on `inspector.html`.
6. **Automatic Threat Interception**: Blocks credential theft (`cat .env`), shell escapes, and unauthorized data exfiltration (`curl evilcorp.com`) *before* any OS process is spawned.

---

## Corporate Nexus / Artifactory Installation

To install `bap-sdk` from your organization's private Nexus or Artifactory PyPI repository:

```bash
# Using pip with corporate index URL
pip install bap-sdk --index-url https://nexus.internal.company.com/repository/pypi-internal/simple --trusted-host nexus.internal.company.com

# Or via ~/.pip/pip.conf (Linux/macOS) or %APPDATA%\pip\pip.ini (Windows)
[global]
index-url = https://nexus.internal.company.com/repository/pypi-internal/simple
trusted-host = nexus.internal.company.com
```

Then simply install:
```bash
# Standard universal package (includes CLI, binaries, and bap_sdk)
pip install bap-ltd

# Or standalone SDK package:
pip install bap-sdk
```

---

## Quickstart (3 Lines of Code)

```python
from bap_sdk import BAPSession, BAPPolicyViolation

with BAPSession(app_id="analytics-worker") as bap:
    # 1. Permitted developer action
    res = bap.exec("git status")
    print("Git branch:", res.stdout)

    # 2. Blocked attack scenario
    try:
        bap.exec("cat .env")
    except BAPPolicyViolation as e:
        print("Threat intercepted by BAP:", e)
```

---

## Framework Integrations

### 1. LangChain Custom Tool
```python
from langchain.tools import tool
from bap_sdk import BAPSession

bap = BAPSession(app_id="langchain-analyst").start()

@tool
def safe_git_status() -> str:
    """Safely checks repository git status governed by BAP."""
    result = bap.exec("git status")
    return result.stdout

@tool
def safe_read_file(filepath: str) -> str:
    """Reads a file with zero-trust BAP path verification."""
    result = bap.exec(f"cat {filepath}")
    return result.stdout
```

### 2. CrewAI Agent Task
```python
from crewai import Agent, Task
from bap_sdk import BAPSession

bap = BAPSession(app_id="crewai-coder").start()

coder = Agent(
    role="Software Engineer",
    goal="Run tests and report coverage",
    backstory="Autonomous agent with BAP zero-trust governance",
    tools=[bap.tool()(lambda cmd: bap.exec(cmd).stdout)]
)
```

---

## Building & Publishing to Corporate Nexus

To build the wheel and tarball for internal distribution:

```cmd
# 1. Build distribution package (.whl and .tar.gz)
build_package.bat

# 2. Publish to Enterprise Nexus using Twine
twine upload --repository-url https://nexus.internal.company.com/repository/pypi-internal/ dist/* --username <nexus-user> --password <nexus-token>
```

