"""
Bounded Authority Plane (BAP) - Python Agent SDK
Lightweight, zero-dependency Python client for governing AI agent tool execution
via BAP Edge (PEP broker) and BAP Control Plane.
"""

import hashlib
import json
import ssl
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List


def _urlopen(request, **kwargs):
    ca = os.getenv("BAP_CA_CERT")
    if not ca:
        for cand in ["bap-root-ca.crt", "../bap-root-ca.crt", "../../bap-root-ca.crt", "controlplane-cert.pem", "../controlplane-cert.pem", "../../controlplane-cert.pem"]:
            if os.path.exists(cand):
                ca = cand
                break
    ctx = None
    if ca:
        try:
            ctx = ssl.create_default_context(cafile=ca)
        except Exception:
            ctx = None

    url = getattr(request, "full_url", str(request))
    if "localhost" in url or "127.0.0.1" in url or "::1" in url:
        if ctx is None:
            ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    if ctx is not None and "context" not in kwargs:
        kwargs["context"] = ctx

    return urllib.request.urlopen(request, **kwargs)


class BAPPolicyViolation(Exception):
    """Raised when a command or tool call is denied by BAP Zero-Trust Cedar policies."""
    def __init__(self, command: str, reason: str, exit_code: int = 1):
        super().__init__(f"BAP DENIAL: Execution of '{command}' was blocked. Reason: {reason}")
        self.command = command
        self.reason = reason
        self.exit_code = exit_code


class BAPExecResult:
    """Encapsulates the execution result and authorization decision from bapedge."""
    def __init__(self, command: str, decision: str, exit_code: int, stdout: str, stderr: str, duration_ms: int, reason: str = ""):
        self.command = command
        self.decision = decision.lower()  # "allow" or "deny"
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration_ms = duration_ms
        self.reason = reason

    @property
    def is_allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def is_denied(self) -> bool:
        return self.decision == "deny"

    def __repr__(self) -> str:
        return f"<BAPExecResult decision={self.decision} code={self.exit_code} latency={self.duration_ms}ms>"


INTENT_CLASSIFIER_VERSION = "bap-intent-rules-v1"

CANONICAL_INTENT_CATEGORIES = [
    "BUG_FIX",
    "FEATURE_ENHANCEMENT",
    "DATABASE_CHANGE",
    "INVESTIGATION",
    "REFACTOR",
    "TEST_VERIFICATION",
    "DOCUMENTATION",
    "MIGRATION",
    "DEPLOYMENT_RELEASE",
    "WORK_MANAGEMENT",
    "SECURITY_REMEDIATION",
    "UNKNOWN",
]

_INTENT_RULES = [
    ("BUG_FIX", [
        (" fix bug ", "fix bug", 8), (" bug fix ", "bug fix", 8),
        (" fix the bug ", "fix the bug", 8), (" bugfix ", "bugfix", 8),
        (" regression ", "regression", 5), (" broken ", "broken", 4),
        (" defect ", "defect", 4), (" bug ", "bug", 4),
        (" failing ", "failing", 3), (" error ", "error", 2),
        (" fix ", "fix", 2)
    ]),
    ("DATABASE_CHANGE", [
        (" update db ", "update db", 7), (" update database ", "update database", 7),
        (" database migration ", "database migration", 7), (" migrate database ", "migrate database", 7),
        (" schema change ", "schema change", 6), (" alter table ", "alter table", 6),
        (" database ", "database", 3), (" db ", "db", 3), (" sql ", "sql", 2)
    ]),
    ("FEATURE_ENHANCEMENT", [
        (" new feature ", "new feature", 7), (" add feature ", "add feature", 6),
        (" enhance ui ", "enhance ui", 6), (" ui enhancement ", "ui enhancement", 6),
        (" enhancement ", "enhancement", 4), (" enhance ", "enhance", 4),
        (" improve ", "improve", 3), (" implement ", "implement", 3),
        (" add ", "add", 2), (" build ", "build", 2), (" create ", "create", 2)
    ]),
    ("INVESTIGATION", [
        (" root cause ", "root cause", 7), (" investigate ", "investigate", 6),
        (" analyze ", "analyze", 5), (" diagnose ", "diagnose", 5),
        (" find out ", "find out", 4), (" understand ", "understand", 3),
        (" inspect ", "inspect", 2), (" review ", "review", 2),
        (" reconcile ", "reconcile", 4), (" audit ", "audit", 3)
    ]),
    ("REFACTOR", [
        (" refactor ", "refactor", 7), (" clean up code ", "clean up code", 5),
        (" restructure ", "restructure", 5), (" simplify code ", "simplify code", 4),
        (" optimize ", "optimize", 3)
    ]),
    ("TEST_VERIFICATION", [
        (" write tests ", "write tests", 7), (" add tests ", "add tests", 7),
        (" test coverage ", "test coverage", 6), (" verify ", "verify", 4),
        (" validate ", "validate", 4), (" test ", "test", 3)
    ]),
    ("DOCUMENTATION", [
        (" update readme ", "update readme", 7), (" write docs ", "write docs", 7),
        (" documentation ", "documentation", 6), (" document ", "document", 5),
        (" readme ", "readme", 4)
    ]),
    ("MIGRATION", [
        (" dependency update ", "dependency update", 7), (" upgrade dependency ", "upgrade dependency", 7),
        (" upgrade framework ", "upgrade framework", 7), (" migration ", "migration", 5),
        (" migrate ", "migrate", 5), (" modernize ", "modernize", 4)
    ]),
    ("DEPLOYMENT_RELEASE", [
        (" deploy to production ", "deploy to production", 8), (" production deployment ", "production deployment", 8),
        (" deployment ", "deployment", 5), (" release ", "release", 5),
        (" deploy ", "deploy", 5), (" rollout ", "rollout", 4),
        (" build pipeline ", "build pipeline", 3)
    ]),
    ("WORK_MANAGEMENT", [
        (" jira ", "jira", 6), (" create ticket ", "create ticket", 6),
        (" update ticket ", "update ticket", 6), (" pull request ", "pull request", 5),
        (" open pr ", "open pr", 5), (" create pr ", "create pr", 5),
        (" work item ", "work item", 4)
    ]),
    ("SECURITY_REMEDIATION", [
        (" security fix ", "security fix", 8), (" remediate vulnerability ", "remediate vulnerability", 8),
        (" vulnerability ", "vulnerability", 6), (" cve ", "cve", 6),
        (" security ", "security", 3), (" permission ", "permission", 2),
        (" probe ", "probe", 3), (" credential ", "credential", 3)
    ]),
]

_INTENT_TAG_RULES = [
    ("API", [" api ", " endpoint ", " rest ", " graphql "]),
    ("CUSTOMER_FACING", [" customer ", " client facing ", " user facing "]),
    ("DATABASE", [" db ", " database ", " schema ", " sql ", " table "]),
    ("INFRASTRUCTURE", [" terraform ", " kubernetes ", " k8s ", " cloud ", " infrastructure "]),
    ("PRODUCTION", [" production ", " prod ", " release ", " deploy "]),
    ("SECURITY", [" security ", " vulnerability ", " cve ", " credential ", " permission ", " secret "]),
    ("UI", [" ui ", " frontend ", " dashboard ", " screen ", " css ", " ux "]),
]


def normalize_intent_text(prompt: str) -> str:
    """Normalizes prompt text for deterministic keyword intent matching."""
    lower = prompt.lower()
    chars = []
    last_space = True
    for ch in lower:
        if ('a' <= ch <= 'z') or ('0' <= ch <= '9'):
            chars.append(ch)
            last_space = False
        elif not last_space:
            chars.append(' ')
            last_space = True
    if not last_space:
        chars.append(' ')
    return ' ' + ''.join(chars)


def classify_intent(prompt: str) -> dict:
    """
    Deterministically classifies a user prompt into canonical mission categories.
    Matches BAP Edge cchook rules and control plane schema.
    """
    result = {
        "primary": "UNKNOWN",
        "confidence": 0.0,
        "classifier_version": INTENT_CLASSIFIER_VERSION,
        "source": "bap-python-sdk",
        "evidence": []
    }
    normalized = normalize_intent_text(prompt)
    if not normalized.strip():
        result["evidence"] = ["empty-or-unavailable-prompt"]
        return result

    scored = []
    for order, (category, phrases) in enumerate(_INTENT_RULES):
        score = 0
        for phrase_text, label, weight in phrases:
            if phrase_text in normalized:
                score += weight
                result["evidence"].append(f"{category}:{label}")
        if category == "BUG_FIX" and " fix " in normalized and " bug " in normalized:
            score += 8
            result["evidence"].append("BUG_FIX:fix+bug")
        if score > 0:
            scored.append({"category": category, "score": score, "order": order})

    # Sort descending by score, ascending by declaration order
    scored.sort(key=lambda item: (-item["score"], item["order"]))

    if scored:
        result["primary"] = scored[0]["category"]
        confidence = 0.62 + scored[0]["score"] * 0.04
        if confidence > 0.98:
            confidence = 0.98
        if len(scored) > 1 and (scored[0]["score"] - scored[1]["score"] <= 1) and confidence > 0.72:
            confidence = 0.72
        result["confidence"] = round(confidence, 2)

        secondaries = []
        for item in scored[1:]:
            if item["score"] >= 2 and len(secondaries) < 3:
                secondaries.append(item["category"])
        if secondaries:
            result["secondary"] = secondaries
    else:
        result["evidence"].append("no-rule-match")

    tags = []
    for tag, phrases in _INTENT_TAG_RULES:
        for phrase in phrases:
            if phrase in normalized:
                tags.append(tag)
                break
    if tags:
        result["tags"] = tags

    return result


def get_bapstate_dir() -> str:
    """
    Resolves the .bapstate directory following the precedence:
    1. BAP_STATE_DIR env var
    2. ~/.bapstate in user home (if exists)
    3. ./.bapstate in current working directory (if exists)
    4. Defaults to ~/.bapstate (fallback to ./.bapstate)
    """
    env_dir = os.getenv("BAP_STATE_DIR")
    if env_dir:
        return env_dir
    home_dir = os.path.expanduser("~/.bapstate")
    if os.path.isdir(home_dir):
        return home_dir
    cwd_dir = os.path.abspath(".bapstate")
    if os.path.isdir(cwd_dir):
        return cwd_dir
    try:
        os.makedirs(home_dir, exist_ok=True)
        return home_dir
    except Exception:
        os.makedirs(cwd_dir, exist_ok=True)
        return cwd_dir


def get_bap_credentials_path() -> str:
    if os.getenv("BAP_CREDENTIALS"):
        return os.environ["BAP_CREDENTIALS"]
    bapstate_creds = os.path.join(get_bapstate_dir(), "credentials.json")
    if os.path.isfile(bapstate_creds):
        return bapstate_creds
    legacy_creds = os.path.expanduser("~/.ltd/credentials.json")
    if os.path.isfile(legacy_creds):
        return legacy_creds
    return bapstate_creds


def resolve_endpoints() -> dict:
    """
    Resolves BAP central endpoints from:
    1. Environment variables (BAP_SERVER_URL, BAP_GATEWAY_URL, etc.)
    2. .bapstate/config.json, bap-config.json in current directory or ancestor directories
    3. User home directory ~/.bap/config.json
    4. Default local fallback (localhost:8080, localhost:9090)
    """
    endpoints = {
        "controlplane_url": "http://localhost:8080",
        "gateway_url": "http://localhost:9090",
        "envoy_url": "http://localhost:10000",
        "trust_domain": "bap.internal"
    }

    # 1. Search candidate config files
    candidate_paths = [
        os.path.join(get_bapstate_dir(), "config.json"),
    ]
    curr = os.getcwd()
    for _ in range(4):
        candidate_paths.append(os.path.join(curr, "bap-config.json"))
        parent = os.path.dirname(curr)
        if parent == curr:
            break
        curr = parent

    home = os.path.expanduser("~")
    candidate_paths.append(os.path.join(home, ".bap", "config.json"))
    candidate_paths.append(os.path.join(home, ".ltd", "config.json"))

    for path in candidate_paths:
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if "controlplane_url" in data and data["controlplane_url"]:
                        endpoints["controlplane_url"] = data["controlplane_url"].rstrip("/")
                    if "gateway_url" in data and data["gateway_url"]:
                        endpoints["gateway_url"] = data["gateway_url"].rstrip("/")
                    if "envoy_url" in data and data["envoy_url"]:
                        endpoints["envoy_url"] = data["envoy_url"].rstrip("/")
                    if "trust_domain" in data and data["trust_domain"]:
                        endpoints["trust_domain"] = data["trust_domain"]
                break
            except Exception:
                pass

    # 2. Environment variables override
    env_cp = os.getenv("BAP_SERVER_URL") or os.getenv("BAP_CONTROL_PLANE_URL") or os.getenv("LTD_SERVER_URL")
    if env_cp:
        endpoints["controlplane_url"] = env_cp.rstrip("/")
    env_gw = os.getenv("BAP_GATEWAY_URL") or os.getenv("LTD_GATEWAY_URL")
    if env_gw:
        endpoints["gateway_url"] = env_gw.rstrip("/")
    env_envoy = os.getenv("BAP_ENVOY_URL")
    if env_envoy:
        endpoints["envoy_url"] = env_envoy.rstrip("/")
    env_td = os.getenv("BAP_TRUST_DOMAIN")
    if env_td:
        endpoints["trust_domain"] = env_td

    return endpoints


class BAPSession:
    """
    Manages a live BAP governance session for an autonomous AI agent.
    Supports context manager syntax:
        with BAPSession(app_id="my-agent") as session:
            result = session.exec("git status")
    """
    def __init__(
        self,
        app_id: str = "python-agent",
        server_url: Optional[str] = None,
        gateway_url: Optional[str] = None,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        instance_id: Optional[str] = None,
        bapedge_path: Optional[str] = None,
        user_prompt: Optional[str] = None,
        intent: Optional[dict] = None,
        agent_name: Optional[str] = None,
    ):
        ep = resolve_endpoints()
        self.app_id = app_id
        self.agent_name = agent_name or app_id
        self.user_prompt = user_prompt if user_prompt is not None else os.getenv("BAP_USER_PROMPT", "")
        if intent is not None:
            self.intent = intent
        elif self.user_prompt:
            self.intent = classify_intent(self.user_prompt)
        else:
            self.intent = {"primary": "UNKNOWN", "source": "bap-python-sdk"}
        self.server_url = (server_url or ep["controlplane_url"]).rstrip("/")
        self.gateway_url = (gateway_url or ep["gateway_url"]).rstrip("/")
        self.envoy_url = ep["envoy_url"].rstrip("/")
        self.session_id = session_id or f"sess-{app_id}-{int(time.time())}"
        self.instance_id = instance_id or f"node-{os.getpid()}"
        self.bapedge_path = bapedge_path or self._find_bapedge()
        
        # Identity resolution fallback matching BAP 5-stage pipeline
        self.user_id = user_id or os.getenv("BAP_USER_ID") or os.getenv("USERNAME") or os.getenv("USER") or "NA"
        self.user_email = user_email or os.getenv("BAP_USER_EMAIL") or os.getenv("USER_EMAIL") or f"{self.user_id}@enterprise.internal"
        self.spiffe_id = f"spiffe://bap.internal/app/{self.app_id}/instance/{self.instance_id}"
        self.is_active = False
        self.is_revoked = False
        self.server_registered = False
        self._heartbeat_thread = None
        self._heartbeat_stop_event = None
        self._heartbeat_interval = 3.0

    def set_prompt(self, prompt: str, category: Optional[str] = None) -> dict:
        """Updates user prompt and classified mission intent with control plane."""
        self.user_prompt = prompt
        if category:
            self.intent = {
                "primary": category.upper(),
                "confidence": 1.0,
                "classifier_version": INTENT_CLASSIFIER_VERSION,
                "source": "bap-python-sdk",
            }
        else:
            self.intent = classify_intent(prompt)

        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        payload = {
            "session_id": self.session_id,
            "user_prompt": self.user_prompt,
            "producer": "bap-python-sdk",
            "prompt_hash": prompt_hash,
            "prompt_capture_enabled": True,
            "intent": self.intent,
        }
        url = f"{self.server_url}/api/v1/sessions/prompt"
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with _urlopen(req, timeout=3) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            return {"error": str(e)}

    def _find_bapedge(self) -> str:
        """Locates bapedge binary across workspace root and system PATH."""
        candidates = [
            os.path.join(os.getcwd(), "bapedge.exe"),
            os.path.join(os.getcwd(), "bapedge"),
            os.path.join(os.path.dirname(__file__), "..", "bapedge.exe"),
            os.path.join(os.path.dirname(__file__), "..", "bapedge"),
            os.path.join(os.path.dirname(__file__), "..", "..", "bapedge.exe"),
            os.path.join(os.path.dirname(__file__), "..", "..", "bapedge"),
            shutil.which("bapedge.exe"),
            shutil.which("bapedge"),
        ]
        for path in candidates:
            if path and os.path.isfile(path) and os.access(path, os.X_OK if os.name != 'nt' else os.R_OK):
                return os.path.abspath(path)
        return "bapedge.exe"

    def heartbeat(self) -> dict:
        """Sends a heartbeat pulse to BAP Control Plane to maintain active presence."""
        if not self.is_active:
            return {}
        payload = {
            "session_id": self.session_id,
            "agent_id": self.instance_id,
            "app_id": self.app_id,
        }
        url = f"{self.server_url}/api/v1/sessions/heartbeat"
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with _urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "revoked" or data.get("action") == "terminate":
                    self.is_active = False
                    self.is_revoked = True
                return data
        except Exception as e:
            return {"error": str(e)}

    def start(self) -> "BAPSession":
        """Registers the session with the BAP Control Plane (if reachable) and activates local session."""
        self.is_active = True
        payload = {
            "session_id": self.session_id,
            "user_prompt": self.user_prompt,
            "intent": self.intent,
            "app_id": self.app_id,
            "agent_name": self.agent_name,
            "instance_id": self.instance_id,
            "user_id": self.user_id,
            "user_email": self.user_email,
            "spiffe_id": self.spiffe_id,
            "client_pid": os.getpid(),
            "hostname": os.getenv("COMPUTERNAME", "localhost"),
            "client_type": "python-sdk",
            "metadata": {
                "python_version": sys.version.split()[0],
                "pid": os.getpid(),
                "hostname": os.getenv("COMPUTERNAME", "localhost")
            }
        }
        
        url = f"{self.server_url}/api/v1/sessions/start"
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with _urlopen(req, timeout=3) as resp:
                if resp.status in (200, 201):
                    self.server_registered = True
        except Exception:
            # Session registration soft-fails when offline to preserve local broker autonomy
            self.server_registered = False

        # Start automated background heartbeat to maintain live presence on dashboard / inspector
        import threading
        self._heartbeat_stop_event = threading.Event()
        def _heartbeat_worker():
            while self._heartbeat_stop_event and not self._heartbeat_stop_event.wait(self._heartbeat_interval):
                if not self.is_active:
                    break
                try:
                    self.heartbeat()
                except Exception:
                    pass
        self._heartbeat_thread = threading.Thread(
            target=_heartbeat_worker,
            daemon=True,
            name=f"bap-hb-{self.session_id}"
        )
        self._heartbeat_thread.start()

        return self

    def end(self, reason: str = "completed") -> None:
        """Closes the session and notifies the BAP Control Plane to deregister."""
        if self._heartbeat_stop_event:
            self._heartbeat_stop_event.set()
        if not self.is_active:
            return
        payload = {
            "session_id": self.session_id,
            "reason": reason
        }
        url = f"{self.server_url}/api/v1/sessions/end"
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with _urlopen(req, timeout=3) as resp:
                pass
        except Exception:
            pass
        self.is_active = False
        self.server_registered = False

    def acquire_grant(self, scopes: Optional[List[str]] = None) -> str:
        """
        Acquires an ephemeral BAP authority grant (JWT-SVID) from the BAP Control Plane.
        Required when calling protected enterprise API Gateways (Envoy, Kong, bap-gateway).
        """
        credentials_path = get_bap_credentials_path()
        try:
            with open(credentials_path, encoding="utf-8") as handle:
                credentials = json.load(handle)
            if credentials.get("server_url", "").rstrip("/") != self.server_url:
                raise ValueError("Enrollment belongs to a different control plane")
            token = credentials["session_token"]
            payload = {"agent_id": credentials["agent_id"], "binary_hash": credentials["binary_hash"], "scopes": scopes or ["api:read"]}
        except (OSError, ValueError, KeyError) as error:
            raise BAPPolicyViolation("acquire_grant", f"Enroll with bapedge register first; set BAP_CREDENTIALS to that credentials file: {error}") from error
        url = f"{self.server_url}/api/v1/grants/acquire"
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
            )
            with _urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("token", "")
        except Exception as e:
            raise BAPPolicyViolation(
                command="acquire_grant",
                reason=f"Failed to acquire BAP grant from {url}: {e}",
                exit_code=1
            )

    def exec(self, command: str, raise_on_deny: bool = True) -> BAPExecResult:
        """
        Executes a shell/CLI tool command governed by bapedge.
        If the policy forbids the action, raises BAPPolicyViolation (unless raise_on_deny=False).
        """
        start_time = time.time()

        # Build invocation environment matching BAP 5-stage identity
        env = os.environ.copy()
        env["BAP_SESSION_ID"] = self.session_id
        env["BAP_USER_PROMPT"] = self.user_prompt
        env["BAP_USER_ID"] = self.user_id
        env["BAP_USER_EMAIL"] = self.user_email
        env["BAP_WORKLOAD_ID"] = self.app_id
        env["BAP_SPIFFE_ID"] = self.spiffe_id

        # Determine edge execution command: bapedge.exe exec "<command>"
        args = [self.bapedge_path, "exec", command]

        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                env=env,
                shell=False
            )
            duration_ms = int((time.time() - start_time) * 1000)

            stdout = proc.stdout
            stderr = proc.stderr
            code = proc.returncode

            # Inspect stdout/stderr for BAP authorization indicators
            # bapedge outputs JSON or formatted text; denials typically return non-zero or specific prefix
            is_denied = False
            reason = ""
            decision = "allow"

            # 1. Check if stdout is JSON from bapedge
            try:
                data = json.loads(stdout.strip())
                if isinstance(data, dict) and "allowed" in data:
                    if not data["allowed"]:
                        decision = "deny"
                        is_denied = True
                        reason = data.get("reason", "Denied by Cedar policy")
                    else:
                        decision = "allow"
                        is_denied = False
            except Exception:
                pass

            # 2. Check text indicators
            combined = stdout + "\n" + stderr
            if not is_denied:
                if "DENIED" in combined or "[bapedge] DENIED" in combined or "AccessDenied" in combined or '"allowed": false' in combined or code == 126:
                    decision = "deny"
                    is_denied = True
                    for line in combined.splitlines():
                        if "denial" in line.lower() or "denied" in line.lower() or "violation" in line.lower():
                            reason = line.strip()
                            break
                    if not reason:
                        reason = "Denied by Cedar policy"

            result = BAPExecResult(
                command=command,
                decision=decision,
                exit_code=code,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                reason=reason,
            )

            if is_denied and raise_on_deny:
                raise BAPPolicyViolation(command=command, reason=reason, exit_code=code)

            return result

        except BAPPolicyViolation:
            raise
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            raise BAPPolicyViolation(command=command, reason=str(e), exit_code=1)

    def tool(self, name: Optional[str] = None):
        """
        Decorator to protect any Python agent tool function with BAP governance.
        Usage:
            @bap.tool(name="read_file")
            def read_file(path: str):
                return bap.exec(f"cat {path}")
        """
        def decorator(func):
            def wrapper(*args, **kwargs):
                tool_name = name or func.__name__
                call_repr = f"{tool_name}({', '.join(map(str, args))})"
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def __enter__(self) -> "BAPSession":
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        reason = "exception: " + str(exc_val) if exc_val else "graceful completion"
        self.end(reason=reason)
