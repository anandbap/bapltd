# Per-user startup and onboarding diagnostics

Implemented P1a: daemon crash supervision, Windows current-user logon registration, readiness checks and local callback diagnostics. This does not complete the 20-person pilot's SSO, roster or native-client acceptance gates.

## Runtime

- `bap install` registers `BAPEdgeSupervisor` under the current user's Windows Run key. The command contains the installed binary and state directory, never enrollment tokens or a second reporting destination. Master enrollment/configuration still selects the control plane. `--no-startup` removes only this installation's owned registration. Uninstall removes that owned entry and gracefully stops its supervisor/daemon; it does not kill unrelated BAP processes by name.
- `bapedge daemon supervise` starts the detached per-user supervisor. `daemon supervise --stop` stops supervision without killing the daemon. `daemon start` explicitly resumes reporting. `daemon stop` records a persistent intentional pause, so the supervisor does not immediately undo it. A logon launch respects that pause until explicit start/login/reinstallation.
- The supervisor checks every two seconds, with launch-failure backoff up to 30 seconds. A crashed daemon restarts; a live but unresponsive process is reported for inspection rather than forcibly killed. Windows mutex/Unix file locks prevent duplicate runtimes. Process-birth checks reject reused PIDs. Readiness requires the expected local process to answer its loopback health endpoint, not simply successful process creation.
- Startup is after user logon, not while logged out, and is not a machine-wide Windows service. Linux/macOS automatic startup is not registered by this implementation. Simultaneous interactive sessions and supervisor-process crash recovery by an external service remain unqualified.

## Inspect

Run `bapedge daemon status --json` and `bap doctor` using the matching installed build. Diagnostics expose:

- Supervisor state, restart attempts, last check and intentional pause; startup registration metadata.
- Daemon version/commit/process birth, last authenticated heartbeat result/time, and successful audit upload/attempt times.
- Pending audit count and oldest queued-event age when known; retained recovery history remains separate.
- Claude SessionStart, UserPromptSubmit, PreToolUse, PostToolUse and Stop callbacks as observed, stale (over 15 minutes), or not observed. Metadata markers contain no prompt, tool input/result, session identifier or credential.

A local enrollment record is not proof that the server accepted it. A public health response is not an authenticated heartbeat. Installed hooks do not prove approval or callback execution. Callback metadata is locally reported evidence, not attestation or proof of complete capture/enforcement. Diagnostics deliberately remain partial until the operator validates the native workflow and central reporting. Missing callbacks do not identify the cause as refused approval.

## Acceptance

Automated tests use private profiles and a mocked startup registry. A real matched Windows binary was tested for duplicate-supervisor prevention, daemon termination/restart, intentional pause/resume and logon-command state-directory handling. No startup registration was applied to the development laptop. Go edge/hook suites, installer regressions, metadata privacy and doctor diagnostic fixtures pass.

On a disposable Windows test user/VM, still qualify actual logoff/logon/reboot startup, upgrade/uninstall, supported Claude callbacks with approval/refusal, corporate IdP verification, build provenance, central roster/expected reporting windows, and offline/redeploy recovery. Keep P1b open until that evidence exists. Deployment requires matching edge, interceptor and packaged installer/doctor modules; copying only server code is insufficient.
