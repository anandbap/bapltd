// BAP Zero-Trust Security Plugin for OpenCode (BAP-807)
const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

module.exports = async function bapPlugin(context) {
  const isWindows = process.platform === 'win32';
  const adapterName = isWindows ? 'bap-hook-adapter.cmd' : 'bap-hook-adapter';
  const adapterPath = path.join(__dirname, 'scripts', adapterName);

  // Auto-initiate SessionStart when OpenCode loads the plugin
  try {
    const sessionId = process.env.BAP_SESSION_ID || `sess-opencode-${process.pid}`;
    const startPayload = JSON.stringify({
      session_id: sessionId,
      client_pid: process.pid,
      app_id: 'opencode'
    });
    spawnSync(adapterPath, ['--client', 'opencode', '--event', 'SessionStart'], {
      input: startPayload,
      encoding: 'utf8',
      shell: isWindows
    });
  } catch (e) {
    // Non-blocking fallback
  }

  return {
    tool: {
      execute: {
        before: async (input, output) => {
          const toolName = input?.tool || input?.name || '';
          const args = output?.args || input?.args || {};
          const command = args?.command || args?.CommandLine || args?.cmd || '';
          const filePath = args?.path || args?.file || args?.filePath || '';

          // Intercept shell and file commands
          const payload = JSON.stringify({
            tool_name: toolName,
            command: command,
            file_path: filePath,
            tool_input: args,
            session_id: process.env.BAP_SESSION_ID || `sess-opencode-${process.pid}`
          });

          const proc = spawnSync(adapterPath, ['--client', 'opencode', '--event', 'PreToolUse'], {
            input: payload,
            encoding: 'utf8',
            shell: isWindows
          });

          if (proc.stdout) {
            try {
              const res = JSON.parse(proc.stdout.trim());
              if (res.allowed === false || res.decision === 'deny') {
                const reason = res.reason || 'Blocked by BAP enterprise zero-trust policy';
                throw new Error(`[BAP POLICY ENFORCEMENT] ${reason}`);
              }
            } catch (err) {
              if (err.message && err.message.includes('[BAP POLICY ENFORCEMENT]')) {
                throw err;
              }
            }
          }
        },
        after: async (input, output) => {
          const payload = JSON.stringify({
            tool_name: input?.tool || input?.name || '',
            tool_input: output?.args || input?.args || {},
            session_id: process.env.BAP_SESSION_ID || `sess-opencode-${process.pid}`
          });

          spawnSync(adapterPath, ['--client', 'opencode', '--event', 'PostToolUse'], {
            input: payload,
            encoding: 'utf8',
            shell: isWindows
          });
        }
      }
    }
  };
};
