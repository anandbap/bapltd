// Cedar Authorization Policy for ltd-agent
// Principal: Agent::"Local"
// Action:    Action::"Execute"
// Resource:  Command::"CLI"
// Context:   { executable: String, full_command: String }

// 1. Permit Policy:
// Allows Action::"Execute" for standard developer toolchains, initialization, and build commands:
permit (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    [
        "pytest", "python", "python3", "py", "pip", "pip3",
        "go", "npm", "npx", "yarn", "pnpm", "node",
        "mvn", "gradle", "cargo", "git",
        "java", "javac",
        "ls", "dir", "mkdir", "echo", "pwd", "cat", "type", "printenv", "whoami",
        "cd", "chdir", "pushd", "popd", "exit",
        "cmd", "powershell", "pwsh", "bash", "sh", "zsh",
        "grep", "findstr", "head", "tail", "wc", "sort", "uniq", "more",
        "taskkill", "kill", "pkill", "killall"
    ].contains(context.executable)
};

// 2. Forbid Policy: Directory Traversal Outside Workspace Boundary
// Strictly blocks any execution that attempts to navigate or access files outside the workspace root.
forbid (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    context.escapes_workspace == true
};

// 3. Forbid Policy: Sensitive Operations & Exfiltration
// Strict forbid overriding permit for:
// - Exfiltration utilities: curl, wget, nc, ssh, socat, PowerShell web cmdlets
// - Sensitive credential directories: ~/.aws, .ssh
// - Any tampering, copying, renaming, or dumping of .env credential files
forbid (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    context.full_command like "*curl*" ||
    context.full_command like "*wget*" ||
    context.full_command like "nc *" ||
    context.full_command like "* nc *" ||
    context.full_command like "*|nc*" ||
    context.full_command like "*&nc*" ||
    context.full_command like "*;nc*" ||
    context.full_command like "nc" ||
    context.full_command like "*netcat*" ||
    context.full_command like "*ncat*" ||
    context.full_command like "ssh *" ||
    context.full_command like "* ssh *" ||
    context.full_command like "*|ssh*" ||
    context.full_command like "*&ssh*" ||
    context.full_command like "*;ssh*" ||
    context.full_command like "*socat*" ||
    (
        context.full_command like "*invoke-webrequest*" &&
        !(context.full_command like "*localhost:11434*" || context.full_command like "*127.0.0.1:11434*")
    ) ||
    (
        context.full_command like "*invoke-restmethod*" &&
        !(context.full_command like "*localhost:11434*" || context.full_command like "*127.0.0.1:11434*")
    ) ||
    context.full_command like "*iwr *" ||
    context.full_command like "*irm *" ||
    context.full_command like "*downloadstring*" ||
    context.full_command like "*downloadfile*" ||
    context.full_command like "*certutil*" ||
    context.full_command like "*bitsadmin*" ||
    context.full_command like "*system.net.sockets*" ||
    context.full_command like "*tcpclient*" ||
    context.full_command like "*udpclient*" ||
    context.full_command like "*socket.socket*" ||
    context.full_command like "*urllib.request*" ||
    context.full_command like "*requests.get*" ||
    context.full_command like "*requests.post*" ||
    context.full_command like "*http.client*" ||
    context.full_command like "*169.254.169.254*" ||
    context.full_command like "*-encodedcommand*" ||
    context.full_command like "*-enc *" ||
    context.full_command like "*-encoded *" ||
    context.full_command like "*comsvcs*" ||
    context.full_command like "*minidump*" ||
    context.full_command like "*sekurlsa*" ||
    context.full_command like "*set-mppreference*" ||
    context.full_command like "*disablerealtimemonitoring*" ||
    context.full_command like "*set-service*disabled*" ||
    context.full_command like "*remove-item* -recurse*" ||
    context.full_command like "*remove-item*-recurse*" ||
    context.full_command like "*rmdir /s*" ||
    context.full_command like "*rd /s*" ||
    context.full_command like "*~/.aws*" ||
    context.full_command like "*.ssh*" ||
    (
        context.full_command like "*.env*" &&
        (
            !(context.executable == "ls" || context.executable == "dir") ||
            context.full_command like "*cat*" ||
            context.full_command like "*type*" ||
            context.full_command like "*more*" ||
            context.full_command like "*head*" ||
            context.full_command like "*tail*" ||
            context.full_command like "*grep*" ||
            context.full_command like "*findstr*" ||
            context.full_command like "*ren*" ||
            context.full_command like "*move*" ||
            context.full_command like "*mv*" ||
            context.full_command like "*cp*" ||
            context.full_command like "*copy*" ||
            context.full_command like "*>*" ||
            context.full_command like "*|*"
        )
    ) ||
    // Anti-Tampering: Prevent agent from killing or deleting BAP governance processes/binaries
    (
        (context.full_command like "*bapedge*" || context.full_command like "*bapcontrolplane*" || context.full_command like "*bapgateway*" || context.full_command like "*cchook*" || context.full_command like "*copilot-interceptor*") &&
        (context.full_command like "*kill*" || context.full_command like "*stop-process*" || context.full_command like "*remove-item*" || context.full_command like "*taskkill*" || context.full_command like "*pkill*" || context.full_command like "*del *" || context.full_command like "*rm *")
    )
};


