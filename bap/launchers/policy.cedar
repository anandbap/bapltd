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
        "sed", "awk", "cut", "tr", "diff", "patch", "tee", "touch",
        "cp", "mv", "copy", "move", "rm", "del", "rmdir", "erase",
        "find", "which", "where", "less",
        "clear", "cls", "true", "false", "test", "date", "uname", "hostname", "env",
        "tar", "zip", "unzip", "gzip", "gunzip",
        "select-object", "where-object", "select-string", "sls", "sort-object", "measure-object", "get-content", "get-childitem", "gci", "out-string",
        "test-path", "copy-item", "cpi", "move-item", "mi", "remove-item", "ri", "new-item", "ni", "set-content", "sc", "add-content", "ac", "out-file", "write-output", "write-host", "format-table", "ft", "format-list", "fl",
        "taskkill", "kill", "pkill", "killall",
        "bapedge", "ltd-agent", "bapcontrolplane", "bapgateway", "bapmcp", "bap", "bapdashboard"
    ].contains(context.executable)
};

// 2. Forbid Policy: Mutating or Destructive Actions Outside Workspace Boundary
// Allows read-only inspection and cross-project dependency traversal across sibling repositories.
// Strictly blocks file modification, deletion, or output redirection escaping the workspace root.
forbid (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    context.escapes_workspace == true &&
    (context.action_type == "write" || context.action_type == "delete" || context.action_type == "tamper")
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
        (context.full_command like "* kill *" || context.full_command like "*kill -*" || context.full_command like "*killall*" || context.full_command like "*stop-process*" || context.full_command like "*remove-item*" || context.full_command like "*taskkill*" || context.full_command like "*pkill*" || context.full_command like "*del *" || context.full_command like "*rm *")
    )
};

// 4. Identity-Aware Egress Policy (BAP-530 PromptArmor Multi-Tenant Exfiltration Defense)
// Permits outbound HTTP:Post when destination resource tenant matches approved enterprise identifiers.
permit (
    principal,
    action == Action::"HTTP:Post",
    resource
) when {
    ["corp-org", "corp-internal"].contains(resource.tenant_id)
};

// 5. Forbid Policy: Unapproved Software Installation & Foreign Binary Execution
// Prevents agents from running unapproved software installers, MSI packages, or setup executables.
forbid (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    context.executable == "msiexec" ||
    context.full_command like "*.msi*" ||
    context.full_command like "*setup.exe*" ||
    context.full_command like "*install.exe*" ||
    context.full_command like "*winget*install*" ||
    context.full_command like "*choco*install*" ||
    context.full_command like "*scoop*install*"
};

// 6. Forbid Policy: Public Repository Bypass (Enforce Corporate Nexus / Artifactory Mirror)
// Blocks package managers attempting to download directly from unapproved public internet registries
// instead of the corporate internal Nexus / Artifactory mirror.
forbid (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    (
        (context.executable == "mvn" || context.executable == "gradle") &&
        (
            context.full_command like "*repo.maven.apache.org*" ||
            context.full_command like "*repo1.maven.org*" ||
            context.full_command like "*repo.spring.io*" ||
            context.full_command like "*-dremoterepositories=http*"
        )
    ) ||
    (
        (context.executable == "pip" || context.executable == "pip3") &&
        (
            context.full_command like "*--index-url*http://pypi.org*" ||
            context.full_command like "*--extra-index-url*http://*" ||
            context.full_command like "*--extra-index-url*https://*"
        )
    ) ||
    (
        (context.executable == "npm" || context.executable == "yarn" || context.executable == "pnpm") &&
        (
            context.full_command like "*--registry*registry.npmjs.org*" ||
            context.full_command like "*--registry*registry.yarnpkg.com*"
        )
    )
};

// 7. Forbid Policy: Honeytoken / Canary Secret Tripwire (BAP-546 Prompt Injection Containment)
// Prohibits reading, querying, or exfiltrating synthetic corporate canary tokens.
// Any attempt to access canary tokens trips an immediate zero-trust containment violation.
forbid (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    context.full_command like "*corp_canary_token*" ||
    context.full_command like "*canary-trap-*" ||
    context.full_command like "*bap-canary-*"
};



