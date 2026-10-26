# BAP Zero-Trust PowerShell Auto-Binding Profile
# ===============================================
# Automatically binds autonomous coding agent sessions (Codex, Claude Code, Antigravity, Copilot)
# to the BAP Zero-Trust Local Trusted Daemon (LTD) and Central Control Plane.
# Ensures full zero-trust governance, audit logging, and clean Ctrl+C teardown.

function Invoke-BapGovernedCli {
    param(
        [Parameter(Mandatory = $true)][string]$AgentId,
        [Parameter(Mandatory = $true)][string]$BinaryName,
        [string[]]$CandidatePaths = @(),
        [string[]]$CliArgs = @()
    )

    # 1. Resolve target binary
    $targetBin = $null
    foreach ($p in $CandidatePaths) {
        if (-not [string]::IsNullOrWhiteSpace($p) -and (Test-Path -LiteralPath $p)) {
            $targetBin = $p
            break
        }
    }
    if ([string]::IsNullOrWhiteSpace($targetBin)) {
        $appCmd = Get-Command -Name $BinaryName -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $appCmd) {
            $targetBin = $appCmd.Source
        }
    }

    if ([string]::IsNullOrWhiteSpace($targetBin)) {
        Write-Error "BAP Auto-Binding: Unable to locate '$BinaryName' for agent '$AgentId'. Please verify it is installed."
        return
    }

    # 2. Resolve bapedge binary
    $bapEdgeBin = $null
    $edgeCandidates = @(
        "$env:USERPROFILE\.bap\bin\bapedge.exe",
        "$env:ProgramFiles\BAP\bin\bapedge.exe",
        "bapedge.exe"
    )
    foreach ($ec in $edgeCandidates) {
        if (Test-Path -LiteralPath $ec) {
            $bapEdgeBin = $ec
            break
        }
    }
    if ([string]::IsNullOrWhiteSpace($bapEdgeBin)) {
        $edgeCmd = Get-Command -Name "bapedge.exe" -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $edgeCmd) {
            $bapEdgeBin = $edgeCmd.Source
        }
    }

    # 3. Establish Governed Session Context
    $sessionId = "sess-$AgentId-cli-$((New-Guid).ToString('N').Substring(0,8))"
    $origSource = $env:LTD_SOURCE
    $origSession = $env:BAP_SESSION_ID

    $env:LTD_SOURCE = $AgentId
    $env:BAP_SESSION_ID = $sessionId

    # 4. Notify Control Plane of Session Start
    if (-not [string]::IsNullOrWhiteSpace($bapEdgeBin)) {
        try {
            & $bapEdgeBin session-start --session-id $sessionId --app-id $AgentId 2>$null | Out-Null
        } catch { }
    }

    # 5. Handle Ctrl+C so child process exits but PowerShell unwinds through finally
    $cancelHandler = $null
    try {
        $cancelHandler = [ConsoleCancelEventHandler]{
            param($sender, $eventArgs)
            $eventArgs.Cancel = $true
        }
        [Console]::add_CancelKeyPress($cancelHandler)
    } catch { }

    try {
        & $targetBin @CliArgs
    }
    finally {
        # 6. Unhook Ctrl+C handler
        if ($null -ne $cancelHandler) {
            try { [Console]::remove_CancelKeyPress($cancelHandler) } catch { }
        }

        # 7. Notify Control Plane of Session End
        if (-not [string]::IsNullOrWhiteSpace($bapEdgeBin)) {
            try {
                & $bapEdgeBin session-end --session-id $sessionId 2>$null | Out-Null
            } catch { }
        }

        # 8. Restore ambient environment
        if ($null -ne $origSource) { $env:LTD_SOURCE = $origSource } else { Remove-Item env:LTD_SOURCE -ErrorAction SilentlyContinue }
        if ($null -ne $origSession) { $env:BAP_SESSION_ID = $origSession } else { Remove-Item env:BAP_SESSION_ID -ErrorAction SilentlyContinue }
    }
}

function codex {
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\OpenAI\Codex\bin\codex.exe",
        "$env:LOCALAPPDATA\Programs\codex\codex.exe",
        "$env:APPDATA\npm\codex.cmd",
        "$env:USERPROFILE\.cargo\bin\codex.exe"
    )
    Invoke-BapGovernedCli -AgentId "codex" -BinaryName "codex.exe" -CandidatePaths $candidates -CliArgs $args
}

function claude {
    $candidates = @(
        "$env:USERPROFILE\.local\bin\claude.exe",
        "$env:APPDATA\npm\claude.cmd"
    )
    Invoke-BapGovernedCli -AgentId "claude-code" -BinaryName "claude.exe" -CandidatePaths $candidates -CliArgs $args
}

function claude-code {
    claude @args
}

function agy {
    $candidates = @(
        "$env:LOCALAPPDATA\agy\bin\agy.exe",
        "$env:APPDATA\Antigravity\bin\agy-node.cmd"
    )
    Invoke-BapGovernedCli -AgentId "antigravity" -BinaryName "agy.exe" -CandidatePaths $candidates -CliArgs $args
}

function antigravity {
    agy @args
}

function copilot {
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages\GitHub.Copilot_Microsoft.Winget.Source_8wekyb3d8bbwe\copilot.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\copilot\copilot.exe")
    )
    Invoke-BapGovernedCli -AgentId "copilot" -BinaryName "copilot.exe" -CandidatePaths $candidates -CliArgs $args
}
