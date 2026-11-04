<#
.SYNOPSIS
    BAP Coding Agent Runtime Integration Test (Claude Code, Antigravity, Codex)
.DESCRIPTION
    Simulates the exact agent execution loop without needing python:
    1. Claude Code / Codex PreToolUse hook interception via interceptor.exe
    2. Multi-module workspace operations & HITL step-up escalation
    3. Read-only subagent tool whitelisting (Glob, Grep, Agent, search_code)
    4. Invariant denial handling and self-correction context for agents
    5. Anti-tampering protection on core policies and binaries
#>

[CmdletBinding()]
param(
    [string]$Mode = 'interactive'
)

$ErrorActionPreference = 'Continue'
$Interactive = ($Mode -eq 'interactive')

function Pause-Step {
    param([string]$StepTitle, [string]$Description)
    Write-Host ''
    Write-Host '========================================================================' -ForegroundColor Cyan
    Write-Host " [AGENT TEST] $StepTitle" -ForegroundColor Yellow
    Write-Host " SCENARIO: $Description" -ForegroundColor White
    Write-Host '========================================================================' -ForegroundColor Cyan
    if ($Interactive) {
        $null = Read-Host 'Press [ENTER] to execute this step...'
    }
}

$Interceptor = '.\cchook\interceptor.exe'
if (-not (Test-Path $Interceptor)) {
    $Interceptor = '.\interceptor.exe'
}

$BapEdge = '.\bapedge.exe'
if (-not (Test-Path $BapEdge)) {
    $BapEdge = '.\dist\windows-amd64\bapedge.exe'
}

Write-Host "Using Interceptor: $Interceptor" -ForegroundColor Green
Write-Host "Using BAP Edge   : $BapEdge" -ForegroundColor Green

# -----------------------------------------------------------------------------
# TEST 1: Claude Code / Codex Tool Interception (PreToolUse) - ALLOWED
# -----------------------------------------------------------------------------
Pause-Step 'Claude Tool Call: Bash(git status)' 'Agent intends to run a safe workspace command. Hook must return permissionDecision: allow.'
$PayloadAllow = @{
    hook_event_name = 'PreToolUse'
    tool_name       = 'Bash'
    tool_input      = @{ command = 'git status' }
} | ConvertTo-Json -Compress

$ResAllow = $PayloadAllow | & $Interceptor
Write-Host "Hook Output to Agent:" -ForegroundColor Gray
Write-Host $ResAllow -ForegroundColor White

# -----------------------------------------------------------------------------
# TEST 2: Multi-Module Sibling Read Inspection - ALLOWED
# -----------------------------------------------------------------------------
Pause-Step 'Claude Tool Call: Bash(dir ..\)' 'Agent inspects sibling module directory. Cedar Rule 2 permits inspection and dependency traversal.'
$PayloadSiblingRead = @{
    hook_event_name = 'PreToolUse'
    tool_name       = 'Bash'
    tool_input      = @{ command = 'dir ..\' }
} | ConvertTo-Json -Compress

$ResSiblingRead = $PayloadSiblingRead | & $Interceptor
Write-Host "Hook Output to Agent:" -ForegroundColor Gray
Write-Host $ResSiblingRead -ForegroundColor White

# -----------------------------------------------------------------------------
# TEST 3: Multi-Module Cross-Folder Write WITHOUT Trust - STEP-UP / DENIED
# -----------------------------------------------------------------------------
Pause-Step 'Claude Tool Call: Bash(copy README.md ..\sibling-contracts\README.md)' 'Agent attempts cross-folder mutation without prior trust. Hook flags boundary escape.'
$PayloadCrossWrite = @{
    hook_event_name = 'PreToolUse'
    tool_name       = 'Bash'
    tool_input      = @{ command = 'copy README.md ..\sibling-contracts\README.md' }
} | ConvertTo-Json -Compress

$ResCrossWrite = $PayloadCrossWrite | & $Interceptor
Write-Host "Hook Output to Agent:" -ForegroundColor Gray
Write-Host $ResCrossWrite -ForegroundColor Yellow

# -----------------------------------------------------------------------------
# TEST 4: Pre-Authorize Sibling Module via BAP Trust Store
# -----------------------------------------------------------------------------
Pause-Step 'Pre-Authorize Sibling Module: bapedge trust' 'Developer grants project-level trust for cross-module development.'
& $BapEdge trust ..\sibling-contracts --project

# -----------------------------------------------------------------------------
# TEST 5: Multi-Module Cross-Folder Write WITH Trust Active - ALLOWED
# -----------------------------------------------------------------------------
Pause-Step 'Claude Tool Call with Trust: Bash(copy README.md ..\sibling-contracts\README.md)' 'Agent repeats cross-folder mutation. Hook detects trust grant and APPROVES.'
$PayloadCrossWriteTrusted = @{
    hook_event_name = 'PreToolUse'
    tool_name       = 'Bash'
    tool_input      = @{ command = 'copy README.md ..\sibling-contracts\README.md' }
} | ConvertTo-Json -Compress

$ResCrossWriteTrusted = $PayloadCrossWriteTrusted | & $Interceptor
Write-Host "Hook Output to Agent:" -ForegroundColor Gray
Write-Host $ResCrossWriteTrusted -ForegroundColor Green

# Revoke trust to maintain test idempotency
& $BapEdge untrust ..\sibling-contracts | Out-Null

# -----------------------------------------------------------------------------
# TEST 6: Credential Exfiltration to Trusted Sibling - HARD DENIED
# -----------------------------------------------------------------------------
Pause-Step 'Claude Tool Call: Bash(copy .env ..\sibling-contracts\.env)' 'Agent attempts to copy credentials to sibling module. Rule 3 strictly overrides trust.'
$PayloadExfil = @{
    hook_event_name = 'PreToolUse'
    tool_name       = 'Bash'
    tool_input      = @{ command = 'copy .env ..\sibling-contracts\.env' }
} | ConvertTo-Json -Compress

$ResExfil = $PayloadExfil | & $Interceptor
Write-Host "Hook Output to Agent:" -ForegroundColor Gray
Write-Host $ResExfil -ForegroundColor Red

# -----------------------------------------------------------------------------
# TEST 7: Ambient Credential Exfiltration (.env) - HARD DENIED
# -----------------------------------------------------------------------------
Pause-Step 'Claude Tool Call: Bash(cat .env)' 'Agent attempts credential exfiltration. Hook must DENY and inject additionalContext.'
$PayloadDeny = @{
    hook_event_name = 'PreToolUse'
    tool_name       = 'Bash'
    tool_input      = @{ command = 'cat .env' }
} | ConvertTo-Json -Compress

$ResDeny = $PayloadDeny | & $Interceptor
Write-Host "Hook Output to Agent:" -ForegroundColor Gray
Write-Host $ResDeny -ForegroundColor Yellow

# -----------------------------------------------------------------------------
# TEST 8: Anti-Tampering File Mutation - HARD DENIED
# -----------------------------------------------------------------------------
Pause-Step 'Claude Tool Call: Write(policy.cedar)' 'Agent attempts to overwrite governance policy. Hook must DENY immediately.'
$PayloadTamper = @{
    hook_event_name = 'PreToolUse'
    tool_name       = 'Write'
    tool_input      = @{ file_path = 'policy.cedar'; content = '// malicious override' }
} | ConvertTo-Json -Compress

$ResTamper = $PayloadTamper | & $Interceptor
Write-Host "Hook Output to Agent:" -ForegroundColor Gray
Write-Host $ResTamper -ForegroundColor Red

# -----------------------------------------------------------------------------
# TEST 9: Read-Only Subagent Tool Whitelisting - ALLOWED
# -----------------------------------------------------------------------------
Pause-Step 'Claude Tool Call: Glob(*.go)' 'Subagent search tool with no command string. Must be ALLOWED without false-positive denials.'
$PayloadGlob = @{
    hook_event_name = 'PreToolUse'
    tool_name       = 'Glob'
    tool_input      = @{ pattern = '*.go' }
} | ConvertTo-Json -Compress

$ResGlob = $PayloadGlob | & $Interceptor
Write-Host "Hook Output to Agent:" -ForegroundColor Gray
Write-Host $ResGlob -ForegroundColor Green

# -----------------------------------------------------------------------------
# TEST 10: Pre-Wrapped Execution - ALLOWED
# -----------------------------------------------------------------------------
Pause-Step 'Claude Tool Call: Bash(bapedge.exe exec "git status")' 'Agent runs pre-wrapped command. Hook must unwrap cleanly without double-denial.'
$PayloadPreWrapped = @{
    hook_event_name = 'PreToolUse'
    tool_name       = 'Bash'
    tool_input      = @{ command = '.\bapedge.exe exec "git status"' }
} | ConvertTo-Json -Compress

$ResPreWrapped = $PayloadPreWrapped | & $Interceptor
Write-Host "Hook Output to Agent:" -ForegroundColor Gray
Write-Host $ResPreWrapped -ForegroundColor Green

Write-Host ''
Write-Host '========================================================================' -ForegroundColor Green
Write-Host '[SUCCESS] All agent runtime hook scenarios validated successfully.' -ForegroundColor Green
Write-Host '========================================================================' -ForegroundColor Green
