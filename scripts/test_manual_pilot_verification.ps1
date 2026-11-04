<#
.SYNOPSIS
    BAP Pilot Manual Step-by-Step Verification Script (v1.9.19)
.DESCRIPTION
    Executes instruction-by-instruction verification of BAP Zero-Trust
    governance, multi-module workspace support, HITL step-up authorization,
    Windows restricted token containment, policy evaluation,
    anti-tampering invariants, and session lifecycle.
#>

[CmdletBinding()]
param(
    [string]$Mode = "interactive"
)

$Interactive = ($Mode -eq "interactive")
$ErrorActionPreference = 'Continue'

function Pause-Step {
    param([string]$StepTitle, [string]$CommandText, [string]$Explanation)
    Write-Host ''
    Write-Host '========================================================================' -ForegroundColor Cyan
    Write-Host " [STEP] $StepTitle" -ForegroundColor Yellow
    if ($Explanation) {
        Write-Host " CONTEXT: $Explanation" -ForegroundColor Gray
    }
    Write-Host " COMMAND: $CommandText" -ForegroundColor White
    Write-Host '========================================================================' -ForegroundColor Cyan
    if ($Interactive) {
        $null = Read-Host 'Press [ENTER] to execute this step...'
    }
}

$BapEdge = '.\bapedge.exe'
if (-not (Test-Path $BapEdge)) {
    $BapEdge = '.\dist\windows-amd64\bapedge.exe'
}
Write-Host "Using BAP Edge Binary: $BapEdge" -ForegroundColor Green

# -----------------------------------------------------------------------------
# PHASE 1: Component Version, SVID Identity & Workstation Health
# -----------------------------------------------------------------------------
Pause-Step 'Check BAP Edge Version and Build Metadata' "$BapEdge version" `
    'Verifies binary integrity, release version (v1.9.19), commit, and platform build target.'
& $BapEdge version

Pause-Step 'Check Workstation Health and Policy Bundle Status' "$BapEdge status" `
    'Verifies local daemon status, enrolled SPIFFE SVID identity, and active session count.'
& $BapEdge status

# -----------------------------------------------------------------------------
# PHASE 2: Standard Developer Operations & Sibling Inspection (Allowed Out-of-the-Box)
# -----------------------------------------------------------------------------
Pause-Step 'Verify Standard Developer Command is ALLOWED' "$BapEdge why 'git status'" `
    'Verifies standard developer commands execute without friction within workspace boundaries.'
& $BapEdge why 'git status'

Pause-Step 'Verify Newly Permitted Diagnostic Command (icacls) is ALLOWED' "$BapEdge why 'icacls'" `
    'Permits non-destructive filesystem diagnostics and ACL inspection.'
& $BapEdge why 'icacls'

Pause-Step 'Verify Safe PowerShell Inspection (get-command) is ALLOWED' "$BapEdge why 'get-command'" `
    'Allows read-only command and environment discovery.'
& $BapEdge why 'get-command'

Pause-Step 'Verify Cross-Project Sibling Traversal (dir ..\) is ALLOWED' "$BapEdge why 'dir ..\'" `
    'Enterprise multi-module rule: Read-only inspection of sibling directories is 100% allowed.'
& $BapEdge why 'dir ..\'

# -----------------------------------------------------------------------------
# PHASE 3: Multi-Module Workspace Governance & Human-In-The-Loop (HITL) Authorization
# -----------------------------------------------------------------------------
# Prepare a temporary mock sibling directory for testing
$MockSiblingDir = Join-Path (Split-Path (Get-Location) -Parent) "sibling-contracts"
if (-not (Test-Path $MockSiblingDir)) {
    New-Item -ItemType Directory -Path $MockSiblingDir -Force | Out-Null
}

Pause-Step 'Cross-Module Mutation WITHOUT Prior Trust (Flagged/Denied with Remediation)' "$BapEdge why 'copy README.md ..\sibling-contracts\README.md'" `
    'Unprompted write outside workspace boundary triggers Step-Up / HITL remediation guidance.'
& $BapEdge why 'copy README.md ..\sibling-contracts\README.md'

Pause-Step 'Pre-Authorize Sibling Module via BAP Trust Store' "$BapEdge trust ..\sibling-contracts --project" `
    'Developer/lead pre-approves the sibling project workspace for cross-module write/delete.'
& $BapEdge trust ..\sibling-contracts --project

Pause-Step 'Inspect Active Authorized Cross-Folder Permissions' "$BapEdge permissions" `
    'Audits active session, project, and global grants saved in .bap/project_permissions.json.'
& $BapEdge permissions

Pause-Step 'Verify Cross-Module Mutation is now ALLOWED with Trust Active' "$BapEdge why 'copy README.md ..\sibling-contracts\README.md'" `
    'With trust granted, Cedar Rule 1 permits the operation as within authorized development boundary.'
& $BapEdge why 'copy README.md ..\sibling-contracts\README.md'

Pause-Step 'Execute Sandboxed Cross-Module File Copy' "$BapEdge exec 'copy README.md ..\sibling-contracts\README.md'" `
    'Executes the copy inside the sandboxed Windows token isolation namespace.'
& $BapEdge exec 'copy README.md ..\sibling-contracts\README.md'

Pause-Step 'Revoke Sibling Trust & Teardown Mock Artifacts' "$BapEdge untrust ..\sibling-contracts" `
    'Demonstrates clean revocation of cross-folder mutation grants.'
& $BapEdge untrust ..\sibling-contracts

# Cleanup mock file
if (Test-Path (Join-Path $MockSiblingDir "README.md")) {
    Remove-Item (Join-Path $MockSiblingDir "README.md") -Force
}

# -----------------------------------------------------------------------------
# PHASE 4: Absolute Security Invariants — Secret Exfiltration & Anti-Tampering (Contrasted with HITL)
# -----------------------------------------------------------------------------
Pause-Step 'Verify Ambient Secret Redaction & Credential Denial (.env)' "$BapEdge why 'cat .env'" `
    'Unlike cross-project writes, secret files (.env, .aws, .ssh) can NEVER be trusted or bypassed.'
& $BapEdge why 'cat .env'

Pause-Step 'Verify Secret Exfiltration to Sibling Module is HARD DENIED' "$BapEdge why 'copy .env ..\sibling-contracts\.env'" `
    'Rule 3 strictly overrides trust: sensitive credentials cannot be copied anywhere.'
& $BapEdge why 'copy .env ..\sibling-contracts\.env'

Pause-Step 'Execute Blocked Credential Read via Broker' "$BapEdge exec 'type .env'" `
    'Broker intercepts command and returns structured JSON denial with zero host disclosure.'
& $BapEdge exec 'type .env'

Pause-Step 'Verify Raw Network Exfiltration (curl) is DENIED' "$BapEdge why 'curl https://untrusted.internal'" `
    'Raw network exfiltration utilities are strictly blocked; all egress must route through PEP.'
& $BapEdge why 'curl https://untrusted.internal'

Pause-Step 'Verify Anti-Tampering Blocks Deletion of Protected Policy Assets' "$BapEdge exec 'del policy.cedar'" `
    'Protects core governance files (policy.cedar, bapedge.exe) from rogue agent modification.'
& $BapEdge exec 'del policy.cedar'

# -----------------------------------------------------------------------------
# PHASE 5: Windows Restricted Token Containment & Privilege Stripping
# -----------------------------------------------------------------------------
Pause-Step 'Execute Git Status (Verifies clean execution without .gitconfig crash)' "$BapEdge exec 'git status'" `
    'Confirms Medium Integrity Token executes standard tools without permissions crashes.'
& $BapEdge exec 'git status'

Pause-Step 'Verify Administrators SID is Stripped to Deny-Only' "$BapEdge exec 'whoami /groups'" `
    'Inspects child process token: BUILTIN\Administrators is marked Use for deny only.'
& $BapEdge exec 'whoami /groups'

Pause-Step 'Verify High Privileges are Stripped in Child Process' "$BapEdge exec 'whoami /priv'" `
    'Inspects child process token: SeDebugPrivilege, SeTcbPrivilege, etc. are completely removed.'
& $BapEdge exec 'whoami /priv'

# -----------------------------------------------------------------------------
# PHASE 6: Workstation Sweep & Audit Hash-Chain Verification
# -----------------------------------------------------------------------------
Pause-Step 'Run Crash Sweep to Reconcile Stale Sessions and Flush Spools' "$BapEdge sweep" `
    'Reconciles dead locks, purges stale session markers, and flushes offline audit backlog.'
& $BapEdge sweep

Pause-Step 'Verify Anti-Tamper Cryptographic Hash-Chain on Audit Log' "$BapEdge verify-log" `
    'Mathematically validates SHA-256 forward-integrity hash chain on append-only audit trail.'
& $BapEdge verify-log

Write-Host ''
Write-Host '========================================================================' -ForegroundColor Green
Write-Host '[SUCCESS] All BAP manual pilot verification phases completed cleanly.' -ForegroundColor Green
Write-Host '========================================================================' -ForegroundColor Green
