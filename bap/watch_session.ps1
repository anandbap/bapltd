param(
    [string]$ServerUrl,
    [string]$SessionId,
    [int]$WatchPid = 0
)

if (-not $ServerUrl -or -not $SessionId) {
    exit 0
}

# Auto-detect parent process PID (the cmd.exe session) if not explicitly passed
if ($WatchPid -le 0) {
    try {
        $parent = (Get-CimInstance Win32_Process -Filter "ProcessId = $PID").ParentProcessId
        if ($parent -gt 0) {
            $WatchPid = [int]$parent
        }
    } catch {}
}

if ($WatchPid -le 0) {
    exit 0
}

# Periodically verify process liveness
while (Get-Process -Id $WatchPid -ErrorAction SilentlyContinue) {
    Start-Sleep -Seconds 2
}

# Process has terminated (normal exit, Ctrl+C, or terminal window closed [X])
try {
    $body = @{
        session_id = $SessionId
        reason = "Claude process exited or window closed"
    } | ConvertTo-Json -Compress
    
    Invoke-RestMethod -Uri "$ServerUrl/api/v1/sessions/end" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 3 -ErrorAction SilentlyContinue
} catch {}

# Clean up local session marker
if (Test-Path ".bap-session.json") {
    Remove-Item -Force ".bap-session.json" -ErrorAction SilentlyContinue
}
