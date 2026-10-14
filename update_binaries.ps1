param()
$ErrorActionPreference = "Stop"

if (Test-Path "bapedge.old") {
    Remove-Item -Force "bapedge.old" -ErrorAction SilentlyContinue
}

Move-Item -Force "bapedge.exe" "bapedge.old"
Copy-Item -Force "bap-edge\bapedge.exe" "bapedge.exe"

if (Test-Path "bapmcp.old") {
    Remove-Item -Force "bapmcp.old" -ErrorAction SilentlyContinue
}
if (Test-Path "bapmcp.exe") {
    Move-Item -Force "bapmcp.exe" "bapmcp.old" -ErrorAction SilentlyContinue
}
Copy-Item -Force "bap-edge\bapedge.exe" "bapmcp.exe"
Copy-Item -Force "bap-edge\bapedge.exe" "ltd-agent.exe"

if (Test-Path "bapcontrolplane.old") {
    Remove-Item -Force "bapcontrolplane.old" -ErrorAction SilentlyContinue
}
if (Test-Path "bapcontrolplane.exe") {
    Move-Item -Force "bapcontrolplane.exe" "bapcontrolplane.old" -ErrorAction SilentlyContinue
}
Copy-Item -Force "bap-controlplane\bapcontrolplane.exe" "bapcontrolplane.exe"
if (Test-Path "bapdashboard.old") {
    Remove-Item -Force "bapdashboard.old" -ErrorAction SilentlyContinue
}
if (Test-Path "bapdashboard.exe") {
    Move-Item -Force "bapdashboard.exe" "bapdashboard.old" -ErrorAction SilentlyContinue
}
Copy-Item -Force "bap-controlplane\bapdashboard.exe" "bapdashboard.exe"

if (Test-Path "dist\windows-amd64") {
    Copy-Item -Force "bap-edge\bapedge.exe" "dist\windows-amd64\bapedge.exe"
    if (Test-Path "cchook\interceptor.exe") {
        Copy-Item -Force "cchook\interceptor.exe" "dist\windows-amd64\interceptor.exe"
        Copy-Item -Force "cchook\interceptor.exe" "dist\windows-amd64\cchook-interceptor.exe"
    }
}

Write-Host "Binaries successfully updated."
