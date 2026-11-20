$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$testRoot = Join-Path $workspace 'test-runtime-tmp'
[void][System.IO.Directory]::CreateDirectory($testRoot)
$testDir = Join-Path $testRoot ('safe-json-' + [Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($testDir)
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$target = Join-Path $testDir 'settings.json'
try {
    foreach ($relative in @('run_claude_bap.ps1', 'scripts/bap_launcher_engine.ps1')) {
        $source = [System.IO.File]::ReadAllText((Join-Path $workspace $relative))
        $parseTokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$parseTokens, [ref]$parseErrors)
        if ($parseErrors.Count -gt 0) { throw "$relative has PowerShell syntax errors: $parseErrors" }
        foreach ($name in @('Write-AtomicText', 'Write-AtomicBytes')) {
            $definition = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true) | Select-Object -First 1
            if ($null -eq $definition) { throw "Missing safe writer $name in $relative" }
            # Load only the two tested functions, never the launcher's main body.
            . ([scriptblock]::Create($definition.Extent.Text))
        }
        $unicode = [string][char]0x7814 + [string][char]0x53D1
        $command = 'C:\Program Files\BAP & Co\' + $unicode + '\broker.exe'
        $good = @{ hooks = @{ PreToolUse = @(@{ hooks = @(@{ type = 'command'; command = $command }) }) } } | ConvertTo-Json -Depth 10
        Write-AtomicText -Path $target -Text $good
        $before = [System.IO.File]::ReadAllBytes($target)
        $parsed = [System.IO.File]::ReadAllText($target) | ConvertFrom-Json
        if ($parsed.hooks.PreToolUse[0].hooks[0].command -ne $command) { throw 'Command characters changed during JSON serialization' }
        $rejected = $false
        try { Write-AtomicText -Path $target -Text '{"hooks": "bad\unescaped"' } catch { $rejected = $true }
        if (-not $rejected) { throw 'Malformed JSON was accepted' }
        $after = [System.IO.File]::ReadAllBytes($target)
        if ([Convert]::ToBase64String($before) -ne [Convert]::ToBase64String($after)) { throw 'Good settings were damaged by rejected JSON' }
        Write-AtomicText -Path $target -Text $good
        if (@(Get-ChildItem -LiteralPath $testDir -Filter '*.tmp.*').Count -ne 0) { throw 'Transient configuration files left behind' }
        Write-Output "$relative : valid Unicode/path JSON preserved; malformed JSON rejected before replacement"
    }
} finally {
    # Only known test-owned files are removed; never recursively sweep a workspace.
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force }
    Remove-Item -LiteralPath $testDir -ErrorAction SilentlyContinue
}
