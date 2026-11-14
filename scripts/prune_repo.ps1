<#
.SYNOPSIS
  Removes tracked junk, duplicates and stale docs from the BAP repo (git history keeps everything).

.DESCRIPTION
  Dry run by default: prints what would be removed. Pass -Apply to run `git rm`.
  Never commits; review with `git status` and commit yourself.

  Tier 1 (always): build debris, backups, scratch output, archived docs, exact duplicates, empty files.
  Tier 2 (-IncludeLegacyDemos): Sept/Oct demo and ad-hoc test scripts that nothing references.
  Tier 3 (-IncludeStaleDocs): superseded planning / deployment notes.

  After applying, it lists remaining tracked files that still mention a removed path, so you can fix links.

.EXAMPLE
  .\scripts\prune_repo.ps1                              # dry run, tier 1 only
  .\scripts\prune_repo.ps1 -IncludeLegacyDemos -IncludeStaleDocs
  .\scripts\prune_repo.ps1 -IncludeLegacyDemos -IncludeStaleDocs -Apply
#>
param(
  [switch]$Apply,
  [switch]$IncludeLegacyDemos,
  [switch]$IncludeStaleDocs
)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

$tier1 = @(
  'bap.exe.old.1025260848',
  'bapedge.exe.old.24736.1794458725168',
  'bapedge.exe.old.29620.1794597844559',
  '.FullName',
  'new(10.0.0.1',
  'GEMINI.md.bap-backup-sess-antigravity-cli-6e0fc81e',
  'GEMINI.md.off',
  '.claude/settings.json.o1',
  '.copilot/bap-session.json.bap-backup-sess-copilot-cli-ac935c60',
  'run_load_test_1000.bat',          # empty file
  'PLUGIN_ARCHITECTURE.md',          # byte-identical to docs/PLUGIN_ARCHITECTURE.md
  'DEMO_CLAUDE.md',                  # redirect stub to DEMO_CLAUDE_CODEX_ZERO_TRUST.md
  'scratch',                         # pytest dumps and one-off search scripts
  'archive'                          # already-archived docs; history keeps them
)
$tier2 = @(
  'run_cio_demo.bat','run_cio_demo.ps1','run_cio_demo.sh',
  'run_25k_scaling_test.ps1','stop_simple_local_test.bat','stop_inspector.ps1',
  'run_ollama_powershell_test.bat','test_ollama_governed.bat','test_inline_complex_ollama.bat'
)
$tier3 = @(
  'ACTIVE_TASK.md',            # Nov 9 sprint notes
  'implementation_plan.md',    # Oct 31 pilot plan; docs/LEADERSHIP_PILOT_PLAN.md and docs/PILOT_RUNBOOK.md supersede it
  'PROJECT_MAP.md',            # Sept file index, out of date
  'DEPLOYMENT_START_HERE.md'   # links to documents that were already archived
)

$targets = @($tier1)
if ($IncludeLegacyDemos) { $targets += $tier2 }
if ($IncludeStaleDocs)   { $targets += $tier3 }

$tracked = git ls-files
$toRemove = foreach ($t in $targets) {
  $hit = $tracked | Where-Object { $_ -eq $t -or $_ -like "$t/*" }
  if ($hit) { $hit } else { Write-Host "  (not tracked, skipped) $t" -ForegroundColor DarkGray }
}
$toRemove = @($toRemove | Sort-Object -Unique)

Write-Host ("{0} tracked files selected{1}" -f $toRemove.Count, $(if ($Apply) { '' } else { ' (DRY RUN - pass -Apply to remove)' })) -ForegroundColor Cyan
$toRemove | ForEach-Object { Write-Host "  - $_" }
if (-not $Apply -or $toRemove.Count -eq 0) { return }

$dirty = git status --porcelain -- $toRemove
if ($dirty) {
  Write-Host "`nUncommitted changes exist in files about to be removed; commit or stash them first:" -ForegroundColor Yellow
  $dirty; exit 1
}

# git rm in batches (Windows command-line length limit)
for ($i = 0; $i -lt $toRemove.Count; $i += 100) {
  $batch = $toRemove[$i..([Math]::Min($i + 99, $toRemove.Count - 1))]
  git rm -q -- $batch
}
Write-Host "`nRemoved. Nothing was committed." -ForegroundColor Green

Write-Host "`nRemaining tracked files that still mention a removed path (fix these links):" -ForegroundColor Cyan
$names = $targets | ForEach-Object { Split-Path $_ -Leaf } | Sort-Object -Unique
$found = $false
foreach ($n in $names) {
  $refs = git grep -l -F -- $n 2>$null
  if ($refs) { $found = $true; Write-Host ("  {0,-48} <- {1}" -f $n, (($refs | Select-Object -First 4) -join ', ')) }
}
if (-not $found) { Write-Host "  none" -ForegroundColor Green }

Write-Host "`nNext: run the Go tests and 'python scripts/check_capability_claims.py', then review 'git status' and commit." -ForegroundColor Cyan
