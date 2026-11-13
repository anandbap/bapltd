# Session review implementation is shared by source checkout and installed package.
$candidates = @(
    (Join-Path $PSScriptRoot 'review_session_impl.ps1'),
    (Join-Path $PSScriptRoot 'bap/review_session_impl.ps1'),
    (Join-Path $PSScriptRoot '../bap/review_session_impl.ps1')
)
foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate) {
        & $candidate @args
        exit $LASTEXITCODE
    }
}
throw 'Missing review_session_impl.ps1. Reinstall the BAP diagnostic tools.'
