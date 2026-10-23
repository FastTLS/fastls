param(
    [string]$Suite = 'offline',
    [string]$Output = '../reports',
    [string]$ReportOnly = '',
    [string]$Filter = '',
    [string]$Plan = 'scripts/check-plan.json'
)
$taskRoot = Split-Path -Parent $PSScriptRoot
$previousWork = $env:GOWORK
$taskBinary = Join-Path ([IO.Path]::GetTempPath()) ('fastls-check-' + [guid]::NewGuid().ToString('N') + '.exe')
$taskExit = 2
try {
    $env:GOWORK = 'off'
    $taskArgs = @('-root', $taskRoot, '-suite', $Suite, '-output', $Output, '-plan', $Plan)
    if ($ReportOnly) { $taskArgs += @('-report-only', $ReportOnly) }
    if ($Filter) { $taskArgs += @('-filter', $Filter) }
    Push-Location -LiteralPath (Join-Path $taskRoot 'tools/fastls-check')
    try {
        & go build -o $taskBinary .
        if ($LASTEXITCODE -eq 0) { & $taskBinary @taskArgs; $taskExit = $LASTEXITCODE }
    } finally { Pop-Location }
} finally {
    $env:GOWORK = $previousWork
    if (Test-Path -LiteralPath $taskBinary) { Remove-Item -LiteralPath $taskBinary }
}
exit $taskExit
