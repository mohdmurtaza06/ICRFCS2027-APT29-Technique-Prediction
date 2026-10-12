[CmdletBinding()]
param(
    [switch]$FullRebuild
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $root
try {
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $auditDir = Join-Path $root (Join-Path 'audit' ("windows_acceptance_{0}" -f $stamp))
    New-Item -ItemType Directory -Path $auditDir | Out-Null
    $logPath = Join-Path $auditDir 'windows_acceptance.log'
    Start-Transcript -Path $logPath -Force | Out-Null

    Write-Host "Project root: $root"
    Write-Host "Evidence folder: $auditDir"
    Write-Host "Full rebuild requested: $FullRebuild"

    $venvPython = Join-Path $root '.venv\Scripts\python.exe'
    if (Test-Path $venvPython) {
        $python = $venvPython
    } else {
        $cmd = Get-Command python -ErrorAction Stop
        $python = $cmd.Source
    }
    Write-Host "Python executable: $python"

    & $python --version
    if ($LASTEXITCODE -ne 0) { throw 'Python version query failed.' }
    $versionCode = @'
import json, platform, sys, importlib.metadata as md
names = ['numpy', 'torch', 'pandas', 'scikit-learn']
out = {'python': platform.python_version(), 'platform': platform.platform(), 'executable': sys.executable}
for name in names:
    try: out[name] = md.version(name)
    except md.PackageNotFoundError: out[name] = 'not-installed'
try:
    import torch
    out['torch_cuda_available'] = torch.cuda.is_available()
    out['torch_num_threads'] = torch.get_num_threads()
except Exception as exc:
    out['torch_import_error'] = repr(exc)
print(json.dumps(out, indent=2))
'@
    $envJsonPath = Join-Path $auditDir 'environment.json'
    $envJson = & $python -c $versionCode
    if ($LASTEXITCODE -ne 0) { throw 'Environment capture failed.' }
    $envJson | Set-Content -Path $envJsonPath -Encoding UTF8
    Get-Content $envJsonPath

    Write-Host "`n[1/4] Compile scripts and tests"
    & $python -m compileall -q scripts tests
    if ($LASTEXITCODE -ne 0) { throw 'compileall failed.' }

    Write-Host "`n[2/4] Run complete unittest suite"
    $testLog = Join-Path $auditDir 'unittest.log'
& $python -m unittest discover -s tests -v *> $testLog
$testExitCode = $LASTEXITCODE
Get-Content $testLog
if ($testExitCode -ne 0) {
    throw "Unit test suite failed with exit code $testExitCode. See $testLog"
}
    if ($LASTEXITCODE -ne 0) { throw 'Unit test suite failed.' }

    $conditions = @(
        @{ Label = 'primary'; Existing = 'artifacts_primary_reflect'; Boundary = 'reflect'; Tactic = 'walk'; Status = 'all' },
        @{ Label = 'clamp'; Existing = 'artifacts_sensitivity_clamp'; Boundary = 'clamp'; Tactic = 'walk'; Status = 'all' },
        @{ Label = 'uniform_tactic'; Existing = 'artifacts_sensitivity_uniform_tactic'; Boundary = 'reflect'; Tactic = 'uniform'; Status = 'all' },
        @{ Label = 'active_only'; Existing = 'artifacts_sensitivity_active_only'; Boundary = 'reflect'; Tactic = 'walk'; Status = 'active' }
    )

    if ($FullRebuild) {
        Write-Host "`n[3/4] Full four-condition rebuild. This can take several minutes."
        $runBase = Join-Path $auditDir 'full_rebuild'
        New-Item -ItemType Directory -Path $runBase | Out-Null
        foreach ($condition in $conditions) {
            $runDir = Join-Path $runBase $condition.Label
            Write-Host ("Running condition: {0} -> {1}" -f $condition.Label, $runDir)
            & $python scripts/run_benchmark.py `
                --outdir $runDir `
                --data-dir data `
                --seeds 20261011 20261012 20261013 `
                --epochs 35 `
                --n-synthetic 500 `
                --boundary $condition.Boundary `
                --tactic-sampling $condition.Tactic `
                --synthetic-status $condition.Status `
                --torch-threads 1
            if ($LASTEXITCODE -ne 0) { throw "Benchmark failed for $($condition.Label)." }
            & $python scripts/reconcile_run.py --run-dir $runDir --data-dir data --out (Join-Path $runDir 'reconciliation.json')
            if ($LASTEXITCODE -ne 0) { throw "Independent reconciliation failed for $($condition.Label)." }
        }
        $summaryArgs = @()
        foreach ($condition in $conditions) {
            $runDir = Join-Path $runBase $condition.Label
            $summaryArgs += @('--condition', ("{0}={1}" -f $condition.Label, $runDir))
        }
        $summaryPath = Join-Path $auditDir 'sensitivity_comparison_windows.json'
        & $python scripts/summarize_conditions.py @summaryArgs --out $summaryPath
        if ($LASTEXITCODE -ne 0) { throw 'Four-condition comparison failed.' }
    } else {
        Write-Host "`n[3/4] Independently reconcile bundled condition artifacts"
        foreach ($condition in $conditions) {
            $runDir = Join-Path $root $condition.Existing
            if (-not (Test-Path (Join-Path $runDir 'run_manifest.json'))) {
                throw "Missing bundled condition directory or manifest: $($condition.Existing)"
            }
            $reportPath = Join-Path $auditDir ("reconciliation_{0}.json" -f $condition.Label)
            Write-Host ("Reconciling: {0}" -f $condition.Existing)
            & $python scripts/reconcile_run.py --run-dir $runDir --data-dir data --out $reportPath
            if ($LASTEXITCODE -ne 0) { throw "Independent reconciliation failed for $($condition.Label)." }
            $report = Get-Content $reportPath -Raw | ConvertFrom-Json
            if (-not $report.all_checks_passed) { throw "Reconciliation reported failure for $($condition.Label)." }
        }
        Write-Host "`n[4/4] Compare bundled condition manifests"
        $summaryArgs = @()
        foreach ($condition in $conditions) {
            $runDir = Join-Path $root $condition.Existing
            $summaryArgs += @('--condition', ("{0}={1}" -f $condition.Label, $runDir))
        }
        $summaryPath = Join-Path $auditDir 'sensitivity_comparison_bundled.json'
        & $python scripts/summarize_conditions.py @summaryArgs --out $summaryPath
        if ($LASTEXITCODE -ne 0) { throw 'Four-condition comparison failed.' }
    }

    $record = @"
Windows acceptance check
Timestamp: $(Get-Date -Format o)
Python: $python
Full rebuild: $FullRebuild
Result: PASS
Evidence directory: $auditDir
Note: without -FullRebuild, this validates bundled artifacts on Windows but does not rerun model training. With -FullRebuild, all four policies are freshly trained using the selected Windows environment; results are a separate Windows run, and bit-identical outputs versus Linux are not assumed.
"@
    $record | Set-Content -Path (Join-Path $auditDir 'RESULT.txt') -Encoding UTF8
    Write-Host "`nRESULT: PASS"
    Write-Host "Evidence folder: $auditDir"
    Stop-Transcript | Out-Null
}
catch {
    [Console]::Error.WriteLine($_.ToString())
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}
finally {
    Pop-Location
}
