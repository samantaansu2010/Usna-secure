<#
 Runs every verification step in order. For each step it records the command, its full output and its
 real exit code in verification-report.txt (repo root). At the end it prints a summary and EXITS WITH
 STATUS 1 if any required step failed (0 only if every required step succeeded).

 Why this is explicit: PowerShell does not stop on a failing native command (cargo), so each step reads
 $LASTEXITCODE itself. A command that cannot be found counts as a failure.

 Usage:  powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
         then check:  echo $LASTEXITCODE
 PowerShell 7 is nicer; Windows PowerShell 5.1 works (stderr lines are only text here).
#>
$ErrorActionPreference = "Continue"
Set-Location (Join-Path $PSScriptRoot "..")
$report = Join-Path (Get-Location) "verification-report.txt"
"USNA Secure verification run: $(Get-Date -Format o)" | Out-File $report -Encoding utf8

$script:results   = New-Object System.Collections.Generic.List[object]
$script:lastLines = @()

function Write-Both([string]$text) {
    Write-Host $text
    Add-Content -Path $report -Value $text
}

function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Exe,
        [string[]]$Arguments = @(),
        [switch]$Optional
    )
    Write-Both ""
    Write-Both "=== $Name ==="
    Write-Both "> $Exe $($Arguments -join ' ')"
    $global:LASTEXITCODE = $null
    $script:lastLines = @()
    if (-not (Get-Command $Exe -ErrorAction SilentlyContinue)) {
        Write-Both "command not found: $Exe"
        $code = 127
    }
    else {
        $script:lastLines = @(
            & $Exe @Arguments 2>&1 | ForEach-Object {
                $s = $_.ToString()
                Write-Both $s
                $s
            }
        )
        $code = $LASTEXITCODE          # read immediately; the native command's real exit code
        if ($null -eq $code) { $code = -1 }
    }
    $status = if ($code -eq 0) { "ok" } elseif ($Optional) { "FAILED (optional)" } else { "FAILED" }
    Write-Both "exit code: $code  [$status]"
    $script:results.Add([pscustomobject]@{ Name = $Name; Code = $code; Optional = [bool]$Optional })
}

# --- steps -------------------------------------------------------------------------------------
Invoke-Step "rustc version"  "rustc"  @("--version", "--verbose")
Invoke-Step "cargo version"  "cargo"  @("--version")
Invoke-Step "rustup toolchain" "rustup" @("show", "active-toolchain") -Optional

if (Test-Path "Cargo.lock") {
    Write-Both "`nCargo.lock exists: not regenerating (all later steps use --locked)."
}
else {
    Invoke-Step "generate lockfile" "cargo" @("generate-lockfile")
}

Invoke-Step "dependency tree (features)" "cargo" @("tree", "--locked", "-p", "usna-vault-core", "-e", "features") -Optional
Invoke-Step "duplicate dependencies"     "cargo" @("tree", "--locked", "-d") -Optional
Invoke-Step "fmt (apply)"  "cargo" @("fmt", "--all")
Invoke-Step "fmt (check)"  "cargo" @("fmt", "--all", "--", "--check")
Invoke-Step "build"        "cargo" @("build", "--locked", "--workspace", "--all-features")
Invoke-Step "clippy (warnings denied)" "cargo" @("clippy", "--locked", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings")

Invoke-Step "test (all features)" "cargo" @("test", "--locked", "--workspace", "--all-features")
$passed = 0; $failed = 0; $ignored = 0; $suites = 0
foreach ($line in $script:lastLines) {
    if ($line -match 'test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored') {
        $suites++; $passed += [int]$Matches[1]; $failed += [int]$Matches[2]; $ignored += [int]$Matches[3]
    }
}

$demoDir = Join-Path $env:TEMP ("usna-demo-" + (Get-Date -Format "yyyyMMddHHmmss"))
Invoke-Step "lifecycle demo (release build, real Argon2id parameters)" "cargo" @(
    "run", "--release", "--locked", "-p", "usna-vault-core", "--example", "lifecycle_demo", "--", $demoDir)

# --- summary -----------------------------------------------------------------------------------
Write-Both ""
Write-Both "================ SUMMARY ================"
foreach ($r in $script:results) {
    $mark = if ($r.Code -eq 0) { "ok    " } elseif ($r.Optional) { "WARN  " } else { "FAIL  " }
    Write-Both ("{0} exit={1,-4} {2}" -f $mark, $r.Code, $r.Name)
}
Write-Both ""
Write-Both "Test counts (summed over $suites test binaries/doc-tests): passed=$passed failed=$failed ignored=$ignored"
Write-Both "Demo vault left for inspection at: $demoDir"
$failedRequired = @($script:results | Where-Object { $_.Code -ne 0 -and -not $_.Optional })
if ($failedRequired.Count -gt 0) {
    Write-Both ("RESULT: FAILED ({0} required step(s) failed). Exiting with status 1." -f $failedRequired.Count)
    Write-Both "Full output: $report"
    exit 1
}
Write-Both "RESULT: all required steps exited 0. Full output: $report"
exit 0
