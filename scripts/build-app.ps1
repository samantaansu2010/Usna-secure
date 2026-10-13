<#
 Builds and checks the desktop app (src-tauri). Same rules as verify.ps1: every step's real exit code is
 recorded in app-build-report.txt, and the script EXITS 1 if any required step failed.
 Run scripts\verify.ps1 first (the core must be green before the app is meaningful).

 Usage:  powershell -ExecutionPolicy Bypass -File scripts\build-app.ps1
 Requires: Rust toolchain (see docs\VERIFICATION.md) and the WebView2 runtime (preinstalled on current
 Windows 10/11). tauri-cli is installed on first run if missing (this compiles it; it takes a while).
#>
$ErrorActionPreference = "Continue"
$root = Join-Path $PSScriptRoot ".."
Set-Location $root
$root = (Get-Location).Path
$report = Join-Path $root "app-build-report.txt"
"USNA Secure app build: $(Get-Date -Format o)" | Out-File $report -Encoding utf8
$script:results = New-Object System.Collections.Generic.List[object]
$script:lastLines = @()

function Write-Both([string]$t) { Write-Host $t; Add-Content -Path $report -Value $t }
function Invoke-Step {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Exe, [string[]]$Arguments = @(), [string]$Dir = $root, [switch]$Optional)
    Write-Both ""; Write-Both "=== $Name ==="; Write-Both "> (in $Dir) $Exe $($Arguments -join ' ')"
    $global:LASTEXITCODE = $null; $script:lastLines = @()
    if (-not (Get-Command $Exe -ErrorAction SilentlyContinue)) { Write-Both "command not found: $Exe"; $code = 127 }
    else {
        Push-Location $Dir
        $script:lastLines = @(& $Exe @Arguments 2>&1 | ForEach-Object { $s = $_.ToString(); Write-Both $s; $s })
        $code = $LASTEXITCODE
        Pop-Location
        if ($null -eq $code) { $code = -1 }
    }
    $status = if ($code -eq 0) { "ok" } elseif ($Optional) { "FAILED (optional)" } else { "FAILED" }
    Write-Both "exit code: $code  [$status]"
    $script:results.Add([pscustomobject]@{ Name = $Name; Code = $code; Optional = [bool]$Optional })
}

$app = Join-Path $root "src-tauri"
if (-not (Test-Path (Join-Path $app "Cargo.lock"))) { Invoke-Step "generate app lockfile" "cargo" @("generate-lockfile") -Dir $app }
Invoke-Step "app unit tests (TOTP RFC vectors, model, generator)" "cargo" @("test", "--locked") -Dir $app
Invoke-Step "app clippy (informational)" "cargo" @("clippy", "--locked", "--all-targets", "--", "-D", "warnings") -Dir $app -Optional
Invoke-Step "tauri-cli present" "cargo" @("tauri", "--version") -Optional
if (($script:results | Where-Object { $_.Name -eq "tauri-cli present" }).Code -ne 0) {
    Invoke-Step "install tauri-cli" "cargo" @("install", "tauri-cli", "--version", "^2", "--locked")
}
Invoke-Step "build desktop app + Windows installer" "cargo" @("tauri", "build")

Write-Both ""; Write-Both "================ SUMMARY ================"
foreach ($r in $script:results) {
    $mark = if ($r.Code -eq 0) { "ok    " } elseif ($r.Optional) { "WARN  " } else { "FAIL  " }
    Write-Both ("{0} exit={1,-4} {2}" -f $mark, $r.Code, $r.Name)
}
$failed = @($script:results | Where-Object { $_.Code -ne 0 -and -not $_.Optional })
if ($failed.Count -gt 0) { Write-Both ("RESULT: FAILED ({0} required step(s)). Exiting 1. Output: $report" -f $failed.Count); exit 1 }
Write-Both "RESULT: all required steps exited 0."
Write-Both "Run the app:   src-tauri\target\release\usna-secure-app.exe"
Write-Both "Installer in:  src-tauri\target\release\bundle\nsis\"
exit 0
