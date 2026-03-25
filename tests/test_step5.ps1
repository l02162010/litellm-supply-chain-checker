# tests/test_step5.ps1
# Fixture-based tests for step 5 (dependency file parsing) on Windows.
# Runs check_litellm.ps1 with $env:LITELLM_SCAN_ROOT pointed at fixture directories.
# No Python installation required.

$scriptRoot = Split-Path $PSScriptRoot -Parent
$script = Join-Path $scriptRoot "check_litellm.ps1"
$fixtures = Join-Path $PSScriptRoot "fixtures"

$pass = 0
$fail = 0

function Invoke-Checker([string]$scriptPath, [string]$scanRoot, [string]$userProfile) {
    $oldCaptureOutput = $env:LITELLM_CAPTURE_OUTPUT
    $oldScanRoot = $env:LITELLM_SCAN_ROOT
    $oldUserProfile = $env:USERPROFILE
    $oldErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'SilentlyContinue'
        $env:LITELLM_CAPTURE_OUTPUT = '1'
        $env:LITELLM_SCAN_ROOT = $scanRoot
        $env:USERPROFILE = $userProfile
        return & $scriptPath 2>$null | Out-String
    } finally {
        $ErrorActionPreference = $oldErrorActionPreference
        $env:LITELLM_CAPTURE_OUTPUT = $oldCaptureOutput
        $env:LITELLM_SCAN_ROOT = $oldScanRoot
        $env:USERPROFILE = $oldUserProfile
    }
}

function Assert-Contains([string]$label, [string]$output, [string]$expected) {
    if ($output -match [regex]::Escape($expected) -or $output -match $expected) {
        Write-Host "  PASS  $label" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  FAIL  $label" -ForegroundColor Red
        Write-Host "        expected to find: $expected" -ForegroundColor Red
        $script:fail++
    }
}

function Assert-NotContains([string]$label, [string]$output, [string]$unexpected) {
    if ($output -match [regex]::Escape($unexpected) -or $output -match $unexpected) {
        Write-Host "  FAIL  $label" -ForegroundColor Red
        Write-Host "        should NOT contain: $unexpected" -ForegroundColor Red
        $script:fail++
    } else {
        Write-Host "  PASS  $label" -ForegroundColor Green
        $script:pass++
    }
}

function Show-DebugOutput([string]$label, [string]$output) {
    Write-Host ""
    Write-Host "[debug] $label output follows" -ForegroundColor Yellow
    Write-Host "--------------------" -ForegroundColor Yellow
    Write-Host $output
    Write-Host "--------------------" -ForegroundColor Yellow
}

Write-Host "========================================"
Write-Host "  Step 5 -- Dependency File Tests"
Write-Host "========================================"

# ── Infected fixtures ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[ infected fixtures ]"
$oldUserProfile = $env:USERPROFILE
$env:USERPROFILE = $fixtures
$env:LITELLM_SCAN_ROOT = Join-Path $fixtures "infected"
$out = Invoke-Checker $script $env:LITELLM_SCAN_ROOT $env:USERPROFILE
$env:LITELLM_SCAN_ROOT = $null
$env:USERPROFILE = $oldUserProfile
$failBefore = $fail

Assert-Contains `
    "flags litellm==1.82.7 in requirements.txt" `
    $out "INFECTED"

Assert-Contains `
    "detects extras syntax litellm[proxy]==1.82.8" `
    $out "1.82.8"

Assert-Contains `
    "detects malicious version in poetry.lock" `
    $out "lock file"

Assert-Contains `
    "final summary shows infection" `
    $out "MALICIOUS litellm version detected"
if ($fail -gt $failBefore) { Show-DebugOutput "infected fixtures" $out }

# ── Safe fixtures ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[ safe fixtures ]"
$oldUserProfile = $env:USERPROFILE
$env:USERPROFILE = $fixtures
$env:LITELLM_SCAN_ROOT = Join-Path $fixtures "safe"
$out = Invoke-Checker $script $env:LITELLM_SCAN_ROOT $env:USERPROFILE
$env:LITELLM_SCAN_ROOT = $null
$env:USERPROFILE = $oldUserProfile
$failBefore = $fail

Assert-NotContains `
    "does NOT flag litellm==1.82.6 as INFECTED" `
    $out "INFECTED"

Assert-NotContains `
    "final summary does NOT show infection for safe pin" `
    $out "MALICIOUS litellm version detected"

Assert-Contains `
    "reports risky range that includes 1.82.8" `
    $out "RISKY"

Assert-NotContains `
    "commented malicious pin is NOT flagged" `
    $out "pins malicious litellm 1.82.8"
if ($fail -gt $failBefore) { Show-DebugOutput "safe fixtures" $out }

# ── Step 10 — .pth filter regression ────────────────────────────────────────────
Write-Host ""
Write-Host "[ step 10 -- .pth filter regression ]"
$tmpSp = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tmpSp | Out-Null
New-Item -ItemType File -Path (Join-Path $tmpSp "bad_actor.pth") | Out-Null
New-Item -ItemType File -Path (Join-Path $tmpSp "_virtualenv.pth") | Out-Null
New-Item -ItemType File -Path (Join-Path $tmpSp "setuptools.pth") | Out-Null
$knownPthPattern = '^(easy-install|distutils|setuptools|wheel|pip|pkg_resources|_virtualenv|_uv_ephemeral_overlay|aeosa)$'
$filterOut = Get-ChildItem -Path $tmpSp -Filter "*.pth" -File |
    Where-Object { $_.BaseName -notmatch $knownPthPattern } |
    ForEach-Object { "UNEXPECTED: $($_.FullName)" } |
    Out-String
Remove-Item -Recurse -Force $tmpSp

Assert-Contains `
    "bad_actor.pth is reported" `
    $filterOut "bad_actor"

Assert-NotContains `
    "_virtualenv.pth is NOT reported" `
    $filterOut "_virtualenv"

Assert-NotContains `
    "setuptools.pth is NOT reported" `
    $filterOut "setuptools"

# ── Step 8/9 — scan root isolation ──────────────────────────────────────────────
Write-Host ""
Write-Host "[ step 8/9 -- scan root isolation ]"
$tmpScan = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
$tmpHome = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path (Join-Path $tmpScan "lib/python3.11/site-packages/litellm-1.82.8.egg-info") -Force | Out-Null
New-Item -ItemType Directory -Path $tmpHome -Force | Out-Null
New-Item -ItemType File -Path (Join-Path $tmpHome "litellm_init.pth") | Out-Null
$oldUserProfile = $env:USERPROFILE
$env:LITELLM_SCAN_ROOT = $tmpScan
$env:USERPROFILE = $tmpHome
$out = Invoke-Checker $script $env:LITELLM_SCAN_ROOT $env:USERPROFILE
$env:LITELLM_SCAN_ROOT = $null
$env:USERPROFILE = $oldUserProfile
Remove-Item -Recurse -Force $tmpScan, $tmpHome

Assert-Contains `
    "egg-info under scan root is detected" `
    $out "dist-info for malicious version 1.82.8"

Assert-NotContains `
    "USERPROFILE-only litellm_init.pth is ignored when scan root is set" `
    $out "SYSTEM IS COMPROMISED"

# ── Summary ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "========================================"
Write-Host "  Results: $pass passed, $fail failed"
Write-Host "========================================"
if ($fail -eq 0) { exit 0 } else { exit 1 }
