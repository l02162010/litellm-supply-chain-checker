# check_litellm.ps1 v2
# Scans Windows for the compromised litellm package (supply chain attack 2026-03-25).
# Malicious versions: 1.82.7 and 1.82.8 only.
# Reference: https://github.com/BerriAI/litellm/issues/24518
#
# Usage:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\check_litellm.ps1

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  LiteLLM Supply Chain Attack Checker"
Write-Host "  (Windows) v2"
Write-Host "========================================="
Write-Host ""

$script:found = $false   # confirmed malicious version
$script:info  = $false   # litellm present but not known-malicious

$maliciousVersions = @("1.82.7", "1.82.8")
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$fixtureExcludePath = if (-not $env:LITELLM_SCAN_ROOT) {
    $candidate = Join-Path $scriptDir "tests\fixtures"
    if (Test-Path $candidate) { $candidate } else { $null }
} else {
    $null
}

function Test-IsExcludedPath([string]$path, [string[]]$regexes) {
    if ($fixtureExcludePath -and $path -like "$fixtureExcludePath*") {
        return $true
    }
    foreach ($regex in $regexes) {
        if ($path -match $regex) {
            return $true
        }
    }
    return $false
}

function Is-Malicious([string]$ver) {
    return $maliciousVersions -contains $ver
}

function Publish-CapturedMessage([string]$message) {
    if ($env:LITELLM_CAPTURE_OUTPUT) {
        Write-Output $message
    }
}

function Flag-PipResult([string[]]$result, [string]$source) {
    $ver = (($result | Select-String "^Version:").Line -replace "Version:\s*", "").Trim()
    $loc = (($result | Select-String "^Location:").Line -replace "Location:\s*", "").Trim()
    if (Is-Malicious $ver) {
        Write-Host "  [!!!] INFECTED - litellm $ver [$source]  ->  $loc" -ForegroundColor Red
        $script:found = $true
    } else {
        Write-Host "  [i]  litellm $ver [$source] (not a known malicious version)  ->  $loc" -ForegroundColor DarkYellow
        $script:info = $true
    }
}

[string]$primaryScanRoot = if ($env:LITELLM_SCAN_ROOT) { $env:LITELLM_SCAN_ROOT } else { $env:USERPROFILE }
[string[]]$scanRoots = @($primaryScanRoot)
$tempExcludePatterns = if ($env:LITELLM_SCAN_ROOT) { @() } else { @('\\AppData\\Local\\Temp\\') }

# Collect known site-packages directories from Python interpreters
function Get-SitePackages {
    $paths = [System.Collections.Generic.List[string]]::new()

    foreach ($py in @("python", "python3", "py")) {
        if (Get-Command $py -ErrorAction SilentlyContinue) {
            $pythonSnippet = @'
import site
pkgs = getattr(site, 'getsitepackages', lambda: [])()
user = getattr(site, 'getusersitepackages', lambda: '')()
for p in pkgs + ([user] if user else []):
    print(p)
'@
            $result = & $py -c $pythonSnippet 2>$null
            if ($result) {
                $result | Where-Object { $_ -and (Test-Path $_) } | ForEach-Object { $paths.Add($_) }
            }
        }
    }

    # pyenv-win
    $pyenvRoot = "$env:USERPROFILE\.pyenv\pyenv-win\versions"
    if (Test-Path $pyenvRoot) {
        Get-ChildItem -Path $pyenvRoot -Recurse -Directory -Filter "site-packages" -ErrorAction SilentlyContinue |
            ForEach-Object { $paths.Add($_.FullName) }
    }

    # System Python locations
    $sysPaths = @(
        "C:\Python*",
        "C:\Program Files\Python*",
        "C:\Program Files (x86)\Python*",
        "$env:LOCALAPPDATA\Programs\Python\*"
    )
    foreach ($pattern in $sysPaths) {
        Get-Item -Path $pattern -ErrorAction SilentlyContinue | ForEach-Object {
            Get-ChildItem -Path $_.FullName -Recurse -Directory -Filter "site-packages" -ErrorAction SilentlyContinue |
                ForEach-Object { $paths.Add($_.FullName) }
        }
    }

    return $paths | Select-Object -Unique | Where-Object { Test-Path $_ }
}

$sitePackages = @(Get-SitePackages)
Write-Host "Python site-packages roots found: $($sitePackages.Count)"
$sitePackages | ForEach-Object { Write-Host "  * $_" }
Write-Host ""

# --- 1. pip global install ----------------------------------------------------
Write-Host "[1] Checking pip global install..." -ForegroundColor Yellow
$step1Found = $false
foreach ($cmd in @("pip", "pip3")) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        $result = & $cmd show litellm 2>$null
        if ($result) {
            Flag-PipResult $result $cmd
            $step1Found = $true
        }
    }
}
if (-not $step1Found) { Write-Host "  [OK] not found" -ForegroundColor Green }

# --- 2. Known site-packages (version via dist-info, not just folder presence) -
Write-Host ""
Write-Host "[2] Scanning known site-packages for litellm..." -ForegroundColor Yellow
$step2Found = $false
foreach ($sp in $sitePackages) {
    if (Test-Path (Join-Path $sp "litellm")) {
        # Find version from dist-info
        $distInfo = Get-ChildItem -Path $sp -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "^litellm-(.+)\.dist-info$" } | Select-Object -First 1
        if ($distInfo) {
            $ver = $distInfo.Name -replace "^litellm-(.+)\.dist-info$", '$1'
            if (Is-Malicious $ver) {
                Write-Host "  [!!!] INFECTED - litellm $ver installed at $sp" -ForegroundColor Red
                $script:found = $true
            } else {
                Write-Host "  [i]  litellm $ver at $sp (not a known malicious version)" -ForegroundColor DarkYellow
                $script:info = $true
            }
        } else {
            Write-Host "  [i]  litellm directory at $sp\litellm - no dist-info (may be source checkout, verify manually)" -ForegroundColor DarkYellow
        }
        $step2Found = $true
    }
}
if (-not $step2Found) { Write-Host "  [OK] not found in known site-packages" -ForegroundColor Green }

# --- 3. conda environments ----------------------------------------------------
Write-Host ""
Write-Host "[3] Checking conda environments..." -ForegroundColor Yellow
if (Get-Command conda -ErrorAction SilentlyContinue) {
    $step3Found = $false
    $envs = conda env list 2>$null | Where-Object { $_ -notmatch "^#" -and $_.Trim() -ne "" }
    foreach ($line in $envs) {
        $envName = ($line -split "\s+")[0]
        if ($envName) {
            $result = conda run -n $envName pip show litellm 2>$null
            if ($result) {
                Flag-PipResult $result "conda:$envName"
                $step3Found = $true
            }
        }
    }
    if (-not $step3Found) { Write-Host "  [OK] not found in any conda env" -ForegroundColor Green }
} else {
    Write-Host "  (conda not installed, skipping)"
}

# --- 4. pyenv-win -------------------------------------------------------------
Write-Host ""
Write-Host "[4] Checking pyenv-win versions..." -ForegroundColor Yellow
$pyenvRoot = "$env:USERPROFILE\.pyenv\pyenv-win\versions"
if (Test-Path $pyenvRoot) {
    $step4Found = $false
    Get-ChildItem -Path $pyenvRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $pipPath = Join-Path $_.FullName "Scripts\pip.exe"
        if (Test-Path $pipPath) {
            $result = & $pipPath show litellm 2>$null
            if ($result) {
                Flag-PipResult $result "pyenv-win:$($_.Name)"
                $step4Found = $true
            }
        }
    }
    if (-not $step4Found) { Write-Host "  [OK] not found in any pyenv-win version" -ForegroundColor Green }
} else {
    Write-Host "  (pyenv-win not installed, skipping)"
}

# --- 5. Dependency files and lock files - version-aware ----------------------
Write-Host ""
Write-Host "[5] Searching project dependency files and lock files..." -ForegroundColor Yellow
$step5Found = $false
$patExact = 'litellm[^\s=]*\s*==\s*["'']?(1\.82\.7|1\.82\.8)'
$patRange = 'litellm[^\s=]*\s*(>=|~=)\s*["'']?1\.82\.[0-8]'
$excludeDirs5 = @('\\\.git\\', '\\node_modules\\', '\\\.cache\\') + $tempExcludePatterns
$depNames = @("pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "poetry.lock", "uv.lock", "pdm.lock")

$scanRoot5 = $primaryScanRoot
$depCandidates = if ($env:LITELLM_SCAN_ROOT) {
    Get-ChildItem -Path $scanRoot5 -Recurse -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer }
} else {
    Get-ChildItem -Path $scanRoot5 -Recurse -Depth 8 -File -ErrorAction SilentlyContinue
}
$depFiles = @(
    $depCandidates | Where-Object {
        $item = $_
        (-not (Test-IsExcludedPath $item.FullName $excludeDirs5)) -and
        ($item.Name -like "requirements*.txt" -or $depNames -contains $item.Name)
    }
)
if ($env:LITELLM_CAPTURE_OUTPUT) {
    Publish-CapturedMessage "[debug step5] scan root: $scanRoot5"
    Publish-CapturedMessage "[debug step5] candidate count: $($depFiles.Count)"
    foreach ($depFile in $depFiles) {
        Publish-CapturedMessage "[debug step5] candidate: $($depFile.FullName)"
    }
}
foreach ($depFile in $depFiles) {
        $filePath = $depFile.FullName
        $isLock = $filePath -match '\.(lock)$'
        $content = Get-Content $filePath -ErrorAction SilentlyContinue
        if (-not $content) { return }

        if ($isLock) {
            # Lock files: check for malicious version within 5 lines of "litellm"
            for ($i = 0; $i -lt $content.Count; $i++) {
                if ($content[$i] -imatch "litellm") {
                    $end = [Math]::Min($i + 5, $content.Count - 1)
                    $window = $content[$i..$end] -join " "
                    if ($window -match '"(1\.82\.7|1\.82\.8)"') {
                        $ver = [regex]::Match($window, "1\.82\.[78]").Value
                        $message = "  [!!!] INFECTED - lock file records malicious litellm $ver  ->  $filePath"
                        Write-Host $message -ForegroundColor Red
                        Publish-CapturedMessage $message
                        $script:found = $true
                        $step5Found = $true
                        break
                    }
                }
            }
        } else {
            $lines = $content | Where-Object { $_ -imatch "litellm" -and $_ -notmatch '^\s*#' }
            foreach ($line in $lines) {
                if ($line -imatch $patExact) {
                    $ver = [regex]::Match($line, "1\.82\.[78]").Value
                    $message = "  [!!!] INFECTED - pins malicious litellm $ver  ->  $filePath"
                    Write-Host $message -ForegroundColor Red
                    Publish-CapturedMessage $message
                    Write-Host "        $line" -ForegroundColor Red
                    $script:found = $true
                } elseif ($line -imatch $patRange) {
                    $message = "  [WARN] RISKY - version range may include malicious versions  ->  $filePath"
                    Write-Host $message -ForegroundColor DarkYellow
                    Publish-CapturedMessage $message
                    Write-Host "         $line" -ForegroundColor DarkYellow
                    $script:info = $true
                } else {
                    Write-Host "  [i]  litellm reference (verify version is safe)  ->  $filePath" -ForegroundColor DarkYellow
                    Write-Host "       $line" -ForegroundColor DarkYellow
                    $script:info = $true
                }
                $step5Found = $true
            }
        }
    }
if (-not $step5Found) { Write-Host "  [OK] no litellm references found" -ForegroundColor Green }

# --- 6. Virtual environments -------------------------------------------------
Write-Host ""
Write-Host "[6] Scanning project virtual environments..." -ForegroundColor Yellow
$step6Found = $false
$excludeDirs6 = @('\\\.git\\', '\\node_modules\\', '\\\.cache\\', '\\AppData\\Local\\Temp\\')
$scanRoot6 = $primaryScanRoot
# Collect into array first to avoid ForEach-Object pipeline scope issue
$venvDirs = Get-ChildItem -Path $scanRoot6 -Recurse -Directory -Depth 6 -ErrorAction SilentlyContinue |
    Where-Object {
        $item = $_
        $item.Name -in @(".venv", "venv", "env") -and
        -not (Test-IsExcludedPath $item.FullName $excludeDirs6)
    }
foreach ($venvDir in $venvDirs) {
    $pipPath = Join-Path $venvDir.FullName "Scripts\pip.exe"
    if (Test-Path $pipPath) {
        $result = & $pipPath show litellm 2>$null
        if ($result) {
            Flag-PipResult $result "venv:$($venvDir.FullName)"
            $step6Found = $true
        }
    }
}
if (-not $step6Found) { Write-Host "  [OK] not found in any virtual env" -ForegroundColor Green }

# --- 7. uv -------------------------------------------------------------------
Write-Host ""
Write-Host "[7] Checking uv..." -ForegroundColor Yellow
if (Get-Command uv -ErrorAction SilentlyContinue) {
    $result = uv pip show litellm 2>$null
    if ($result) {
        Flag-PipResult $result "uv"
    } else {
        Write-Host "  [OK] not found in uv default environment" -ForegroundColor Green
    }
} else {
    Write-Host "  (uv not installed, skipping)"
}

# --- 8. dist-info / egg-info - version-aware ---------------------------------
Write-Host ""
Write-Host "[8] Searching for litellm dist-info / egg-info..." -ForegroundColor Yellow
$step8Found = $false
$excludeDirsBroad = @('\\\.git\\', '\\node_modules\\', '\\\.cache\\') + $tempExcludePatterns
$broadArtifacts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($root in $scanRoots) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem -Path $root -Recurse -Depth 10 -ErrorAction SilentlyContinue |
        Where-Object {
            $item = $_
            (-not (Test-IsExcludedPath $item.FullName $excludeDirsBroad)) -and (
                $item.Name -eq "litellm_init.pth" -or
                $item.Name -like "litellm*.dist-info" -or
                $item.Name -like "litellm*.egg-info"
            )
        } |
        ForEach-Object { [void]$broadArtifacts.Add($_.FullName) }
}
$distInfoPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($sp in $sitePackages) {
    Get-ChildItem -Path $sp -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "^litellm-(.+)\.(dist-info|egg-info)$" } |
        ForEach-Object { [void]$distInfoPaths.Add($_.FullName) }
}
foreach ($artifactPath in $broadArtifacts) {
    $leaf = Split-Path $artifactPath -Leaf
    if ($leaf -like "litellm*.dist-info" -or $leaf -like "litellm*.egg-info") {
        [void]$distInfoPaths.Add($artifactPath)
    }
}
foreach ($path in $distInfoPaths) {
    $name = Split-Path $path -Leaf
    $ver = [regex]::Match($name, "^litellm-(.+)\.(dist-info|egg-info)$").Groups[1].Value
    if (Is-Malicious $ver) {
        Write-Host "  [!!!] INFECTED - dist-info for malicious version $ver`: $path" -ForegroundColor Red
        Publish-CapturedMessage "  [!!!] INFECTED - dist-info for malicious version $ver`: $path"
        $script:found = $true
    } else {
        Write-Host "  [i]  dist-info for litellm $ver`: $path (not a known malicious version)" -ForegroundColor DarkYellow
        $script:info = $true
    }
    $step8Found = $true
}
if (-not $step8Found) { Write-Host "  [OK] not found" -ForegroundColor Green }

# --- 9. CRITICAL: litellm_init.pth (v1.82.8 backdoor) -----------------------
Write-Host ""
Write-Host "[9] CRITICAL: Searching for litellm_init.pth (v1.82.8 backdoor)..." -ForegroundColor Yellow
$step9Found = $false
# Check in known site-packages (fast)
foreach ($sp in $sitePackages) {
    $pth = Join-Path $sp "litellm_init.pth"
    if (Test-Path $pth) {
        Write-Host "  [!!!] FOUND litellm_init.pth - SYSTEM IS COMPROMISED: $pth" -ForegroundColor Red -BackgroundColor Black
        $script:found = $true
        $step9Found = $true
    }
}
# Also scan broader roots for anything that landed outside known paths
foreach ($artifactPath in $broadArtifacts) {
    if ((Split-Path $artifactPath -Leaf) -ne "litellm_init.pth") { continue }
    Write-Host "  [!!!] FOUND litellm_init.pth - SYSTEM IS COMPROMISED: $artifactPath" -ForegroundColor Red -BackgroundColor Black
    $script:found = $true
    $step9Found = $true
}
if (-not $step9Found) { Write-Host "  [OK] litellm_init.pth not found" -ForegroundColor Green }

# --- 10. Non-standard .pth files in known site-packages only -----------------
Write-Host ""
Write-Host "[10] Listing non-standard .pth files in known site-packages..." -ForegroundColor Yellow
$knownPthPattern = '^(easy-install|distutils|distutils-precedence|setuptools|wheel|pip|pkg_resources|_virtualenv|_uv_ephemeral_overlay|aeosa)$'
$step10Found = $false
foreach ($sp in $sitePackages) {
    Get-ChildItem -Path $sp -Filter "*.pth" -File -ErrorAction SilentlyContinue |
        Where-Object {
            $name = $_.BaseName
            -not ($name -match $knownPthPattern)
        } |
        ForEach-Object {
            Write-Host "  [WARN] Unexpected .pth file (review manually): $($_.FullName)" -ForegroundColor DarkYellow
            $step10Found = $true
        }
}
if (-not $step10Found) { Write-Host "  [OK] no unexpected .pth files" -ForegroundColor Green }

# --- Summary -----------------------------------------------------------------
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
if ($script:found) {
    $summaryMessage = "  [!!!] MALICIOUS litellm version detected!"
    Write-Host $summaryMessage -ForegroundColor Red
    Publish-CapturedMessage $summaryMessage
    Write-Host ""
    Write-Host "  Immediate actions:" -ForegroundColor Yellow
    Write-Host "  1. pip uninstall litellm -y  (in every affected env)"
    Write-Host "  2. Delete litellm_init.pth if found (check step 9)"
    Write-Host "  3. ROTATE ALL CREDENTIALS immediately:"
    Write-Host "     - API keys (OpenAI, Anthropic, etc.)"
    Write-Host "     - SSH keys"
    Write-Host "     - AWS / GCP / Azure credentials"
    Write-Host "     - Database passwords"
    Write-Host "     - Any secrets in .env files or shell history"
    Write-Host "  4. Review all connected services for unauthorized access"
} elseif ($script:info) {
    $summaryMessage = "  [i]  litellm found - NOT a known malicious version."
    Write-Host $summaryMessage -ForegroundColor DarkYellow
    Publish-CapturedMessage $summaryMessage
    Write-Host "       Confirm version is not 1.82.7 or 1.82.8." -ForegroundColor DarkYellow
    Write-Host "       Note: PyPI has suspended the package; consider alternatives." -ForegroundColor DarkYellow
} else {
    $summaryMessage = "  [OK] No litellm infection detected. You are safe."
    Write-Host $summaryMessage -ForegroundColor Green
    Publish-CapturedMessage $summaryMessage
}
Write-Host "=========================================" -ForegroundColor Cyan
