#!/bin/bash
# check_litellm.sh v2
# Scans macOS for the compromised litellm package (supply chain attack 2026-03-25).
# Malicious versions: 1.82.7 and 1.82.8 only.
# Reference: https://github.com/BerriAI/litellm/issues/24518

echo "========================================="
echo "  LiteLLM Supply Chain Attack Checker"
echo "  (macOS) v2"
echo "========================================="
echo ""

FOUND=0   # 1 = confirmed malicious version
INFO=0    # 1 = litellm present but not known-malicious

MALICIOUS_VERSIONS=("1.82.7" "1.82.8")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN_ROOT="${LITELLM_SCAN_ROOT:-$HOME}"
FIXTURE_EXCLUDE=""
if [ -z "${LITELLM_SCAN_ROOT:-}" ] && [ -d "$SCRIPT_DIR/tests/fixtures" ]; then
  FIXTURE_EXCLUDE="$SCRIPT_DIR/tests/fixtures"
fi
if [ -n "${LITELLM_SCAN_ROOT:-}" ]; then
  BROAD_SCAN_ROOTS=("$LITELLM_SCAN_ROOT")
else
  BROAD_SCAN_ROOTS=("$HOME" "/usr/local/lib" "/opt/homebrew/lib" "/Library/Python")
fi

is_malicious() {
  local v="$1"
  for m in "${MALICIOUS_VERSIONS[@]}"; do [[ "$v" == "$m" ]] && return 0; done
  return 1
}

# Parse `pip show` output and flag by version
flag_pip_result() {
  local result="$1" source="$2"
  local ver loc
  ver=$(printf '%s' "$result" | grep "^Version:" | awk '{print $2}')
  loc=$(printf '%s' "$result" | grep "^Location:" | cut -d' ' -f2-)
  if is_malicious "$ver"; then
    echo "  🚨 INFECTED — litellm $ver [$source]  →  $loc"
    FOUND=1
  else
    echo "  ℹ️  litellm $ver [$source] (not a known malicious version)  →  $loc"
    INFO=1
  fi
}

collect_dependency_files() {
  if [ -n "$FIXTURE_EXCLUDE" ]; then
    find "$SCAN_ROOT" -maxdepth 8 \
      \( -path "*/.git" -o -path "*/node_modules" -o -path "*/__pycache__" \
         -o -path "*/.cache" -o -path "*/Library/Caches" -o -path "$FIXTURE_EXCLUDE" \) -prune -o \
      \( -name "requirements*.txt" -o -name "pyproject.toml" -o -name "setup.py" \
         -o -name "setup.cfg" -o -name "Pipfile" -o -name "poetry.lock" \
         -o -name "uv.lock" -o -name "pdm.lock" \) -print 2>/dev/null
  else
    find "$SCAN_ROOT" -maxdepth 8 \
      \( -path "*/.git" -o -path "*/node_modules" -o -path "*/__pycache__" \
         -o -path "*/.cache" -o -path "*/Library/Caches" \) -prune -o \
      \( -name "requirements*.txt" -o -name "pyproject.toml" -o -name "setup.py" \
         -o -name "setup.cfg" -o -name "Pipfile" -o -name "poetry.lock" \
         -o -name "uv.lock" -o -name "pdm.lock" \) -print 2>/dev/null
  fi
}

collect_venv_dirs() {
  if [ -n "$FIXTURE_EXCLUDE" ]; then
    find "$SCAN_ROOT" -maxdepth 6 \
      \( -path "*/.git" -o -path "*/node_modules" -o -path "*/__pycache__" \
         -o -path "*/.cache" -o -path "*/Library/Caches" -o -path "$FIXTURE_EXCLUDE" \) -prune -o \
      \( -type d \( -name ".venv" -o -name "venv" -o -name "env" \) -print \) 2>/dev/null
  else
    find "$SCAN_ROOT" -maxdepth 6 \
      \( -path "*/.git" -o -path "*/node_modules" -o -path "*/__pycache__" \
         -o -path "*/.cache" -o -path "*/Library/Caches" \) -prune -o \
      \( -type d \( -name ".venv" -o -name "venv" -o -name "env" \) -print \) 2>/dev/null
  fi
}

collect_broad_hits() {
  if [ -n "$FIXTURE_EXCLUDE" ]; then
    find "${BROAD_SCAN_ROOTS[@]}" -maxdepth 10 \
      \( -path "*/.git" -o -path "*/node_modules" -o -path "*/__pycache__" \
         -o -path "*/.cache" -o -path "*/Library/Caches" -o -path "$FIXTURE_EXCLUDE" \) -prune -o \
      \( -name "litellm_init.pth" -o -name "litellm*.dist-info" -o -name "litellm*.egg-info" \) -print 2>/dev/null
  else
    find "${BROAD_SCAN_ROOTS[@]}" -maxdepth 10 \
      \( -path "*/.git" -o -path "*/node_modules" -o -path "*/__pycache__" \
         -o -path "*/.cache" -o -path "*/Library/Caches" \) -prune -o \
      \( -name "litellm_init.pth" -o -name "litellm*.dist-info" -o -name "litellm*.egg-info" \) -print 2>/dev/null
  fi
}

# Collect known site-packages directories from Python interpreters (avoids find /)
get_site_packages() {
  {
    for py in python3 python python3.9 python3.10 python3.11 python3.12 python3.13; do
      command -v "$py" &>/dev/null || continue
      "$py" -c "
import site
pkgs = getattr(site, 'getsitepackages', lambda: [])()
user = getattr(site, 'getusersitepackages', lambda: '')()
for p in pkgs + ([user] if user else []):
    print(p)
" 2>/dev/null
    done
    # Homebrew
    for prefix in /usr/local /opt/homebrew; do
      [ -d "$prefix/lib" ] && find "$prefix/lib" -maxdepth 4 -name "site-packages" -type d 2>/dev/null
    done
    # pyenv
    [ -d "$HOME/.pyenv/versions" ] && \
      find "$HOME/.pyenv/versions" -maxdepth 6 -name "site-packages" -type d 2>/dev/null
    # System Python
    find /usr/lib /usr/local/lib /Library/Python \
      -maxdepth 7 -name "site-packages" -type d 2>/dev/null
    # macOS framework Python
    find /System/Library/Frameworks/Python.framework \
      -maxdepth 8 -name "site-packages" -type d 2>/dev/null
  } | sort -u | grep -v '^$'
}

SITE_PACKAGES=()
while IFS= read -r p; do
  [ -d "$p" ] && SITE_PACKAGES+=("$p")
done < <(get_site_packages)

BROAD_HITS_FILE=$(mktemp -t litellm_broad_hits)
trap 'rm -f "$BROAD_HITS_FILE"' EXIT
collect_broad_hits | sort -u > "$BROAD_HITS_FILE"

echo "Python site-packages roots found: ${#SITE_PACKAGES[@]}"
for sp in "${SITE_PACKAGES[@]}"; do echo "  • $sp"; done
echo ""

# ─── 1. pip global install ────────────────────────────────────────────────────
echo "[1] Checking pip global install..."
_step1_found=0
for cmd in pip pip3 pip3.9 pip3.10 pip3.11 pip3.12 pip3.13; do
  command -v "$cmd" &>/dev/null || continue
  result=$($cmd show litellm 2>/dev/null)
  if [ -n "$result" ]; then
    flag_pip_result "$result" "$cmd"
    _step1_found=1
  fi
done
[ $_step1_found -eq 0 ] && echo "  ✅ not found"

# ─── 2. Known site-packages (installed package, not source clone) ─────────────
echo ""
echo "[2] Scanning known site-packages for litellm..."
_step2_found=0
for sp in "${SITE_PACKAGES[@]}"; do
  [ -d "$sp/litellm" ] || continue
  ver=$(ls "$sp" 2>/dev/null \
    | grep -E "^litellm-[0-9].*\.dist-info$" \
    | head -1 \
    | sed 's/litellm-\(.*\)\.dist-info/\1/')
  if [ -n "$ver" ]; then
    if is_malicious "$ver"; then
      echo "  🚨 INFECTED — litellm $ver installed at $sp"
      FOUND=1
    else
      echo "  ℹ️  litellm $ver at $sp (not a known malicious version)"
      INFO=1
    fi
  else
    echo "  ℹ️  litellm directory at $sp/litellm — no dist-info (may be source checkout, verify manually)"
  fi
  _step2_found=1
done
[ $_step2_found -eq 0 ] && echo "  ✅ not found in known site-packages"

# ─── 3. conda environments ────────────────────────────────────────────────────
echo ""
echo "[3] Checking conda environments..."
if command -v conda &>/dev/null; then
  _step3_found=0
  while IFS= read -r env; do
    result=$(conda run -n "$env" pip show litellm 2>/dev/null)
    if [ -n "$result" ]; then
      flag_pip_result "$result" "conda:$env"
      _step3_found=1
    fi
  done < <(conda env list 2>/dev/null | awk '{print $1}' | grep -v "^#" | grep -v "^$")
  [ $_step3_found -eq 0 ] && echo "  ✅ not found in any conda env"
else
  echo "  (conda not installed, skipping)"
fi

# ─── 4. pyenv versions ────────────────────────────────────────────────────────
echo ""
echo "[4] Checking pyenv versions..."
if command -v pyenv &>/dev/null; then
  _step4_found=0
  while IFS= read -r ver; do
    pip_path="$HOME/.pyenv/versions/$ver/bin/pip"
    [ -x "$pip_path" ] || continue
    result=$("$pip_path" show litellm 2>/dev/null)
    if [ -n "$result" ]; then
      flag_pip_result "$result" "pyenv:$ver"
      _step4_found=1
    fi
  done < <(pyenv versions --bare 2>/dev/null)
  [ $_step4_found -eq 0 ] && echo "  ✅ not found in any pyenv version"
else
  echo "  (pyenv not installed, skipping)"
fi

# ─── 5. Dependency files and lock files — version-aware ──────────────────────
echo ""
echo "[5] Searching project dependency files and lock files..."
_step5_found=0
# Exact pin to malicious version; covers extras (litellm[proxy]==), quoted variants
_PAT_EXACT='litellm([^=[:space:]]*)?\s*==\s*["'"'"']?(1\.82\.7|1\.82\.8)'
# Range/compatible release that could resolve to a malicious version
_PAT_RANGE='litellm([^=[:space:]]*)?\s*(>=|~=)\s*["'"'"']?1\.82\.[0-8]'

while IFS= read -r f; do
  # Lock files: look for malicious version string appearing within 5 lines of "litellm"
  if [[ "$f" == *.lock ]]; then
    if grep -qi "litellm" "$f" 2>/dev/null \
       && grep -qE '"(1\.82\.7|1\.82\.8)"' "$f" 2>/dev/null; then
      if grep -A5 -i "litellm" "$f" 2>/dev/null | grep -qE '"(1\.82\.7|1\.82\.8)"'; then
        ver=$(grep -A5 -i "litellm" "$f" 2>/dev/null \
              | grep -oE '"1\.82\.[78]"' | head -1 | tr -d '"')
        echo "  🚨 INFECTED — lock file records malicious litellm $ver  →  $f"
        FOUND=1; _step5_found=1
      fi
    fi
    continue
  fi

  matches=$(grep -i "litellm" "$f" 2>/dev/null | grep -ivE '^[[:space:]]*#') || continue
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    if echo "$line" | grep -qiE "$_PAT_EXACT"; then
      ver=$(echo "$line" | grep -oE "1\.82\.[78]" | head -1)
      echo "  🚨 INFECTED — pins malicious litellm $ver  →  $f"
      echo "     $line"
      FOUND=1
    elif echo "$line" | grep -qiE "$_PAT_RANGE"; then
      echo "  ⚠️  RISKY — version range may include malicious versions  →  $f"
      echo "     $line"
      INFO=1
    else
      echo "  ℹ️  litellm reference (verify version is safe)  →  $f"
      echo "     $line"
      INFO=1
    fi
    _step5_found=1
  done <<< "$matches"
done < <(collect_dependency_files)
[ $_step5_found -eq 0 ] && echo "  ✅ no litellm references found"

# ─── 6. Virtual environments (.venv / venv / env) ────────────────────────────
echo ""
echo "[6] Scanning project virtual environments..."
_step6_found=0
while IFS= read -r venv; do
  pip_bin="$venv/bin/pip"
  [ -x "$pip_bin" ] || continue
  result=$("$pip_bin" show litellm 2>/dev/null)
  if [ -n "$result" ]; then
    flag_pip_result "$result" "venv:$venv"
    _step6_found=1
  fi
done < <(collect_venv_dirs)
[ $_step6_found -eq 0 ] && echo "  ✅ not found in any virtual env"

# ─── 7. uv ───────────────────────────────────────────────────────────────────
echo ""
echo "[7] Checking uv..."
if command -v uv &>/dev/null; then
  result=$(uv pip show litellm 2>/dev/null)
  if [ -n "$result" ]; then
    flag_pip_result "$result" "uv"
  else
    echo "  ✅ not found in uv default environment"
  fi
else
  echo "  (uv not installed, skipping)"
fi

# ─── 8. dist-info / egg-info — version-aware ─────────────────────────────────
echo ""
echo "[8] Searching for litellm dist-info / egg-info..."
_step8_found=0
while IFS= read -r d; do
  ver=$(basename "$d" | sed -E 's/litellm-(.+)\.(dist-info|egg-info)$/\1/')
  if is_malicious "$ver"; then
    echo "  🚨 INFECTED — dist-info for malicious version $ver: $d"
    FOUND=1
  else
    echo "  ℹ️  dist-info for litellm $ver: $d (not a known malicious version)"
    INFO=1
  fi
  _step8_found=1
done < <({
  for sp in "${SITE_PACKAGES[@]}"; do
    find "$sp" -maxdepth 1 \( -name "litellm*.dist-info" -o -name "litellm*.egg-info" \) 2>/dev/null
  done
  grep -E 'litellm.*\.(dist-info|egg-info)$' "$BROAD_HITS_FILE" 2>/dev/null
} | sort -u)
[ $_step8_found -eq 0 ] && echo "  ✅ not found"

# ─── 9. CRITICAL: litellm_init.pth (v1.82.8 backdoor) ───────────────────────
echo ""
echo "[9] CRITICAL: Searching for litellm_init.pth (v1.82.8 backdoor)..."
_step9_found=0
# Check in known site-packages first (fast)
for sp in "${SITE_PACKAGES[@]}"; do
  if [ -f "$sp/litellm_init.pth" ]; then
    echo "  🚨 FOUND litellm_init.pth — SYSTEM IS COMPROMISED: $sp/litellm_init.pth"
    _step9_found=1
    FOUND=1
  fi
done
# Broader scan of user dirs and common Python locations
while IFS= read -r f; do
  echo "  🚨 FOUND litellm_init.pth — SYSTEM IS COMPROMISED: $f"
  _step9_found=1
  FOUND=1
done < <(grep '/litellm_init\.pth$' "$BROAD_HITS_FILE" 2>/dev/null)
[ $_step9_found -eq 0 ] && echo "  ✅ litellm_init.pth not found"

# ─── 10. Non-standard .pth files in site-packages only ───────────────────────
echo ""
echo "[10] Listing non-standard .pth files in known site-packages..."
# Match against filename only (not full path) to avoid false negatives from path components like "site-packages"
KNOWN_PTH_NAMES="^(_virtualenv|_uv_ephemeral_overlay|easy-install|distutils|distutils-precedence|setuptools|wheel|pip|pkg_resources|aeosa)$"
_step10_found=0
for sp in "${SITE_PACKAGES[@]}"; do
  while IFS= read -r f; do
    fname=$(basename "$f" .pth)
    echo "$fname" | grep -qE "$KNOWN_PTH_NAMES" && continue
    echo "  ⚠️  Unexpected .pth file (review manually): $f"
    _step10_found=1
  done < <(find "$sp" -maxdepth 1 -name "*.pth" 2>/dev/null)
done
[ $_step10_found -eq 0 ] && echo "  ✅ no unexpected .pth files"

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "========================================="
if [ $FOUND -eq 1 ]; then
  echo "  🚨 MALICIOUS litellm version detected!"
  echo ""
  echo "  Immediate actions:"
  echo "  1. pip uninstall litellm -y  (in every affected env)"
  echo "  2. Delete litellm_init.pth if found (step 9)"
  echo "  3. ROTATE ALL CREDENTIALS immediately:"
  echo "     - API keys (OpenAI, Anthropic, etc.)"
  echo "     - SSH keys (~/.ssh/)"
  echo "     - AWS / GCP / Azure credentials"
  echo "     - Database passwords"
  echo "     - Any secrets in .env files or shell history"
  echo "  4. Review all connected services for unauthorized access"
elif [ $INFO -eq 1 ]; then
  echo "  ℹ️  litellm found — NOT a known malicious version."
  echo "     Confirm version is not 1.82.7 or 1.82.8."
  echo "     Note: PyPI has suspended the package; consider alternatives."
else
  echo "  ✅ No litellm infection detected. You are safe."
fi
echo "========================================="
