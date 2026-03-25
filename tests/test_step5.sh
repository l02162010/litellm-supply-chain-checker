#!/bin/bash
# tests/test_step5.sh
# Fixture-based tests for step 5 (dependency file parsing).
# Runs check_litellm.sh with LITELLM_SCAN_ROOT pointed at fixture directories.
# No Python installation required.

SCRIPT="$(cd "$(dirname "$0")/.." && pwd)/check_litellm.sh"
FIXTURES="$(dirname "$0")/fixtures"
PASS=0
FAIL=0

assert_contains() {
  local label="$1" output="$2" expected="$3"
  if echo "$output" | grep -q "$expected"; then
    echo "  PASS  $label"
    ((PASS++))
  else
    echo "  FAIL  $label"
    echo "        expected to find: $expected"
    ((FAIL++))
  fi
}

assert_not_contains() {
  local label="$1" output="$2" unexpected="$3"
  if echo "$output" | grep -q "$unexpected"; then
    echo "  FAIL  $label"
    echo "        should NOT contain: $unexpected"
    ((FAIL++))
  else
    echo "  PASS  $label"
    ((PASS++))
  fi
}

echo "========================================"
echo "  Step 5 — Dependency File Tests"
echo "========================================"

# ── Infected fixtures ─────────────────────────────────────────────────────────
echo ""
echo "[ infected fixtures ]"
OUT=$(HOME="$FIXTURES" LITELLM_SCAN_ROOT="$FIXTURES/infected" bash "$SCRIPT" 2>/dev/null)

assert_contains \
  "flags litellm==1.82.7 in requirements.txt" \
  "$OUT" "INFECTED"

assert_contains \
  "detects extras syntax litellm[proxy]==1.82.8" \
  "$OUT" "1.82.8"

assert_contains \
  "detects malicious version in poetry.lock" \
  "$OUT" "lock file"

assert_contains \
  "final summary shows infection" \
  "$OUT" "MALICIOUS litellm version detected"

# ── Safe fixtures ─────────────────────────────────────────────────────────────
echo ""
echo "[ safe fixtures ]"
OUT=$(HOME="$FIXTURES" LITELLM_SCAN_ROOT="$FIXTURES/safe" bash "$SCRIPT" 2>/dev/null)

assert_not_contains \
  "does NOT flag litellm==1.82.6 as INFECTED" \
  "$OUT" "INFECTED"

assert_not_contains \
  "final summary does NOT show infection for safe pin" \
  "$OUT" "MALICIOUS litellm version detected"

assert_contains \
  "reports risky range that includes 1.82.8" \
  "$OUT" "RISKY"

assert_not_contains \
  "commented malicious pin is NOT flagged" \
  "$OUT" "pins malicious litellm 1.82.8"

# ── .pth filter regression ────────────────────────────────────────────────────
echo ""
echo "[ step 10 — .pth filter regression ]"
TMP_SP=$(mktemp -d)
touch "$TMP_SP/bad_actor.pth"
touch "$TMP_SP/_virtualenv.pth"
touch "$TMP_SP/setuptools.pth"
# Inject a fake site-packages path by checking the filter logic directly
FILTER_OUT=$(
  KNOWN_PTH_NAMES="^(_virtualenv|_uv_ephemeral_overlay|easy-install|distutils|setuptools|wheel|pip|pkg_resources|aeosa)$"
  for f in "$TMP_SP"/*.pth; do
    fname=$(basename "$f" .pth)
    echo "$fname" | grep -qE "$KNOWN_PTH_NAMES" && continue
    echo "UNEXPECTED: $f"
  done
)
rm -rf "$TMP_SP"

assert_contains \
  "bad_actor.pth is reported (not filtered by path component)" \
  "$FILTER_OUT" "bad_actor"

assert_not_contains \
  "_virtualenv.pth is NOT reported" \
  "$FILTER_OUT" "_virtualenv"

assert_not_contains \
  "setuptools.pth is NOT reported" \
  "$FILTER_OUT" "setuptools"

# ── Step 8/9 — scan root isolation ─────────────────────────────────────────────
echo ""
echo "[ step 8/9 — scan root isolation ]"
TMP_SCAN=$(mktemp -d)
TMP_HOME=$(mktemp -d)
mkdir -p "$TMP_SCAN/lib/python3.11/site-packages/litellm-1.82.8.egg-info"
touch "$TMP_HOME/litellm_init.pth"
OUT=$(HOME="$TMP_HOME" LITELLM_SCAN_ROOT="$TMP_SCAN" bash "$SCRIPT" 2>/dev/null)
rm -rf "$TMP_SCAN" "$TMP_HOME"

assert_contains \
  "egg-info under scan root is detected" \
  "$OUT" "dist-info for malicious version 1.82.8"

assert_not_contains \
  "HOME-only litellm_init.pth is ignored when scan root is set" \
  "$OUT" "SYSTEM IS COMPROMISED"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "========================================"
[ $FAIL -eq 0 ] && exit 0 || exit 1
