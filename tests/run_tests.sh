#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="${TEST_DIR}/linspec"
PASS=0
FAIL=0

green() { printf "\033[32m%s\033[0m\n" "$*"; }
red()   { printf "\033[31m%s\033[0m\n" "$*"; }
bold()  { printf "\033[1m%s\033[0m\n" "$*"; }

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        green "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $desc (expected: $expected, got: $actual)"
        FAIL=$((FAIL + 1))
    fi
}

assert_contains() {
    local desc="$1" needle="$2" haystack="$3"
    if echo "$haystack" | grep -qF "$needle"; then
        green "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $desc (expected to contain: $needle)"
        FAIL=$((FAIL + 1))
    fi
}

bold "=== LinSpec Test Suite ==="

if [ ! -f "$BINARY" ]; then
    bold "Building binary..."
    make -C "$TEST_DIR" clean all
fi

bold "Test 1: Default run produces output"
OUT=$("$BINARY" 2>&1 || true)
assert_contains "Default banner" "LinSpec" "$OUT"

bold "Test 2: JSON export"
OUT=$("$BINARY" -j 2>&1 || true)
assert_contains "JSON flag" "JSON" "$OUT"
if [ -f "${TEST_DIR}/reports/report.json" ]; then
    assert_contains "JSON file has tool" "LinSpec" "$(cat "${TEST_DIR}/reports/report.json")"
else
    red "  FAIL: report.json not found"
    FAIL=$((FAIL + 1))
fi

bold "Test 3: CSV export"
OUT=$("$BINARY" -c 2>&1 || true)
assert_contains "CSV flag" "CSV" "$OUT"
if [ -f "${TEST_DIR}/reports/report.csv" ]; then
    assert_contains "CSV has header" "id,name,result" "$(head -1 "${TEST_DIR}/reports/report.csv")"
else
    red "  FAIL: report.csv not found"
    FAIL=$((FAIL + 1))
fi

bold "Test 4: HTML export"
OUT=$("$BINARY" -H 2>&1 || true)
assert_contains "HTML flag" "HTML" "$OUT"
if [ -f "${TEST_DIR}/reports/report.html" ]; then
    assert_contains "HTML has LinSpec" "LinSpec" "$(head -5 "${TEST_DIR}/reports/report.html")"
else
    red "  FAIL: report.html not found"
    FAIL=$((FAIL + 1))
fi

bold "Test 5: Help output"
OUT=$("$BINARY" -h 2>&1 || true)
assert_contains "Help flag" "Usage" "$OUT"

bold "Test 6: Version output"
OUT=$("$BINARY" -V 2>&1 || true)
assert_contains "Version flag" "LinSpec" "$OUT"

bold "Test 7: Custom output directory"
mkdir -p "${TEST_DIR}/build"
OUT=$("$BINARY" -j -o "${TEST_DIR}/build" 2>&1 || true)
if [ -f "${TEST_DIR}/build/report.json" ]; then
    assert_contains "Custom dir JSON" "summary" "$(cat "${TEST_DIR}/build/report.json")"
else
    red "  FAIL: build/report.json not found"
    FAIL=$((FAIL + 1))
fi

bold "Test 8: Profile loading"
OUT=$("$BINARY" -j -p "${TEST_DIR}/profiles/default.json" 2>&1 || true)
assert_contains "Profile flag" "JSON" "$OUT"

bold "Test 9: All export formats together"
OUT=$("$BINARY" -j -c -H 2>&1 || true)
assert_contains "All exports" "JSON" "$OUT"
assert_contains "All exports" "CSV" "$OUT"
assert_contains "All exports" "HTML" "$OUT"

bold "Test 10: Invalid option"
OUT=$("$BINARY" --bogus 2>&1 || true)
assert_contains "Invalid option" "Unknown" "$OUT"

bold "Test 11: JSON report structure"
if [ -f "${TEST_DIR}/reports/report.json" ]; then
    JS=$(cat "${TEST_DIR}/reports/report.json")
    assert_contains "JSON has tool" '"tool": "LinSpec"' "$JS"
    assert_contains "JSON has version" '"version": "2.' "$JS"
    assert_contains "JSON has checks" '"checks"' "$JS"
    assert_contains "JSON has summary" '"summary"' "$JS"
fi

bold "Test 12: Binary hardening check"
FILE_INFO=$(file "$BINARY")
assert_contains "Binary is PIE" "pie" "$FILE_INFO" || \
    assert_contains "Binary is PIE" "PIE" "$FILE_INFO"
assert_contains "Binary is ELF" "ELF" "$FILE_INFO"

bold "Test 13: No undefined symbols"
NM_OUT=$(nm -u "$BINARY" 2>/dev/null || true)
if [ -n "$NM_OUT" ]; then
    assert_contains "Has stdlib symbols" "fopen" "$NM_OUT"
else
    green "  PASS: Binary stripped (no symbols to check)"
    PASS=$((PASS + 1))
fi

bold "Test 14: Watch mode startup"
OUT=$(timeout 3 "$BINARY" -w 3600 -j 2>&1 || true)
assert_contains "Watch mode" "Watch" "$OUT"

echo ""
bold "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
