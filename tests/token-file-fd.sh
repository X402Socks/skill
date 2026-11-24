#!/usr/bin/env bash
# Regression test for Skillstore audit v8 medium: token validation and the read
# must use the same descriptor. A sitecustomize hook fails if the helper ever
# reopens the token by path. Runs offline with a fake curl; no real token.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="$ROOT/skills/x402socks/scripts/x402socks.sh"
[ -f "$SKILL" ] || { echo "missing $SKILL" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/x402socks-fd.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/bin"
PY="$WORK/py"
DIR="$WORK/tokens"
export FAKE_CURL_LOG="$WORK/curl-argv.log"
mkdir -p "$BIN" "$PY" "$DIR"
chmod 700 "$WORK" "$DIR"

cat > "$BIN/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${FAKE_CURL_LOG:?}"
cat >/dev/null 2>&1 || true
printf '%s' '{}'
EOF
chmod +x "$BIN/curl"
export PATH="$BIN:$PATH"

cat > "$PY/sitecustomize.py" <<'EOF'
import builtins, os
target = os.path.abspath(os.environ.get("X402_TEST_TOKEN_PATH", ""))
_real_open = builtins.open

def guarded_open(file, *args, **kwargs):
    try:
        path = os.path.abspath(os.fspath(file))
    except TypeError:
        path = ""
    if target and path == target:
        raise AssertionError("token file was reopened by path")
    return _real_open(file, *args, **kwargs)

builtins.open = guarded_open
EOF
export PYTHONPATH="$PY${PYTHONPATH:+:$PYTHONPATH}"

fail=0
pass() { printf 'PASS %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*" >&2; fail=1; }
contains() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }
calls() {
  [ -f "$FAKE_CURL_LOG" ] && wc -l < "$FAKE_CURL_LOG" || printf '0\n'
}

TOKEN='TOKEN-fd-abc123'
TOK="$DIR/token"
printf '%s' "$TOKEN" > "$TOK"
chmod 600 "$TOK"
export X402_TEST_TOKEN_PATH="$TOK"

# Prove the guard would catch a path-based reopen.
guard_out="$(python3 -c 'import os; open(os.environ["X402_TEST_TOKEN_PATH"])' 2>&1)"; guard_rc=$?
if [ "$guard_rc" -ne 0 ] && contains "$guard_out" "reopened by path"; then
  pass "test guard detects a path-based token reopen"
else
  bad "test guard did not fire (rc=$guard_rc) output=$guard_out"
fi

rm -f "$FAKE_CURL_LOG"
out="$(env X402SOCKS_TOKEN_FILE="$TOK" bash "$SKILL" status 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && [ "$(calls)" -ge 1 ] && ! contains "$out" "reopened by path"; then
  pass "descriptor-bound token read succeeds without reopening the path"
else
  bad "descriptor-bound read (rc=$rc calls=$(calls)) output=$out"
fi
if ! contains "$(cat "$FAKE_CURL_LOG")" "$TOKEN"; then
  pass "token never appears in curl arguments"
else
  bad "token leaked into curl arguments"
fi

rm -f "$FAKE_CURL_LOG"
ln -s "$TOK" "$DIR/link"
out="$(env X402SOCKS_TOKEN_FILE="$DIR/link" bash "$SKILL" status 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && [ "$(calls)" -eq 0 ] && contains "$out" "not a regular file"; then
  pass "symlink is refused without opening the target"
else
  bad "symlink (rc=$rc calls=$(calls)) output=$out"
fi

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES PRESENT" >&2; fi
exit "$fail"
