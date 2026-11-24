#!/usr/bin/env bash
# Regression test for Skillstore audit v7 medium: token reads must enforce the
# same ownership, file type, permission, and symlink checks as writes. Runs
# offline with a fake `curl`; no network, no real token.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="$ROOT/skills/x402socks/scripts/x402socks.sh"
[ -f "$SKILL" ] || { echo "missing $SKILL" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/x402socks-read.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/bin"
DIR="$WORK/tokens"
export FAKE_CURL_LOG="$WORK/curl-argv.log"
mkdir -p "$BIN" "$DIR"
chmod 700 "$WORK" "$DIR"

export PATH="$BIN:$PATH"

cat > "$BIN/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${FAKE_CURL_LOG:?}"
cat >/dev/null 2>&1 || true
printf '%s' "${FAKE_RESPONSE-}"
EOF
chmod +x "$BIN/curl"

fail=0
pass() { printf 'PASS %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*" >&2; fail=1; }
contains() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }
calls() {
  if [ -f "$FAKE_CURL_LOG" ]; then wc -l < "$FAKE_CURL_LOG" | tr -d ' '; else printf '0'; fi
}

LAST_OUT=""
LAST_RC=0
LAST_CALLS=0

run_status() {
  rm -f "$FAKE_CURL_LOG"
  LAST_OUT="$(printf '' | env X402SOCKS_TOKEN_FILE="$1" FAKE_RESPONSE='{}' \
    bash "$SKILL" status 2>&1)"
  LAST_RC=$?
  LAST_CALLS="$(calls)"
}

# 1. A private regular file is read and used.
TOK="$DIR/token"
printf '%s' 'TOKEN-abc123' > "$TOK"
chmod 600 "$TOK"
run_status "$TOK"
if [ "$LAST_RC" -eq 0 ] && [ "$LAST_CALLS" -ge 1 ]; then
  pass "private mode-600 token is read and used"
else
  bad "private token (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

# 2. A group/world readable token is refused before any request.
chmod 644 "$TOK"
run_status "$TOK"
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
   contains "$LAST_OUT" "accessible to group/other"; then
  pass "mode-644 token is refused before any request"
else
  bad "mode-644 token (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

# 3. A symlink is refused even when its target is private.
chmod 600 "$TOK"
ln -s "$TOK" "$DIR/link"
run_status "$DIR/link"
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
   contains "$LAST_OUT" "not a regular file"; then
  pass "symlinked token is refused before any request"
else
  bad "symlinked token (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

# 4. A FIFO is refused before any request.
mkfifo "$DIR/fifo"
run_status "$DIR/fifo"
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
   contains "$LAST_OUT" "not a regular file"; then
  pass "FIFO token is refused before any request"
else
  bad "FIFO token (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

# 5. A directory is refused before any request.
mkdir "$DIR/asdir"
run_status "$DIR/asdir"
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
   contains "$LAST_OUT" "not a regular file"; then
  pass "directory token is refused before any request"
else
  bad "directory token (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

# 6. save-token refuses to replace a group/world readable file and leaves it
#    unchanged.
printf '%s' 'OLD-TOKEN-abc123' > "$TOK"
chmod 644 "$TOK"
rm -f "$FAKE_CURL_LOG"
LAST_OUT="$(printf '%s\n' 'NEW-TOKEN-abc123' | env X402SOCKS_TOKEN_FILE="$TOK" \
  bash "$SKILL" save-token 2>&1)"
LAST_RC=$?
LAST_CALLS="$(calls)"
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
   [ "$(cat "$TOK")" = 'OLD-TOKEN-abc123' ] &&
   contains "$LAST_OUT" "accessible to group/other"; then
  pass "save-token refuses a mode-644 destination and keeps the old file"
else
  bad "save-token mode-644 (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES PRESENT" >&2; fi
exit "$fail"
