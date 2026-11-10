#!/usr/bin/env bash
# Regression test for Skillstore audit v5 medium: rotation invalidates the old
# token before local storage is validated. The helper must reserve a private,
# writable staging file before the rotate request, and abort without contacting
# the API when the token directory or file is unsafe. Runs offline with a fake
# `curl`; no network, no real token.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="$ROOT/skills/x402socks/scripts/x402socks.sh"
[ -f "$SKILL" ] || { echo "missing $SKILL" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/x402socks-rotate.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/bin"
mkdir -p "$BIN"
chmod 700 "$WORK"

export PATH="$BIN:$PATH"
export FAKE_CURL_LOG="$WORK/curl-argv.log"

# Fake curl: record argv, drain stdin (the curl --config payload), and emit the
# configured response.
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
mode() { python3 -c 'import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777)[2:])' "$1"; }
calls() { if [ -f "$FAKE_CURL_LOG" ]; then wc -l < "$FAKE_CURL_LOG" | tr -d ' '; else printf '0'; fi; }
new_secret_file() { find "$1" -maxdepth 1 -name '.token.*' -print -quit; }

SECRET="NEW-TOKEN-DO-NOT-PRINT"
LAST_OUT=""
LAST_RC=0
LAST_CALLS=0

run_rotate() {
  local tok="$1"
  rm -f "$FAKE_CURL_LOG"
  LAST_OUT="$(FAKE_RESPONSE="{\"token\":\"$SECRET\",\"account\":{\"id\":\"acct-1\"}}" \
    X402SOCKS_TOKEN_FILE="$tok" bash "$SKILL" rotate 2>&1)"
  LAST_RC=$?
  LAST_CALLS="$(calls)"
}

contains() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }
leaked() { contains "$1" "$SECRET"; }

# 1. Private storage: rotation proceeds, saves the replacement, redacts it, and
#    leaves no staging file behind.
DIR="$WORK/private"
mkdir -m 700 "$DIR"
TOK="$DIR/token"
printf '%s' 'OLD-TOKEN' > "$TOK"
chmod 600 "$TOK"
run_rotate "$TOK"
if [ "$LAST_RC" -eq 0 ] && [ "$LAST_CALLS" -eq 1 ] &&
   [ "$(cat "$TOK")" = "$SECRET" ] && [ "$(mode "$TOK")" = 600 ] &&
   ! leaked "$LAST_OUT" && [ -z "$(new_secret_file "$DIR")" ]; then
  pass "private storage: rotate saves mode-600 token, redacted, no staging left"
else
  bad "private storage rotate (rc=$LAST_RC calls=$LAST_CALLS mode=$(mode "$TOK")) output=$LAST_OUT"
fi

# 2. World-writable directory: abort before the API call, keep the old token.
DIR="$WORK/public"
mkdir -m 777 "$DIR"
TOK="$DIR/token"
printf '%s' 'OLD-TOKEN' > "$TOK"
chmod 600 "$TOK"
chmod 777 "$DIR"
run_rotate "$TOK"
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
   [ "$(cat "$TOK")" = 'OLD-TOKEN' ] && ! leaked "$LAST_OUT" &&
   contains "$LAST_OUT" "not private"; then
  pass "unsafe directory: aborts before rotate, old token untouched"
else
  bad "unsafe directory (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

# 3. Symlinked token file: abort before the API call, leave the target alone.
DIR="$WORK/symlink-file"
mkdir -m 700 "$DIR"
printf '%s' 'OLD-TOKEN' > "$DIR/real-token"
chmod 600 "$DIR/real-token"
ln -s "$DIR/real-token" "$DIR/token"
run_rotate "$DIR/token"
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
   [ "$(cat "$DIR/real-token")" = 'OLD-TOKEN' ] && ! leaked "$LAST_OUT" &&
   contains "$LAST_OUT" "symlink"; then
  pass "symlinked token file: aborts before rotate"
else
  bad "symlinked token file (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

# 4. Symlinked token directory: abort before the API call.
mkdir -m 700 "$WORK/real-dir"
ln -s "$WORK/real-dir" "$WORK/link-dir"
TOK="$WORK/link-dir/token"
printf '%s' 'OLD-TOKEN' > "$TOK"
chmod 600 "$TOK"
run_rotate "$TOK"
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
   [ "$(cat "$TOK")" = 'OLD-TOKEN' ] && ! leaked "$LAST_OUT" &&
   contains "$LAST_OUT" "not a real directory"; then
  pass "symlinked token directory: aborts before rotate"
else
  bad "symlinked token directory (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES PRESENT" >&2; fi
exit "$fail"
