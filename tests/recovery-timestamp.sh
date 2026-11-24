#!/usr/bin/env bash
# Regression test for Skillstore audit v7 low: recovery must use the timestamp
# that was actually signed, not a fresh one chosen by the helper. Runs offline
# with a fake `curl`; no network, no real token.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="$ROOT/skills/x402socks/scripts/x402socks.sh"
[ -f "$SKILL" ] || { echo "missing $SKILL" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/x402socks-recover.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/bin"
TOK="$WORK/token"
export FAKE_CURL_LOG="$WORK/curl-argv.log"
mkdir -p "$BIN"
chmod 700 "$WORK"
printf '%s' 'TOKEN-abc123' > "$TOK"
chmod 600 "$TOK"

export X402SOCKS_TOKEN_FILE="$TOK"
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

# 1. recover without issued_at fails before any request.
rm -f "$FAKE_CURL_LOG"
LAST_OUT="$(printf '0xsig\n' | FAKE_RESPONSE='{}' bash "$SKILL" recover 0xabc 2>&1)"
LAST_RC=$?
LAST_CALLS="$(calls)"
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
   contains "$LAST_OUT" "usage: recover <tx_hash> <issued_at>"; then
  pass "recover without issued_at fails before any request"
else
  bad "missing issued_at (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

# 2. recover-message prints the issued_at that must be passed back.
rm -f "$FAKE_CURL_LOG"
LAST_OUT="$(bash "$SKILL" recover-message 0xabc 2>&1)"
LAST_RC=$?
if [ "$LAST_RC" -eq 0 ] &&
   contains "$LAST_OUT" "pass the same issued_at to: recover 0xabc"; then
  pass "recover-message prints the issued_at to pass to recover"
else
  bad "recover-message (rc=$LAST_RC) output=$LAST_OUT"
fi

# 3. recover with issued_at proceeds to the request.
rm -f "$FAKE_CURL_LOG"
LAST_OUT="$(printf '0xsig\n' | FAKE_RESPONSE='{}' \
  bash "$SKILL" recover 0xabc 1700000000 2>&1)"
LAST_RC=$?
LAST_CALLS="$(calls)"
if [ "$LAST_CALLS" -ge 1 ]; then
  pass "recover with issued_at proceeds to the request"
else
  bad "issued_at present (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES PRESENT" >&2; fi
exit "$fail"
