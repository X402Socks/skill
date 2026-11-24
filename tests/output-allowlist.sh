#!/usr/bin/env bash
# Regression test for Skillstore audit v8 medium: credential-bearing responses
# must be printed as an allowlist. Runs offline with a fake curl; no network.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="$ROOT/skills/x402socks/scripts/x402socks.sh"
[ -f "$SKILL" ] || { echo "missing $SKILL" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/x402socks-allow.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/bin"
TOK="$WORK/token"
mkdir -p "$BIN"
chmod 700 "$WORK"

cat > "$BIN/curl" <<'EOF'
#!/usr/bin/env bash
cat >/dev/null 2>&1 || true
printf '%s' "${FAKE_RESPONSE-}"
EOF
chmod +x "$BIN/curl"
export PATH="$BIN:$PATH"
export X402SOCKS_TOKEN_FILE="$TOK"
printf '%s' 'OLD-TOKEN-aaaa' > "$TOK"
chmod 600 "$TOK"

fail=0
pass() { printf 'PASS %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*" >&2; fail=1; }
contains() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }

status_response='{"status":"ok","account":{"id":"acct-1","token":"SECRET-A","api_key":"SECRET-B"},"usage":{"bytes_used":123},"request_id":"req-1","debug":"SECRET-C"}'
out="$(FAKE_RESPONSE="$status_response" bash "$SKILL" status 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && contains "$out" '"bytes_used": 123' &&
   ! contains "$out" 'acct-1' && ! contains "$out" 'SECRET-A' &&
   ! contains "$out" 'SECRET-B' && ! contains "$out" 'SECRET-C' &&
   ! contains "$out" 'request_id'; then
  pass "status prints only allowlisted non-credential fields"
else
  bad "status allowlist (rc=$rc) output=$out"
fi

rotate_response='{"token":"NEW-TOKEN-bbbb","account":{"id":"acct-1"},"secret_note":"SECRET-D","request_id":"req-2"}'
out="$(FAKE_RESPONSE="$rotate_response" bash "$SKILL" rotate 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && [ "$(cat "$TOK")" = 'NEW-TOKEN-bbbb' ] &&
   contains "$out" '<redacted: saved to' && contains "$out" '"saved_to"' &&
   ! contains "$out" 'acct-1' && ! contains "$out" 'SECRET-D' &&
   ! contains "$out" 'req-2' && ! contains "$out" 'NEW-TOKEN-bbbb'; then
  pass "rotation prints only the redacted marker and saved path"
else
  bad "rotation allowlist (rc=$rc token=$(cat "$TOK")) output=$out"
fi

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES PRESENT" >&2; fi
exit "$fail"
