#!/usr/bin/env bash
# Regression test for Skillstore audit v7 high: credential-bearing commands must
# only target x402socks hosts. A valid certificate proves which host answered,
# not that the host is allowed to receive a token. Runs offline with a fake
# `curl`; no network, no real token.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="$ROOT/skills/x402socks/scripts/x402socks.sh"
[ -f "$SKILL" ] || { echo "missing $SKILL" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/x402socks-host.XXXXXX")"
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
unset X402SOCKS_ALLOW_INSECURE_API || true

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

run_case() {
  local var="$1" url="$2" cmd="$3"
  shift 3
  rm -f "$FAKE_CURL_LOG"
  LAST_OUT="$(printf '' | env "$var=$url" FAKE_RESPONSE='{}' \
    bash "$SKILL" "$cmd" "$@" 2>&1)"
  LAST_RC=$?
  LAST_CALLS="$(calls)"
}

# 1. Every credential command refuses a non-x402socks host before any request.
for spec in \
  'X402SOCKS_WEB https://evil.example status' \
  'X402SOCKS_WEB https://evil.example validate' \
  'X402SOCKS_API https://evil.example rotate' \
  'X402SOCKS_PAY https://evil.example recover 0xabc 1700000000' \
  'X402SOCKS_WEB https://evil.example test eu-north1'
do
  set -- $spec
  var="$1"; url="$2"; cmd="$3"; shift 3
  run_case "$var" "$url" "$cmd" "$@"
  # Credential commands pin exact origins, including the default port.
  want="got an untrusted origin"
  if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
     contains "$LAST_OUT" "$want"; then
    pass "$cmd refuses $url before any request"
  else
    bad "$cmd host refusal (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
  fi
done

# 2. The production hosts are accepted.
run_case X402SOCKS_WEB "https://x402socks.com" status
if [ "$LAST_CALLS" -ge 1 ]; then
  pass "status accepts https://x402socks.com"
else
  bad "status trusted host (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

run_case X402SOCKS_API "https://api.x402socks.com" rotate
if [ "$LAST_CALLS" -ge 1 ]; then
  pass "rotate accepts https://api.x402socks.com"
else
  bad "rotate trusted host (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

rm -f "$FAKE_CURL_LOG"
LAST_OUT="$(printf '0xsig\n' | env X402SOCKS_PAY="https://payments.x402socks.com" \
  FAKE_RESPONSE='{}' bash "$SKILL" recover 0xabc 1700000000 2>&1)"
LAST_RC=$?
LAST_CALLS="$(calls)"
if [ "$LAST_CALLS" -ge 1 ]; then
  pass "recover accepts https://payments.x402socks.com"
else
  bad "recover trusted host (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

# 3. The explicit insecure opt-in permits only a loopback test host.
rm -f "$FAKE_CURL_LOG"
LAST_OUT="$(printf '' | env X402SOCKS_WEB="http://127.0.0.1:9" \
  X402SOCKS_ALLOW_INSECURE_API=1 FAKE_RESPONSE='{}' bash "$SKILL" status 2>&1)"
LAST_RC=$?
LAST_CALLS="$(calls)"
if [ "$LAST_CALLS" -ge 1 ] && contains "$LAST_OUT" "WARNING:"; then
  pass "X402SOCKS_ALLOW_INSECURE_API=1 permits a loopback test with a warning"
else
  bad "loopback opt-in (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

rm -f "$FAKE_CURL_LOG"
LAST_OUT="$(printf '' | env X402SOCKS_WEB="https://evil.example" \
  X402SOCKS_ALLOW_INSECURE_API=1 FAKE_RESPONSE='{}' bash "$SKILL" status 2>&1)"
LAST_RC=$?
LAST_CALLS="$(calls)"
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
   contains "$LAST_OUT" "loopback host"; then
  pass "non-loopback test host is refused even with the opt-in"
else
  bad "opt-in host (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES PRESENT" >&2; fi
exit "$fail"
