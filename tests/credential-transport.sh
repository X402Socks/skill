#!/usr/bin/env bash
# Regression test for Skillstore audit v5 medium: credential-bearing requests
# must use HTTPS. A plaintext endpoint override is refused before the token or
# signature is read, and a real credential request restricts curl's transfer
# and redirect protocols to HTTPS.
#
# Runs entirely offline against a fake `curl` that records its argv. No network,
# no real token.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="$ROOT/skills/x402socks/scripts/x402socks.sh"
[ -f "$SKILL" ] || { echo "missing $SKILL" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/x402socks-transport.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/bin"
TOK="$WORK/token"
export FAKE_CURL_LOG="$WORK/curl-argv.log"
mkdir -p "$BIN"
chmod 700 "$WORK"
printf '%s' 'TOKEN-abc' > "$TOK"
chmod 600 "$TOK"

export X402SOCKS_TOKEN_FILE="$TOK"
export PATH="$BIN:$PATH"
unset X402SOCKS_ALLOW_INSECURE_API || true

# Fake curl: append its arguments to FAKE_CURL_LOG, drain stdin (the curl
# --config payload), then print FAKE_RESPONSE.
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

STDIN_DATA=""
ALLOW_INSECURE=0
FAKE_RESPONSE='{}'
LAST_OUT=""
LAST_RC=0
LAST_CALLS=0

# Run one credential command against an endpoint URL. $1 is the environment
# variable to override, $2 the URL, and the rest is the command.
run_cred() {
  local var="$1" url="$2"
  shift 2
  rm -f "$FAKE_CURL_LOG"
  LAST_OUT="$(printf '%s\n' "$STDIN_DATA" |
    env "$var=$url" \
        "X402SOCKS_ALLOW_INSECURE_API=$ALLOW_INSECURE" \
        "FAKE_RESPONSE=$FAKE_RESPONSE" \
        "$@" 2>&1)"
  LAST_RC=$?
  LAST_CALLS="$(calls)"
}

run_named() {
  local name="$1" url="$2"
  case "$name" in
    status)   run_cred X402SOCKS_WEB "$url" bash "$SKILL" status ;;
    validate) run_cred X402SOCKS_WEB "$url" bash "$SKILL" validate ;;
    rotate)   run_cred X402SOCKS_API "$url" bash "$SKILL" rotate ;;
    recover)  STDIN_DATA='0xsig'; run_cred X402SOCKS_PAY "$url" bash "$SKILL" recover 0xabc 1700000000 ;;
    test)     run_cred X402SOCKS_WEB "$url" bash "$SKILL" test eu-north1 ;;
    *)        bad "unknown case $name" ;;
  esac
}

# 1. Every credential command refuses a plaintext override by default, without
#    contacting any endpoint.
for name in status validate rotate recover test; do
  STDIN_DATA=""; ALLOW_INSECURE=0; FAKE_RESPONSE='{}'
  run_named "$name" "http://127.0.0.1:9"
  if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
     contains "$LAST_OUT" "must be an https:// URL"; then
    pass "$name refuses plaintext override before any request"
  else
    bad "$name plaintext refusal (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
  fi
done

# 2. A non-HTTP(S) scheme is always refused, even with the opt-in.
STDIN_DATA=""; ALLOW_INSECURE=1; FAKE_RESPONSE='{}'
run_named status "file:///tmp/evil"
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
   contains "$LAST_OUT" "must be an https:// URL"; then
  pass "non-HTTP(S) override refused even with opt-in"
else
  bad "non-HTTP(S) refusal (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

# 3. The explicit insecure opt-in lets a trusted local test proceed, and warns.
for name in status validate rotate recover test; do
  STDIN_DATA=""; ALLOW_INSECURE=1; FAKE_RESPONSE='{}'
  run_named "$name" "http://127.0.0.1:9"
  if [ "$LAST_CALLS" -ge 1 ] && contains "$LAST_OUT" "WARNING:"; then
    pass "$name honors X402SOCKS_ALLOW_INSECURE_API=1 with a warning"
  else
    bad "$name insecure opt-in (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
  fi
done

# 4. Real credential requests restrict the transfer and redirects to HTTPS.
STDIN_DATA=""; ALLOW_INSECURE=0; FAKE_RESPONSE='{}'
run_cred X402SOCKS_WEB "https://x402socks.com" bash "$SKILL" status
if [ "$LAST_CALLS" -ge 1 ] &&
   grep -qF -- "--proto =https" "$FAKE_CURL_LOG" &&
   grep -qF -- "--proto-redir =https" "$FAKE_CURL_LOG"; then
  pass "status request pins curl --proto and --proto-redir to https"
else
  bad "status https protocol pinning (calls=$LAST_CALLS) argv=$(cat "$FAKE_CURL_LOG" 2>/dev/null)"
fi

STDIN_DATA='0xsig'; ALLOW_INSECURE=0; FAKE_RESPONSE='{}'
run_cred X402SOCKS_PAY "https://payments.x402socks.com" bash "$SKILL" recover 0xabc 1700000000
if [ "$LAST_CALLS" -ge 1 ] &&
   grep -qF -- "--proto =https" "$FAKE_CURL_LOG" &&
   grep -qF -- "--proto-redir =https" "$FAKE_CURL_LOG"; then
  pass "recover request pins curl --proto and --proto-redir to https"
else
  bad "recover https protocol pinning (calls=$LAST_CALLS) argv=$(cat "$FAKE_CURL_LOG" 2>/dev/null)"
fi

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES PRESENT" >&2; fi
exit "$fail"
