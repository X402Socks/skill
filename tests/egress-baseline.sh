#!/usr/bin/env bash
# Regression test for Skillstore audit v7 medium plus v1.4.0 transport order.
# The helper must ignore ambient curl config and NO_PROXY, try SOCKS5 then TLS
# CONNECT then plaintext CONNECT, fetch a direct baseline only with consent, and
# fail when the egress IP is unchanged. Runs offline with a fake curl.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="$ROOT/skills/x402socks/scripts/x402socks.sh"
[ -f "$SKILL" ] || { echo "missing $SKILL" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/x402socks-egress.XXXXXX")"
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
unset X402SOCKS_ALLOW_INSECURE_API X402SOCKS_PROXY_TRANSPORT || true

cat > "$BIN/curl" <<'EOF'
#!/usr/bin/env bash
cfg="$(cat)"
{
  printf 'ARGS:'
  for a in "$@"; do
    if [ -z "$a" ]; then printf " ''"; else printf ' %s' "$a"; fi
  done
  printf '\n'
} >> "${FAKE_CURL_LOG:?}"
printf 'CFG:%s\n' "$cfg" >> "$FAKE_CURL_LOG"
case "$*" in
  *"/nodes.json"*)
    printf '%s' '{"nodes":[{"id":"eu-north1","health":"healthy","disabled":false}]}'
    exit 0
    ;;
esac
dest=""
prev=""
noproxy=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then dest="$a"; fi
  if [ "$prev" = "--noproxy" ]; then noproxy="$a"; fi
  prev="$a"
done
# Proxy requests put the URL in the curl config; the consent baseline uses argv.
if printf '%s\n' "$cfg" | grep -q 'api\.ipify\.org' ||
   [[ "$*" == *"api.ipify.org"* ]]; then
  if [ "$noproxy" = "*" ]; then
    printf '%s' "${FAKE_DIRECT_IP:?}"
    exit 0
  fi
  if [ -z "$noproxy" ]; then
    attempt="$(grep -c '^CFG:proxy = ' "$FAKE_CURL_LOG" || true)"
    if [ "$attempt" -le "${FAKE_FAIL_PROXY_ATTEMPTS:-0}" ]; then exit 7; fi
    printf '%s' "${FAKE_PROXY_IP:?}" > "$dest"
    printf '%s' "${FAKE_PROXY_STATUS:-200}"
    exit 0
  fi
fi
case "$*" in
  *"%{http_code}"*) printf '%s' "${FAKE_STATUS:-204}" ;;
  *) printf '%s' "${FAKE_RESPONSE-}" ;;
esac
EOF
chmod +x "$BIN/curl"

fail=0
pass() { printf 'PASS %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*" >&2; fail=1; }
contains() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }
calls() {
  if [ -f "$FAKE_CURL_LOG" ]; then grep -c '^ARGS:' "$FAKE_CURL_LOG" || true; else printf '0'; fi
}

LAST_OUT=""
LAST_RC=0
LAST_CALLS=0
EXTRA_ENV=()

run_test() {
  rm -f "$FAKE_CURL_LOG"
  LAST_OUT="$(env FAKE_DIRECT_IP="$1" FAKE_PROXY_IP="$2" \
    X402SOCKS_BASELINE_IP="$1" X402SOCKS_ALLOW_DIRECT_BASELINE=0 \
    "${EXTRA_ENV[@]}" bash "$SKILL" test eu-north1 2>&1)"
  LAST_RC=$?
  LAST_CALLS="$(calls)"
}

run_consent_test() {
  rm -f "$FAKE_CURL_LOG"
  LAST_OUT="$(env FAKE_DIRECT_IP="$1" FAKE_PROXY_IP="$2" \
    X402SOCKS_ALLOW_DIRECT_BASELINE=1 \
    "${EXTRA_ENV[@]}" bash "$SKILL" test eu-north1 2>&1)"
  LAST_RC=$?
  LAST_CALLS="$(calls)"
}

line_of() { grep -n -F -- "$1" "$FAKE_CURL_LOG" | head -1 | cut -d: -f1; }

# 1. An unchanged egress IP is a failure, not a pass.
EXTRA_ENV=(FAKE_FAIL_PROXY_ATTEMPTS=0)
run_test "203.0.113.10" "203.0.113.10"
if [ "$LAST_RC" -ne 0 ] && contains "$LAST_OUT" "did not change"; then
  pass "unchanged egress IP fails the probe"
else
  bad "unchanged IP (rc=$LAST_RC) output=$LAST_OUT"
fi

# 2. A different egress IP passes through SOCKS5 and reports the transport.
run_test "203.0.113.10" "198.51.100.20"
if [ "$LAST_RC" -eq 0 ] &&
   contains "$LAST_OUT" "transport: socks5" &&
   contains "$LAST_OUT" "direct IP: 203.0.113.10" &&
   contains "$LAST_OUT" "egress IP: 198.51.100.20"; then
  pass "different egress IP passes through the default SOCKS5 hop"
else
  bad "different IP (rc=$LAST_RC) output=$LAST_OUT"
fi

# 3. An operator baseline avoids a public IP lookup and the probe forces the proxy.
if grep -qF -- "--noproxy ''" "$FAKE_CURL_LOG" &&
   ! grep -qF -- "--noproxy *" "$FAKE_CURL_LOG" &&
   grep -qF -- 'proxy = "socks5h://eu-north1.x402socks.com:1080"' "$FAKE_CURL_LOG" &&
   contains "$LAST_OUT" "operator-provided direct egress baseline"; then
  pass "operator baseline avoids the direct lookup and the probe forces SOCKS5"
else
  bad "operator-baseline argv=$(cat "$FAKE_CURL_LOG" 2>/dev/null) output=$LAST_OUT"
fi

# 4. Explicit consent still permits a direct public IP baseline.
run_consent_test "203.0.113.10" "198.51.100.20"
if [ "$LAST_RC" -eq 0 ] && grep -qF -- "--noproxy *" "$FAKE_CURL_LOG"; then
  pass "explicit consent permits a direct no-proxy baseline"
else
  bad "consent baseline (rc=$LAST_RC) argv=$(cat "$FAKE_CURL_LOG" 2>/dev/null) output=$LAST_OUT"
fi

# 5. Failures move through TLS CONNECT to plaintext CONNECT in that order.
EXTRA_ENV=(FAKE_FAIL_PROXY_ATTEMPTS=2)
run_test "203.0.113.10" "198.51.100.20"
s5="$(line_of 'proxy = "socks5h://eu-north1.x402socks.com:1080"')"
tls="$(line_of 'proxy = "https://eu-north1.x402socks.com:3129"')"
plain="$(line_of 'proxy = "http://eu-north1.x402socks.com:3128"')"
if [ "$LAST_RC" -eq 0 ] && contains "$LAST_OUT" "transport: plaintext" &&
   [ -n "$s5" ] && [ -n "$tls" ] && [ -n "$plain" ] &&
   [ "$s5" -lt "$tls" ] && [ "$tls" -lt "$plain" ]; then
  pass "failed hops fall back from SOCKS5 to TLS CONNECT to plaintext CONNECT"
else
  bad "fallback order (rc=$LAST_RC) output=$LAST_OUT log=$(cat "$FAKE_CURL_LOG" 2>/dev/null)"
fi

# 6. No direct fallback when every proxy hop fails.
EXTRA_ENV=(FAKE_FAIL_PROXY_ATTEMPTS=3)
run_test "203.0.113.10" "198.51.100.20"
if [ "$LAST_RC" -ne 0 ] && contains "$LAST_OUT" "all allowed proxy transports failed" &&
   ! grep -qF -- "--noproxy *" "$FAKE_CURL_LOG"; then
  pass "all proxy failures stop without a direct fallback"
else
  bad "all hops fail (rc=$LAST_RC) output=$LAST_OUT"
fi

# 7. Explicit proxy-only TLS opt-in adds one warning and one insecure retry.
EXTRA_ENV=(FAKE_FAIL_PROXY_ATTEMPTS=3 X402SOCKS_ALLOW_INSECURE_PROXY_TLS=1)
run_test "203.0.113.10" "198.51.100.20"
if [ "$LAST_RC" -eq 0 ] && contains "$LAST_OUT" "transport: tls-insecure" &&
   contains "$LAST_OUT" "WARNING: retrying TLS CONNECT without proxy certificate verification" &&
   grep -qF -- '--proxy-insecure' "$FAKE_CURL_LOG" &&
   grep -qF -- 'proxy = "https://eu-north1.x402socks.com:3129"' "$FAKE_CURL_LOG"; then
  pass "explicit proxy-only TLS opt-in retries after all normal hops fail"
else
  bad "insecure proxy opt-in (rc=$LAST_RC) output=$LAST_OUT"
fi

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES PRESENT" >&2; fi
exit "$fail"
