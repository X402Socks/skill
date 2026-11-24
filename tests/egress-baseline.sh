#!/usr/bin/env bash
# Regression test for Skillstore audit v7 medium: a successful probe must prove
# routing. The helper must ignore ambient curl config and NO_PROXY, fetch a
# direct baseline, force the selected proxy, and fail when the egress IP is
# unchanged. Runs offline with a fake `curl`; no network, no real token.
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
unset X402SOCKS_ALLOW_INSECURE_API || true

cat > "$BIN/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${FAKE_CURL_LOG:?}"
cat >/dev/null 2>&1 || true
case "$*" in
  *"/nodes.json"*)
    printf '%s' '{"nodes":[{"id":"eu-north1","health":"healthy","disabled":false}]}'
    exit 0
    ;;
esac
case "$*" in
  *"%{http_code}"*) printf '204'; exit 0 ;;
esac
prev=""
for a in "$@"; do
  if [ "$prev" = "--noproxy" ]; then
    if [ "$a" = "*" ]; then printf '%s' "${FAKE_DIRECT_IP:?}"; else printf '%s' "${FAKE_PROXY_IP:?}"; fi
    exit 0
  fi
  prev="$a"
done
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

run_test() {
  rm -f "$FAKE_CURL_LOG"
  LAST_OUT="$(env FAKE_DIRECT_IP="$1" FAKE_PROXY_IP="$2" \
    X402SOCKS_BASELINE_IP="$1" X402SOCKS_ALLOW_DIRECT_BASELINE=0 \
    bash "$SKILL" test eu-north1 2>&1)"
  LAST_RC=$?
  LAST_CALLS="$(calls)"
}

run_consent_test() {
  rm -f "$FAKE_CURL_LOG"
  LAST_OUT="$(env FAKE_DIRECT_IP="$1" FAKE_PROXY_IP="$2" \
    X402SOCKS_ALLOW_DIRECT_BASELINE=1 \
    bash "$SKILL" test eu-north1 2>&1)"
  LAST_RC=$?
  LAST_CALLS="$(calls)"
}

# 1. An unchanged egress IP is a failure, not a pass.
run_test "203.0.113.10" "203.0.113.10"
if [ "$LAST_RC" -ne 0 ] && contains "$LAST_OUT" "did not change"; then
  pass "unchanged egress IP fails the probe"
else
  bad "unchanged IP (rc=$LAST_RC) output=$LAST_OUT"
fi

# 2. A different egress IP passes and prints both values.
run_test "203.0.113.10" "198.51.100.20"
if [ "$LAST_RC" -eq 0 ] &&
   contains "$LAST_OUT" "direct IP: 203.0.113.10" &&
   contains "$LAST_OUT" "egress IP: 198.51.100.20"; then
  pass "different egress IP passes and prints the baseline"
else
  bad "different IP (rc=$LAST_RC) output=$LAST_OUT"
fi

# 3. An operator baseline avoids a public IP lookup; only the proxy is forced.
if grep -qF -- "-q " "$FAKE_CURL_LOG" &&
   grep -qF -- "--noproxy " "$FAKE_CURL_LOG" &&
   ! grep -qF -- "--noproxy *" "$FAKE_CURL_LOG" &&
   contains "$LAST_OUT" "operator-provided direct egress baseline"; then
  pass "operator baseline avoids the direct lookup and the probe forces the proxy"
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

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES PRESENT" >&2; fi
exit "$fail"
