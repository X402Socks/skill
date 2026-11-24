#!/usr/bin/env bash
# Regression test for Skillstore audit v10: fail-closed target checks, exact
# provider origins, three-state reconciliation, trusted single-use approvals,
# actual signer binding, untrusted provider labels, and hardened credential
# preflight. Runs offline with a fake curl; no network and no real token.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HELPER="$ROOT/skills/x402socks/scripts/x402socks.sh"
SKILL="$ROOT/skills/x402socks/SKILL.md"
PAY="$ROOT/skills/x402socks/references/payments.md"
END="$ROOT/skills/x402socks/references/endpoints.md"
TROUBLE="$ROOT/skills/x402socks/references/troubleshooting.md"
APPROVAL="$ROOT/skills/x402socks/assets/purchase-approval.md"
PLUGIN="$ROOT/.claude-plugin/plugin.json"
MARKETPLACE="$ROOT/.claude-plugin/marketplace.json"
[ -f "$HELPER" ] || { echo "missing $HELPER" >&2; exit 2; }

fail=0
pass() { printf 'PASS %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*" >&2; fail=1; }
has() { grep -Fq -- "$2" "$1"; }
lacks() { ! grep -Fq -- "$2" "$1"; }
check_has() {
  local file="$1" text="$2" label="$3"
  if has "$file" "$text"; then pass "$label"; else bad "$label"; fi
}
check_lacks() {
  local file="$1" text="$2" label="$3"
  if lacks "$file" "$text"; then pass "$label"; else bad "$label"; fi
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/x402socks-v135.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/bin"
TOK="$WORK/token"
mkdir -p "$BIN"
chmod 700 "$WORK"
printf '%s' 'TOKEN-abc123' > "$TOK"
chmod 600 "$TOK"
BADTOK="$WORK/bad-token"
printf '%s' 'TOKEN-abc123' > "$BADTOK"
chmod 644 "$BADTOK"
export X402SOCKS_TOKEN_FILE="$TOK"
export FAKE_CURL_LOG="$WORK/curl.log"
unset X402SOCKS_ALLOW_INSECURE_API X402SOCKS_BASELINE_IP X402SOCKS_ALLOW_DIRECT_BASELINE || true

cat > "$BIN/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${FAKE_CURL_LOG:?}"
cat >/dev/null 2>&1 || true
if [ "${FAKE_STATUS-}" = fail ]; then
  exit 7
fi
case "$*" in
  *"/nodes.json"*) printf '%s' "${NODES_JSON:-${FAKE_RESPONSE:-}}" ; exit 0 ;;
  *"%{http_code}"*) printf '%s' "${FAKE_STATUS:-204}" ; exit 0 ;;
esac
prev=""
for a in "$@"; do
  if [ "$prev" = "--noproxy" ]; then
    if [ "$a" = "*" ]; then printf '%s' "${FAKE_DIRECT_IP:-203.0.113.10}"; else printf '%s' "${FAKE_PROXY_IP:-198.51.100.20}"; fi
    exit 0
  fi
  prev="$a"
done
printf '%s' "${FAKE_RESPONSE:-${FAKE_STATUS:-204}}"
EOF
chmod +x "$BIN/curl"
PATH="$BIN:$PATH"
export PATH
NODES_JSON='{"nodes":[{"id":"eu-north1","hostname":"https://eu-north1.x402socks.com","port":3129,"health":"healthy","disabled":false,"label":"EU North"}]}'
export NODES_JSON

run_helper() {
  local out rc
  rm -f "$FAKE_CURL_LOG"
  out="$(env "$@" bash "$HELPER" "${HELPER_ARGS[@]}" 2>&1)"
  rc=$?
  LAST_OUT="$out"
  LAST_RC="$rc"
  LAST_CALLS=0
  [ -f "$FAKE_CURL_LOG" ] && LAST_CALLS="$(wc -l < "$FAKE_CURL_LOG" | tr -d ' ')"
  return 0
}

# 1. Reconciliation is three-state and never guesses after an inconclusive check.
HELPER_ARGS=(reconcile)
run_helper FAKE_STATUS=204
if [ "$LAST_RC" -eq 0 ] && has <(printf '%s' "$LAST_OUT") '"state":"valid_token"'; then
  pass "reconcile exit 0 means a valid token exists"
else
  bad "reconcile valid (rc=$LAST_RC) output=$LAST_OUT"
fi

run_helper FAKE_STATUS=401
if [ "$LAST_RC" -eq 10 ] && has <(printf '%s' "$LAST_OUT") '"state":"no_valid_token"'; then
  pass "reconcile exit 10 means definitively no token"
else
  bad "reconcile none (rc=$LAST_RC) output=$LAST_OUT"
fi

run_helper FAKE_STATUS=500
if [ "$LAST_RC" -eq 1 ] && has <(printf '%s' "$LAST_OUT") '"state":"inconclusive"'; then
  pass "reconcile exit 1 means inconclusive"
else
  bad "reconcile inconclusive (rc=$LAST_RC) output=$LAST_OUT"
fi

run_helper FAKE_STATUS=fail
if [ "$LAST_RC" -eq 1 ] && has <(printf '%s' "$LAST_OUT") '"state":"inconclusive"'; then
  pass "reconcile transport failure is inconclusive"
else
  bad "reconcile transport failure (rc=$LAST_RC) output=$LAST_OUT"
fi

run_helper X402SOCKS_TOKEN_FILE="$BADTOK" FAKE_STATUS=401
if [ "$LAST_RC" -eq 1 ] && has <(printf '%s' "$LAST_OUT") '"state":"inconclusive"'; then
  pass "reconcile refuses to call an unreadable token 'no token'"
else
  bad "reconcile unreadable token (rc=$LAST_RC) output=$LAST_OUT"
fi

# 2. Credentials use the helper's private file checks through proxy-config.
HELPER_ARGS=(proxy-config eu-north1)
run_helper FAKE_RESPONSE="$NODES_JSON" FAKE_STATUS=204
if [ "$LAST_RC" -eq 0 ] &&
   has <(printf '%s' "$LAST_OUT") 'proxy = "https://eu-north1.x402socks.com:3129"' &&
   has <(printf '%s' "$LAST_OUT") 'proxy-user = "TOKEN-abc123:TOKEN-abc123"'; then
  pass "proxy-config emits a TLS CONNECT config from the checked token file"
else
  bad "proxy-config (rc=$LAST_RC) output=$LAST_OUT"
fi

HELPER_ARGS=(proxy-config)
run_helper FAKE_STATUS=204
if [ "$LAST_RC" -ne 0 ] && has <(printf '%s' "$LAST_OUT") "usage: proxy-config"; then
  pass "proxy-config requires an exit id"
else
  bad "proxy-config missing exit (rc=$LAST_RC) output=$LAST_OUT"
fi

# 3. The insecure opt-in only permits loopback origins.
HELPER_ARGS=(status)
run_helper X402SOCKS_WEB=http://127.0.0.1:9 X402SOCKS_ALLOW_INSECURE_API=1 FAKE_RESPONSE='{}'
if [ "$LAST_RC" -eq 0 ] && [ "$LAST_CALLS" -ge 1 ]; then
  pass "loopback test override still works with explicit consent"
else
  bad "loopback override (rc=$LAST_RC) output=$LAST_OUT"
fi

run_helper X402SOCKS_WEB=https://evil.example X402SOCKS_ALLOW_INSECURE_API=1
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
   has <(printf '%s' "$LAST_OUT") "loopback host"; then
  pass "non-loopback test override is refused before any request"
else
  bad "non-loopback override (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

run_helper X402SOCKS_WEB=https://x402socks.com:8443
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
   has <(printf '%s' "$LAST_OUT") ":443"; then
  pass "credential origin pins the port"
else
  bad "credential origin port (rc=$LAST_RC) output=$LAST_OUT"
fi

# 4. The egress baseline needs an operator value or explicit consent.
HELPER_ARGS=(test eu-north1)
run_helper FAKE_RESPONSE="$NODES_JSON" FAKE_STATUS=204
if [ "$LAST_RC" -ne 0 ] && has <(printf '%s' "$LAST_OUT") "X402SOCKS_BASELINE_IP"; then
  pass "egress test refuses to fetch a direct IP without consent"
else
  bad "egress consent (rc=$LAST_RC) output=$LAST_OUT"
fi

run_helper X402SOCKS_BASELINE_IP=203.0.113.10 FAKE_RESPONSE="$NODES_JSON" FAKE_STATUS=204
if [ "$LAST_RC" -eq 0 ] && has <(printf '%s' "$LAST_OUT") "operator-provided direct egress baseline"; then
  pass "operator-provided egress baseline is used without a public lookup"
else
  bad "operator baseline (rc=$LAST_RC) output=$LAST_OUT"
fi

run_helper X402SOCKS_BASELINE_IP=not-an-ip FAKE_RESPONSE="$NODES_JSON" FAKE_STATUS=204
if [ "$LAST_RC" -ne 0 ] && has <(printf '%s' "$LAST_OUT") "must be an IP address"; then
  pass "operator-provided egress baseline is parsed as an IP"
else
  bad "operator baseline validation (rc=$LAST_RC) output=$LAST_OUT"
fi

# 5. Provider text is labelled before it reaches an agent transcript.
HELPER_ARGS=(nodes)
run_helper FAKE_RESPONSE='{"nodes":[]}' FAKE_STATUS=
if [ "$LAST_RC" -eq 0 ] && has <(printf '%s' "$LAST_OUT") "UNTRUSTED PROVIDER DATA"; then
  pass "provider-derived helper output is labelled untrusted"
else
  bad "provider label (rc=$LAST_RC) output=$LAST_OUT"
fi

# 6. Documentation enforces the same contract.
check_has "$SKILL" "version: 1.3.5" "skill version is 1.3.5"
check_has "$SKILL" "UNTRUSTED PROVIDER DATA" "skill labels provider output"
check_has "$SKILL" '"state":"inconclusive"' "skill names the inconclusive reconcile state"
check_has "$SKILL" "set -e" "skill shell example is fail-fast"
check_has "$SKILL" "proxy-config" "skill uses the hardened credential preflight"
check_lacks "$SKILL" 'cat ~/.config/x402socks/token' "skill does not read the token directly"

check_has "$PAY" "approvalId" "payment example binds a durable approval ID"
check_has "$PAY" "approvalHash" "payment example verifies an approval hash"
check_has "$PAY" "reconcile" "payment example uses three-state reconciliation"
check_has "$PAY" "code === 10" "TypeScript accepts only definitive no-token"
check_has "$PAY" "result.returncode != 10" "Python accepts only definitive no-token"
check_has "$PAY" "loadHostSigner" "TypeScript binds the actual signer"
check_has "$PAY" "load_host_signer" "Python binds the actual signer"
check_has "$PAY" "hstat.mode" "TypeScript checks helper permissions"
check_has "$PAY" "st_mode" "Python checks helper permissions"
check_lacks "$PAY" "X402SOCKS_HELPER" "payment examples reject helper path overrides"
check_lacks "$PAY" "hasValidToken" "payment examples no longer fail open"

check_has "$END" "proxy-config" "client snippets use the hardened credential preflight"
check_has "$END" "serviceWorkers: \"block\"" "Playwright blocks service workers"
check_has "$END" "--disable-webrtc" "Playwright disables WebRTC"
check_has "$END" "UNTRUSTED PROVIDER DATA" "endpoints labels provider output"
check_lacks "$END" "socks5h://" "endpoints publish no SOCKS5 address"
check_lacks "$END" "http://<exit>.x402socks.com:3128" "endpoints publish no plaintext address"
check_lacks "$END" 'cat ~/.config/x402socks/token' "endpoints do not read the token directly"

check_has "$TROUBLE" "reconcile" "troubleshooting uses the three-state check"
check_has "$TROUBLE" "exit 1" "troubleshooting stops on inconclusive reconciliation"
check_has "$TROUBLE" "serviceWorkers: \"block\"" "troubleshooting blocks service workers"
check_has "$TROUBLE" "--disable-webrtc" "troubleshooting disables WebRTC"
check_has "$TROUBLE" "X402SOCKS_BASELINE_IP" "troubleshooting documents egress consent"
check_has "$TROUBLE" "UNTRUSTED PROVIDER DATA" "troubleshooting labels provider output"

check_has "$APPROVAL" "approval_id" "approval template has a durable approval ID"
check_has "$APPROVAL" "approval_hash" "approval template has an approval hash"
check_has "$APPROVAL" "reconcile" "approval template uses three-state reconciliation"
check_has "$APPROVAL" "approval-claims" "approval template claims by ID in a private dir"
check_has "$APPROVAL" "Actual signer object" "approval template binds the actual signer"
check_lacks "$APPROVAL" "<approval-file>.consumed" "approval template no longer marks a path"

check_has "$PLUGIN" '"version": "1.3.5"' "plugin manifest is 1.3.5"
check_has "$MARKETPLACE" '"version": "1.3.5"' "marketplace manifest is 1.3.5"

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES PRESENT" >&2; fi
exit "$fail"
