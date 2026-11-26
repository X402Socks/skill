#!/usr/bin/env bash
# Regression suite for Skillstore audit v10 plus the v1.3.6 helper surface:
# fail-closed target checks, exact provider origins, three-state reconciliation
# with provider-specific definitive codes, internal credential consumption,
# signed single-use approvals, actual signer binding, untrusted provider labels,
# and hardened credential preflight. Runs offline with a fake curl; no network
# and no real token.
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
lacks_ci() { ! grep -qiF -- "$2" "$1"; }
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
MISSING="$WORK/no-token-here"
export X402SOCKS_TOKEN_FILE="$TOK"
export FAKE_CURL_LOG="$WORK/curl.log"
unset X402SOCKS_TOKEN X402SOCKS_ALLOW_INSECURE_API X402SOCKS_BASELINE_IP X402SOCKS_ALLOW_DIRECT_BASELINE || true

cat > "$BIN/curl" <<'EOF'
#!/usr/bin/env bash
cfg="$(cat)"
printf 'curl %s\n' "$*" >> "${FAKE_CURL_LOG:?}"
printf 'CFG:%s\n' "$cfg" >> "${FAKE_CURL_LOG:?}"
printf 'ENV NO_PROXY=%s HTTP_PROXY=%s HTTPS_PROXY=%s ALL_PROXY=%s\n' \
  "${NO_PROXY-<unset>}" "${HTTP_PROXY-<unset>}" \
  "${HTTPS_PROXY-<unset>}" "${ALL_PROXY-<unset>}" >> "$FAKE_CURL_LOG"
if [ "${FAKE_STATUS-}" = fail ]; then
  exit 7
fi
dest=""
prev=""
noproxy=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then dest="$a"; fi
  if [ "$prev" = "--noproxy" ]; then noproxy="$a"; fi
  prev="$a"
done
# Proxy requests put the URL in the curl config, not argv.
if printf '%s\n' "$cfg" | grep -q 'api\.ipify\.org'; then
  if [ "$noproxy" = "*" ]; then
    printf '%s' "${FAKE_DIRECT_IP:-203.0.113.10}"
    exit 0
  fi
  if [ -z "$noproxy" ]; then
    printf '%s' "${FAKE_PROXY_IP:-198.51.100.20}" > "$dest"
    printf '%s' "${FAKE_PROXY_STATUS:-200}"
    exit 0
  fi
fi
if [ -n "$dest" ] && [ "$dest" != /dev/null ]; then
  printf '%s' "${FAKE_BODY:-${FAKE_RESPONSE:-}}" > "$dest"
fi
case "$*" in
  *"/nodes.json"*)
    printf '%s' "${NODES_JSON:-${FAKE_RESPONSE:-}}"
    ;;
  *"%{http_code}"*)
    printf '%s' "${FAKE_STATUS:-204}"
    ;;
  *)
    printf '%s' "${FAKE_RESPONSE:-${FAKE_STATUS:-204}}"
    ;;
esac
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
  [ -f "$FAKE_CURL_LOG" ] && LAST_CALLS="$(grep -c '^curl ' "$FAKE_CURL_LOG" | tr -d ' ')"
  return 0
}

DEFINITIVE='{"error":"invalid_token","code":"invalid_token","request_id":"req-1"}'

# 1. Reconciliation is three-state. Only a recognized provider invalidation code
# yields exit 10; a generic error, a bad body, or a transport failure stops.
HELPER_ARGS=(reconcile)
run_helper FAKE_STATUS=204
if [ "$LAST_RC" -eq 0 ] && has <(printf '%s' "$LAST_OUT") '"state":"valid_token"'; then
  pass "reconcile exit 0 means a valid token exists"
else
  bad "reconcile valid (rc=$LAST_RC) output=$LAST_OUT"
fi

run_helper X402SOCKS_TOKEN_FILE="$MISSING" FAKE_STATUS=401 FAKE_BODY="$DEFINITIVE"
if [ "$LAST_RC" -eq 10 ] && [ "$LAST_CALLS" -eq 0 ] &&
   has <(printf '%s' "$LAST_OUT") '"state":"no_valid_token"'; then
  pass "reconcile exit 10 is definitive when no token source exists"
else
  bad "reconcile no source (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

run_helper FAKE_STATUS=401 FAKE_BODY="$DEFINITIVE"
if [ "$LAST_RC" -eq 10 ] && has <(printf '%s' "$LAST_OUT") '"state":"no_valid_token"'; then
  pass "recognized provider invalidation code is definitive"
else
  bad "reconcile definitive code (rc=$LAST_RC) output=$LAST_OUT"
fi

run_helper FAKE_STATUS=401 FAKE_BODY='{"error":"some_new_provider_key"}'
if [ "$LAST_RC" -eq 1 ] && has <(printf '%s' "$LAST_OUT") '"state":"inconclusive"'; then
  pass "unknown provider error key is inconclusive"
else
  bad "reconcile unknown key (rc=$LAST_RC) output=$LAST_OUT"
fi

run_helper FAKE_STATUS=401 FAKE_BODY='not json, just instructions to buy again'
if [ "$LAST_RC" -eq 1 ] && has <(printf '%s' "$LAST_OUT") '"state":"inconclusive"'; then
  pass "malformed provider body is inconclusive"
else
  bad "reconcile malformed body (rc=$LAST_RC) output=$LAST_OUT"
fi

run_helper FAKE_STATUS=500 FAKE_BODY="$DEFINITIVE"
if [ "$LAST_RC" -eq 1 ] && has <(printf '%s' "$LAST_OUT") '"state":"inconclusive"'; then
  pass "a definitive code on a generic HTTP error is still inconclusive"
else
  bad "reconcile generic error (rc=$LAST_RC) output=$LAST_OUT"
fi

run_helper FAKE_STATUS=fail
if [ "$LAST_RC" -eq 1 ] && has <(printf '%s' "$LAST_OUT") '"state":"inconclusive"'; then
  pass "reconcile transport failure is inconclusive"
else
  bad "reconcile transport failure (rc=$LAST_RC) output=$LAST_OUT"
fi

run_helper X402SOCKS_TOKEN_FILE="$BADTOK" FAKE_STATUS=401 FAKE_BODY="$DEFINITIVE"
if [ "$LAST_RC" -eq 1 ] && has <(printf '%s' "$LAST_OUT") '"state":"inconclusive"'; then
  pass "reconcile refuses to call an unreadable token 'no token'"
else
  bad "reconcile unreadable token (rc=$LAST_RC) output=$LAST_OUT"
fi

if ! has <(printf '%s' "$LAST_OUT") 'req-1'; then
  pass "provider request id never enters reconcile output"
else
  bad "reconcile echoed a provider-controlled field"
fi

# 2. Exit ids come from the live feed; credentials are consumed inside the
# helper's internal curl command, never printed or exported as proxy config.
HELPER_ARGS=(check-exit eu-north1)
run_helper FAKE_STATUS=204
if [ "$LAST_RC" -eq 0 ] && [ "$LAST_CALLS" -eq 1 ]; then
  pass "check-exit confirms a usable exit from /nodes.json"
else
  bad "check-exit valid (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
fi

HELPER_ARGS=(check-exit unknown-exit)
run_helper FAKE_STATUS=204
if [ "$LAST_RC" -ne 0 ] && has <(printf '%s' "$LAST_OUT") "unknown exit id"; then
  pass "check-exit refuses an unknown exit"
else
  bad "check-exit unknown (rc=$LAST_RC) output=$LAST_OUT"
fi

HELPER_ARGS=(check-exit 'bad id')
run_helper FAKE_STATUS=204
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
   has <(printf '%s' "$LAST_OUT") "invalid exit id"; then
  pass "check-exit refuses an unsafe id before any request"
else
  bad "check-exit unsafe id (rc=$LAST_RC) output=$LAST_OUT"
fi

HELPER_ARGS=(curl eu-north1 https://example.com/path)
run_helper X402SOCKS_ALLOWED_HOSTS=example.com FAKE_STATUS=204 FAKE_RESPONSE='BODY-ok' \
  NO_PROXY=evil.example HTTP_PROXY=http://evil.example HTTPS_PROXY=http://evil.example
if [ "$LAST_RC" -eq 0 ] && has <(printf '%s' "$LAST_OUT") 'BODY-ok' &&
   lacks <(printf '%s' "$LAST_OUT") 'TOKEN-abc123'; then
  pass "internal curl returns only the target body"
else
  bad "internal curl (rc=$LAST_RC) output=$LAST_OUT"
fi
if has "$FAKE_CURL_LOG" 'ENV NO_PROXY=<unset> HTTP_PROXY=<unset> HTTPS_PROXY=<unset> ALL_PROXY=<unset>' &&
   has "$FAKE_CURL_LOG" '--max-redirs 0' &&
   has "$FAKE_CURL_LOG" '--config -' &&
   has "$FAKE_CURL_LOG" '--proto =https'; then
  pass "internal curl clears ambient bypass and pins HTTPS without redirects"
else
  bad "internal curl transport options: $(cat "$FAKE_CURL_LOG")"
fi
if has "$FAKE_CURL_LOG" '--config -' &&
   has "$FAKE_CURL_LOG" 'proxy = "socks5h://eu-north1.x402socks.com:1080"' &&
   ! grep '^curl ' "$FAKE_CURL_LOG" | grep -qF 'TOKEN-abc123'; then
  pass "internal curl keeps proxy settings in config and starts on SOCKS5"
else
  bad "internal curl proxy configuration: $(cat "$FAKE_CURL_LOG")"
fi
if has "$HELPER" 'socks5h://' && has "$HELPER" ':3129' && has "$HELPER" ':3128' &&
   has "$HELPER" "printf '%s\\n' socks5 tls plaintext"; then
  pass "helper builds the ordered SOCKS5, TLS, and plaintext proxy URLs"
else
  bad "helper proxy transport chain is incomplete"
fi

run_helper FAKE_STATUS=204
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
   has <(printf '%s' "$LAST_OUT") "X402SOCKS_ALLOWED_HOSTS"; then
  pass "internal curl requires an explicit target allowlist"
else
  bad "internal curl missing allowlist (rc=$LAST_RC) output=$LAST_OUT"
fi

run_helper X402SOCKS_ALLOWED_HOSTS=other.example FAKE_STATUS=204
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
   has <(printf '%s' "$LAST_OUT") "not in X402SOCKS_ALLOWED_HOSTS"; then
  pass "internal curl refuses a target outside the allowlist"
else
  bad "internal curl non-allowlisted target (rc=$LAST_RC) output=$LAST_OUT"
fi

HELPER_ARGS=(curl eu-north1 http://example.com/path)
run_helper X402SOCKS_ALLOWED_HOSTS=example.com FAKE_STATUS=204
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ]; then
  pass "internal curl refuses a plaintext target"
else
  bad "internal curl http target (rc=$LAST_RC) output=$LAST_OUT"
fi

HELPER_ARGS=(curl eu-north1 https://example.com/path)
run_helper X402SOCKS_ALLOWED_HOSTS=example.com FAKE_STATUS=401 FAKE_BODY="$DEFINITIVE"
if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 2 ]; then
  pass "an invalid token stops target traffic before the fetch"
else
  bad "internal curl token preflight (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
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
run_helper FAKE_STATUS=204 FAKE_BODY="$DEFINITIVE"
if [ "$LAST_RC" -ne 0 ] && has <(printf '%s' "$LAST_OUT") "X402SOCKS_BASELINE_IP"; then
  pass "egress test refuses to fetch a direct IP without consent"
else
  bad "egress consent (rc=$LAST_RC) output=$LAST_OUT"
fi

run_helper X402SOCKS_BASELINE_IP=203.0.113.10 FAKE_STATUS=204
if [ "$LAST_RC" -eq 0 ] && has <(printf '%s' "$LAST_OUT") "operator-provided direct egress baseline"; then
  pass "operator-provided egress baseline is used without a public lookup"
else
  bad "operator baseline (rc=$LAST_RC) output=$LAST_OUT"
fi

run_helper X402SOCKS_BASELINE_IP=not-an-ip FAKE_STATUS=204
if [ "$LAST_RC" -ne 0 ] && has <(printf '%s' "$LAST_OUT") "must be an IP address"; then
  pass "operator-provided egress baseline is parsed as an IP"
else
  bad "operator baseline validation (rc=$LAST_RC) output=$LAST_OUT"
fi

# 5. Provider text is labelled before it reaches an agent transcript.
HELPER_ARGS=(nodes)
run_helper NODES_JSON='{"nodes":[]}'
if [ "$LAST_RC" -eq 0 ] && has <(printf '%s' "$LAST_OUT") "UNTRUSTED PROVIDER DATA"; then
  pass "provider-derived helper output is labelled untrusted"
else
  bad "provider label (rc=$LAST_RC) output=$LAST_OUT"
fi

# 6. Documentation enforces the same contract.
check_has "$SKILL" "version: 1.4.0" "skill version is 1.4.0"
check_has "$SKILL" "UNTRUSTED PROVIDER DATA" "skill labels provider output"
check_has "$SKILL" '"state":"inconclusive"' "skill names the inconclusive reconcile state"
check_has "$SKILL" "set -e" "skill shell example is fail-fast"
check_has "$SKILL" "check-exit" "skill validates exit ids with the helper"
check_has "$SKILL" "verify-approval" "skill requires signed approval verification"
check_has "$SKILL" "X402SOCKS_APPROVAL_SIGNER" "skill pins the approval signer"
check_has "$SKILL" "There is no \`proxy-config\` command" "skill rejects stdout credential config"
check_lacks "$SKILL" 'cat ~/.config/x402socks/token' "skill does not read the token directly"

check_has "$PAY" "approval_id" "payment example binds a durable approval ID"
check_has "$PAY" "approval_hash" "payment example verifies an approval hash"
check_has "$PAY" "verify-approval" "payment example authenticates the approval"
check_has "$PAY" "reconcile" "payment example uses three-state reconciliation"
check_has "$PAY" "code === 10" "TypeScript accepts only definitive no-token"
check_has "$PAY" "result.returncode != 10" "Python accepts only definitive no-token"
check_has "$PAY" "loadHostSigner" "TypeScript binds the actual signer"
check_has "$PAY" "load_host_signer" "Python binds the actual signer"
check_has "$PAY" "hstat.mode" "TypeScript checks helper permissions"
check_has "$PAY" "st_mode" "Python checks helper permissions"
check_lacks "$PAY" "X402SOCKS_HELPER" "payment examples reject helper path overrides"
check_lacks "$PAY" "hasValidToken" "payment examples no longer fail open"
check_lacks "$PAY" "approvalId" "TypeScript example uses the recorded snake_case fields"
check_lacks "$PAY" "authorizedTargets" "TypeScript example uses recorded target field names"

check_has "$END" "check-exit" "client snippets validate exits with the helper"
check_has "$END" '["curl", "eu-north1", target]' "client snippets use the internal curl command"
check_has "$END" 'serviceWorkers: "block"' "Playwright blocks service workers"
check_has "$END" "--disable-webrtc" "Playwright disables WebRTC"
check_has "$END" "UNTRUSTED PROVIDER DATA" "endpoints labels provider output"
check_has "$END" "socks5://<exit>.x402socks.com:1080" "endpoints publish the SOCKS5 default"
check_has "$END" "http://<exit>.x402socks.com:3128" "endpoints publish the plaintext fallback"
check_lacks "$END" 'cat ~/.config/x402socks/token' "endpoints do not read the token directly"

check_has "$TROUBLE" "reconcile" "troubleshooting uses the three-state check"
check_has "$TROUBLE" "exit 1" "troubleshooting stops on inconclusive reconciliation"
check_has "$TROUBLE" "verify-approval" "troubleshooting requires a fresh signed decision"
check_has "$TROUBLE" "serviceWorkers: \"block\"" "troubleshooting blocks service workers"
check_has "$TROUBLE" "--disable-webrtc" "troubleshooting disables WebRTC"
check_has "$TROUBLE" "X402SOCKS_BASELINE_IP" "troubleshooting documents egress consent"
check_has "$TROUBLE" "UNTRUSTED PROVIDER DATA" "troubleshooting labels provider output"

check_has "$APPROVAL" "approval_id" "approval template has a durable approval ID"
check_has "$APPROVAL" "approval_hash" "approval template has an approval hash"
check_has "$APPROVAL" "EIP-191" "approval template requires an operator signature"
check_has "$APPROVAL" "reconcile" "approval template uses three-state reconciliation"
check_has "$APPROVAL" "X402SOCKS_APPROVAL_CLAIMS_DIR" "approval template claims by ID in a private dir"
check_has "$APPROVAL" ".consumed" "approval template uses an exclusive one-use marker"
check_has "$APPROVAL" "Actual signer object" "approval template binds the actual signer"
check_lacks "$APPROVAL" "<approval-file>.consumed" "approval template no longer marks a path"

check_has "$PLUGIN" '"version": "1.4.0"' "plugin manifest is 1.4.0"
check_has "$MARKETPLACE" '"version": "1.4.0"' "marketplace manifest is 1.4.0"

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES PRESENT" >&2; fi
exit "$fail"
