#!/usr/bin/env bash
# Regression test for Skillstore audit v9 helper findings: quote requires an
# approved cap, quote/recover pin the canonical payment origin, and provider text
# is strictly validated before it reaches an agent transcript. Offline, fake curl.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="$ROOT/skills/x402socks/scripts/x402socks.sh"
[ -f "$SKILL" ] || { echo "missing $SKILL" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/x402socks-v134.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/bin"
TOK="$WORK/token"
mkdir -p "$BIN"
chmod 700 "$WORK"

cat > "$BIN/curl" <<'EOF'
#!/usr/bin/env bash
cat >/dev/null 2>&1 || true
dest=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  if [ "${args[i]}" = "-D" ]; then
    dest="${args[i + 1]:-}"
  fi
done
[ -z "$dest" ] || printf '%b' "${FAKE_HEADERS-}" > "$dest"
printf '%s' "${FAKE_RESPONSE-}${FAKE_STATUS-}"
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

challenge() {
  python3 -c '
import base64, json
data = {"x402Version": 2, "resource": {
    "url": "https://payments.x402socks.com/v1/access",
    "description": "Create an x402socks proxy access account",
    "serviceName": "x402socks",
}, "accepts": [{
    "scheme": "exact", "network": "eip155:8453", "asset": "0xasset",
    "payTo": "0xpayto", "amount": "1000000", "maxTimeoutSeconds": 300,
    "extra": {"name": "USD Coin", "version": "2"},
}]}
print(base64.b64encode(json.dumps(data).encode()).decode())
'
}
hdr="payment-required: $(challenge)\n"

# 1. A missing cap is a hard error, not a warning with a successful quote.
out="$(bash "$SKILL" quote time_6h 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && contains "$out" "requires X402SOCKS_MAX_USDC"; then
  pass "quote refuses to run without an approved cap"
else
  bad "unset cap was accepted (rc=$rc) output=$out"
fi

# 2. quote pins the payment origin before any request.
out="$(X402SOCKS_PAY=https://evil.example.com X402SOCKS_MAX_USDC=1.00 \
       bash "$SKILL" quote time_6h 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && contains "$out" "must use https://payments.x402socks.com"; then
  pass "quote refuses a non-canonical payment origin"
else
  bad "quote accepted a foreign payment origin (rc=$rc) output=$out"
fi

# 3. recover pins the same origin before reading the signature.
out="$(printf '%s\n' 'SIG' | X402SOCKS_PAY=https://evil.example.com \
       bash "$SKILL" recover 0xabc 1792000000 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && contains "$out" "must use https://payments.x402socks.com"; then
  pass "recover refuses a non-canonical payment origin"
else
  bad "recover accepted a foreign payment origin (rc=$rc) output=$out"
fi

# 4. The explicit insecure opt-in is the only way past the origin check. With a
#    cap set, the request proceeds and fails on the empty fake 402 status.
out="$(X402SOCKS_PAY=http://127.0.0.1:9999 X402SOCKS_ALLOW_INSECURE_API=1 \
       X402SOCKS_MAX_USDC=1.00 bash "$SKILL" quote time_6h 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && contains "$out" "expected HTTP 402" &&
   contains "$out" "WARNING"; then
  pass "insecure opt-in is required and visible for a test origin"
else
  bad "insecure opt-in behavior wrong (rc=$rc) output=$out"
fi

# 5. Provider text with non-ASCII is refused by the catalog summary.
out="$(FAKE_RESPONSE='{"packages":[{"id":"time_6h","price_usd":"1","name":"caf\u00e9","entitlements":[]}]}' \
       bash "$SKILL" catalog --summary 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && contains "$out" "strict text validation"; then
  pass "catalog summary rejects non-ASCII provider text"
else
  bad "catalog summary accepted non-ASCII text (rc=$rc) output=$out"
fi

# 6. Provider text with a control character is refused by price.
out="$(FAKE_RESPONSE='{"packages":[{"id":"time_6h","name":"bad\nname"}]}' \
       bash "$SKILL" price time_6h 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && contains "$out" "strict text validation"; then
  pass "price rejects control characters in provider text"
else
  bad "price accepted a control character (rc=$rc) output=$out"
fi

# 7. Node labels are validated before printing.
out="$(FAKE_RESPONSE='{"nodes":[{"id":"eu-north1","hostname":"h","port":3129,"health":"healthy","label":"bad\rtab"}]}' \
       bash "$SKILL" nodes 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && contains "$out" "strict text validation"; then
  pass "nodes rejects control characters in labels"
else
  bad "nodes accepted a control character (rc=$rc) output=$out"
fi

# 8. Status fields are validated before the allowlist prints them.
out="$(FAKE_RESPONSE='{"status":"o\u00e9k"}' bash "$SKILL" status 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && contains "$out" "strict text validation"; then
  pass "status rejects non-ASCII provider text"
else
  bad "status accepted non-ASCII text (rc=$rc) output=$out"
fi

# 9. A clean provider response still prints through the allowlist.
out="$(FAKE_RESPONSE='{"status":"ok","usage":{"bytes_used":10}}' \
       bash "$SKILL" status 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && contains "$out" '"status": "ok"' &&
   contains "$out" '"bytes_used": 10'; then
  pass "clean status output still works"
else
  bad "clean status regression (rc=$rc) output=$out"
fi

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES PRESENT" >&2; fi
exit "$fail"
