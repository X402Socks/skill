#!/usr/bin/env bash
# Regression test for Skillstore audit v8 medium: quote must prove HTTP 402,
# require exactly one option, and reject non-finite or over-precise caps using
# integer atomic amounts. Runs offline with a fake curl; no network, no token.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="$ROOT/skills/x402socks/scripts/x402socks.sh"
[ -f "$SKILL" ] || { echo "missing $SKILL" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/x402socks-quote.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/bin"
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
printf '%s' "${FAKE_STATUS:-}"
EOF
chmod +x "$BIN/curl"
export PATH="$BIN:$PATH"

fail=0
pass() { printf 'PASS %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*" >&2; fail=1; }
contains() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }

challenge() {
  local count="$1" amount="$2"
  python3 -c '
import base64, json, sys
count, amount = int(sys.argv[1]), sys.argv[2]
accepts = [{
    "scheme": "exact", "network": "eip155:8453", "asset": "0xasset",
    "payTo": "0xpayto", "amount": amount, "maxTimeoutSeconds": 300,
    "extra": {"name": "USD Coin", "version": "2"},
}] * count
data = {"x402Version": 2, "resource": {
    "url": "https://payments.x402socks.com/v1/access",
    "description": "Create an x402socks proxy access account",
    "serviceName": "x402socks",
}, "accepts": accepts}
print(base64.b64encode(json.dumps(data).encode()).decode())
' "$count" "$amount"
}

run_quote() {
  local name="$1" status="$2" header="$3" cap="$4" want_rc="$5" want_text="$6"
  local out rc
  out="$(FAKE_STATUS="$status" FAKE_HEADERS="$header" \
         X402SOCKS_MAX_USDC="$cap" bash "$SKILL" quote time_6h 2>&1)"
  rc=$?
  if [ "$rc" = "$want_rc" ] && contains "$out" "$want_text"; then
    pass "$name"
  else
    bad "$name (rc=$rc, expected $want_rc) output=$out"
  fi
}

b64="$(challenge 1 1000000)"
hdr="payment-required: $b64\n"
run_quote "HTTP 402 with exact cap passes" 402 "$hdr" 1.00 0 "within approved cap"
run_quote "quote binds request URL and resource" 402 "$hdr" 1.00 0 '"request_url"'
run_quote "quote binds resource description" 402 "$hdr" 1.00 0 '"resource_description"'
run_quote "non-finite cap nan is refused" 402 "$hdr" nan 1 "finite, non-negative"
run_quote "non-finite cap inf is refused" 402 "$hdr" inf 1 "finite, non-negative"
run_quote "over-precise cap is refused" 402 "$hdr" 1.0000001 1 "6 decimal places"
run_quote "cap below live amount is refused" 402 "$hdr" 0.99 1 "approved cap is"
run_quote "non-402 reply is refused" 200 "$hdr" 1.00 1 "expected HTTP 402"
run_quote "multiple options are refused" 402 "payment-required: $(challenge 2 1000000)\n" 1.00 1 "exactly one"
run_quote "non-integer amount is refused" 402 "payment-required: $(challenge 1 1.5)\n" 1.00 1 "positive integer"
run_quote "missing header is refused" 402 "" 1.00 1 "no PAYMENT-REQUIRED"

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES PRESENT" >&2; fi
exit "$fail"
