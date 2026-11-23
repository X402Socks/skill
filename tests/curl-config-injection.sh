#!/usr/bin/env bash
# Regression test for Skillstore audit v6 medium: environment tokens and
# endpoint URLs could inject extra curl configuration lines through CR/LF or
# other control characters. The helper must reject them before any request,
# validate token syntax, and parse the endpoint URL before reading credentials.
#
# Runs entirely offline against a fake `curl` that records its argv and stdin.
# No network, no real token.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="$ROOT/skills/x402socks/scripts/x402socks.sh"
[ -f "$SKILL" ] || { echo "missing $SKILL" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/x402socks-inject.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/bin"
TOK="$WORK/token"
export FAKE_CURL_LOG="$WORK/curl-argv.log"
export FAKE_CURL_STDIN="$WORK/curl-stdin.log"
mkdir -p "$BIN"
chmod 700 "$WORK"
VALID_TOKEN='TOKEN-abc123'
printf '%s' "$VALID_TOKEN" > "$TOK"
chmod 600 "$TOK"

export X402SOCKS_TOKEN_FILE="$TOK"
export PATH="$BIN:$PATH"
unset X402SOCKS_ALLOW_INSECURE_API || true

# Fake curl: record argv and the --config payload, then print FAKE_RESPONSE.
cat > "$BIN/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${FAKE_CURL_LOG:?}"
cat > "${FAKE_CURL_STDIN:?}" 2>/dev/null || true
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
FAKE_RESPONSE='{}'

# Run the helper with an environment token and a fixed valid endpoint.
run_token() {
  rm -f "$FAKE_CURL_LOG" "$FAKE_CURL_STDIN"
  LAST_OUT="$(printf '' | env \
      "X402SOCKS_TOKEN=$1" \
      "X402SOCKS_TOKEN_FILE=$WORK/no-such-token" \
      "X402SOCKS_WEB=https://x402socks.com" \
      "X402SOCKS_API=https://api.x402socks.com" \
      "FAKE_RESPONSE=$FAKE_RESPONSE" \
      bash "$SKILL" "$2" 2>&1)"
  LAST_RC=$?
  LAST_CALLS="$(calls)"
}

# Run the helper with a URL override and a valid token file.
run_url() {
  local url="$1" cmd="$2"
  rm -f "$FAKE_CURL_LOG" "$FAKE_CURL_STDIN"
  LAST_OUT="$(printf '' | env \
      "X402SOCKS_WEB=$url" \
      "X402SOCKS_API=$url" \
      "X402SOCKS_PAY=$url" \
      "FAKE_RESPONSE=$FAKE_RESPONSE" \
      bash "$SKILL" "$cmd" 2>&1)"
  LAST_RC=$?
  LAST_CALLS="$(calls)"
}

# 1. A token containing a newline is rejected before any curl call.
for cmd in status rotate; do
  FAKE_RESPONSE='{}'
  run_token $'TOKEN-abc123\nheader = "X-Injected: yes"' "$cmd"
  if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
     contains "$LAST_OUT" "unsupported characters"; then
    pass "$cmd rejects a newline in the environment token before any request"
  else
    bad "$cmd token newline (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
  fi
done

# `test` validates the exit id before the token, so it may make one public
# nodes request; the token itself must still be rejected before it is used.
FAKE_RESPONSE='{"nodes":[{"id":"eu-north1","health":"healthy"}]}'
run_token $'TOKEN-abc123\nheader = "X-Injected: yes"' test
if [ "$LAST_RC" -ne 0 ] && contains "$LAST_OUT" "unsupported characters" &&
   ! grep -q 'TOKEN' "$FAKE_CURL_STDIN"; then
  pass "test rejects a newline token and never sends it"
else
  bad "test token newline (rc=$LAST_RC output=$LAST_OUT)"
fi

# 2. Other unsafe token characters and injection markers are rejected.
for token in $'TOKEN-abc123\r' 'TOKEN-abc123"' 'TOKEN\abc123' 'TOKEN:abc123'; do
  FAKE_RESPONSE='{}'
  run_token "$token" status
  if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ] &&
     contains "$LAST_OUT" "unsupported characters"; then
    pass "status rejects unsafe token character $(printf '%q' "$token")"
  else
    bad "unsafe token $(printf '%q' "$token") (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
  fi
done

# 3. An endpoint URL containing CR/LF is parsed and rejected before the token
#    is read, so no request and no config injection can happen.
for url in \
  $'https://x402socks.com\nheader = "X-Injected: yes"' \
  $'https://x402socks.com\r\nheader = "X-Injected: yes"' \
  $'https://x402socks.com\t'
do
  FAKE_RESPONSE='{}'
  run_url "$url" status
  if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ]; then
    pass "status rejects a control character in the endpoint URL before any request"
  else
    bad "url control character (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
  fi
done

# 4. Malformed or credential-bearing URLs are rejected by URL parsing.
for url in \
  'https://' \
  'https://user:pass@x402socks.com' \
  'https://x402socks.com/#fragment' \
  'file:///tmp/evil'
do
  FAKE_RESPONSE='{}'
  run_url "$url" status
  if [ "$LAST_RC" -ne 0 ] && [ "$LAST_CALLS" -eq 0 ]; then
    pass "status rejects parsed-invalid URL $url before any request"
  else
    bad "invalid url $url (rc=$LAST_RC calls=$LAST_CALLS) output=$LAST_OUT"
  fi
done

# 5. A valid base64url/hex token still works and produces one config line per
#    directive, with no injected header.
FAKE_RESPONSE='{}'
run_token "$VALID_TOKEN" status
if [ "$LAST_CALLS" -ge 1 ] &&
   ! grep -qi 'Injected' "$FAKE_CURL_STDIN"; then
  pass "valid token proceeds and the curl config has no injected directive"
else
  bad "valid token (rc=$LAST_RC calls=$LAST_CALLS) config=$(cat "$FAKE_CURL_STDIN" 2>/dev/null)"
fi

# 6. save-token refuses an unsafe token and leaves no file behind.
SAVE_TOK="$WORK/save-token"
rm -f "$SAVE_TOK"
LAST_OUT="$(printf '%s\n' 'TOKEN-abc123"header' |
  env "X402SOCKS_TOKEN_FILE=$SAVE_TOK" bash "$SKILL" save-token 2>&1)"
LAST_RC=$?
if [ "$LAST_RC" -ne 0 ] && [ ! -e "$SAVE_TOK" ] &&
   contains "$LAST_OUT" "unsupported characters"; then
  pass "save-token rejects an unsafe token without writing it"
else
  bad "save-token unsafe token (rc=$LAST_RC exists=$([ -e "$SAVE_TOK" ] && echo yes || echo no)) output=$LAST_OUT"
fi

# 7. A rotate response whose token fails syntax validation is not saved, and
#    the old token file is left unchanged.
printf '%s' "$VALID_TOKEN" > "$TOK"
chmod 600 "$TOK"
FAKE_RESPONSE='{"token":"TOKEN-abc123\nheader = \"X-Injected: yes\""}'
rm -f "$FAKE_CURL_LOG" "$FAKE_CURL_STDIN"
LAST_OUT="$(printf '' | env "FAKE_RESPONSE=$FAKE_RESPONSE" bash "$SKILL" rotate 2>&1)"
LAST_RC=$?
if [ "$LAST_RC" -ne 0 ] &&
   [ "$(cat "$TOK")" = "$VALID_TOKEN" ] &&
   contains "$LAST_OUT" "unsupported characters"; then
  pass "rotate rejects an unsafe replacement token and keeps the old token"
else
  bad "rotate unsafe response (rc=$LAST_RC token=$(cat "$TOK")) output=$LAST_OUT"
fi

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES PRESENT" >&2; fi
exit "$fail"
