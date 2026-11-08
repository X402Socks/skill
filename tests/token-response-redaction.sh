#!/usr/bin/env bash
# Regression test for Skillstore audit v4 RISK-001: malformed rotate/recover
# responses must never be echoed, and a failed parse must not touch the token
# file. Runs entirely offline against a fake `curl`; no network, no real token.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="$ROOT/skills/x402socks/scripts/x402socks.sh"
[ -f "$SKILL" ] || { echo "missing $SKILL" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/x402socks-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/bin"
TOK="$WORK/token"
mkdir -p "$BIN"
chmod 700 "$WORK"

export X402SOCKS_TOKEN_FILE="$TOK"
export PATH="$BIN:$PATH"

# Fake curl: emits FAKE_RESPONSE verbatim and ignores every argument. It drains
# stdin (the curl --config payload) so the caller never sees SIGPIPE.
cat > "$BIN/curl" <<'EOF'
#!/usr/bin/env bash
cat >/dev/null 2>&1 || true
printf '%s' "${FAKE_RESPONSE-}"
EOF
chmod +x "$BIN/curl"

mode() {
  python3 -c 'import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777)[2:])' "$1"
}

SECRET="LEAKME-7f3a9c2e-DO-NOT-PRINT"
fail=0

run_case() {
  local name="$1" cmd="$2" resp="$3"
  printf '%s' 'OLD-TOKEN-aaaa' > "$TOK"
  chmod 600 "$TOK"
  local before after out rc leaked changed status
  before="$(cat "$TOK")"
  if [ "$cmd" = rotate ]; then
    out="$(FAKE_RESPONSE="$resp" bash "$SKILL" rotate 2>&1)"; rc=$?
  else
    out="$(printf '%s\n' '0xsig' | FAKE_RESPONSE="$resp" bash "$SKILL" recover 0xabc 1700000000 2>&1)"; rc=$?
  fi
  after="$(cat "$TOK")"
  leaked=0; case "$out" in *"$SECRET"*) leaked=1 ;; esac
  changed=0; [ "$before" = "$after" ] || changed=1
  status=PASS
  if [ "$leaked" = 1 ] || [ "$changed" = 1 ] || [ "$(mode "$TOK")" != 600 ]; then
    status=FAIL; fail=1
  fi
  printf '%-4s %-7s %-36s rc=%s leaked=%s token_changed=%s\n' \
    "$status" "$cmd" "$name" "$rc" "$leaked" "$changed"
  [ "$status" = PASS ] || printf '      output: %s\n' "$out"
}

for cmd in rotate recover; do
  run_case "truncated after token" "$cmd" "{\"token\":\"$SECRET\",\"account\":{\"id\":"
  run_case "raw text carrying token" "$cmd" "token=$SECRET"
  run_case "JSON array carrying token" "$cmd" "[\"$SECRET\"]"
  run_case "token-less object, secret value" "$cmd" "{\"error\":\"boom\",\"signature\":\"$SECRET\"}"
  run_case "empty body" "$cmd" ""
done

# Success must save the replacement, keep mode 600, and print only a redacted
# value (never the new token).
check_success() {
  local cmd="$1"
  printf '%s' 'OLD-TOKEN-aaaa' > "$TOK"; chmod 600 "$TOK"
  local out rc ok=1
  if [ "$cmd" = rotate ]; then
    out="$(FAKE_RESPONSE='{"token":"NEW-TOKEN-bbbb","account":{"id":"acct-1"}}' bash "$SKILL" rotate 2>&1)"; rc=$?
  else
    out="$(printf '%s\n' '0xsig' | FAKE_RESPONSE='{"token":"NEW-TOKEN-bbbb","account":{"id":"acct-1"}}' bash "$SKILL" recover 0xabc 1700000000 2>&1)"; rc=$?
  fi
  [ "$rc" = 0 ] || ok=0
  [ "$(cat "$TOK")" = NEW-TOKEN-bbbb ] || ok=0
  [ "$(mode "$TOK")" = 600 ] || ok=0
  case "$out" in *NEW-TOKEN-bbbb*) ok=0 ;; esac
  case "$out" in *"<redacted: saved to"*) ;; *) ok=0 ;; esac
  if [ "$ok" = 1 ]; then
    printf 'PASS %-7s success path (saved, mode 600, redacted)\n' "$cmd"
  else
    printf 'FAIL %-7s success path\n      rc=%s token=%s output=%s\n' "$cmd" "$rc" "$(cat "$TOK")" "$out"
    fail=1
  fi
}

check_success rotate
check_success recover

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES PRESENT" >&2; fi
exit "$fail"
