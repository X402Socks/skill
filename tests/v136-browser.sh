#!/usr/bin/env bash
# Regression test for Skillstore audit v11 browser findings. Offline: static
# source assertions plus a copied runner, a fake helper, and a mocked Playwright
# module reached through NODE_PATH. No real browser, network, or token secret.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNNER="$ROOT/skills/x402socks/scripts/x402socks-browser.mjs"
[ -f "$RUNNER" ] || { echo "missing $RUNNER" >&2; exit 2; }
command -v node >/dev/null 2>&1 || { echo "node is required" >&2; exit 2; }

fail=0
pass() { printf 'PASS %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*" >&2; fail=1; }
has() { grep -Fq -- "$2" "$1"; }
lacks() { ! grep -Fq -- "$2" "$1"; }
lacks_ci() { ! grep -qiF -- "$2" "$1"; }
contains() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }
check_has() {
  local file="$1" text="$2" label="$3"
  if has "$file" "$text"; then pass "$label"; else bad "$label"; fi
}
check_lacks() {
  local file="$1" text="$2" label="$3"
  if lacks "$file" "$text"; then pass "$label"; else bad "$label"; fi
}
check_lacks_ci() {
  local file="$1" text="$2" label="$3"
  if lacks_ci "$file" "$text"; then pass "$label"; else bad "$label"; fi
}

# 1. Static invariants on the shipped runner.
check_has "$RUNNER" 'serviceWorkers: "block"' "browser context blocks service workers"
check_has "$RUNNER" '--disable-webrtc' "Chromium disables WebRTC"
check_has "$RUNNER" 'context.route("**/*"' "every browser request is intercepted"
check_has "$RUNNER" 'maxRedirects: 0' "route.fetch never follows redirects for the client"
check_has "$RUNNER" 'assertAllowedUrl(route.request().url(), allowlist)' "each request URL is allowlisted"
check_has "$RUNNER" 'assertAllowedUrl(redirectUrl.toString(), allowlist)' "each redirect target is allowlisted before fulfill"
check_has "$RUNNER" 'assertAllowedUrl(page.url(), allowlist)' "the final URL is rechecked before success"
check_has "$RUNNER" 'execFileSync(' "the sibling helper is invoked with execFileSync"
check_has "$RUNNER" '"check-exit"' "exit ids are validated by the helper"
check_has "$RUNNER" '"reconcile"' "token validity is required via reconcile"
check_has "$RUNNER" 'O_NOFOLLOW' "token open refuses a symlink"
check_has "$RUNNER" 'fstatSync(fd)' "token checks use the open descriptor"
check_has "$RUNNER" 'process.getuid()' "token file must be owned by this user"
check_has "$RUNNER" '(st.mode & 0o7000) !== 0' "token file refuses special mode bits"
check_has "$RUNNER" '((st.mode & 0o777) & ~0o600) !== 0' "token file refuses group/world access"
check_has "$RUNNER" 'st.size === 0' "empty token files are refused"
check_has "$RUNNER" 'MAX_TOKEN_BYTES = 4096' "token length is capped"
check_has "$RUNNER" 'CONTROL.test(token)' "token control characters are refused"
check_has "$RUNNER" 'MAX_BODY_BYTES = 1024 * 1024' "response body is capped at 1 MiB"
check_has "$RUNNER" 'writeFileSync(output, capped, { mode: 0o600 })' "output file is private"
check_has "$RUNNER" 'const PROXY_TRANSPORTS = [' "runner defines an ordered transport chain"
check_has "$RUNNER" 'socks5://${exitId}.x402socks.com:1080' "runner starts on SOCKS5 port 1080"
check_has "$RUNNER" 'https://${exitId}.x402socks.com:3129' "runner falls back to TLS CONNECT 3129"
check_has "$RUNNER" 'http://${exitId}.x402socks.com:3128' "runner falls back to plaintext CONNECT 3128"
check_has "$RUNNER" 'X402SOCKS_PROXY_TRANSPORT' "runner can isolate one transport for diagnosis"
check_has "$RUNNER" 'cannot bypass only the proxy certificate' "runner explains the missing insecure proxy retry"
check_lacks "$RUNNER" 'console.log' "runner never logs values with console.log"
check_lacks "$RUNNER" '--proxy-insecure' "runner never bypasses proxy certificate verification"
check_lacks "$RUNNER" 'ignoreHTTPSErrors' "runner never bypasses target certificate verification"
check_lacks "$RUNNER" 'from "node:http"' "runner makes no direct HTTP requests"
check_lacks "$RUNNER" 'from "node:https"' "runner makes no direct HTTPS requests"

# 2. Offline harness. Only a copy is modified; the installed runner stays clean.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/x402socks-v136.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"
SCRIPTS="$WORK/scripts"
MODULE="$WORK/node_modules/playwright"
mkdir -p "$SCRIPTS" "$MODULE"
cp "$RUNNER" "$SCRIPTS/x402socks-browser.mjs"

HELPER_LOG="$WORK/helper.log"
PLAYWRIGHT_LOG="$WORK/playwright.log"
FAKE_TOKEN='FAKE-TOKEN-abc123'
TOKEN="$WORK/token"
printf '%s' "$FAKE_TOKEN" > "$TOKEN"
chmod 600 "$TOKEN"
TOKEN_PATH="$TOKEN"

cat > "$SCRIPTS/x402socks.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${FAKE_HELPER_LOG:?}"
case "$1" in
  check-exit)
    [ "$2" = "${FAKE_EXIT_ID:-eu-north1}" ] || exit 1
    exit "${FAKE_EXIT_RC:-0}"
    ;;
  reconcile) exit "${FAKE_RECONCILE_RC:-0}" ;;
esac
exit 2
EOF
chmod 700 "$SCRIPTS/x402socks.sh"

cat > "$MODULE/package.json" <<'EOF'
{"name":"playwright","version":"0.0.0","main":"index.js"}
EOF
cat > "$MODULE/index.js" <<'EOF'
'use strict';
const fs = require('node:fs');
function log(line) {
  fs.appendFileSync(process.env.FAKE_PLAYWRIGHT_LOG, line + '\n');
}
function routeFor(url) {
  return {
    request() { return { url: () => url }; },
    async fetch(options) {
      log('fetch:' + JSON.stringify({ maxRedirects: options.maxRedirects }));
      return {
        status: () => Number(process.env.FAKE_STATUS || 200),
        headers: () => {
          const headers = {};
          if (process.env.FAKE_LOCATION) headers.location = process.env.FAKE_LOCATION;
          return headers;
        },
        body: async () => Buffer.from(process.env.FAKE_BODY || 'BODY-ok'),
      };
    },
    async fulfill(result) {
      if (result && result.response) {
        log('fulfill:response');
      } else {
        log('fulfill:redirect:' + result.headers.location);
      }
    },
    async abort(reason) {
      log('abort:' + reason);
      throw new Error('offline route was aborted');
    },
  };
}
class FakePage {
  async goto(url) {
    await globalThis.__x402Route(routeFor(url));
    const sub = process.env.FAKE_SUBREQUEST || '';
    if (sub) {
      try {
        await globalThis.__x402Route(routeFor(sub));
      } catch {
        // A blocked subresource does not fail the main navigation.
      }
    }
    return { body: async () => Buffer.from(process.env.FAKE_BODY || 'BODY-ok') };
  }
  url() {
    const value = process.env.FAKE_FINAL_URL || process.env.FAKE_TARGET || 'https://example.com/';
    log('final:' + value);
    return value;
  }
  async content() { return '<html>fallback</html>'; }
}
const chromium = {
  async launch(options) {
    const proxy = options.proxy || {};
    const auth = typeof proxy.username === 'string' && proxy.username.length > 0 &&
      proxy.username === proxy.password ? 'matched' : 'missing';
    log('launch:' + JSON.stringify({
      server: proxy.server,
      auth: auth,
      args: (options.args || []).join(','),
    }));
    const prior = fs.existsSync(process.env.FAKE_PLAYWRIGHT_LOG)
      ? fs.readFileSync(process.env.FAKE_PLAYWRIGHT_LOG, 'utf8')
        .split('\n').filter((line) => line.startsWith('launch:')).length
      : 0;
    if (prior <= Number(process.env.FAKE_FAIL_PROXY_COUNT || 0)) {
      throw new Error('offline transport failure');
    }
    return {
      async newContext(contextOptions) {
        log('context:' + JSON.stringify({ serviceWorkers: contextOptions.serviceWorkers }));
        return {
          async route(pattern, handler) {
            log('route:' + pattern);
            globalThis.__x402Route = handler;
          },
          async newPage() { return new FakePage(); },
        };
      },
      async close() { log('close'); },
    };
  },
};
module.exports = { chromium };
EOF

LAST_OUT=""
LAST_RC=0
run_runner() {
  local target="$1"
  rm -f "$HELPER_LOG" "$PLAYWRIGHT_LOG" "$WORK/out.bin"
  LAST_OUT="$(env \
    X402SOCKS_TOKEN_FILE="${TOKEN_PATH:-$TOKEN}" \
    X402SOCKS_ALLOWED_HOSTS="${FAKE_ALLOWED_HOSTS:-example.com}" \
    FAKE_HELPER_LOG="$HELPER_LOG" \
    FAKE_PLAYWRIGHT_LOG="$PLAYWRIGHT_LOG" \
    FAKE_EXIT_ID="${FAKE_EXIT_ID:-eu-north1}" \
    FAKE_EXIT_RC="${FAKE_EXIT_RC:-0}" \
    FAKE_RECONCILE_RC="${FAKE_RECONCILE_RC:-0}" \
    FAKE_FAIL_PROXY_COUNT="${FAKE_FAIL_PROXY_COUNT:-0}" \
    FAKE_STATUS="${FAKE_STATUS:-200}" \
    FAKE_LOCATION="${FAKE_LOCATION:-}" \
    FAKE_SUBREQUEST="${FAKE_SUBREQUEST:-}" \
    FAKE_FINAL_URL="${FAKE_FINAL_URL:-$target}" \
    FAKE_BODY="${FAKE_BODY:-BODY-ok}" \
    NODE_PATH="$WORK/node_modules" \
    node "$SCRIPTS/x402socks-browser.mjs" eu-north1 "$target" \
      --output "$WORK/out.bin" 2>&1)"
  LAST_RC=$?
  return 0
}

# 3. Happy path: the checked proxy configuration and route behavior are exact,
#    and only fixed metadata plus the body reach the caller.
run_runner "https://example.com/page"
if [ "$LAST_RC" -eq 0 ] &&
   contains "$LAST_OUT" "status: ok" &&
   [ -f "$WORK/out.bin" ] && [ "$(cat "$WORK/out.bin")" = BODY-ok ]; then
  pass "allowed target returns fixed metadata and the capped body"
else
  bad "happy path (rc=$LAST_RC) output=$LAST_OUT"
fi
if [ -f "$HELPER_LOG" ] &&
   [ "$(sed -n '1p' "$HELPER_LOG")" = "check-exit eu-north1" ] &&
   [ "$(sed -n '2p' "$HELPER_LOG")" = "reconcile" ]; then
  pass "helper validates the exit before reconciling the token"
else
  bad "helper call order: $(cat "$HELPER_LOG" 2>/dev/null)"
fi
if [ -f "$PLAYWRIGHT_LOG" ] &&
   has "$PLAYWRIGHT_LOG" '"server":"socks5://eu-north1.x402socks.com:1080"' &&
   has "$PLAYWRIGHT_LOG" '"auth":"matched"' &&
   has "$PLAYWRIGHT_LOG" '"args":"--disable-webrtc"' &&
   has "$PLAYWRIGHT_LOG" '"serviceWorkers":"block"' &&
   has "$PLAYWRIGHT_LOG" 'route:**/*' &&
   has "$PLAYWRIGHT_LOG" '"maxRedirects":0' &&
   has "$PLAYWRIGHT_LOG" 'final:https://example.com/page' &&
   has "$PLAYWRIGHT_LOG" 'fulfill:response' &&
   lacks "$PLAYWRIGHT_LOG" 'abort:' &&
   lacks "$PLAYWRIGHT_LOG" "$FAKE_TOKEN"; then
  pass "browser preflight and SOCKS5 transport are exact without leaking the token"
else
  bad "browser log: $(cat "$PLAYWRIGHT_LOG" 2>/dev/null)"
fi
if ! contains "$LAST_OUT" "$FAKE_TOKEN"; then
  pass "runner output never contains the token"
else
  bad "runner output contained the fake token"
fi

# 3a. A failed SOCKS5 hop retries TLS CONNECT then plaintext CONNECT. Each
#     attempt is a fresh browser with a fresh allowlist and final URL recheck.
FAKE_FAIL_PROXY_COUNT=2
run_runner "https://example.com/page"
launches="$(grep -c '^launch:' "$PLAYWRIGHT_LOG" 2>/dev/null || true)"
routes="$(grep -c '^route:\*\*/\*$' "$PLAYWRIGHT_LOG" 2>/dev/null || true)"
finals="$(grep -c '^final:' "$PLAYWRIGHT_LOG" 2>/dev/null || true)"
s5="$(grep -n -F '"server":"socks5://eu-north1.x402socks.com:1080"' "$PLAYWRIGHT_LOG" | head -1 | cut -d: -f1)"
tls="$(grep -n -F '"server":"https://eu-north1.x402socks.com:3129"' "$PLAYWRIGHT_LOG" | head -1 | cut -d: -f1)"
plain="$(grep -n -F '"server":"http://eu-north1.x402socks.com:3128"' "$PLAYWRIGHT_LOG" | head -1 | cut -d: -f1)"
if [ "$LAST_RC" -eq 0 ] && contains "$LAST_OUT" "transport: plaintext" &&
   contains "$LAST_OUT" "transport socks5 failed; trying the next transport" &&
   contains "$LAST_OUT" "transport tls failed; trying the next transport" &&
   [ "$launches" = 3 ] && [ "$routes" -ge 1 ] && [ "$finals" -ge 1 ] &&
   [ -n "$s5" ] && [ -n "$tls" ] && [ -n "$plain" ] &&
   [ "$s5" -lt "$tls" ] && [ "$tls" -lt "$plain" ] &&
   [ -f "$WORK/out.bin" ] && [ "$(cat "$WORK/out.bin")" = BODY-ok ]; then
  pass "failed browser hops retry in order and the surviving attempt rechecks the target"
else
  bad "browser fallback (rc=$LAST_RC) output=$LAST_OUT log=$(cat "$PLAYWRIGHT_LOG" 2>/dev/null)"
fi

# 3b. When every transport fails, there is no direct fallback and no output.
FAKE_FAIL_PROXY_COUNT=3
run_runner "https://example.com/page"
if [ "$LAST_RC" -ne 0 ] && contains "$LAST_OUT" "all proxy transports failed" &&
   [ ! -f "$WORK/out.bin" ]; then
  pass "all browser proxy failures stop without a direct fallback"
else
  bad "all browser hops fail (rc=$LAST_RC) output=$LAST_OUT"
fi
FAKE_FAIL_PROXY_COUNT=0

# 4. Definitive no-token and inconclusive reconcile stop before browser traffic.
FAKE_RECONCILE_RC=10
run_runner "https://example.com/page"
if [ "$LAST_RC" -ne 0 ] && contains "$LAST_OUT" "no valid token" &&
   [ ! -f "$PLAYWRIGHT_LOG" ] && [ ! -f "$WORK/out.bin" ]; then
  pass "reconcile exit 10 stops before browser traffic"
else
  bad "reconcile 10 (rc=$LAST_RC) output=$LAST_OUT"
fi

FAKE_RECONCILE_RC=1
run_runner "https://example.com/page"
if [ "$LAST_RC" -ne 0 ] && contains "$LAST_OUT" "inconclusive" &&
   [ ! -f "$PLAYWRIGHT_LOG" ] && [ ! -f "$WORK/out.bin" ]; then
  pass "reconcile exit 1 stops before browser traffic"
else
  bad "reconcile 1 (rc=$LAST_RC) output=$LAST_OUT"
fi
FAKE_RECONCILE_RC=0

# 5. Target validation happens before launch.
run_runner "http://example.com/page"
if [ "$LAST_RC" -ne 0 ] && contains "$LAST_OUT" "X402SOCKS_ALLOWED_HOSTS" &&
   [ ! -f "$PLAYWRIGHT_LOG" ]; then
  pass "plaintext target is refused before launch"
else
  bad "plaintext target (rc=$LAST_RC) output=$LAST_OUT"
fi
run_runner "https://user:pass@example.com/page"
if [ "$LAST_RC" -ne 0 ] && contains "$LAST_OUT" "must not embed credentials" &&
   [ ! -f "$PLAYWRIGHT_LOG" ]; then
  pass "userinfo in a target is refused before launch"
else
  bad "target userinfo (rc=$LAST_RC) output=$LAST_OUT"
fi
run_runner "https://example.com:8443/page"
if [ "$LAST_RC" -ne 0 ] && contains "$LAST_OUT" "X402SOCKS_ALLOWED_HOSTS" &&
   [ ! -f "$PLAYWRIGHT_LOG" ]; then
  pass "an unlisted port is refused before launch"
else
  bad "unlisted port (rc=$LAST_RC) output=$LAST_OUT"
fi

# 6. Token-file checks are enforced by the runner itself, not only the helper.
chmod 644 "$TOKEN"
run_runner "https://example.com/page"
if [ "$LAST_RC" -ne 0 ] && contains "$LAST_OUT" "private regular file" &&
   [ ! -f "$PLAYWRIGHT_LOG" ]; then
  pass "a group/world readable token file is refused"
else
  bad "token mode (rc=$LAST_RC) output=$LAST_OUT"
fi
chmod 600 "$TOKEN"
ln -s "$TOKEN" "$WORK/token-link"
TOKEN_PATH="$WORK/token-link"
run_runner "https://example.com/page"
if [ "$LAST_RC" -ne 0 ] && contains "$LAST_OUT" "private regular file" &&
   [ ! -f "$PLAYWRIGHT_LOG" ]; then
  pass "a symlinked token file is refused"
else
  bad "token symlink (rc=$LAST_RC) output=$LAST_OUT"
fi
TOKEN_PATH="$TOKEN"

# 7. Redirects are inspected by the same allowlist, even though the client does
#    not follow them itself.
FAKE_STATUS=302
FAKE_LOCATION="https://evil.example/landing"
run_runner "https://example.com/start"
if [ "$LAST_RC" -ne 0 ] &&
   has "$PLAYWRIGHT_LOG" '"maxRedirects":0' &&
   has "$PLAYWRIGHT_LOG" 'abort:blockedbyclient' &&
   lacks "$PLAYWRIGHT_LOG" 'fulfill:redirect:' &&
   [ ! -f "$WORK/out.bin" ]; then
  pass "a redirect to an unlisted host is aborted without a body"
else
  bad "bad redirect (rc=$LAST_RC) log=$(cat "$PLAYWRIGHT_LOG" 2>/dev/null)"
fi

FAKE_ALLOWED_HOSTS="example.com,second.example.com"
FAKE_LOCATION="https://second.example.com/next"
FAKE_FINAL_URL="https://second.example.com/next"
run_runner "https://example.com/start"
if [ "$LAST_RC" -eq 0 ] &&
   has "$PLAYWRIGHT_LOG" 'fulfill:redirect:https://second.example.com/next' &&
   [ -f "$WORK/out.bin" ] && [ "$(cat "$WORK/out.bin")" = BODY-ok ]; then
  pass "a redirect to an allowlisted origin is fulfilled"
else
  bad "allowed redirect (rc=$LAST_RC) log=$(cat "$PLAYWRIGHT_LOG" 2>/dev/null)"
fi

# 8. The interceptor covers subresources, not just the initial navigation.
FAKE_STATUS=200
FAKE_LOCATION=""
FAKE_ALLOWED_HOSTS="example.com"
FAKE_FINAL_URL="https://example.com/page"
FAKE_SUBREQUEST="https://tracker.example/pixel"
run_runner "https://example.com/page"
if [ "$LAST_RC" -eq 0 ] &&
   has "$PLAYWRIGHT_LOG" 'abort:blockedbyclient' &&
   has "$PLAYWRIGHT_LOG" 'fulfill:response' &&
   [ -f "$WORK/out.bin" ] && [ "$(cat "$WORK/out.bin")" = BODY-ok ]; then
  pass "unlisted subresources are aborted while the page succeeds"
else
  bad "subresource check (rc=$LAST_RC) log=$(cat "$PLAYWRIGHT_LOG" 2>/dev/null)"
fi

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES PRESENT" >&2; fi
exit "$fail"
