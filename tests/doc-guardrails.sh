#!/usr/bin/env bash
# Regression test for Skillstore audit v8 documentation findings: approvals bind
# request/resource/signer, retries need fresh approval, curl ignores ambient
# config, target allowlists are enforced, and no sample terms act as approval.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="$ROOT/skills/x402socks/SKILL.md"
PAY="$ROOT/skills/x402socks/references/payments.md"
END="$ROOT/skills/x402socks/references/endpoints.md"
TROUBLE="$ROOT/skills/x402socks/references/troubleshooting.md"
APPROVAL="$ROOT/skills/x402socks/assets/purchase-approval.md"

for f in "$SKILL" "$PAY" "$END" "$TROUBLE" "$APPROVAL"; do
  [ -f "$f" ] || { echo "missing $f" >&2; exit 2; }
done

fail=0
pass() { printf 'PASS %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*" >&2; fail=1; }
has() { grep -Fq "$2" "$1"; }
lacks() { ! grep -Fq "$2" "$1"; }

check_has() {
  local file="$1" text="$2" label="$3"
  if has "$file" "$text"; then pass "$label"; else bad "$label"; fi
}
check_lacks() {
  local file="$1" text="$2" label="$3"
  if lacks "$file" "$text"; then pass "$label"; else bad "$label"; fi
}

check_has "$APPROVAL" "Exact request URL" "approval template binds request URL"
check_has "$APPROVAL" "Expected \`resource.url\`" "approval template binds challenge resource"
check_has "$APPROVAL" "Signer (keystore / hardware wallet; never a pasted key)" "approval template binds signer"
check_has "$APPROVAL" "Reuse and retries" "approval template covers reuse"
check_has "$APPROVAL" "new explicit approval" "approval template requires fresh approval"

check_has "$PAY" "assertApprovedChallenge" "TypeScript guard receives request context"
check_has "$PAY" "X402_APPROVAL_FILE" "examples load approvals from an operator file"
check_has "$PAY" "onPaymentRequired" "TypeScript binds the decoded challenge"
check_has "$PAY" "authorizedTargets" "examples carry authorized targets"
check_lacks "$PAY" "APPROVED = {" "no hardcoded approval object in examples"
check_lacks "$PAY" "Parse the new challenge and re-sign" "no stale re-sign guidance"

check_has "$TROUBLE" "later 402" "troubleshooting mentions a later 402"
check_has "$TROUBLE" "fresh explicit approval" "troubleshooting requires fresh approval"
check_has "$TROUBLE" "X402SOCKS_ALLOWED_HOSTS" "troubleshooting enforces target allowlist"

check_has "$SKILL" "## Target authorization (hard)" "skill states target authorization rule"
check_has "$SKILL" "X402SOCKS_ALLOWED_HOSTS" "skill requires an explicit target allowlist"
check_has "$SKILL" "fresh explicit approval" "skill requires fresh approval for a later 402"
check_has "$SKILL" "version: 1.3.3" "skill version is 1.3.3"

check_has "$END" "X402SOCKS_ALLOWED_HOSTS" "client snippets require target allowlist"
check_has "$END" "curl -q" "manual curl examples ignore ambient config"
check_has "$END" "allowlisted set of account and usage fields" "status output is documented as allowlisted"

bad_curl=0
while IFS= read -r line; do
  case "$line" in
    curl\ *)
      case "$line" in
        *"curl -q"*) ;;
        *) bad_curl=1 ;;
      esac
      ;;
  esac
done < <(grep -h '^curl ' "$SKILL" "$PAY" "$END")
if [ "$bad_curl" -eq 0 ]; then
  pass "every documented curl invocation starts with curl -q"
else
  bad "a documented curl invocation does not start with curl -q"
fi

if grep -q '"version": "1.3.3"' "$ROOT/.claude-plugin/plugin.json" &&
   grep -q '"version": "1.3.3"' "$ROOT/.claude-plugin/marketplace.json"; then
  pass "plugin manifests are version 1.3.3"
else
  bad "plugin manifests are not version 1.3.3"
fi

if [ "$fail" = 0 ]; then echo "ALL PASS"; else echo "FAILURES PRESENT" >&2; fi
exit "$fail"
