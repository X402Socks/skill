# x402socks skill

An [Agent Skill](https://agentskills.io) for buying short-lived proxy egress
from a different source IP or a specific region for targets you are authorized
to access. It pays in USDC on Base through [x402](https://x402.org).

Transport order is fixed: SOCKS5 on `1080`, TLS HTTP CONNECT on `3129`, then
plaintext HTTP CONNECT on `3128`. CONNECT hops are compatibility fallbacks and
may not exist on every exit. Target TLS verification stays on. A proxy-only
certificate bypass requires an explicit operator opt-in after all three hops
fail.

The skill teaches an agent to quote a package, get signed approval for exact
terms, complete the x402 v2 payment, store the one-time token safely, route
traffic through a chosen exit, and verify that egress changed.

## Wallet access (required)

The agent cannot use this skill without a wallet it can sign with. There is no
free tier and no account credit.

1. **An EVM-compatible wallet funded with USDC on Base.** The cheapest package is
   $1.00 for 6 hours / 1 GB. USDC on Base is
   `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`. No ETH is needed for the x402
   purchase because the facilitator submits the EIP-3009 transfer. A manual send
   needs ETH for gas.
2. **A signer the agent can use non-interactively.** Prefer an injected browser
   wallet (EIP-1193), a signer-owned store, or an x402 client signer. No extra
   install is required. A Foundry encrypted keystore, hardware wallet, KMS, or
   HSM is also valid. Do not paste a raw private key into chat or argv.
3. **A Base RPC is optional** for low-volume checks, for example
   `https://mainnet.base.org`, `https://base-rpc.publicnode.com`,
   `https://1rpc.io/base`, or `https://base.drpc.org`.

Never print or output a private key in a terminal, log, chat, or commit. Keep
key material in a signer-owned store or mode `0600` files. See
[`references/wallet.md`](references/wallet.md) for browser and host signer paths.
`cast` recipes there are optional.

### Other requirements

- An Agent Skills client that can run shell commands.
- `curl` and `python3` for the helper. No `cast` requirement.
- Node.js + npm for the TypeScript x402 client, or Python 3.10+ with `uv` for
  the Python client.

No account, email, card, or API key.

## Install

```bash
npx skills add X402Socks/skill
```

Or copy this folder to your client's skills directory:

```bash
cp -r skills/x402socks ~/.claude/skills/       # Claude Code
cp -r skills/x402socks ~/.agents/skills/       # OpenCode and other clients
```

## What is here

| Path | Purpose |
| --- | --- |
| `SKILL.md` | Triggers, wallet requirement, spending rule, buy flow, routing, credential rules. |
| `references/wallet.md` | Browser and host signers, optional `cast` recipes, key handling. |
| `references/payments.md` | x402 v2 flow, approval pinning, guarded clients, recovery. |
| `references/endpoints.md` | Endpoints, client snippets, transport chain, credential handling. |
| `references/troubleshooting.md` | Symptom-to-cause table for 401/402/407/transport errors. |
| `scripts/x402socks.sh` | Helper CLI: quote, status, validate, rotate, recover, test, curl. |
| `scripts/x402socks-browser.mjs` | Allowlisted Playwright runner with transport fallbacks. |
| `assets/purchase-approval.md` | Template for recording the approved terms. |

## Safety defaults

- **Spending:** the skill requires operator-signed approval for an exact term
  set and checks it against the live 402 challenge before signing. The bundled
  pure-Python verifier needs no extra install.
- **Credentials:** the helper reads the token from a `0600` file
  (`~/.config/x402socks/token`) or a signer-owned store. Proxy credentials are
  consumed inside the helper and never reach stdout, argv, logs, URLs, or
  browser storage. Rotation and recovery save the replacement token instead of
  printing it.
- **Origins:** credential-bearing requests only go to pinned `https://`
  x402socks origins with exact ports. Public discovery origins are validated too.
  `X402SOCKS_ALLOW_INSECURE_API=1` is for a trusted loopback test only and is
  separate from the proxy TLS opt-in.
- **Transport:** all traffic goes through the proxy. SOCKS5 is first, TLS
  CONNECT is second, plaintext CONNECT is last. The helper clears ambient proxy
  bypass settings, pins HTTPS targets, and disables redirects. The browser
  runner blocks service workers, disables WebRTC, allows every request and
  redirect through an exact host and port allowlist, and rechecks the final URL
  on each transport attempt.

## Links

- Repository: https://github.com/X402Socks/skill
- Directory: https://skills.sh/X402Socks/skill
- Service: https://x402socks.com

MIT. Maintained by the x402socks project.
