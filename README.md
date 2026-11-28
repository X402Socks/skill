# x402socks skill

An agent-first skill for [x402socks.com](https://x402socks.com): short-lived,
paid proxy egress packages for authorized agent traffic. Clients connect
directly to an exit node and present a package-bound proxy token, so the
destination sees the exit address. Tokens are reusable within the purchased plan,
not one-use. Most packages are cheap and expire within hours, so one token
is typically spent in a single session or a few sessions over a few hours. Use
a separate token for each agent or job to keep agent memory and context small
and avoid cross-contamination between agents; this is operational hygiene, not
only a security precaution. Tokens can be obtained through
[x402](https://x402.org) payments in USDC on Base or by the documented
[manual checkout](https://x402socks.com/buy). No account signup is required by
the skill. The agent discovers packages, confirms the exact terms, obtains or
guides acquisition of a token, stores it locally, and routes only authorized
traffic through a healthy exit.

Both SOCKS5 and CONNECT TLS are native transports. Prefer SOCKS5 when the client
supports it, then CONNECT + TLS; use plaintext HTTP CONNECT only when no secure
channel works. Plaintext exposes the CONNECT target and proxy credentials on the
client-to-exit hop, so use a short-lived token there and prefer a fresh token
for another agent or job; the request does not consume the token. Listener
availability is exit-dependent; never assume a CONNECT listener is present on
every exit. Target TLS verification stays on. A proxy-only certificate bypass
requires an explicit operator opt-in after the normal transport chain fails.

**Repository:** [github.com/X402Socks/skill](https://github.com/X402Socks/skill)
**Directory:** [skills.sh/X402Socks/skill](https://skills.sh/X402Socks/skill)

## Wallet access for agent-side x402 purchases

For the skill to buy a package with x402, the agent must be given a wallet it can
sign with. There is no free tier. A token can also be obtained through the
[manual checkout](https://x402socks.com/buy), where the operator handles the
on-chain transfer and saves the resulting token locally; that path does not give
the agent wallet access.

- **Wallet:** an EVM-compatible wallet funded with **USDC on Base**. The cheapest
  package is **$1.00** for 6 hours / 1 GB. No ETH is needed for an x402 purchase
  because the facilitator submits the EIP-3009 transfer. A manual send needs ETH
  for gas.
- **Signer:** prefer a browser wallet with an injected EIP-1193 signer, a
  signer-owned store, or an x402 client signer. No extra install is required.
  A Foundry keystore, hardware wallet, KMS, or HSM is also valid. Do not paste a
  raw private key into chat or pass it in argv.
- **RPC:** optional for low-volume balance checks. Public endpoints include
  `https://mainnet.base.org`, `https://base-rpc.publicnode.com`,
  `https://1rpc.io/base`, and `https://base.drpc.org`. USDC on Base is
  `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`.

Keep key material in a signer-owned store or mode `0600` files. Mode `0600` does
not isolate those files from other code running as the same OS user, so give the
agent access only to a signer intended for this job. If the agent cannot use a
signer, it cannot buy anything.

`cast` recipes in [`skills/x402socks/references/wallet.md`](skills/x402socks/references/wallet.md)
are optional compatibility examples, not a requirement.

## Who it's for

- **Agents that need a different source IP** for an authorized target, such as
  geo-specific egress or a network path from a different provider. Targets must
  allow automated access.
- **People running scrapers or web tools** whose authorized targets are
  rate-limited or region-restricted from their current network, provided the
  target's terms and access rules allow that access.
- **Developers running autonomous agents** that can acquire network access with
  a spending guardrail built in.
- **People evaluating x402** with a complete purchase loop rather than a demo.

## How to use it

Install the skill for your agent:

```bash
# skills CLI
npx skills add X402Socks/skill

# or clone it
git clone https://github.com/X402Socks/skill

# Claude Code
cp -r skills/x402socks ~/.claude/skills/

# OpenCode / ~/.agents/skills
cp -r skills/x402socks ~/.agents/skills/
```

Then invoke the skill with a package or without one:

> `x402socks` — list the current packages with IDs, prices, and entitlements, then
> ask which package to use. After the choice, explain the x402 path (when a usable
> signer is available) and the manual checkout path.

> `x402socks time_6h` — use that package without asking again. With a usable
> signer, go through the guarded quote → one-use approval → x402 payment → local
> token-save flow. Without one, stop with the manual checkout URL rather than
> requesting another package choice.

For a job, also give the agent the exact authorized target and let it verify the
egress change. It never buys before the operator-approved terms match the live
challenge.

### What it will and won't do

- It **quotes before spending** and starts with a low-cost package ($1 / 6
  hours / 1 GB). You approve the full term set: scheme, network, asset,
  recipient, asset domain, amount, request URL, signer, and target hosts. The
  client requires exactly one live 402 `accepts[]` option that matches those
  terms, with no cheapest-option selection.
- It **verifies a signed, one-use approval** before a wallet signature. The
  bundled verifier is pure Python and needs no extra install.
- It **stores the token** in a `0600` file or signer-owned secret store, keeping
  it out of process arguments, logs, and transcripts.
- It **recovers a lost token** from a settled payment instead of buying again,
  with a fresh signed approval before any recovery signature.
- It **rotates** a token on any hint of exposure.
- It **stops and asks** if a target's terms forbid automated access. A proxy
  changes your source IP, not the agreement.

### Try it without spending anything

```bash
cd skills/x402socks/scripts
./x402socks.sh health             # service liveness
./x402socks.sh nodes --available  # usable exits
./x402socks.sh catalog --summary  # current prices
./x402socks.sh quote time_6h      # live 402 amount
```

Those hit public endpoints only. Payment needs a wallet signature.

## Layout

```
skills/x402socks/
├── SKILL.md            entry point: wallet, pricing, buy flow, credential rules
├── README.md           install, wallet requirements, safety defaults
├── assets/             purchase-approval template
├── references/         wallet, payments, endpoints, troubleshooting
└── scripts/            helper CLI and browser runner
```

## License

MIT. Maintained by the x402socks project.
