# x402socks skill

An agent skill for [x402socks.com](https://x402socks.com): anonymous proxy
egress for AI agents (TLS HTTP CONNECT by default, SOCKS5 opt-in), bought per job
in USDC on Base through the [x402](https://x402.org) protocol. No signup, no
card. The agent quotes a price, pays, receives a one-time proxy token, and routes
traffic through a global exit pool.

**Repository:** [github.com/X402Socks/skill](https://github.com/X402Socks/skill)
**Directory:** [skills.sh/X402Socks/skill](https://skills.sh/X402Socks/skill)

## Wallet access (required)

The agent must be given a wallet it can use. There is no free tier, and without
wallet access there is no way to buy a package.

- **Wallet:** an EVM-compatible wallet funded with **USDC on Base**. The cheapest
  package is **$1.00** for 6 hours / 1 GB. No ETH is needed for the x402 purchase
  because the facilitator submits the EIP-3009 transfer; a manual `cast send`
  needs ETH for gas.
- **Signing:** give the agent non-interactive access to a signer - a Foundry
  encrypted keystore (`cast wallet import <name> --interactive`, then
  `--keystore <path> --password-file <0600 file>`), a hardware wallet, or a
  signer configured in the x402 client. Do not paste a raw private key into
  chat.
- **Knowledge and tools:** the agent needs `cast` and a free Base RPC for
  low-volume balance checks and manual sends, for example:

  ```bash
  export BASE_RPC=https://mainnet.base.org
  export USDC=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
  export KEYSTORE="$HOME/.foundry/keystores/x402socks"
  export KEYPASS="$HOME/.config/x402socks/keystore.pass"   # mode 600
  export ADDR="$(cast wallet address --keystore "$KEYSTORE" --password-file "$KEYPASS")"
  cast call "$USDC" "balanceOf(address)(uint256)" "$ADDR" --rpc-url "$BASE_RPC"
  ```

  The result is atomic USDC (6 decimals): `1000000` = $1.00. Other free RPCs:
  `https://base-rpc.publicnode.com`, `https://1rpc.io/base`,
  `https://base.drpc.org`.

**Never print or output the private key in a terminal, log, chat, or commit, and
never pass it as a command argument.** Use an encrypted keystore or hardware
wallet; keep the keystore and password file at mode `0600`. If the agent cannot
access a signer, it cannot buy anything.

Full `cast` recipes: [`skills/x402socks/references/wallet.md`](skills/x402socks/references/wallet.md).

## Who it's for

- **Agents that need a different source IP** - geo-specific egress, rate-limit
  hygiene, or keeping the operator's IP out of third-party logs.
- **Developers running autonomous agents** that should be able to acquire
  network access on their own, with a spending guardrail built in.
- **People evaluating x402** as a payment rail, since this is a complete
  real-world purchase loop rather than a demo.

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

Then ask:

> "Get me a proxy so I can fetch example.com from a French IP."

The agent checks the catalog, tells you the price and what it buys, waits for
approval, completes the x402 payment, and uses the token.

### What it will and won't do

- It **quotes before spending** and defaults to the cheapest package ($1 / 6
  hours / 1 GB). You approve the **full payment terms** - scheme, network, asset,
  recipient, asset domain, and maximum amount - and the client checks every live
  402 `accepts[]` option against them before signing.
- It **stores the token** in a `0600` file and keeps it out of process
  arguments, logs, and transcripts.
- It **recovers a lost token** from a settled payment instead of buying again,
  and **rotates** a token on any hint of exposure.
- It **stops and asks** if a target's terms forbid automated access - a proxy
  changes your source IP, not the agreement.

### Try it without spending anything

```bash
cd skills/x402socks/scripts
./x402socks.sh health             # is the service up
./x402socks.sh nodes --available  # which exits are usable
./x402socks.sh catalog --summary  # current prices
./x402socks.sh quote time_6h      # live 402 amount (free)
```

Those hit only public endpoints. Anything that costs money needs a wallet
signature, so it cannot run by accident.

## Layout

```
skills/x402socks/
├── SKILL.md            entry point: wallet, pricing, buy flow, credential rules
├── README.md           install, wallet requirements, safety defaults
├── assets/             purchase-approval template
├── references/         wallet, payments, endpoints, troubleshooting (on demand)
└── scripts/            helper CLI for quote, status, rotation, recovery, egress test
```

## License

MIT. Maintained by the x402socks project.
