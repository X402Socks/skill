# x402socks skill

An agent skill for [x402socks.com](https://x402socks.com): anonymous SOCKS5 egress for AI agents, bought per-job in USDC on Base through the [x402](https://x402.org) protocol. No signup, no card — the agent quotes a price, pays, receives a one-time proxy token, and routes traffic through a pool of global exit nodes.

**Repository:** [github.com/X402Socks/skill](https://github.com/X402Socks/skill)
**Directory:** [skills.sh/X402Socks/skill](https://skills.sh/X402Socks/skill)

## Who it's for

- **Agents that need a different source IP** — geo-specific egress, rate-limit hygiene, or keeping the operator's IP out of third-party logs.
- **Developers running autonomous agents** that should be able to acquire network access on their own, with a spending guardrail built in.
- **People evaluating x402** as a payment rail, since this is a complete real-world purchase loop rather than a demo.

You need a wallet with a small USDC balance on Base. Nothing else — no account, no API key.

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

Then just ask:

> "Get me a proxy so I can fetch example.com from a French IP."

The agent will check the catalog, tell you the price and what it buys, wait for your approval, complete the x402 payment, and use the token. It will pick `eu-central1` on its own once the job implies Paris.

### What it will and won't do

- It **quotes before spending** and defaults to the cheapest package ($1 / 6 hours / 1 GB). You approve an **amount**, and the client checks the live 402 challenge against it before signing.
- It **stores the token** in a `0600` file and keeps it out of process arguments, logs, and transcripts.
- It **recovers a lost token** from a settled payment instead of buying again, and **rotates** a token on any hint of exposure.
- It **stops and asks** if a target's terms forbid automated access — a proxy changes your source IP, not the agreement.

### Try it without spending anything

```bash
cd skills/x402socks/scripts
./x402socks.sh health             # is the service up
./x402socks.sh nodes --available  # which exits are usable
./x402socks.sh catalog --summary  # current prices
./x402socks.sh quote time_6h      # live 402 amount (free)
```

Those hit only public endpoints. Anything that costs money needs a wallet signature, so it can't run by accident.

## Layout

```
skills/x402socks/
├── SKILL.md            entry point: pricing, buy flow, credential rules
├── README.md           install, requirements, safety defaults
├── assets/             purchase-approval template
├── references/         payments, endpoints, troubleshooting (loaded on demand)
└── scripts/            helper CLI for quote, status, rotation, recovery, egress test
```

## License

MIT. Maintained by the x402socks project.
