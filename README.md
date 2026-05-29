# Pharos Wallet Approval Auditor

An [Agent Skill](https://agentskills.io) for the [Pharos Network](https://www.pharos.xyz) that finds every ERC-20 token approval a wallet has ever granted — and tells you which ones to revoke. Built for the **Pharos Agent Center Skill Builder Campaign**.

## Why this matters

Token approvals are the leading attack vector in crypto. Every time you click "Approve" on a DEX or a DeFi app, you're granting that contract permission to spend your tokens — often **unlimited** amounts. Approvals don't expire. They accumulate silently over years. A single malicious or hacked contract can drain every token you've ever approved.

Block explorers don't surface this well. Most wallets have no idea what they've approved. **This skill makes the hidden surface visible — and revocable.**

For Pharos specifically: as the RealFi ecosystem grows and institutional capital arrives, the per-wallet value at risk grows with it. Approval hygiene is no longer optional.

## What it does

For any Pharos wallet, the skill:

1. **Scans on-chain `Approval` event logs** filtered by the wallet as owner, batched into 1000-block chunks to respect the Pharos RPC limit
2. **Verifies current allowances** — many old approvals have been revoked or reduced over time
3. **Categorizes risk**:
   - **CRITICAL**: unlimited approvals (≥ 2^128)
   - **HIGH**: large bounded approvals (≥ 1000 token units)
   - **NORMAL**: smaller bounded approvals
4. **Quantifies exposure per token**
5. **Generates revoke commands** — copy-paste ready `cast send` commands to clean up the dangerous ones

All operations are read-only. Zero gas cost to audit; gas only required if you choose to run the generated revoke commands.

## Installation

```bash
git clone https://github.com/<your-username>/pharos-approval-auditor.git
cd pharos-approval-auditor
npm install
```

Requires Node.js 18+.

## Usage

### Basic audit

```bash
node scripts/audit_approvals.js <walletAddress> [mainnet|testnet]
```

### With custom scan range

```bash
node scripts/audit_approvals.js <walletAddress> mainnet --max-blocks 500000
node scripts/audit_approvals.js <walletAddress> mainnet --from-block 8000000
```

## Example output

```
Wallet:          0xabc...
Network:         Pharos Pacific Ocean Mainnet
Blocks scanned:  200,000 (8,238,338 → 8,438,338)
Approval events: 47 found
Active spenders: 12

CRITICAL — Unlimited approvals (2):
  USDC     → 0xUnknownRouter...  (unlimited, last set block #8,402,193)
  WPROS    → 0xUnknownVault...   (unlimited, last set block #8,388,021)

HIGH — Large approvals (3):
  USDC     → 0xDexRouter...      (1,000,000 USDC)
  USDC     → 0xVault...          (500,000 USDC)
  pAlpha   → 0xStrategy...       (250,000 pAlpha)

NORMAL — Bounded approvals (7):
  WPROS    → 0xRouter...         (1,000 WPROS)
  ... 6 more

— Exposure by token —
  USDC: 1 unlimited + 1,500,000 bounded
  WPROS: 1 unlimited + 1,000 bounded
  pAlpha: 250,000 bounded

— Recommended revoke commands —
cast send 0xUSDC_TOKEN "approve(address,uint256)" 0xUnknownRouter 0 --rpc-url https://rpc.pharos.xyz --private-key $KEY
cast send 0xWPROS_TOKEN "approve(address,uint256)" 0xUnknownVault 0 --rpc-url https://rpc.pharos.xyz --private-key $KEY
... 3 more

Explorer:        https://pharosscan.xyz/address/0xabc...
```

If the wallet has no active approvals, the skill reports a clean bill of health.

## How it works (technical)

1. **Event topic filter**: `keccak256("Approval(address,address,uint256)")` = `0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925`
2. **Owner topic**: the wallet address left-padded to 32 bytes, passed as the second topic filter
3. **`eth_getLogs` batched in 1000-block windows** to respect Pharos's per-query limit
4. **Spender extraction**: from `topics[2]`, taking the last 20 bytes as the spender address
5. **Current-state verification**: for each unique `(token, spender)` pair, calling `allowance(owner, spender)` to get today's allowance (the log only tells you *historic* allowances)
6. **Risk classification**: any allowance ≥ 2^128 is treated as "unlimited" (the standard pattern for max-uint256 approvals)
7. **Revoke commands**: produces `cast send <token> "approve(address,uint256)" <spender> 0` for each item to revoke

## Using as an Agent Skill

This repo follows the [open Agent Skills format](https://agentskills.io/specification):

```
pharos-approval-auditor/
├── SKILL.md
├── scripts/
│   └── audit_approvals.js
├── package.json
└── README.md
```

Agents compatible with Pharos Agent Center load `SKILL.md` and trigger on natural prompts like:

- "Audit my Pharos wallet 0x... for dangerous approvals"
- "What tokens have I approved?"
- "Is my wallet safe?"
- "Find approval scams on this address"

## Edge cases handled

- **Wallet with no approvals** — clean bill of health
- **Token with broken `allowance()`** — skipped, logged
- **Self-approval** — filtered out
- **Approval increased then revoked** — only the current state matters
- **Very large scan ranges** — progress printed live
- **RPC failure mid-scan** — partial results still reported

## Network details

| Network | Chain ID | RPC | Explorer |
|---|---|---|---|
| Mainnet | 1672 | `https://rpc.pharos.xyz` | `https://pharosscan.xyz` |
| Atlantic Testnet | 688689 | `https://atlantic.dplabs-internal.com` | `https://atlantic.pharosscan.xyz` |

## License

MIT
