---
name: pharos-approval-auditor
description: Audit every ERC-20 token approval a wallet has ever granted on the Pharos Network. This skill scans on-chain Approval event logs, identifies every spender the wallet has authorized, verifies the current allowance on each one, flags dangerous patterns (unlimited approvals to unverified contracts, large approvals to unknown addresses, stale approvals to dead protocols), calculates total exposure per token, and generates the exact revoke commands needed to fix problems. Use whenever a user asks "is my wallet safe", "audit my approvals", "what tokens have I approved", "do I have any dangerous allowances", "find approval scams", "revoke my approvals", or any question about wallet security and ERC-20 approval hygiene on Pharos.
license: MIT
---

# Pharos Wallet Approval Auditor

A wallet-security Agent Skill that finds and quantifies every ERC-20 token approval a wallet has granted on the Pharos Network — and generates the exact commands to revoke the dangerous ones.

## Why this matters

Token approvals are how most wallets get drained. When a user clicks "approve" on a DEX or DeFi app, they're granting that contract permission to spend their tokens — sometimes an **unlimited** amount. Approvals never expire. They accumulate silently over time. A single malicious or hacked contract can drain every token the user ever approved.

This is the leading attack vector in crypto. And as Pharos's RealFi ecosystem grows and institutional capital arrives, the value at risk per wallet grows with it.

**Block explorers don't surface this information well.** Most wallets don't even know what they've approved. This skill makes the hidden surface visible — and revocable.

## When to use

Use this skill when the user wants to:
- Audit their wallet's security posture on Pharos
- Find every spender that can move their tokens
- Identify dangerous unlimited approvals
- Discover stale approvals to abandoned protocols
- See total exposure per token
- Generate revoke commands for cleanup

## Inputs

1. **Wallet address** — the wallet to audit (0x-prefixed, 42 chars)

Optional:
- **Network** — `mainnet` (default, chain 1672) or `testnet` (chain 688689 Atlantic)
- **--from-block** — start of scan range (default: 0, scans full history)
- **--max-blocks** — limit the total blocks scanned (default: 200,000)

## How to run it

```bash
node scripts/audit_approvals.js <walletAddress> [mainnet|testnet]
```

Optional flags:

```bash
node scripts/audit_approvals.js <wallet> mainnet --max-blocks 500000
```

## Output format

```
Wallet:          0xabc...
Network:         Pharos Pacific Ocean Mainnet
Blocks scanned:  100,000 (8,338,338 → 8,438,338)
Approval events: 47 found
Active spenders: 12 (after verifying current allowances)

⚠️  CRITICAL — Unlimited approvals (2):
  USDC  → 0xUnknown1...  (unlimited, granted block #8,402,193)
  WPROS → 0xUnknown2...  (unlimited, granted block #8,388,021)

⚠️  HIGH — Large approvals (3):
  USDC  → 0xDexRouter...  (1,000,000 USDC)
  USDC  → 0xVault...      (500,000 USDC)
  pAlpha → 0xStrategy...  (250,000 pAlpha)

NORMAL — Bounded approvals (7):
  WPROS → 0xRouter...     (1,000 WPROS)
  ... 6 more

— Total exposure by token —
USDC:   Unlimited (≥ 2^128) + 1,500,000 bounded
WPROS:  Unlimited (≥ 2^128) + 1,000 bounded
pAlpha: 250,000

— Recommended revoke commands —
cast send 0xUSDC_TOKEN "approve(address,uint256)" 0xUnknown1 0 --rpc-url https://rpc.pharos.xyz --private-key $KEY
cast send 0xWPROS_TOKEN "approve(address,uint256)" 0xUnknown2 0 --rpc-url https://rpc.pharos.xyz --private-key $KEY
... 1 more

Explorer:        https://pharosscan.xyz/address/0xabc...
```

## How it works

1. **Event scan**: queries `Approval(address indexed owner, address indexed spender, uint256 value)` event logs filtered by the wallet as owner, batched in 1000-block chunks (Pharos RPC's per-query limit)
2. **Verify current state**: for each unique `(token, spender)` pair found in logs, calls `allowance(owner, spender)` on the token to get the *current* allowance — many older approvals will have been revoked or reduced
3. **Filter live ones**: drops `(token, spender)` pairs whose current allowance is zero
4. **Categorize risk**:
   - **CRITICAL**: unlimited approvals (>= 2^128, the standard pattern for "max uint256")
   - **HIGH**: bounded approvals over a configurable threshold
   - **NORMAL**: smaller bounded approvals
5. **Fetch token metadata**: reads name, symbol, decimals for each token to format amounts nicely
6. **Generate revoke commands**: produces ready-to-run `cast send ... approve(..., 0)` commands for each critical/high item

## Edge cases

- **Wallet with no approvals**: reports a clean bill of health
- **Token whose `allowance()` reverts** (broken contract): skipped, logged as warning
- **Self-approval** (wallet approving itself): filtered out
- **Approval increased then decreased**: only the current allowance matters; intermediate states ignored
- **Very large scan range**: progress is printed so the user sees scanning isn't hung
- **RPC failure mid-scan**: partial results are still reported, with a note on which range failed

## Dependencies

- Node.js 18+
- `viem` (installed via `npm install`)

See `README.md` for setup.
