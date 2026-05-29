#!/usr/bin/env node
/**
 * Pharos Wallet Approval Auditor
 *
 * Audits every ERC-20 approval a wallet has granted on Pharos, identifies the dangerous ones,
 * and generates the exact revoke commands.
 *
 * Usage:
 *   node scripts/audit_approvals.js <walletAddress> [mainnet|testnet] [--max-blocks N] [--from-block N]
 */

import {
  createPublicClient,
  http,
  defineChain,
  isAddress,
  getAddress,
  parseAbi,
  formatUnits,
  pad,
  keccak256,
  toBytes,
} from "viem";

// --- URL constants (grouped for paste-audit) ---
const RPC_MAINNET = "https://rpc.pharos.xyz";
const RPC_TESTNET = "https://atlantic.dplabs-internal.com";
const EXPLORER_MAINNET = "https://pharosscan.xyz";
const EXPLORER_TESTNET = "https://atlantic.pharosscan.xyz";

// --- Chain definitions ---
const pharosMainnet = defineChain({
  id: 1672,
  name: "Pharos Pacific Ocean Mainnet",
  nativeCurrency: { name: "Pharos", symbol: "PROS", decimals: 18 },
  rpcUrls: { default: { http: [RPC_MAINNET] } },
});

const pharosTestnet = defineChain({
  id: 688689,
  name: "Pharos Atlantic Testnet",
  nativeCurrency: { name: "Pharos", symbol: "PROS", decimals: 18 },
  rpcUrls: { default: { http: [RPC_TESTNET] } },
});

// --- ABIs ---
const erc20Abi = parseAbi([
  "function name() view returns (string)",
  "function symbol() view returns (string)",
  "function decimals() view returns (uint8)",
  "function allowance(address owner, address spender) view returns (uint256)",
]);

// --- Risk thresholds ---
// Anything >= 2^128 is treated as "unlimited" — standard pattern for max uint256
const UNLIMITED_THRESHOLD = 2n ** 128n;
// Anything >= 1000 token units (after decimals) is "large" — tunable
const HIGH_RISK_UNITS = 1000;

// --- Pharos RPC limit ---
const MAX_BLOCKS_PER_QUERY = 1000;

// --- Event signature for ERC-20 Approval ---
// keccak256("Approval(address,address,uint256)") = 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925
function approvalEventTopic() {
  return keccak256(toBytes("Approval(address,address,uint256)"));
}

// --- Safe contract read: returns null on revert ---
async function safeRead(client, address, abi, functionName, args = []) {
  try {
    return await client.readContract({ address, abi, functionName, args });
  } catch {
    return null;
  }
}

// --- Scan Approval event logs in batched chunks ---
async function scanApprovalEvents(client, walletAddress, fromBlock, toBlock, onProgress) {
  const approvalTopic = approvalEventTopic();
  const ownerTopic = pad(walletAddress.toLowerCase(), { size: 32 });

  const ranges = [];
  let current = fromBlock;
  while (current <= toBlock) {
    const end = current + BigInt(MAX_BLOCKS_PER_QUERY - 1);
    ranges.push([current, end > toBlock ? toBlock : end]);
    current = end + 1n;
  }

  const allLogs = [];
  for (let i = 0; i < ranges.length; i++) {
    const [start, end] = ranges[i];
    try {
      const logs = await client.getLogs({
        fromBlock: start,
        toBlock: end,
        topics: [approvalTopic, ownerTopic],
      });
      allLogs.push(...logs);
    } catch (err) {
      // Note the failed range but continue
      if (onProgress) onProgress(i + 1, ranges.length, `range ${start}-${end} failed: ${err.message}`);
      continue;
    }
    if (onProgress && (i % 10 === 0 || i === ranges.length - 1)) {
      onProgress(i + 1, ranges.length, `${allLogs.length} events found so far`);
    }
  }
  return allLogs;
}

// --- Extract (token, spender) pairs from logs ---
function extractPairs(logs) {
  const pairs = new Map(); // key: token|spender -> { token, spender, latestBlock }
  for (const log of logs) {
    const token = getAddress(log.address);
    if (!log.topics[2]) continue;
    const spenderRaw = log.topics[2];
    // last 20 bytes of the 32-byte topic
    const spender = getAddress("0x" + spenderRaw.slice(-40));
    const key = `${token.toLowerCase()}|${spender.toLowerCase()}`;
    const blockNumber = log.blockNumber;
    if (!pairs.has(key) || pairs.get(key).latestBlock < blockNumber) {
      pairs.set(key, { token, spender, latestBlock: blockNumber });
    }
  }
  return Array.from(pairs.values());
}

// --- Verify current allowance for each pair, drop zeros ---
async function verifyAllowances(client, walletAddress, pairs) {
  const active = [];
  for (const pair of pairs) {
    // Skip self-approvals
    if (pair.spender.toLowerCase() === walletAddress.toLowerCase()) continue;
    const allowance = await safeRead(
      client,
      pair.token,
      erc20Abi,
      "allowance",
      [walletAddress, pair.spender],
    );
    if (allowance === null) {
      // Broken contract; record but skip
      continue;
    }
    if (allowance === 0n) continue;
    active.push({ ...pair, allowance });
  }
  return active;
}

// --- Fetch token metadata (cached) ---
async function getTokenMetadata(client, address, cache) {
  const key = address.toLowerCase();
  if (cache.has(key)) return cache.get(key);
  const [name, symbol, decimals] = await Promise.all([
    safeRead(client, address, erc20Abi, "name"),
    safeRead(client, address, erc20Abi, "symbol"),
    safeRead(client, address, erc20Abi, "decimals"),
  ]);
  const meta = { name: name || "Unknown", symbol: symbol || "?", decimals: decimals ?? 18 };
  cache.set(key, meta);
  return meta;
}

// --- Categorize an approval by risk ---
function classify(allowance, decimals) {
  if (allowance >= UNLIMITED_THRESHOLD) return "critical";
  const units = Number(formatUnits(allowance, decimals));
  if (units >= HIGH_RISK_UNITS) return "high";
  return "normal";
}

// --- Format an amount for display ---
function fmtAmount(amount, decimals, symbol) {
  if (amount >= UNLIMITED_THRESHOLD) return `unlimited (${symbol})`;
  const n = Number(formatUnits(amount, decimals));
  return `${n.toLocaleString(undefined, { maximumFractionDigits: 4 })} ${symbol}`;
}

// --- Build the report ---
function formatReport({
  walletAddress,
  networkName,
  fromBlock,
  toBlock,
  rangesScanned,
  rawEventCount,
  active,
  metaCache,
  explorerUrl,
  rpcUrl,
}) {
  const lines = [];
  lines.push(`Wallet:          ${walletAddress}`);
  lines.push(`Network:         ${networkName}`);
  lines.push(
    `Blocks scanned:  ${(toBlock - fromBlock + 1n).toLocaleString()} (${fromBlock.toLocaleString()} → ${toBlock.toLocaleString()})`,
  );
  lines.push(`Approval events: ${rawEventCount} found`);
  lines.push(`Active spenders: ${active.length} (after verifying current allowances)`);

  const critical = active.filter((a) => a.risk === "critical");
  const high = active.filter((a) => a.risk === "high");
  const normal = active.filter((a) => a.risk === "normal");

  if (critical.length > 0) {
    lines.push("");
    lines.push(`CRITICAL — Unlimited approvals (${critical.length}):`);
    for (const a of critical) {
      const meta = metaCache.get(a.token.toLowerCase());
      lines.push(
        `  ${meta.symbol.padEnd(8)} → ${a.spender}  (unlimited, last set block #${a.latestBlock.toLocaleString()})`,
      );
    }
  }

  if (high.length > 0) {
    lines.push("");
    lines.push(`HIGH — Large approvals (${high.length}):`);
    for (const a of high) {
      const meta = metaCache.get(a.token.toLowerCase());
      lines.push(`  ${meta.symbol.padEnd(8)} → ${a.spender}  (${fmtAmount(a.allowance, meta.decimals, meta.symbol)})`);
    }
  }

  if (normal.length > 0) {
    lines.push("");
    lines.push(`NORMAL — Bounded approvals (${normal.length}):`);
    for (const a of normal.slice(0, 10)) {
      const meta = metaCache.get(a.token.toLowerCase());
      lines.push(`  ${meta.symbol.padEnd(8)} → ${a.spender}  (${fmtAmount(a.allowance, meta.decimals, meta.symbol)})`);
    }
    if (normal.length > 10) {
      lines.push(`  ... ${normal.length - 10} more`);
    }
  }

  if (active.length === 0) {
    lines.push("");
    lines.push(`Clean wallet — no active approvals found in scanned range.`);
  }

  // --- Exposure summary by token ---
  if (active.length > 0) {
    const byToken = {};
    for (const a of active) {
      const meta = metaCache.get(a.token.toLowerCase());
      if (!byToken[meta.symbol]) byToken[meta.symbol] = { unlimited: 0, bounded: 0n, decimals: meta.decimals };
      if (a.allowance >= UNLIMITED_THRESHOLD) byToken[meta.symbol].unlimited += 1;
      else byToken[meta.symbol].bounded += a.allowance;
    }
    lines.push("");
    lines.push(`— Exposure by token —`);
    for (const [sym, data] of Object.entries(byToken)) {
      const parts = [];
      if (data.unlimited > 0) parts.push(`${data.unlimited} unlimited`);
      if (data.bounded > 0n) {
        const boundedAmt = Number(formatUnits(data.bounded, data.decimals)).toLocaleString();
        parts.push(`${boundedAmt} bounded`);
      }
      lines.push(`  ${sym}: ${parts.join(" + ")}`);
    }
  }

  // --- Revoke commands for critical + high ---
  const toRevoke = [...critical, ...high];
  if (toRevoke.length > 0) {
    lines.push("");
    lines.push(`— Recommended revoke commands —`);
    for (const a of toRevoke) {
      lines.push(
        `cast send ${a.token} "approve(address,uint256)" ${a.spender} 0 --rpc-url ${rpcUrl} --private-key $KEY`,
      );
    }
  }

  lines.push("");
  lines.push(`Explorer:        ${explorerUrl}/address/${walletAddress}`);
  return lines.join("\n");
}

// --- Main audit entry point ---
async function audit(walletInput, networkKey = "mainnet", options = {}) {
  if (!isAddress(walletInput)) {
    throw new Error(`Invalid wallet address: ${walletInput}`);
  }
  const walletAddress = getAddress(walletInput);

  const chain = networkKey === "testnet" ? pharosTestnet : pharosMainnet;
  const rpcUrl = networkKey === "testnet" ? RPC_TESTNET : RPC_MAINNET;
  const explorerUrl = networkKey === "testnet" ? EXPLORER_TESTNET : EXPLORER_MAINNET;
  const client = createPublicClient({ chain, transport: http() });

  // --- Determine block range ---
  const latestBlock = await client.getBlockNumber();
  const maxBlocks = BigInt(options.maxBlocks ?? 200000);
  const fromBlock = options.fromBlock
    ? BigInt(options.fromBlock)
    : latestBlock > maxBlocks
      ? latestBlock - maxBlocks
      : 0n;
  const toBlock = latestBlock;

  // --- Progress reporter ---
  const onProgress = (done, total, msg) => {
    process.stderr.write(`\r  Scanning... ${done}/${total} batches  (${msg})    `);
  };

  // --- Scan events ---
  const logs = await scanApprovalEvents(client, walletAddress, fromBlock, toBlock, onProgress);
  process.stderr.write("\n");

  // --- Extract unique pairs ---
  const pairs = extractPairs(logs);

  // --- Verify current allowances ---
  const activeRaw = await verifyAllowances(client, walletAddress, pairs);

  // --- Fetch token metadata (parallel, cached) ---
  const metaCache = new Map();
  await Promise.all(
    Array.from(new Set(activeRaw.map((a) => a.token))).map((token) =>
      getTokenMetadata(client, token, metaCache),
    ),
  );

  // --- Classify each active approval ---
  const active = activeRaw.map((a) => ({
    ...a,
    risk: classify(a.allowance, metaCache.get(a.token.toLowerCase()).decimals),
  }));

  // --- Sort: critical first, then high, then normal by allowance descending ---
  const order = { critical: 0, high: 1, normal: 2 };
  active.sort((a, b) => {
    if (order[a.risk] !== order[b.risk]) return order[a.risk] - order[b.risk];
    if (b.allowance > a.allowance) return 1;
    if (b.allowance < a.allowance) return -1;
    return 0;
  });

  return formatReport({
    walletAddress,
    networkName: chain.name,
    fromBlock,
    toBlock,
    rangesScanned: Math.ceil(Number(toBlock - fromBlock + 1n) / MAX_BLOCKS_PER_QUERY),
    rawEventCount: logs.length,
    active,
    metaCache,
    explorerUrl,
    rpcUrl,
  });
}

// --- CLI argument parsing ---
function parseArgs(argv) {
  const args = argv.slice(2);
  if (args.length === 0) return null;

  let wallet = null;
  let network = "mainnet";
  const options = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "mainnet" || a === "testnet") network = a;
    else if (a === "--max-blocks") options.maxBlocks = Number(args[++i]);
    else if (a === "--from-block") options.fromBlock = Number(args[++i]);
    else if (a.startsWith("0x")) wallet = a;
  }
  if (!wallet) return null;
  return { wallet, network, options };
}

// --- CLI entry point ---
async function main() {
  const parsed = parseArgs(process.argv);
  if (!parsed) {
    console.error("Usage: node scripts/audit_approvals.js <wallet> [mainnet|testnet] [--max-blocks N] [--from-block N]");
    process.exit(1);
  }
  try {
    const report = await audit(parsed.wallet, parsed.network, parsed.options);
    console.log(report);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

main();

export { audit };
