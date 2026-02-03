# KAI Anchor Receipts

Deployment receipts provide tamper-evident proof of what was deployed, when, and by whom.

## Receipt Format v1.0

| Field | Type | Description |
|-------|------|-------------|
| `receiptVersion` | string | Format version (e.g., "1.0") |
| `chainId` | number | EIP-155 chain ID |
| `network` | string | Network name (e.g., "sepolia", "mainnet") |
| `contractAddress` | string | Deployed contract address |
| `contractName` | string | Contract name (e.g., "KAICharterRegistry") |
| `txHash` | string | Deployment transaction hash |
| `blockNumber` | number | Block number of deployment |
| `deployedAt` | string | ISO 8601 timestamp |
| `owner` | string | Contract owner address |
| `coreHash` | string | SHA-256 hash of Core constitution |
| `coreVersion` | number | Version number (integer) |
| `bytecodeHash` | string | keccak256 of **runtime** bytecode |
| `solcVersion` | string | Solidity compiler version |
| `optimizerRuns` | number | Optimizer runs setting |
| `gasUsed` | string | Gas used for deployment |
| `receiptHash` | string | SHA-256 of canonical JSON (see below) |

## Canonical JSON Hashing

The `receiptHash` is computed from canonical JSON:

1. **Exclude** `receiptHash` from the input
2. **Sort** keys alphabetically
3. **Stringify** with no whitespace
4. **Hash** with SHA-256, prefix with `0x`

```typescript
const { receiptHash, ...dataToHash } = receipt;
const sortedKeys = Object.keys(dataToHash).sort();
const canonical = JSON.stringify(dataToHash, sortedKeys);
const hash = "0x" + crypto.createHash("sha256").update(canonical).digest("hex");
```

This ensures anyone can reproduce the same hash from the same data.

## Verification

```bash
# Verify receipt hash (offline)
npx tsx verify_receipt.ts sepolia-enhanced-20260202.json

# Verify against on-chain state
npx tsx verify_receipt.ts sepolia-enhanced-20260202.json --rpc https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
```

## Files in this Directory

| File | Description |
|------|-------------|
| `sepolia-original-20260202.json` | Original deployment receipt (basic format) |
| `sepolia-enhanced-20260202.json` | Enhanced receipt with full metadata |
| `verify_receipt.ts` | Verification script |

## Why This Matters

1. **Tamper-evident**: If anyone modifies the receipt, the `receiptHash` won't match
2. **Reproducible**: Anyone can verify the hash computation
3. **On-chain verifiable**: `bytecodeHash` and `coreHash` can be checked against the live contract
4. **Audit-ready**: All deployment metadata in one file
