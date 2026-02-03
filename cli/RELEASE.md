# KAI v0.1.0-beta Release Instructions

## Pre-Release Checklist

- [x] All 319 tests passing
- [x] THREAT_MODEL.md with honest security claims
- [x] README.md (60-second explainer)
- [x] DEMO_PROOF.md template ready
- [x] demo-runbook.ts (simulated)
- [x] demo-runbook-realchain.ts (real transactions)
- [x] verify-live command implemented
- [x] Merkle odd-leaf bug fixed (Bitcoin-style)
- [x] Key role separation implemented
- [x] SecureSigner with OS Keychain support

## Tagging the Release

```bash
# Remove any stale lock file
rm -f .git/index.lock

# Add all CLI files
git add cli/

# Commit
git commit -m "KAI v0.1.0-beta: Verifiable Governance for AI Agents

Features:
- Tool execution gating with governance policies
- Human approval flow with replay prevention
- Signed receipt chains with Merkle batching
- On-chain anchoring and verify-live command
- Smuggling defense for LLM outputs
- OS Keychain key isolation (with honest JS limitations)

Test Coverage: 319 tests across 10 test files

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"

# Tag the release
git tag -a v0.1.0-beta -m "First beta release - shippable and defensible"

# Push (when ready)
git push origin main --tags
```

## Running the Real-Chain Demo

```bash
# Start local Anvil (or use Sepolia)
anvil &

# Set environment
export RPC_URL=http://127.0.0.1:8545
export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# Run real-chain demo
npx tsx scripts/demo-runbook-realchain.ts

# Save output to DEMO_PROOF.md
```

## Filling in DEMO_PROOF.md

After running the real-chain demo:

1. Copy the transaction hashes into DEMO_PROOF.md
2. Copy the verify-live output
3. Record the adversarial demo scenarios
4. Commit the filled DEMO_PROOF.md

This creates a "receipt for your receipts" - permanent proof the system works as designed.

## What You Can Now Legitimately Claim

**Enforced:**
- Tool execution gating
- Approval requirements
- Replay prevention
- Receipt WAL + chaining
- Merkle batching for any N
- Smuggling defenses

**Verified:**
- Deterministic root hashing
- Content change detection

**Operational:**
- verify-live against on-chain anchor

**Honest Limitations:**
- JS cannot guarantee memory zeroization
- LLM text output is best-effort compliance

---

*"Trust from a promise into a checkable artifact."*
