# Release: v0.1.0-beta — Deterministic governance + real-chain proof

This beta release delivers a complete, end-to-end reference implementation of verifiable governance for AI agents, with real blockchain transactions and reproducible proof artifacts.

## Highlights

### Deterministic governance hashing

- Fixed non-determinism in release hashing
- Governance manifests now rebuild to the same root hash
- Verification uses the original signed root, not regenerated timestamps

### Real-chain demo with proof output

- End-to-end demo runs against a real local blockchain (Anvil)
- Release anchoring, receipt batching, and verification all use real transactions
- New `--proof-out` flag auto-generates proof artifacts

```bash
CONTRACT_ADDRESS=… npm run demo:realchain -- --proof-out ./DEMO_PROOF.md
```

### Proof artifacts

- Transaction hashes
- Block numbers
- Merkle roots
- Live verification output
- All written automatically to DEMO_PROOF.md

### Security & correctness

- Expanded threat model
- Key isolation and role separation enforced
- Full test suite green (320 tests passing)

## What this release demonstrates

- You can prove what governance an AI agent is running
- You can verify it independently
- You do not need to trust the runtime or operator
- Proof is inspectable and reproducible

## Repository structure

- `cli/` — CLI, release builder, verification, demo scripts
- `contracts/` — Solidity contracts + Foundry tooling

---

This release is a beta reference implementation, not a production SaaS or hosted service.
