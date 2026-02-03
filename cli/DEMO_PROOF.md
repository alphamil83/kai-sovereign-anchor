# KAI v0.1.0-beta Demo Proof

This document contains immutable proof of the KAI governance system functioning as designed.

## Demo Environment

| Property | Value |
|----------|-------|
| Demo Date | 2026-02-03T21:24:20.618Z |
| CLI Version | @kai/cli@0.1.0-beta |
| Chain | Chain ID 31337 |
| Contract Address | `0x5FbDB2315678afecb367f032d93F642f64180aa3` |

## Artifacts

| Artifact | Value |
|----------|-------|
| Release root hash | `0x39635fa2b27ccf5414f6900382c283169b27304e31a891841718e2b5d33722d4` |
| Release anchor tx | `(already anchored)` |
| Release anchor block | 4 |
| Signer address | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` |
| Receipt batch Merkle root | `0xc267d318ef4bc1098751a289a985a8ca2d7a449b6c4d1a398d891f2ca6fa351c` |
| Receipt batch anchor tx | `0x763965c581e2fbefb085109ba6729c17deaf1dc3b046f2dcf4f43f84cf0da5a5` |
| Receipt batch anchor block | 6 |

## Verification Statement

- **verify-live succeeded**: ✅ YES
- **Deterministic hashing**: Rebuilt hash matches signed release
- Local manifest matches on-chain anchor at block 4

## Verify-Live Output

```
  ╔════════════════════════════════════════════════════════════╗
  ║                                                            ║
  ║   ✓ RUNNING VERIFIED RELEASE v1.0.0                       ║
  ║                                                            ║
  ║   Local manifest matches on-chain anchor                   ║
  ║                                                            ║
  ╚════════════════════════════════════════════════════════════╝

  Root hash: 0x39635fa2b27ccf5414f6900382c283169b27304e31a891841718e2b5d33722d4
  On-chain block: 4
```

---

**Generated**: 2026-02-03T21:24:20.618Z
