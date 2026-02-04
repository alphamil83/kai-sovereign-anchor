# KAI v0.1.0-beta Demo Proof

This document contains immutable proof of the KAI governance system functioning as designed.

## Demo Environment

| Property | Value |
|----------|-------|
| Demo Date | 2026-02-04T01:19:08.373Z |
| CLI Version | @kai/cli@0.1.0-beta |
| Chain | Chain ID 31337 |
| Contract Address | `0x5fbdb2315678afecb367f032d93f642f64180aa3` |

## Artifacts

| Artifact | Value |
|----------|-------|
| Release root hash | `0x39635fa2b27ccf5414f6900382c283169b27304e31a891841718e2b5d33722d4` |
| Release anchor tx | `(already anchored)` |
| Release anchor block | 4 |
| Signer address | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` |
| Receipt batch Merkle root | `0x22c5703b54318088e872ba82752f82024831b8ac8bd6196f96369e4686a9c17a` |
| Receipt batch anchor tx | `0x1a6438366b2cf0d2ae51adf88f338b827d12560aa8cb883bf39092afdb2d5985` |
| Receipt batch anchor block | 12 |

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

**Generated**: 2026-02-04T01:19:08.373Z
