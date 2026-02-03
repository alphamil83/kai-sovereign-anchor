# Ticket 10: Key Isolation / External Signer

## Status: PLANNED (Post v0.1β)

## Problem

Current implementation (Ticket 6) uses file-based encrypted keys with PBKDF2. This means:
- Keys are decrypted into process memory when signing
- A compromised executor host can potentially access keys
- Does NOT achieve "keys never in RAM" security claim

## Security Gap

A memory-read attacker could:
- Extract decrypted private keys during signing operations
- Forge approvals/receipts if release key is accessible
- Compromise identity if release key is on executor host

## Solution Options (Pick One)

### Option A: Hardware Wallet / Passkey (Best Security + Decent UX)
- Use Ledger/Trezor for release signing
- WebAuthn/Passkey for approval tokens
- Keys never touch executor memory

### Option B: OS Keychain Signing (Good Middle Ground)
- macOS Keychain / Windows DPAPI / Linux Secret Service
- OS handles key protection
- Still in RAM briefly but protected by OS

### Option C: Key Separation (Minimum Viable)
- Release key: NEVER on executor host (separate signing service)
- Receipt key: Rotates per-session
- Approval key: User-held, signs via callback

## Implementation Notes

For external signer integration:
```typescript
interface ExternalSigner {
  getAddress(): Promise<string>;
  signMessage(message: string): Promise<string>;
  signHash(hash: string): Promise<string>;
}

// Hardware wallet adapter
class LedgerSigner implements ExternalSigner { ... }

// WebAuthn adapter
class PasskeySigner implements ExternalSigner { ... }

// OS keychain adapter
class KeychainSigner implements ExternalSigner { ... }
```

## Current State Disclosure

v0.1β should NOT claim:
- ❌ "Keys never in memory"
- ❌ "Hardware-backed signing"
- ❌ "Memory-read resistant"

v0.1β CAN claim:
- ✅ "Encrypted at rest with PBKDF2"
- ✅ "Password-protected key storage"
- ✅ "BIP39 seed backup support"

## Priority

HIGH for production deployment
Can ship v0.1β-MVP without this, but must be explicit about limitations.
