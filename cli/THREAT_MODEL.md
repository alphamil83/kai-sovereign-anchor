# KAI v0.5 Threat Model

## Security Claims

### What KAI DOES Enforce

| Capability | Enforcement Level | Mechanism |
|------------|-------------------|-----------|
| Tool execution boundary | **ENFORCED** | Hard executor validates all tool calls |
| Approval requirement | **ENFORCED** | Cryptographic tokens required for sensitive actions |
| Replay prevention | **ENFORCED** | Nonce database + sequence numbers |
| Receipt integrity | **ENFORCED** | Hash-chained, signed receipts |
| Batch anchoring | **ENFORCED** | Merkle roots anchored on-chain |
| Sensitivity tainting | **ENFORCED** | Never de-escalates; egress requires approval |
| Smuggling detection | **ENFORCED** | Entropy analysis + secret pattern matching |
| Path restrictions | **ENFORCED** | Allowlist-based path rules |
| Rate limiting | **ENFORCED** | Approval fatigue controls |

### What KAI Does NOT Enforce

| Capability | Status | Notes |
|------------|--------|-------|
| LLM text output | **ADVISORY** | LLM can still say harmful text |
| Parameter injection | **BEST-EFFORT** | Schema validation helps but isn't perfect |
| Tool composition | **MONITORED** | Taint + egress rules limit, don't prevent |

## Key Isolation Model

### Current Implementation (v0.1β)

```
┌─────────────────────────────────────────────────────┐
│                  OS Keychain                         │
│  ┌─────────────────────────────────────────────┐    │
│  │  Encrypted Key (AES-256-GCM + PBKDF2)       │    │
│  │  - release key (offline preferred)          │    │
│  │  - receipt key (runtime, rotatable)         │    │
│  │  - approver key (separate from release)     │    │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
                        │
                        ▼ (password unlock)
┌─────────────────────────────────────────────────────┐
│              Signing Operation                       │
│  - Decrypt key (briefly in RAM)                     │
│  - Sign message                                     │
│  - Clear key from memory                            │
│  - Attack window: milliseconds                      │
└─────────────────────────────────────────────────────┘
```

### What This Provides

1. **Keys stored in OS Keychain** - macOS Keychain, Windows Credential Vault, Linux libsecret (when keytar available)
2. **No plaintext keys on disk** - Raw key material never persisted in plaintext files
3. **Key role separation** - Different keys for different operations (release ≠ receipt ≠ approver)
4. **Password-protected decryption** - User interaction required for signing

### What This Does NOT Provide

1. **True memory zeroization** - JavaScript/Node.js cannot guarantee memory clearing due to:
   - Garbage collection timing is non-deterministic
   - String immutability means copies may exist
   - V8 may optimize/inline values in unpredictable ways
   - `clearSensitiveString()` is best-effort, not guaranteed
2. **HSM-level isolation** - No hardware security module
3. **Memory dump protection** - During signing, decrypted key exists in process memory (unavoidable in JS)
4. **Compromised OS protection** - If OS keychain is compromised, keys are exposed

### Precise Claims

| Claim | Status | Notes |
|-------|--------|-------|
| Keys stored in OS keychain | ✅ True | When keytar available |
| No plaintext keys on disk | ✅ True | Encrypted before storage |
| Key cleared after signing | ⚠️ Best-effort | JS can't guarantee zeroization |
| Memory-safe signing | ❌ False | Decrypted key in RAM briefly |

### Note on Double Encryption

The current implementation encrypts keys with PBKDF2 before storing in OS keychain. This is defense-in-depth but adds complexity. The passphrase handling matters:

- ✅ **Interactive passphrase** (user-entered, not stored) - Adds real protection
- ⚠️ **Passphrase in env var/config** - Just moves the secret, limited benefit
- Consider simplifying to keychain-only if passphrase management becomes a foot-gun

### Future Hardening Options

| Option | Security Level | Complexity | Notes |
|--------|---------------|------------|-------|
| Hardware wallet (Ledger/Trezor) | Highest | High | Key never leaves device |
| WebAuthn/Passkey | High | Medium | Browser-based, requires setup |
| Remote signing with HSM | Highest | Highest | Enterprise solution |

## Bypass Vectors (Known Limitations)

### 1. Output Channel Bypass
**Risk**: LLM can output harmful text directly.
**Mitigation**: Advisory monitoring, content filters.
**Status**: Not enforced by KAI - handled by LLM provider.

### 2. Tool Composition Bypass
**Risk**: Combining allowed tools to achieve disallowed effect.
**Example**: Read secret → compose into email → send
**Mitigation**: Sensitivity tainting + egress approval requirement.
**Status**: Significantly limited but not eliminated.

### 3. Parameter Injection
**Risk**: Malicious parameters crafted to bypass validation.
**Mitigation**: Schema validation, size limits, pattern matching.
**Status**: Best-effort defense.

### 4. Time-of-Check-to-Time-of-Use (TOCTOU)
**Risk**: State changes between approval and execution.
**Mitigation**: Action hash binds exact parameters; short token expiry.
**Status**: Mitigated.

### 5. Social Engineering
**Risk**: User approves harmful action due to deceptive summary.
**Mitigation**: Clear summaries, approval fatigue controls, cooldowns.
**Status**: Partially mitigated.

## Correct Public Claims

When describing KAI, use these precise statements:

### DO Say
- "Tool actions are enforced by a hard executor boundary"
- "Approvals are one-time and replay-resistant"
- "Receipts are append-only and tamper-evident"
- "Receipt batch anchoring works for any batch size"
- "Key storage uses OS Keychain with encryption"

### DON'T Say
- "KAI prevents all harmful AI behavior" (text output not enforced)
- "Keys never touch RAM" (briefly in memory during signing)
- "Parameter injection is impossible" (best-effort only)
- "KAI is HSM-grade secure" (it's not, yet)

## Attack Scenarios and Responses

### Scenario 1: Memory Dump Attack
**Attack**: Attacker dumps process memory during signing.
**Window**: Milliseconds while key is decrypted.
**v0.1β Response**: Accepted risk; key cleared immediately after use.
**Future**: Hardware wallet eliminates this entirely.

### Scenario 2: Stolen Receipt Key
**Attack**: Attacker obtains receipt signing key.
**Impact**: Can forge receipts (but not releases or approvals).
**v0.1β Response**: Key role separation limits blast radius.
**Future**: Per-session key rotation further limits exposure.

### Scenario 3: Approval Token Theft
**Attack**: Attacker intercepts approval token.
**Impact**: Can execute one approved action.
**v0.1β Response**: Nonce prevents replay; short expiry limits window.
**Future**: Hardware-bound tokens (WebAuthn).

### Scenario 4: Malicious Governance Release
**Attack**: Attacker signs malicious governance bundle.
**Impact**: Defines new rules that weaken protections.
**v0.1β Response**: Release key offline + multi-sig recommended.
**Future**: On-chain governance with time-lock.

## Deterministic Hashing

### Release Root Hash Computation

The `root_hash` is computed from **only deterministic fields** to ensure identical governance content always produces identical hashes, regardless of when or where the build occurs.

**Fields INCLUDED in root_hash:**
```typescript
{
  manifest_version: "0.5",      // Protocol version
  release_version: "1.0.0",    // Release semver
  files: [                      // Sorted by path
    { path: "...", sha256: "...", size: N }
  ]
}
```

**Fields EXCLUDED from root_hash:**
- `created_at` - Build timestamp
- `builder_info.built_at` - Same
- `builder_info.cli_version` - Tool version may differ
- `builder_info.git_commit` - Informational only
- `builder_info.node_version` - Runtime version

### Why This Matters

| Scenario | Timestamps in Hash | Timestamps Excluded |
|----------|-------------------|---------------------|
| Rebuild same content | ❌ Different hash | ✅ Same hash |
| Verify on different machine | ❌ Must trust original | ✅ Can recompute |
| Audit governance | ❌ Cannot verify | ✅ Deterministic |

### Verification Test

```bash
# Build twice with different timestamps
kai build -d ./governance -v 1.0.0 -o /tmp/manifest1.json
sleep 1
kai build -d ./governance -v 1.0.0 -o /tmp/manifest2.json

# Root hashes MUST match (timestamps differ but are not hashed)
jq .root_hash /tmp/manifest1.json
jq .root_hash /tmp/manifest2.json
```

## Verification Commands

```bash
# Verify current release matches on-chain anchor
kai verify live

# Verify receipt chain integrity
kai verify receipts --chain ./receipts/

# Verify specific release
kai verify release ./releases/v1.0.0.json --governance ./governance/
```

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.5.0-beta | 2025-01 | Initial threat model |

---

*This threat model is part of KAI's "trust is an artifact" philosophy.*
*Security claims should be verifiable, not aspirational.*
