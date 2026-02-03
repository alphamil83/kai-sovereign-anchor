# KAI Sovereign Anchor v1.4

**A portable, hashable governance system for personal AI agents.**

> "Guardians are helpers, not owners."

## Overview

KAI Sovereign Anchor implements a governance framework for personal AI agents with:

- **On-chain**: Proofs, registry, and audit trail only (NO private data)
- **Off-chain**: Encrypted vault + policy enforcement
- **Adversarial resilience**: Tested against injection, coercion, and guardian compromise

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     KAI SOVEREIGN ANCHOR                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
│  │  On-Chain   │    │  Off-Chain  │    │   Vault     │    │
│  │  Registry   │    │   Policy    │    │  (Local)    │    │
│  │             │    │   Engine    │    │             │    │
│  │ • Core hash │    │ • Mirror    │    │ • Encrypted │    │
│  │ • Guardian  │    │   Protocol  │    │ • Portable  │    │
│  │   keys      │    │ • Injection │    │ • Receipts  │    │
│  │ • Receipts  │    │   Defense   │    │ • Config    │    │
│  │ • Events    │    │ • Coercion  │    │             │    │
│  │             │    │   Detection │    │             │    │
│  └─────────────┘    └─────────────┘    └─────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Install dependencies
make install

# Run the demo
make demo

# Run all tests
make test
```

## Core Principles

### 1. DATA not COMMANDS
Instructions from untrusted sources (documents, emails, API responses) are treated as **data to be processed**, not commands to be executed.

### 2. Guardians are Helpers
Guardians can:
- Trigger cooling-off periods
- Access non-sensitive memory during succession
- Execute pre-authorized maintenance

Guardians cannot:
- Modify the Core constitution
- Access sensitive memory
- Transfer ownership
- Override verified Kamil

### 3. On-Chain = Proofs Only
```
✅ Core constitution hash
✅ Guardian key fingerprints
✅ Receipt hashes
✅ Event logs

❌ Private memory
❌ Personal data
❌ Credentials
❌ Conversation history
```

### 4. Friction Matches Stakes
| Level | Name | When |
|-------|------|------|
| 0 | Flow | Normal operations |
| 1 | Nudge | Brief concern |
| 2 | Friction | High-stakes, slow down |
| 3 | Brother Moment | Direct confrontation |
| 4 | Guardian Escalation | Involve guardian, require co-sign |

## Components

### Charter Registry (Solidity)

On-chain smart contract storing:
- Core constitution hash
- Guardian fingerprints + status
- Succession configuration
- Safe mode state

```solidity
// Key functions
function registerGuardian(bytes32 fingerprint, GuardianRank rank)
function revokeGuardian(bytes32 fingerprint, string reason)
function activateSafeMode(string reason)
function triggerSuccession()
```

### Policy Engine (TypeScript)

Off-chain governance enforcement:
- Injection detection (IGNORE PREVIOUS, persona switch, authority claims)
- Coercion detection (urgency, secrecy, timing patterns)
- Stake classification (financial, irreversible, family impact)
- Mirror Protocol (values alignment check)

```typescript
const decision = engine.evaluate(request);
// Returns: { decision, frictionLevel, requiredVerification, ... }
```

### Encrypted Vault

Local-first encrypted storage:
- AES-256-GCM encryption
- Export/import for portability
- Guardian fingerprints
- Second-channel configuration
- Receipts + audit log

## Succession Protocol

```
Day 0-180:   Normal operation
Day 180:     Inactivity threshold reached
Day 180:     Guardian triggers succession
Day 180-187: Cooling period (read-only)
Day 187+:    Expanded guardian access (still limited)

At any point: Kamil verifies → immediate exit
```

### Safe Mode

Triggered by:
- Coercion indicators
- Guardian compromise suspected
- Multiple hostile guardian signals

Behavior:
- All irreversible actions blocked
- Read-only operations continue
- Exits only with verified Kamil

## Testing

### Scenario Test Categories

1. **Injection attacks** - IGNORE PREVIOUS, persona switch, encoded instructions
2. **Coercion detection** - Urgency, secrecy, timing patterns
3. **Guardian compromise** - "Don't tell Kamil", scope creep
4. **Succession edge cases** - Return during cooling, guardian went dark
5. **Values alignment** - Violence, fraud, family impact

```bash
# Run all tests
make test

# Run scenario tests only
cd policy-engine && npm test -- --testPathPattern="PolicyEngine.test.ts"
```

## Directory Structure

```
kai-sovereign-anchor/
├── constitution/
│   ├── core/         # Immutable Core (hashable)
│   ├── manual/       # Operating Manual (mutable)
│   └── scenarios/    # Test scenarios
├── chain/
│   ├── contracts/    # Solidity contracts
│   ├── scripts/      # Deployment scripts
│   └── test/         # Contract tests
├── policy-engine/
│   ├── src/          # TypeScript source
│   └── test/         # Unit tests
├── vault/
│   └── src/          # Encrypted storage
├── demo/
│   └── cli/          # Demo CLI
├── .github/
│   └── workflows/    # CI configuration
├── Makefile
└── README.md
```

## Configuration

### Living Appendix (vault)

```typescript
{
  guardians: [
    { fingerprint: "0x...", rank: "G1", status: "ACTIVE" }
  ],
  secondChannels: [
    { type: "EMAIL", identifier: "kamil@...", confirmationRule: "includes daily codeword" }
  ],
  succession: {
    inactivityThreshold: 180,  // days
    coolingPeriod: 7,          // days
    safeModeExitCondition: "verified_kamil_only"
  }
}
```

## Security

### What's Protected

- Constitution integrity (hash verification)
- Guardian key management (fingerprint-only, no private keys)
- Injection attempts (detected and blocked)
- Coercion attempts (triggers verification or safe mode)
- Privacy (no private data on-chain)

### What's NOT Protected (Out of Scope)

- Physical access to local vault
- Model-level jailbreaks (handled by model, not this system)
- Social engineering of Kamil directly

## Deployment

### Local Development

```bash
# Start local Hardhat node
make deploy-local
```

### Sepolia Testnet

1. **Get API Keys**
   - RPC: Get a free API key from [Alchemy](https://www.alchemy.com) or [Infura](https://infura.io)
   - ETH: Get Sepolia ETH from [sepoliafaucet.com](https://sepoliafaucet.com)

2. **Configure Environment**
   ```bash
   cd chain
   cp .env.example .env
   # Edit .env with your values:
   # SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
   # PRIVATE_KEY=your_wallet_private_key_without_0x
   ```

3. **Deploy**
   ```bash
   make deploy-sepolia
   ```

4. **Verify on Etherscan** (optional)
   ```bash
   cd chain
   npx hardhat verify --network sepolia DEPLOYED_ADDRESS "CORE_HASH"
   ```

### Deployed Contracts

| Network | Address | Explorer |
|---------|---------|----------|
| Sepolia | `0x3974555c82b75F0022a7Ec33D03f7c22931BE3f7` | [View on Etherscan](https://sepolia.etherscan.io/address/0x3974555c82b75F0022a7Ec33D03f7c22931BE3f7) |

**Anchored Core Hash:** `0x77cae9b45b3ddc681ff58450289daf9d401908e5c53855d4c416fe99f31fd76e`

**Deployment Receipt:** See [`receipts/sepolia-enhanced-20260202.json`](receipts/sepolia-enhanced-20260202.json)

## License

MIT

## Contributing

1. Fork the repository
2. Create a feature branch
3. Ensure all tests pass (`make test`)
4. Submit a pull request

---

Built with ❤️ for sovereign AI.
