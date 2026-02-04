# KAI: Verifiable Governance for AI Agents

**What this does in 60 seconds:**

An LLM can *suggest* actions, but cannot *execute* tools without passing a verifier. This creates accountability where "trust me" becomes "check the receipt."

## Three Core Guarantees

1. **Tool Execution is Gated**
   The AI cannot call sensitive tools (send email, write file, make API call) unless the governance policy explicitly allows it—or a human approves.

2. **Governance is Signed and Anchored**
   The rules the AI runs under are cryptographically signed and can be anchored on-chain. At any moment, you can verify: "Is this AI running the policy I approved?"

3. **Every Action Leaves a Receipt**
   Tool calls generate signed, chained receipts. You get a tamper-evident audit trail proving what happened, when, under what policy.

## Quick Start

```bash
# Install
npm install

# Build and sign a governance release
kai build -d ./my-governance
kai sign -m manifest.json -k 0x...privatekey

# Run the executor (blocks disallowed tools)
kai executor start -m manifest.json

# Verify a running release matches on-chain anchor
kai verify-live -m manifest.json --rpc-url https://...
```

## Global Installation (One-Time Setup)

Install the `kai` command globally for easy access:

```bash
# Create directory and copy script
mkdir -p ~/.local/bin
cp ~/KAI_dev/kai-sovereign-anchor/cli/bin/kai ~/.local/bin/kai
chmod +x ~/.local/bin/kai

# Add to PATH (add to your ~/.zshrc for persistence)
export PATH="$HOME/.local/bin:$PATH"
```

Now you can run from anywhere:

```bash
kai demo     # Run the demo
kai proof    # Show the generated proof
kai status   # Check environment
kai test     # Run test suite
```

## What's Enforced vs Best-Effort

| Guarantee | Status |
|-----------|--------|
| Tool execution gating | ✅ Enforced |
| Human approval requirements | ✅ Enforced |
| Replay attack prevention | ✅ Enforced |
| Receipt chain integrity | ✅ Enforced |
| Deterministic hashing | ✅ Enforced |
| LLM text output filtering | ⚠️ Best-effort |
| Memory zeroization | ⚠️ Best-effort (JS limitation) |

See [THREAT_MODEL.md](./THREAT_MODEL.md) for precise security claims.

## The Comfort Story

Before KAI:
> "The AI said it wouldn't leak data. I guess I trust it?"

After KAI:
> "The governance policy blocks egress tools. The receipt chain proves no unauthorized calls were made. The on-chain anchor proves this is the policy I approved."

## Test Suite

```bash
npm test  # 319 tests covering tool gating, approvals, receipts, Merkle proofs, smuggling defense
```

## Demo

```bash
npm run demo  # 5-minute walkthrough of all guarantees
```

---

**Version:** 0.1-beta
**Status:** Shippable and defensible
