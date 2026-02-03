# Demo Video Script (60-90 seconds)

**Tone:** steady, matter-of-fact, no hype
**Visuals:** terminal only

---

"This is a live demo of KAI Sovereign Anchor running against a real blockchain.

I'm going to build and sign a governance release, anchor it on-chain, and then verify that the running system matches the anchored rules—without trusting the runtime.

*(Run the command)*

This command builds a deterministic governance manifest, signs it, and submits a real transaction to anchor the release root hash on-chain.

*(Pause on tx hash / block number)*

Next, it creates a Merkle receipt batch and anchors that as well, producing an auditable trail.

*(Pause)*

Now we run live verification. The system rebuilds the governance manifest locally and checks that its hash matches the on-chain anchor.

*(Show verification success box)*

Verification passes. The running system matches the anchored governance.

Finally, the demo writes all proof artifacts—transaction hashes, block numbers, roots, and verification output—into a markdown file.

*(Open DEMO_PROOF.md briefly)*

This is verifiable governance for AI agents.
Trust isn't assumed. It's proven."

---

## Recording Notes

1. Start with terminal visible, Anvil already running in background
2. Run: `CONTRACT_ADDRESS=0x5FbDB2315678afecb367f032d93F642f64180aa3 npm run demo:realchain -- --proof-out ./DEMO_PROOF.md`
3. Let it run to completion
4. Briefly show the generated DEMO_PROOF.md
5. Keep it under 90 seconds
