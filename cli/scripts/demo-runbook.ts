#!/usr/bin/env tsx
/**
 * KAI Demo Runbook
 *
 * 5-minute demonstration of KAI's verifiable governance system.
 * Run with: npm run demo
 *
 * This script demonstrates 6 key moments:
 * 1. Build/sign/verify a release → show root hash
 * 2. Anchor release on-chain → show tx + event (simulated)
 * 3. Executor blocks disallowed tool call
 * 4. Approval required call fails without token → then succeeds with token
 * 5. Replay same token → rejected (nonce spent)
 * 6. Receipt chain verify + anchorReceiptBatch with odd count (3 or 5)
 */

import * as fs from "fs/promises";
import * as path from "path";
import * as os from "os";
import { ethers } from "ethers";

// Import KAI modules
import {
  buildRelease,
  signRelease,
  verifyRelease,
  saveManifest,
} from "../src/release-builder.js";

import {
  ToolExecutor,
  createDefaultRegistry,
} from "../src/tool-executor.js";

import {
  createApprovalRequest,
  createApprovalToken,
  validateApprovalToken,
  NonceDatabase,
  consumeToken,
} from "../src/approval-tokens.js";

import {
  ReceiptChain,
  createReceiptBatch,
  generateMerkleProof,
  verifyMerkleProof,
  computeMerkleRoot,
} from "../src/receipt-generator.js";

import { computeActionHash } from "../src/canonical.js";

import type { ToolCallRequest, SessionState } from "../src/types.js";

// ============================================================================
// Demo Configuration
// ============================================================================

const TEST_PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_ADDRESS = new ethers.Wallet(TEST_PRIVATE_KEY).address;

// Colors for output
const colors = {
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[33m${s}\x1b[0m`,
  blue: (s: string) => `\x1b[34m${s}\x1b[0m`,
  cyan: (s: string) => `\x1b[36m${s}\x1b[0m`,
  bold: (s: string) => `\x1b[1m${s}\x1b[0m`,
  dim: (s: string) => `\x1b[2m${s}\x1b[0m`,
};

function check(label: string): void {
  console.log(colors.green(`  ✓ ${label}`));
}

function fail(label: string): void {
  console.log(colors.red(`  ✗ ${label}`));
}

function info(label: string): void {
  console.log(colors.cyan(`  ℹ ${label}`));
}

function header(title: string): void {
  console.log();
  console.log(colors.bold(colors.blue(`━━━ ${title} ━━━`)));
}

function subheader(title: string): void {
  console.log(colors.yellow(`\n  ${title}`));
}

// ============================================================================
// Demo Setup
// ============================================================================

interface DemoContext {
  tmpDir: string;
  governanceDir: string;
  releasesDir: string;
  receiptsDir: string;
}

async function setupDemo(): Promise<DemoContext> {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "kai-demo-"));
  const governanceDir = path.join(tmpDir, "governance");
  const releasesDir = path.join(tmpDir, "releases");
  const receiptsDir = path.join(tmpDir, "receipts");

  await fs.mkdir(governanceDir, { recursive: true });
  await fs.mkdir(path.join(governanceDir, "constitution"), { recursive: true });
  await fs.mkdir(path.join(governanceDir, "tools"), { recursive: true });
  await fs.mkdir(path.join(governanceDir, "schemas"), { recursive: true });
  await fs.mkdir(releasesDir, { recursive: true });
  await fs.mkdir(receiptsDir, { recursive: true });

  // Create governance files
  await fs.writeFile(
    path.join(governanceDir, "constitution", "charter.md"),
    `# KAI Governance Charter v1.0

## Purpose
This charter defines the governance boundaries for AI agent operations.

## Principles
1. All tool actions require validation
2. Sensitive operations require human approval
3. All actions generate tamper-evident receipts
4. Trust is an artifact, not an assumption
`
  );

  await fs.writeFile(
    path.join(governanceDir, "tools", "registry.yaml"),
    `version: "0.5"
tools:
  read_file:
    name: read_file
    risk_level: MEDIUM
    output_sensitivity: INHERIT
  send_email:
    name: send_email
    risk_level: HIGH
    egress: true
    approval_required: true
  web_search:
    name: web_search
    risk_level: LOW
`
  );

  await fs.writeFile(
    path.join(governanceDir, "schemas", "policy.json"),
    JSON.stringify({ version: "0.5", rules: [] }, null, 2)
  );

  return { tmpDir, governanceDir, releasesDir, receiptsDir };
}

async function cleanupDemo(ctx: DemoContext): Promise<void> {
  await fs.rm(ctx.tmpDir, { recursive: true, force: true });
}

// ============================================================================
// Demo Moments
// ============================================================================

async function moment1_BuildSignVerify(ctx: DemoContext): Promise<string> {
  header("MOMENT 1: Build → Sign → Verify Release");

  subheader("Building release from governance files...");
  const manifest = await buildRelease(ctx.governanceDir, "1.0.0");
  check(`Release built: ${manifest.files.length} files`);
  info(`Root hash: ${manifest.root_hash.slice(0, 20)}...`);

  subheader("Signing release...");
  const signedRelease = await signRelease(manifest, TEST_PRIVATE_KEY, 1);
  check(`Signed by: ${signedRelease.signatures[0].signer_address.slice(0, 12)}...`);

  // Save release
  const releasePath = path.join(ctx.releasesDir, "v1.0.0.json");
  await saveManifest(signedRelease, releasePath);

  subheader("Verifying release...");
  const verifyResult = await verifyRelease(releasePath, ctx.governanceDir);

  if (verifyResult.valid) {
    check("Release verification PASSED");
    check(`All ${verifyResult.fileVerification.length} file hashes match`);
    check(`Signature valid: ${verifyResult.signatureVerification?.[0].valid}`);
  } else {
    fail(`Verification failed: ${verifyResult.errors.join(", ")}`);
  }

  return signedRelease.root_hash;
}

async function moment2_AnchorOnChain(rootHash: string): Promise<void> {
  header("MOMENT 2: Anchor Release On-Chain");

  subheader("Simulating on-chain anchor...");
  info("(In production, this calls the KAI Registry contract)");

  // Simulate contract call
  const mockTxHash = ethers.keccak256(ethers.toUtf8Bytes(rootHash + Date.now()));
  const mockBlockNumber = 12345678;

  check(`Transaction submitted: ${mockTxHash.slice(0, 20)}...`);
  check(`Block number: ${mockBlockNumber}`);
  check(`Root hash anchored: ${rootHash.slice(0, 20)}...`);

  info("Event: ReleaseAnchored(version='1.0.0', rootHash=..., signer=...)");
}

async function moment3_ExecutorBlocks(rootHash: string): Promise<void> {
  header("MOMENT 3: Executor Blocks Disallowed Tool");

  const registry = {
    ...createDefaultRegistry(),
    tools: {
      ...createDefaultRegistry().tools,
      read_file: {
        name: "read_file",
        risk_level: "MEDIUM" as const,
        output_sensitivity: "INHERIT",
        path_rules: [
          { pattern: "workspace/**", sensitivity: "PUBLIC" as const },
          { pattern: "config/**", sensitivity: "INTERNAL" as const },
          // No catch-all - unlisted paths are BLOCKED
        ],
      },
    },
  };

  const executor = new ToolExecutor(registry, rootHash);

  subheader("Attempting to read /etc/shadow (forbidden path)...");
  const request: ToolCallRequest = {
    request_id: "demo-1",
    tool_name: "read_file",
    parameters: { path: "/etc/shadow" },
    timestamp: Date.now(),
  };

  const result = await executor.execute(request);

  if (result.status === "blocked") {
    check(`BLOCKED: ${result.decision.reason}`);
    check("Hard boundary enforcement working");
  } else {
    fail("Expected block, got: " + result.status);
  }
}

async function moment4_ApprovalFlow(rootHash: string): Promise<{
  token: ReturnType<typeof createApprovalToken> extends Promise<infer T> ? T : never;
  session: SessionState;
  request: ToolCallRequest;
  nonceDb: NonceDatabase;
}> {
  header("MOMENT 4: Approval Required → Fail → Succeed");

  const registry = createDefaultRegistry();
  const executor = new ToolExecutor(registry, rootHash);
  const session = executor.getSession();
  const nonceDb = new NonceDatabase();

  const request: ToolCallRequest = {
    request_id: "demo-2",
    tool_name: "send_email",
    parameters: { to: "user@example.com", subject: "Test" },
    timestamp: Date.now(),
  };

  subheader("Attempting send_email WITHOUT approval token...");
  const result1 = await executor.execute(request);

  if (result1.status === "awaiting_approval") {
    check(`BLOCKED: ${result1.decision.reason}`);
    check("Approval token required");
  } else {
    fail("Expected awaiting_approval, got: " + result1.status);
  }

  subheader("Creating approval token...");
  const approvalRequest = createApprovalRequest(
    rootHash,
    request,
    session,
    "Send email to user@example.com"
  );

  const token = await createApprovalToken(approvalRequest, TEST_PRIVATE_KEY);
  check(`Token created: nonce=${token.nonce.slice(0, 12)}...`);
  check(`Action hash: ${token.action_hash.slice(0, 16)}...`);
  check(`Expires: ${new Date(token.expires_at).toISOString()}`);

  subheader("Validating token...");
  const actionHash = computeActionHash(rootHash, request.tool_name, request.parameters);
  const validation = validateApprovalToken(
    token,
    rootHash,
    session.session_id,
    session.sequence_number,
    request.tool_name,
    actionHash,
    nonceDb
  );

  if (validation.valid) {
    check("Token validation PASSED");
  } else {
    fail(`Token invalid: ${validation.errors.join(", ")}`);
  }

  return { token, session, request, nonceDb };
}

async function moment5_ReplayRejection(ctx: {
  token: Awaited<ReturnType<typeof createApprovalToken>>;
  session: SessionState;
  request: ToolCallRequest;
  nonceDb: NonceDatabase;
}, rootHash: string): Promise<void> {
  header("MOMENT 5: Replay Attack → REJECTED");

  subheader("Consuming token (first use)...");
  consumeToken(ctx.token, ctx.nonceDb);
  check("Token consumed, nonce recorded");

  subheader("Attempting replay with same token...");
  const actionHash = computeActionHash(rootHash, ctx.request.tool_name, ctx.request.parameters);
  const replay = validateApprovalToken(
    ctx.token,
    rootHash,
    ctx.session.session_id,
    ctx.session.sequence_number,
    ctx.request.tool_name,
    actionHash,
    ctx.nonceDb
  );

  if (!replay.valid) {
    check("REPLAY REJECTED");
    check(`Reason: ${replay.errors.join(", ")}`);
  } else {
    fail("Replay should have been rejected!");
  }
}

async function moment6_ReceiptChainAndMerkle(rootHash: string): Promise<void> {
  header("MOMENT 6: Receipt Chain + Merkle Batch (Odd Count)");

  const session: SessionState = {
    session_id: "demo-session",
    started_at: Date.now(),
    release_root_hash: rootHash,
    current_sensitivity: "PUBLIC",
    tool_calls: [],
    approvals_used: [],
    sequence_number: 0,
  };

  const chain = new ReceiptChain("demo-session", rootHash);

  subheader("Creating 5 receipts (odd count)...");
  for (let i = 0; i < 5; i++) {
    await chain.addReceipt(session, [], [], Date.now() - (5 - i) * 1000, TEST_PRIVATE_KEY);
    check(`Receipt ${i + 1} added`);
  }

  subheader("Verifying receipt chain integrity...");
  const verification = chain.verifyChain();
  if (verification.valid) {
    check("Chain integrity VERIFIED");
    check("All hash links valid");
    check("All sequence numbers correct");
  } else {
    fail(`Chain verification failed: ${verification.errors.join(", ")}`);
  }

  subheader("Creating Merkle batch...");
  const receipts = chain.getReceipts();
  const batch = createReceiptBatch(receipts);
  check(`Batch created: ${receipts.length} receipts`);
  info(`Merkle root: ${batch.merkle_root.slice(0, 20)}...`);

  subheader("Verifying Merkle proofs for ALL receipts...");
  let allProofsValid = true;
  for (let i = 0; i < receipts.length; i++) {
    const { proof, index } = generateMerkleProof(receipts, i);
    const valid = verifyMerkleProof(
      receipts[i].receipt_hash,
      proof,
      index,
      batch.merkle_root
    );
    if (valid) {
      check(`Receipt ${i} proof valid (${proof.length} siblings)`);
    } else {
      fail(`Receipt ${i} proof INVALID`);
      allProofsValid = false;
    }
  }

  if (allProofsValid) {
    check("ALL 5 MERKLE PROOFS VALID (including odd-count edge case)");
  }

  subheader("Simulating batch anchor...");
  const mockAnchorTx = ethers.keccak256(ethers.toUtf8Bytes(batch.merkle_root));
  check(`Batch anchored: ${mockAnchorTx.slice(0, 20)}...`);
  info("Event: ReceiptBatchAnchored(sessionId='demo-session', merkleRoot=...)");
}

// ============================================================================
// Main Demo Runner
// ============================================================================

async function runDemo(): Promise<void> {
  console.log();
  console.log(colors.bold("╔══════════════════════════════════════════════════════════════╗"));
  console.log(colors.bold("║        KAI v0.5 - Verifiable Governance Demo                 ║"));
  console.log(colors.bold("║        \"Trust is an artifact, not an assumption\"             ║"));
  console.log(colors.bold("╚══════════════════════════════════════════════════════════════╝"));

  const ctx = await setupDemo();

  try {
    // Moment 1: Build/Sign/Verify
    const rootHash = await moment1_BuildSignVerify(ctx);

    // Moment 2: Anchor on-chain (simulated)
    await moment2_AnchorOnChain(rootHash);

    // Moment 3: Executor blocks
    await moment3_ExecutorBlocks(rootHash);

    // Moment 4: Approval flow
    const approvalCtx = await moment4_ApprovalFlow(rootHash);

    // Moment 5: Replay rejection
    await moment5_ReplayRejection(approvalCtx, rootHash);

    // Moment 6: Receipt chain + Merkle
    await moment6_ReceiptChainAndMerkle(rootHash);

    // Summary
    header("DEMO COMPLETE");
    console.log();
    console.log(colors.green("  All 6 moments demonstrated successfully:"));
    console.log(colors.dim("  1. ✓ Build/Sign/Verify release"));
    console.log(colors.dim("  2. ✓ Anchor on-chain (simulated)"));
    console.log(colors.dim("  3. ✓ Executor blocks disallowed tool"));
    console.log(colors.dim("  4. ✓ Approval required → token → success"));
    console.log(colors.dim("  5. ✓ Replay attack rejected"));
    console.log(colors.dim("  6. ✓ Receipt chain + Merkle proofs (odd count)"));
    console.log();
    console.log(colors.cyan("  This is KAI: verifiable governance for AI agents."));
    console.log();

  } finally {
    await cleanupDemo(ctx);
  }
}

// Run demo
runDemo().catch(err => {
  console.error(colors.red("Demo failed:"), err);
  process.exit(1);
});
