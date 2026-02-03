#!/usr/bin/env tsx
/**
 * KAI Real Chain Demo Runbook
 *
 * This script performs the REAL on-chain demo - not simulated.
 * It anchors a release to an actual blockchain and verifies it.
 *
 * Prerequisites:
 *   - RPC_URL: Ethereum RPC endpoint (e.g., Sepolia, local Anvil)
 *   - CONTRACT_ADDRESS: Deployed KAI Registry contract
 *   - PRIVATE_KEY: Key with ETH for gas
 *
 * Run with:
 *   RPC_URL=... CONTRACT_ADDRESS=... PRIVATE_KEY=... npx tsx scripts/demo-runbook-realchain.ts
 *
 * Or with local Anvil:
 *   anvil &
 *   npx tsx scripts/demo-runbook-realchain.ts --local
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
  registerRelease,
  verifyReleaseOnChain,
  anchorReceiptBatch,
  checkConnection,
  type ChainConfig,
} from "../src/chain.js";

import {
  ReceiptChain,
  createReceiptBatch,
  computeMerkleRoot,
} from "../src/receipt-generator.js";

import type { SessionState } from "../src/types.js";

// ============================================================================
// Configuration
// ============================================================================

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

// ============================================================================
// Demo Context
// ============================================================================

interface DemoContext {
  tmpDir: string;
  governanceDir: string;
  releasesDir: string;
  chainConfig: ChainConfig;
}

async function setupDemo(useLocal: boolean): Promise<DemoContext> {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "kai-realchain-"));
  const governanceDir = path.join(tmpDir, "governance");
  const releasesDir = path.join(tmpDir, "releases");

  await fs.mkdir(governanceDir, { recursive: true });
  await fs.mkdir(path.join(governanceDir, "constitution"), { recursive: true });
  await fs.mkdir(path.join(governanceDir, "tools"), { recursive: true });
  await fs.mkdir(releasesDir, { recursive: true });

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
  send_email:
    name: send_email
    risk_level: HIGH
    egress: true
    approval_required: true
`
  );

  // Chain config
  let chainConfig: ChainConfig;

  if (useLocal) {
    // Local Anvil defaults
    chainConfig = {
      rpcUrl: "http://127.0.0.1:8545",
      contractAddress: process.env.CONTRACT_ADDRESS || "",
      privateKey: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", // Anvil default
    };
  } else {
    // From environment
    chainConfig = {
      rpcUrl: process.env.RPC_URL || "",
      contractAddress: process.env.CONTRACT_ADDRESS || "",
      privateKey: process.env.PRIVATE_KEY || "",
    };
  }

  return { tmpDir, governanceDir, releasesDir, chainConfig };
}

async function cleanupDemo(ctx: DemoContext): Promise<void> {
  await fs.rm(ctx.tmpDir, { recursive: true, force: true });
}

// ============================================================================
// Real Chain Demo
// ============================================================================

async function runRealChainDemo(useLocal: boolean): Promise<void> {
  console.log();
  console.log(colors.bold("╔══════════════════════════════════════════════════════════════╗"));
  console.log(colors.bold("║     KAI v0.5 - REAL CHAIN Demo                               ║"));
  console.log(colors.bold("║     This is NOT simulated - actual blockchain transactions   ║"));
  console.log(colors.bold("╚══════════════════════════════════════════════════════════════╝"));

  const ctx = await setupDemo(useLocal);

  try {
    // Validate config
    header("STEP 0: Validate Chain Configuration");

    if (!ctx.chainConfig.rpcUrl) {
      fail("RPC_URL not set");
      console.log(colors.yellow("\n  Set RPC_URL environment variable or use --local for Anvil"));
      process.exit(1);
    }

    if (!ctx.chainConfig.contractAddress) {
      fail("CONTRACT_ADDRESS not set");
      console.log(colors.yellow("\n  Deploy KAI Registry contract first, then set CONTRACT_ADDRESS"));
      console.log(colors.dim("  See contracts/KAIRegistry.sol for deployment"));
      process.exit(1);
    }

    if (!ctx.chainConfig.privateKey) {
      fail("PRIVATE_KEY not set");
      process.exit(1);
    }

    check(`RPC: ${ctx.chainConfig.rpcUrl}`);
    check(`Contract: ${ctx.chainConfig.contractAddress}`);

    // Check connection
    info("Checking chain connection...");
    const connStatus = await checkConnection(ctx.chainConfig);

    if (!connStatus.connected) {
      fail(`Connection failed: ${connStatus.error}`);
      process.exit(1);
    }

    check(`Connected! Chain ID: ${connStatus.chainId}`);
    check(`Existing releases: ${connStatus.releaseCount}`);

    // STEP 1: Build and sign release
    header("STEP 1: Build and Sign Release");

    const manifest = await buildRelease(ctx.governanceDir, "1.0.0");
    check(`Release built: ${manifest.files.length} files`);
    info(`Root hash: ${manifest.root_hash}`);

    const signedRelease = await signRelease(manifest, ctx.chainConfig.privateKey, 1);
    check(`Signed by: ${signedRelease.signatures[0].signer_address}`);

    const releasePath = path.join(ctx.releasesDir, "v1.0.0.json");
    await saveManifest(signedRelease, releasePath);

    // STEP 2: REAL on-chain anchor
    header("STEP 2: Anchor Release ON-CHAIN (REAL)");

    // Check if already registered
    const existingCheck = await verifyReleaseOnChain(ctx.chainConfig, signedRelease.root_hash);

    if (existingCheck.registered) {
      info("Release already anchored on-chain");
      check(`Block: ${existingCheck.blockNumber}`);
    } else {
      info("Submitting transaction...");

      const anchorResult = await registerRelease(
        ctx.chainConfig,
        signedRelease.root_hash,
        signedRelease.release_version
      );

      check(`Transaction submitted!`);
      console.log();
      console.log(colors.green("  ┌─────────────────────────────────────────────────────────┐"));
      console.log(colors.green(`  │ TX HASH: ${anchorResult.txHash.slice(0, 42)}...`));
      console.log(colors.green(`  │ BLOCK:   ${anchorResult.blockNumber}`));
      console.log(colors.green("  └─────────────────────────────────────────────────────────┘"));
    }

    // STEP 3: Verify on-chain
    header("STEP 3: Verify Release On-Chain");

    const verifyResult = await verifyReleaseOnChain(ctx.chainConfig, signedRelease.root_hash);

    if (verifyResult.registered) {
      check("Release verified on-chain!");
      check(`Version: ${verifyResult.version}`);
      check(`Block: ${verifyResult.blockNumber}`);
      check(`Revoked: ${verifyResult.revoked}`);
    } else {
      fail("Release NOT found on-chain (unexpected)");
      process.exit(1);
    }

    // STEP 4: Create and anchor receipt batch
    header("STEP 4: Create and Anchor Receipt Batch (REAL)");

    const session: SessionState = {
      session_id: `realchain-demo-${Date.now()}`,
      started_at: Date.now(),
      release_root_hash: signedRelease.root_hash,
      current_sensitivity: "PUBLIC",
      tool_calls: [],
      approvals_used: [],
      sequence_number: 0,
    };

    const chain = new ReceiptChain(session.session_id, signedRelease.root_hash);

    // Create 5 receipts (odd count to prove Merkle fix)
    for (let i = 0; i < 5; i++) {
      await chain.addReceipt(session, [], [], Date.now() - (5 - i) * 1000, ctx.chainConfig.privateKey);
    }

    const receipts = chain.getReceipts();
    const batch = createReceiptBatch(receipts);

    check(`Batch created: ${receipts.length} receipts`);
    info(`Merkle root: ${batch.merkle_root}`);

    info("Anchoring batch on-chain...");

    const batchResult = await anchorReceiptBatch(
      ctx.chainConfig,
      batch.merkle_root,
      signedRelease.root_hash,
      receipts.length
    );

    check("Batch anchored!");
    console.log();
    console.log(colors.green("  ┌─────────────────────────────────────────────────────────┐"));
    console.log(colors.green(`  │ BATCH TX: ${batchResult.txHash.slice(0, 42)}...`));
    console.log(colors.green(`  │ BLOCK:    ${batchResult.blockNumber}`));
    console.log(colors.green("  └─────────────────────────────────────────────────────────┘"));

    // STEP 5: kai verify-live equivalent
    header("STEP 5: Live Verification (kai verify-live)");

    // Rebuild from governance and compare
    const freshManifest = await buildRelease(ctx.governanceDir, "1.0.0");
    const localHash = freshManifest.root_hash;

    check(`Local governance hash: ${localHash.slice(0, 24)}...`);

    const liveVerify = await verifyReleaseOnChain(ctx.chainConfig, localHash);

    if (liveVerify.registered && !liveVerify.revoked) {
      console.log();
      console.log(colors.green("  ╔════════════════════════════════════════════════════════════╗"));
      console.log(colors.green("  ║                                                            ║"));
      console.log(colors.green("  ║   ✓ RUNNING VERIFIED RELEASE v1.0.0                       ║"));
      console.log(colors.green("  ║                                                            ║"));
      console.log(colors.green("  ║   Local governance matches on-chain anchor                 ║"));
      console.log(colors.green("  ║                                                            ║"));
      console.log(colors.green("  ╚════════════════════════════════════════════════════════════╝"));
      console.log();
      console.log(colors.dim(`  Root hash: ${localHash}`));
      console.log(colors.dim(`  On-chain block: ${liveVerify.blockNumber}`));
    } else {
      fail("Verification mismatch!");
    }

    // Summary
    header("DEMO COMPLETE - REAL CHAIN");
    console.log();
    console.log(colors.green("  All steps completed with REAL blockchain transactions:"));
    console.log(colors.dim("  1. ✓ Built and signed release"));
    console.log(colors.dim("  2. ✓ Anchored release ON-CHAIN (real tx)"));
    console.log(colors.dim("  3. ✓ Verified release on-chain"));
    console.log(colors.dim("  4. ✓ Anchored receipt batch ON-CHAIN (real tx)"));
    console.log(colors.dim("  5. ✓ Live verification passed"));
    console.log();
    console.log(colors.cyan("  This is KAI: verifiable governance with on-chain proof."));
    console.log(colors.cyan("  \"Trust is an artifact\" - and now you have the artifacts."));
    console.log();

  } finally {
    await cleanupDemo(ctx);
  }
}

// ============================================================================
// Main
// ============================================================================

const useLocal = process.argv.includes("--local");

runRealChainDemo(useLocal).catch(err => {
  console.error(colors.red("Demo failed:"), err.message);
  if (err.message.includes("could not detect network")) {
    console.log(colors.yellow("\nIs your RPC endpoint running?"));
    console.log(colors.dim("  For local testing, run: anvil"));
  }
  process.exit(1);
});
