#!/usr/bin/env npx tsx
/**
 * Receipt Verification Script
 *
 * Verifies that a deployment receipt is tamper-evident by:
 * 1. Recomputing the receiptHash from canonical JSON (RFC 8785-style)
 * 2. Checking bytecodeHash matches on-chain (if RPC available)
 * 3. Checking coreHash matches on-chain (if RPC available)
 *
 * Usage:
 *   npx tsx verify_receipt.ts <receipt.json>
 *   npx tsx verify_receipt.ts <receipt.json> --rpc <RPC_URL>
 */

import * as fs from "fs";
import { verifyCanonicalHash } from "./canonical";

interface DeploymentReceipt {
  receiptVersion: string;
  chainId: number;
  network: string;
  contractAddress: string;
  contractName: string;
  txHash: string;
  blockNumber: number;
  deployedAt: string;
  owner: string;
  coreHash: string;
  coreVersion: number;
  bytecodeHash: string;
  solcVersion: string;
  optimizerRuns: number;
  gasUsed: string;
  receiptHash: string;
}

async function verifyOnChain(receipt: DeploymentReceipt, rpcUrl: string): Promise<{
  bytecodeMatch: boolean;
  computedBytecodeHash: string;
  coreHashMatch: boolean;
  ownerMatch: boolean;
  onChainCoreHash: string;
  onChainOwner: string;
  error?: string;
}> {
  const { ethers } = await import("ethers");
  const provider = new ethers.JsonRpcProvider(rpcUrl);

  // Get deployed bytecode (RUNTIME bytecode via eth_getCode)
  const deployedBytecode = await provider.getCode(receipt.contractAddress);

  // GUARD: Check for empty bytecode (wrong address, wrong network, or RPC issue)
  if (!deployedBytecode || deployedBytecode === "0x" || deployedBytecode === "0x0") {
    return {
      bytecodeMatch: false,
      computedBytecodeHash: "0x_NO_BYTECODE_FOUND",
      coreHashMatch: false,
      ownerMatch: false,
      onChainCoreHash: "unknown",
      onChainOwner: "unknown",
      error: `No bytecode at ${receipt.contractAddress}. Wrong address, network, or RPC?`
    };
  }

  const computedBytecodeHash = ethers.keccak256(deployedBytecode);

  // Get contract state (minimal ABI)
  const abi = [
    "function coreHash() view returns (bytes32)",
    "function owner() view returns (address)"
  ];
  const contract = new ethers.Contract(receipt.contractAddress, abi, provider);

  const onChainCoreHash = await contract.coreHash();
  const onChainOwner = await contract.owner();

  return {
    bytecodeMatch: computedBytecodeHash.toLowerCase() === receipt.bytecodeHash.toLowerCase(),
    computedBytecodeHash,
    coreHashMatch: onChainCoreHash.toLowerCase() === receipt.coreHash.toLowerCase(),
    ownerMatch: onChainOwner.toLowerCase() === receipt.owner.toLowerCase(),
    onChainCoreHash,
    onChainOwner
  };
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length < 1) {
    console.log("Usage: npx tsx verify_receipt.ts <receipt.json> [--rpc <RPC_URL>]");
    console.log("");
    console.log("Examples:");
    console.log("  npx tsx verify_receipt.ts sepolia-enhanced-20260202.json");
    console.log("  npx tsx verify_receipt.ts sepolia-enhanced-20260202.json --rpc https://eth-sepolia.g.alchemy.com/v2/KEY");
    process.exit(1);
  }

  const receiptPath = args[0];
  const rpcIndex = args.indexOf("--rpc");
  const rpcUrl = rpcIndex !== -1 ? args[rpcIndex + 1] : null;

  // Load receipt
  if (!fs.existsSync(receiptPath)) {
    console.error(`❌ Receipt file not found: ${receiptPath}`);
    process.exit(1);
  }

  const receipt: DeploymentReceipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));

  console.log("═══════════════════════════════════════════════════════════════");
  console.log("  KAI Receipt Verification");
  console.log("═══════════════════════════════════════════════════════════════\n");

  console.log(`Receipt:  ${receiptPath}`);
  console.log(`Contract: ${receipt.contractAddress}`);
  console.log(`Network:  ${receipt.network} (chainId: ${receipt.chainId})`);
  console.log(`Deployed: ${receipt.deployedAt}`);
  console.log(`TxHash:   ${receipt.txHash}\n`);

  // ═══════════════════════════════════════════════════════════════
  // 1. Verify receipt hash (tamper evidence)
  // ═══════════════════════════════════════════════════════════════
  console.log("--- Receipt Hash Verification ---\n");

  const verification = verifyCanonicalHash(receipt, receipt.receiptHash, "receiptHash");

  console.log(`Stored receiptHash:   ${verification.storedHash}`);
  console.log(`Computed receiptHash: ${verification.computedHash}`);
  console.log(`Status: ${verification.match ? "✅ MATCH - Receipt is tamper-evident" : "❌ MISMATCH - Receipt may have been modified"}\n`);

  if (!verification.match) {
    console.log("Debug: Canonical JSON used for hash:");
    console.log(verification.canonicalJson.substring(0, 200) + "...\n");
  }

  // ═══════════════════════════════════════════════════════════════
  // 2. Verify on-chain (if RPC provided)
  // ═══════════════════════════════════════════════════════════════
  if (rpcUrl) {
    console.log("--- On-Chain Verification ---\n");
    console.log(`RPC: ${rpcUrl}\n`);

    try {
      const onChain = await verifyOnChain(receipt, rpcUrl);

      if (onChain.error) {
        console.log(`❌ ERROR: ${onChain.error}\n`);
      } else {
        // Bytecode
        console.log(`Bytecode Hash (receipt):   ${receipt.bytecodeHash}`);
        console.log(`Bytecode Hash (on-chain):  ${onChain.computedBytecodeHash}`);
        console.log(`Status: ${onChain.bytecodeMatch ? "✅ MATCH" : "❌ MISMATCH"}\n`);

        // Core Hash
        console.log(`Core Hash (receipt):   ${receipt.coreHash}`);
        console.log(`Core Hash (on-chain):  ${onChain.onChainCoreHash}`);
        console.log(`Status: ${onChain.coreHashMatch ? "✅ MATCH" : "❌ MISMATCH"}\n`);

        // Owner
        console.log(`Owner (receipt):   ${receipt.owner}`);
        console.log(`Owner (on-chain):  ${onChain.onChainOwner}`);
        console.log(`Status: ${onChain.ownerMatch ? "✅ MATCH" : "❌ MISMATCH"}\n`);

        if (!onChain.bytecodeMatch || !onChain.coreHashMatch) {
          console.log("⚠️  WARNING: On-chain state differs from receipt!");
          console.log("    This could mean: contract upgraded, wrong network, or tampering.\n");
        }
      }
    } catch (error: any) {
      console.log(`⚠️  Could not verify on-chain: ${error.message}`);
      console.log("    Check: RPC URL valid? Network correct? Rate limited?\n");
    }
  } else {
    console.log("--- On-Chain Verification ---\n");
    console.log("⏭️  Skipped (no --rpc provided)\n");
    console.log("To verify on-chain, run:");
    console.log(`  npx tsx verify_receipt.ts ${receiptPath} --rpc <RPC_URL>\n`);
  }

  // ═══════════════════════════════════════════════════════════════
  // 3. Summary
  // ═══════════════════════════════════════════════════════════════
  console.log("═══════════════════════════════════════════════════════════════");
  if (verification.match) {
    console.log("  ✅ Receipt verification PASSED");
    console.log("     The receipt hash is valid and tamper-evident.");
  } else {
    console.log("  ❌ Receipt verification FAILED");
    console.log("     The receipt may have been modified after creation.");
    process.exit(1);
  }
  console.log("═══════════════════════════════════════════════════════════════\n");

  // ═══════════════════════════════════════════════════════════════
  // 4. Spec Summary (for transparency)
  // ═══════════════════════════════════════════════════════════════
  console.log("--- Hash Specification ---");
  console.log("• receiptHash = SHA-256(canonical_json(receipt without receiptHash))");
  console.log("• bytecodeHash = keccak256(runtime_bytecode from eth_getCode)");
  console.log("• coreHash = bytes32 stored in contract state (constructor arg)");
  console.log("• Canonical JSON: deterministic (recursive key sort, UTF-8, no whitespace, omits undefined)");
  console.log("  Note: Project-defined canonicalization, not RFC 8785/JCS.\n");
}

main().catch((err) => {
  console.error("Fatal error:", err.message);
  process.exit(1);
});
