import { ethers, run } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import hardhatConfig from "../hardhat.config";

// Receipt version for forward compatibility
const RECEIPT_VERSION = "1.0";

// ═══════════════════════════════════════════════════════════════
// CANONICAL JSON (must match receipts/canonical.ts exactly!)
// RFC 8785-style: recursive key sort, no whitespace, UTF-8
// ═══════════════════════════════════════════════════════════════

function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Cannot canonicalize Infinity or NaN");
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((el) => canonicalize(el)).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const pairs = keys
      .filter((k) => obj[k] !== undefined)
      .map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k]));
    return "{" + pairs.join(",") + "}";
  }
  throw new Error(`Cannot canonicalize type: ${typeof value}`);
}

function computeCanonicalHash(data: Record<string, unknown>, excludeFields: string[] = []): string {
  const filtered: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data)) {
    if (!excludeFields.includes(key)) filtered[key] = value;
  }
  const canonical = canonicalize(filtered);
  return "0x" + crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

async function main() {
  console.log("═══════════════════════════════════════════════════════════════");
  console.log("  KAI Charter Registry - Deployment");
  console.log("═══════════════════════════════════════════════════════════════\n");

  // Load and hash the Core constitution
  const corePath = path.join(__dirname, "../../constitution/core/kai_constitution_core_v1_4.txt");
  let coreHash: string;

  if (fs.existsSync(corePath)) {
    const coreContent = fs.readFileSync(corePath, "utf8");
    coreHash = "0x" + crypto.createHash("sha256").update(coreContent).digest("hex");
    console.log("✓ Loaded Core constitution from:", corePath);
    console.log("✓ Core hash (SHA-256):", coreHash);
  } else {
    // Fallback hash for testing
    coreHash = ethers.keccak256(ethers.toUtf8Bytes("KAI Constitution Core v1.4"));
    console.log("⚠ Core file not found, using default hash:", coreHash);
  }

  console.log("\n--- Deploying Contract ---\n");

  const [deployer] = await ethers.getSigners();
  console.log("Deployer address:", deployer.address);
  console.log("Deployer balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH");

  const KAICharterRegistry = await ethers.getContractFactory("KAICharterRegistry");
  const registry = await KAICharterRegistry.deploy(coreHash);

  // Capture deployment transaction
  const deployTx = registry.deploymentTransaction();
  await registry.waitForDeployment();

  const address = await registry.getAddress();
  console.log("\n✓ KAICharterRegistry deployed to:", address);

  // Get transaction receipt for txHash and gas info
  const txReceipt = deployTx ? await deployTx.wait() : null;
  const txHash = txReceipt?.hash || deployTx?.hash || "unknown";
  console.log("✓ Transaction hash:", txHash);

  // Verify deployment
  const deployedCoreHash = await registry.coreHash();
  const owner = await registry.owner();
  const version = await registry.coreVersion();

  console.log("\n--- Deployment Verification ---\n");
  console.log("Owner:", owner);
  console.log("Core Hash:", deployedCoreHash);
  console.log("Core Version:", version.toString());

  // Get deployed bytecode and hash it
  const deployedBytecode = await ethers.provider.getCode(address);
  const bytecodeHash = ethers.keccak256(deployedBytecode);
  console.log("Bytecode Hash:", bytecodeHash);

  // Get compiler settings from hardhat config
  const solcConfig = hardhatConfig.solidity;
  const solcVersion = typeof solcConfig === "string" ? solcConfig : solcConfig?.version || "unknown";
  const optimizerRuns = typeof solcConfig === "object" && solcConfig?.settings?.optimizer?.runs || 200;

  // Build publication-ready receipt
  const network = await ethers.provider.getNetwork();
  const blockNumber = txReceipt?.blockNumber || await ethers.provider.getBlockNumber();

  const deploymentInfo = {
    receiptVersion: RECEIPT_VERSION,
    chainId: Number(network.chainId),
    network: network.name || (Number(network.chainId) === 11155111 ? "sepolia" : "unknown"),
    contractAddress: address,
    contractName: "KAICharterRegistry",
    txHash: txHash,
    blockNumber: blockNumber,
    deployedAt: new Date().toISOString(),
    owner: owner,
    coreHash: deployedCoreHash,
    coreVersion: Number(version),
    bytecodeHash: bytecodeHash,
    solcVersion: solcVersion,
    optimizerRuns: optimizerRuns,
    gasUsed: txReceipt?.gasUsed?.toString() || "unknown"
  };

  // Generate canonical receipt hash (RFC 8785-style, recursive sort)
  const receiptHash = computeCanonicalHash(deploymentInfo, []);
  (deploymentInfo as any).receiptHash = receiptHash;

  console.log("Receipt Hash:", receiptHash);

  const deploymentPath = path.join(__dirname, "../deployments");
  if (!fs.existsSync(deploymentPath)) {
    fs.mkdirSync(deploymentPath, { recursive: true });
  }

  const filename = `deployment-${deploymentInfo.chainId}-${Date.now()}.json`;
  fs.writeFileSync(
    path.join(deploymentPath, filename),
    JSON.stringify(deploymentInfo, null, 2)
  );

  console.log("\n✓ Deployment info saved to:", filename);
  console.log("\n═══════════════════════════════════════════════════════════════");
  console.log("  Deployment Complete!");
  console.log("═══════════════════════════════════════════════════════════════\n");

  return deploymentInfo;
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
