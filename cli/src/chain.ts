/**
 * Chain Integration
 * Ticket 9: On-chain Registry operations
 *
 * Provides methods to:
 * - Register releases on-chain
 * - Anchor receipt batches
 * - Verify on-chain anchors
 */

import { ethers } from "ethers";

// Contract ABI (just the functions we need)
const CONTRACT_ABI = [
  // Release Registry
  "function registerRelease(bytes32 _rootHash, string calldata _version) external",
  "function revokeRelease(bytes32 _rootHash, string calldata _reason) external",
  "function verifyRelease(bytes32 _rootHash) external view returns (bool registered, bool revoked, string memory version, uint256 blockNumber)",
  "function getAllReleaseHashes() external view returns (bytes32[] memory)",
  "function getReleaseCount() external view returns (uint256)",

  // Receipt Batches
  "function anchorReceiptBatch(bytes32 _batchHash, bytes32 _releaseRootHash, uint256 _receiptCount) external",
  "function getReceiptBatch(bytes32 _batchHash) external view returns (bytes32 releaseRootHash, uint256 blockNumber, uint256 timestamp, uint256 receiptCount)",
  "function getAllBatchHashes() external view returns (bytes32[] memory)",
  "function getBatchCount() external view returns (uint256)",

  // Events
  "event ReleaseRegistered(bytes32 indexed rootHash, string version, address indexed registrar, uint256 blockNumber, uint256 timestamp)",
  "event ReleaseRevoked(bytes32 indexed rootHash, string reason, uint256 timestamp)",
  "event ReceiptBatchAnchored(bytes32 indexed batchHash, bytes32 indexed releaseRootHash, uint256 receiptCount, uint256 blockNumber, uint256 timestamp)",
];

export interface ChainConfig {
  rpcUrl: string;
  contractAddress: string;
  privateKey?: string;
}

export interface ReleaseVerification {
  registered: boolean;
  revoked: boolean;
  version: string;
  blockNumber: number;
}

export interface BatchVerification {
  releaseRootHash: string;
  blockNumber: number;
  timestamp: number;
  receiptCount: number;
}

/**
 * Creates a provider for read-only operations
 */
export function createProvider(rpcUrl: string): ethers.JsonRpcProvider {
  return new ethers.JsonRpcProvider(rpcUrl);
}

/**
 * Creates a signer for write operations
 */
export function createSigner(
  rpcUrl: string,
  privateKey: string
): ethers.Wallet {
  const provider = createProvider(rpcUrl);
  return new ethers.Wallet(privateKey, provider);
}

/**
 * Creates contract instance for read operations
 */
export function getContract(
  contractAddress: string,
  providerOrSigner: ethers.Provider | ethers.Signer
): ethers.Contract {
  return new ethers.Contract(contractAddress, CONTRACT_ABI, providerOrSigner);
}

// ============================================================================
// Release Operations
// ============================================================================

/**
 * Register a release on-chain
 */
export async function registerRelease(
  config: ChainConfig,
  rootHash: string,
  version: string
): Promise<{ txHash: string; blockNumber: number }> {
  if (!config.privateKey) {
    throw new Error("Private key required for write operations");
  }

  const signer = createSigner(config.rpcUrl, config.privateKey);
  const contract = getContract(config.contractAddress, signer);

  // Ensure rootHash is bytes32
  const rootHashBytes = rootHash.startsWith("0x") ? rootHash : `0x${rootHash}`;

  const tx = await contract.registerRelease(rootHashBytes, version);
  const receipt = await tx.wait();

  return {
    txHash: receipt.hash,
    blockNumber: receipt.blockNumber,
  };
}

/**
 * Verify a release on-chain
 */
export async function verifyReleaseOnChain(
  config: ChainConfig,
  rootHash: string
): Promise<ReleaseVerification> {
  const provider = createProvider(config.rpcUrl);
  const contract = getContract(config.contractAddress, provider);

  const rootHashBytes = rootHash.startsWith("0x") ? rootHash : `0x${rootHash}`;
  const result = await contract.verifyRelease(rootHashBytes);

  return {
    registered: result[0],
    revoked: result[1],
    version: result[2],
    blockNumber: Number(result[3]),
  };
}

/**
 * Get all registered releases
 */
export async function getAllReleases(
  config: ChainConfig
): Promise<string[]> {
  const provider = createProvider(config.rpcUrl);
  const contract = getContract(config.contractAddress, provider);

  return await contract.getAllReleaseHashes();
}

/**
 * Revoke a release
 */
export async function revokeReleaseOnChain(
  config: ChainConfig,
  rootHash: string,
  reason: string
): Promise<{ txHash: string }> {
  if (!config.privateKey) {
    throw new Error("Private key required for write operations");
  }

  const signer = createSigner(config.rpcUrl, config.privateKey);
  const contract = getContract(config.contractAddress, signer);

  const rootHashBytes = rootHash.startsWith("0x") ? rootHash : `0x${rootHash}`;
  const tx = await contract.revokeRelease(rootHashBytes, reason);
  await tx.wait();

  return { txHash: tx.hash };
}

// ============================================================================
// Receipt Batch Operations
// ============================================================================

/**
 * Anchor a receipt batch on-chain
 */
export async function anchorReceiptBatch(
  config: ChainConfig,
  batchHash: string,
  releaseRootHash: string,
  receiptCount: number
): Promise<{ txHash: string; blockNumber: number }> {
  if (!config.privateKey) {
    throw new Error("Private key required for write operations");
  }

  const signer = createSigner(config.rpcUrl, config.privateKey);
  const contract = getContract(config.contractAddress, signer);

  const batchHashBytes = batchHash.startsWith("0x") ? batchHash : `0x${batchHash}`;
  const releaseHashBytes = releaseRootHash.startsWith("0x")
    ? releaseRootHash
    : `0x${releaseRootHash}`;

  const tx = await contract.anchorReceiptBatch(
    batchHashBytes,
    releaseHashBytes,
    receiptCount
  );
  const receipt = await tx.wait();

  return {
    txHash: receipt.hash,
    blockNumber: receipt.blockNumber,
  };
}

/**
 * Verify a receipt batch on-chain
 */
export async function verifyReceiptBatch(
  config: ChainConfig,
  batchHash: string
): Promise<BatchVerification> {
  const provider = createProvider(config.rpcUrl);
  const contract = getContract(config.contractAddress, provider);

  const batchHashBytes = batchHash.startsWith("0x") ? batchHash : `0x${batchHash}`;
  const result = await contract.getReceiptBatch(batchHashBytes);

  return {
    releaseRootHash: result[0],
    blockNumber: Number(result[1]),
    timestamp: Number(result[2]),
    receiptCount: Number(result[3]),
  };
}

/**
 * Get all anchored batches
 */
export async function getAllBatches(
  config: ChainConfig
): Promise<string[]> {
  const provider = createProvider(config.rpcUrl);
  const contract = getContract(config.contractAddress, provider);

  return await contract.getAllBatchHashes();
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Check contract connection
 */
export async function checkConnection(config: ChainConfig): Promise<{
  connected: boolean;
  chainId?: number;
  releaseCount?: number;
  error?: string;
}> {
  try {
    const provider = createProvider(config.rpcUrl);
    const network = await provider.getNetwork();
    const contract = getContract(config.contractAddress, provider);

    const releaseCount = await contract.getReleaseCount();

    return {
      connected: true,
      chainId: Number(network.chainId),
      releaseCount: Number(releaseCount),
    };
  } catch (error) {
    return {
      connected: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Get default chain config from environment
 */
export function getDefaultChainConfig(): ChainConfig {
  const rpcUrl = process.env.RPC_URL || "https://sepolia.infura.io/v3/YOUR_KEY";
  const contractAddress =
    process.env.CONTRACT_ADDRESS ||
    "0x0000000000000000000000000000000000000000";
  const privateKey = process.env.PRIVATE_KEY;

  return {
    rpcUrl,
    contractAddress,
    privateKey,
  };
}
