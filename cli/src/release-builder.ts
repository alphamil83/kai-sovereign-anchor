/**
 * Release Builder
 * Ticket 1: Build, sign, verify, publish governance releases
 *
 * Per KAI v0.5 Specification
 */

import * as fs from "fs/promises";
import * as path from "path";
import * as crypto from "crypto";
import { ethers } from "ethers";
import { parse as parseYaml } from "yaml";

import {
  canonicalize,
  sha256,
  computeCanonicalHash,
  hashFile,
} from "./canonical.js";

import type {
  ReleaseManifest,
  SignedRelease,
  ReleaseSignature,
  FileEntry,
  BuilderInfo,
  BuildOptions,
  SignOptions,
  VerifyOptions,
} from "./types.js";

// ============================================================================
// Constants
// ============================================================================

const CLI_VERSION = "0.5.0";

const GOVERNANCE_FILES = [
  "constitution/core/**/*.yaml",
  "constitution/core/**/*.md",
  "constitution/manual/**/*.yaml",
  "agents/*.yaml",
  "tools/registry.yaml",
  "schemas/*.json",
];

const IGNORED_FILES = [
  ".DS_Store",
  "*.log",
  "node_modules",
  ".git",
  "*.env",
  "*.local",
];

// ============================================================================
// Build Release
// ============================================================================

/**
 * Builds a release manifest from governance files.
 * Deterministically hashes all files and computes root_hash.
 */
export async function buildRelease(
  governanceDir: string,
  version: string,
  options: BuildOptions = {}
): Promise<ReleaseManifest> {
  const verbose = options.verbose ?? false;

  if (verbose) {
    console.log(`Building release v${version} from ${governanceDir}`);
  }

  // Collect all governance files
  const files = await collectGovernanceFiles(governanceDir, verbose);

  if (files.length === 0) {
    throw new Error(`No governance files found in ${governanceDir}`);
  }

  // Hash each file
  const fileEntries: FileEntry[] = [];
  for (const filePath of files) {
    const fullPath = path.join(governanceDir, filePath);
    const content = await fs.readFile(fullPath);
    const hash = sha256(content);
    const stat = await fs.stat(fullPath);

    fileEntries.push({
      path: filePath,
      sha256: hash,
      size: stat.size,
    });

    if (verbose) {
      console.log(`  ${filePath}: ${hash.slice(0, 18)}...`);
    }
  }

  // Sort files by path for determinism
  fileEntries.sort((a, b) => a.path.localeCompare(b.path));

  // Build deterministic payload (ONLY these fields are hashed)
  // This ensures identical governance content always produces identical root_hash
  const deterministicPayload = {
    manifest_version: "0.5",
    release_version: version,
    files: fileEntries,
  };

  // Compute root_hash from ONLY deterministic fields
  // Timestamps are explicitly NOT part of the commitment
  const rootHash = computeCanonicalHash(deterministicPayload as Record<string, unknown>, []);

  // Non-deterministic metadata (stored but not hashed)
  const builderInfo: BuilderInfo = {
    cli_version: CLI_VERSION,
    git_commit: await getGitCommit(governanceDir),
    built_at: new Date().toISOString(),
    node_version: process.version,
  };

  const manifest: Omit<ReleaseManifest, "root_hash"> = {
    manifest_version: "0.5",
    release_version: version,
    created_at: new Date().toISOString(),
    builder_info: builderInfo,
    files: fileEntries,
  };

  const fullManifest: ReleaseManifest = {
    ...manifest,
    root_hash: rootHash,
  };

  if (verbose) {
    console.log(`\nRoot hash: ${rootHash}`);
    console.log(`Files: ${fileEntries.length}`);
  }

  return fullManifest;
}

/**
 * Collects all governance files from directory.
 * Returns relative paths.
 */
async function collectGovernanceFiles(
  baseDir: string,
  verbose: boolean
): Promise<string[]> {
  const files: string[] = [];

  async function walkDir(dir: string, relativePath: string = ""): Promise<void> {
    const entries = await fs.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relPath = path.join(relativePath, entry.name);

      // Skip ignored files
      if (shouldIgnore(entry.name)) {
        continue;
      }

      if (entry.isDirectory()) {
        await walkDir(fullPath, relPath);
      } else if (entry.isFile()) {
        // Only include governance files
        if (isGovernanceFile(relPath)) {
          files.push(relPath);
        }
      }
    }
  }

  await walkDir(baseDir);
  return files;
}

function shouldIgnore(name: string): boolean {
  return IGNORED_FILES.some((pattern) => {
    if (pattern.includes("*")) {
      const regex = new RegExp("^" + pattern.replace("*", ".*") + "$");
      return regex.test(name);
    }
    return name === pattern;
  });
}

function isGovernanceFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  const allowedExtensions = [".yaml", ".yml", ".json", ".md", ".txt", ".ts", ".sol"];

  if (!allowedExtensions.includes(ext)) {
    return false;
  }

  // Check if it's in a governance directory
  const governanceDirs = [
    "constitution",
    "agents",
    "tools",
    "schemas",
    "policy-engine",
    "contracts",
  ];

  return governanceDirs.some((dir) => filePath.startsWith(dir + path.sep) || filePath.startsWith(dir + "/"));
}

async function getGitCommit(dir: string): Promise<string | undefined> {
  try {
    const { execSync } = await import("child_process");
    const commit = execSync("git rev-parse HEAD", {
      cwd: dir,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "ignore"],
    }).trim();
    return commit;
  } catch {
    return undefined;
  }
}

// ============================================================================
// Sign Release
// ============================================================================

/**
 * Signs a release manifest.
 * Uses ethers.js for secp256k1 ECDSA signing.
 */
export async function signRelease(
  manifest: ReleaseManifest,
  privateKey: string,
  keyVersion: number = 1
): Promise<SignedRelease> {
  // Create wallet from private key
  const wallet = new ethers.Wallet(privateKey);

  // Sign the root_hash
  const messageHash = ethers.hashMessage(manifest.root_hash);
  const signature = await wallet.signMessage(manifest.root_hash);

  const releaseSignature: ReleaseSignature = {
    signer_address: wallet.address,
    signature: signature,
    signed_at: new Date().toISOString(),
    key_version: keyVersion,
  };

  return {
    ...manifest,
    signatures: [releaseSignature],
  };
}

/**
 * Signs using OS keychain (placeholder - requires keytar integration)
 */
export async function signReleaseWithKeychain(
  manifest: ReleaseManifest,
  keyName: string = "kai-release-key",
  keyVersion: number = 1
): Promise<SignedRelease> {
  // TODO: Integrate with keytar for OS keychain
  // For now, throw an error indicating this is not yet implemented
  throw new Error(
    "OS keychain signing not yet implemented. Use --key-file option or set PRIVATE_KEY env var."
  );
}

// ============================================================================
// Verify Release
// ============================================================================

export interface VerifyResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  manifest: ReleaseManifest;
  fileVerification: {
    path: string;
    expected: string;
    actual: string;
    match: boolean;
  }[];
  signatureVerification?: {
    signer: string;
    valid: boolean;
    recoveredAddress?: string;
  }[];
  onChainVerification?: {
    anchored: boolean;
    contractAddress?: string;
    anchoredHash?: string;
    blockNumber?: number;
  };
}

/**
 * Verifies a release manifest.
 * Checks file hashes, root_hash, and optionally signatures and on-chain anchor.
 */
export async function verifyRelease(
  manifestPath: string,
  governanceDir: string,
  options: VerifyOptions = {}
): Promise<VerifyResult> {
  const errors: string[] = [];
  const warnings: string[] = [];
  const fileVerification: VerifyResult["fileVerification"] = [];

  // Load manifest
  const manifestContent = await fs.readFile(manifestPath, "utf8");
  const manifest = JSON.parse(manifestContent) as SignedRelease;

  // Verify root_hash using ONLY deterministic fields
  // Must match the exact same payload structure used in buildRelease
  const deterministicPayload = {
    manifest_version: manifest.manifest_version,
    release_version: manifest.release_version,
    files: manifest.files,
  };
  const computedRootHash = computeCanonicalHash(deterministicPayload as Record<string, unknown>, []);

  if (computedRootHash.toLowerCase() !== manifest.root_hash.toLowerCase()) {
    errors.push(
      `Root hash mismatch: expected ${manifest.root_hash}, got ${computedRootHash}`
    );
  }

  // Verify each file
  for (const file of manifest.files) {
    const fullPath = path.join(governanceDir, file.path);

    try {
      const content = await fs.readFile(fullPath);
      const actualHash = sha256(content);

      const match =
        actualHash.toLowerCase() === file.sha256.toLowerCase();
      fileVerification.push({
        path: file.path,
        expected: file.sha256,
        actual: actualHash,
        match,
      });

      if (!match) {
        errors.push(`File hash mismatch: ${file.path}`);
      }
    } catch (err) {
      errors.push(`File not found: ${file.path}`);
      fileVerification.push({
        path: file.path,
        expected: file.sha256,
        actual: "FILE_NOT_FOUND",
        match: false,
      });
    }
  }

  // Verify signatures if present
  let signatureVerification: VerifyResult["signatureVerification"];
  if ("signatures" in manifest && manifest.signatures.length > 0) {
    signatureVerification = [];

    for (const sig of manifest.signatures) {
      try {
        const recoveredAddress = ethers.verifyMessage(
          manifest.root_hash,
          sig.signature
        );

        const valid =
          recoveredAddress.toLowerCase() === sig.signer_address.toLowerCase();

        signatureVerification.push({
          signer: sig.signer_address,
          valid,
          recoveredAddress,
        });

        if (!valid) {
          errors.push(`Invalid signature from ${sig.signer_address}`);
        }
      } catch (err) {
        signatureVerification.push({
          signer: sig.signer_address,
          valid: false,
        });
        errors.push(`Signature verification failed for ${sig.signer_address}`);
      }
    }
  }

  // On-chain verification if requested
  let onChainVerification: VerifyResult["onChainVerification"];
  if (options.onChain && options.rpcUrl) {
    // TODO: Implement on-chain verification
    warnings.push("On-chain verification not yet implemented");
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    manifest,
    fileVerification,
    signatureVerification,
    onChainVerification,
  };
}

// ============================================================================
// Save/Load Manifest
// ============================================================================

/**
 * Saves manifest to file.
 */
export async function saveManifest(
  manifest: ReleaseManifest | SignedRelease,
  outputPath: string
): Promise<void> {
  const json = JSON.stringify(manifest, null, 2);
  await fs.writeFile(outputPath, json, "utf8");
}

/**
 * Loads manifest from file.
 */
export async function loadManifest(
  manifestPath: string
): Promise<SignedRelease> {
  const content = await fs.readFile(manifestPath, "utf8");
  return JSON.parse(content) as SignedRelease;
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Generates a default output path for manifest.
 */
export function getDefaultManifestPath(version: string): string {
  const timestamp = new Date().toISOString().split("T")[0].replace(/-/g, "");
  return `releases/v${version}-${timestamp}.json`;
}

/**
 * Validates a version string (semver).
 */
export function validateVersion(version: string): boolean {
  const semverRegex = /^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$/;
  return semverRegex.test(version);
}
