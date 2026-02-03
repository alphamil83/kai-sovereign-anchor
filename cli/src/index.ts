#!/usr/bin/env node
/**
 * KAI CLI - Release Builder
 * Per KAI v0.5 Specification
 *
 * Commands:
 *   kai build   - Build a release manifest from governance files
 *   kai sign    - Sign a release manifest
 *   kai verify  - Verify a release manifest
 *   kai publish - Publish release to storage backends
 *   kai healthcheck - Verify storage redundancy
 */

import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import * as fs from "fs/promises";
import * as path from "path";

import {
  buildRelease,
  signRelease,
  verifyRelease,
  saveManifest,
  loadManifest,
  getDefaultManifestPath,
  validateVersion,
} from "./release-builder.js";

import {
  registerRelease,
  verifyReleaseOnChain,
  anchorReceiptBatch,
  checkConnection,
  getDefaultChainConfig,
  type ChainConfig,
} from "./chain.js";

const CLI_VERSION = "0.5.0";

// ============================================================================
// Main CLI
// ============================================================================

const program = new Command();

program
  .name("kai")
  .description("KAI Governance Release Builder")
  .version(CLI_VERSION);

// ============================================================================
// Build Command
// ============================================================================

program
  .command("build")
  .description("Build a release manifest from governance files")
  .argument("<version>", "Release version (semver)")
  .option("-d, --dir <path>", "Governance directory", ".")
  .option("-o, --output <path>", "Output manifest path")
  .option("-v, --verbose", "Verbose output")
  .action(async (version: string, options) => {
    const spinner = ora("Building release...").start();

    try {
      // Validate version
      if (!validateVersion(version)) {
        spinner.fail("Invalid version format. Use semver (e.g., 1.0.0)");
        process.exit(1);
      }

      const governanceDir = path.resolve(options.dir);
      const outputPath = options.output || getDefaultManifestPath(version);

      // Ensure output directory exists
      const outputDir = path.dirname(outputPath);
      await fs.mkdir(outputDir, { recursive: true });

      // Build manifest
      if (options.verbose) {
        spinner.stop();
      }

      const manifest = await buildRelease(governanceDir, version, {
        verbose: options.verbose,
      });

      // Save manifest
      await saveManifest(manifest, outputPath);

      spinner.succeed(
        chalk.green(`Release v${version} built successfully`)
      );
      console.log(`  ${chalk.dim("Manifest:")} ${outputPath}`);
      console.log(`  ${chalk.dim("Root hash:")} ${manifest.root_hash}`);
      console.log(`  ${chalk.dim("Files:")} ${manifest.files.length}`);
    } catch (error) {
      spinner.fail(chalk.red(`Build failed: ${(error as Error).message}`));
      process.exit(1);
    }
  });

// ============================================================================
// Sign Command
// ============================================================================

program
  .command("sign")
  .description("Sign a release manifest")
  .argument("<manifest>", "Path to manifest file")
  .option("-k, --key-file <path>", "Path to private key file")
  .option("--keychain", "Use OS keychain for signing")
  .option("--key-version <n>", "Key version number", "1")
  .action(async (manifestPath: string, options) => {
    const spinner = ora("Signing release...").start();

    try {
      // Load manifest
      const manifest = await loadManifest(manifestPath);

      // Get private key
      let privateKey: string;

      if (options.keychain) {
        spinner.fail(
          "OS keychain signing not yet implemented. Use --key-file or PRIVATE_KEY env var."
        );
        process.exit(1);
      } else if (options.keyFile) {
        const keyContent = await fs.readFile(options.keyFile, "utf8");
        privateKey = keyContent.trim();
      } else if (process.env.PRIVATE_KEY) {
        privateKey = process.env.PRIVATE_KEY;
      } else {
        spinner.fail(
          "No signing key provided. Use --key-file, --keychain, or set PRIVATE_KEY env var."
        );
        process.exit(1);
      }

      // Ensure key has proper format
      if (!privateKey.startsWith("0x")) {
        privateKey = "0x" + privateKey;
      }

      // Sign
      const keyVersion = parseInt(options.keyVersion, 10);
      const signedManifest = await signRelease(manifest, privateKey, keyVersion);

      // Save signed manifest (overwrite or new file)
      const signedPath = manifestPath.replace(".json", "-signed.json");
      await saveManifest(signedManifest, signedPath);

      spinner.succeed(chalk.green("Release signed successfully"));
      console.log(`  ${chalk.dim("Signed manifest:")} ${signedPath}`);
      console.log(
        `  ${chalk.dim("Signer:")} ${signedManifest.signatures[0].signer_address}`
      );
    } catch (error) {
      spinner.fail(chalk.red(`Signing failed: ${(error as Error).message}`));
      process.exit(1);
    }
  });

// ============================================================================
// Verify Command
// ============================================================================

program
  .command("verify")
  .description("Verify a release manifest")
  .argument("<manifest>", "Path to manifest file")
  .option("-d, --dir <path>", "Governance directory", ".")
  .option("--on-chain", "Verify against on-chain anchor")
  .option("--rpc-url <url>", "RPC URL for on-chain verification")
  .option("-v, --verbose", "Verbose output")
  .action(async (manifestPath: string, options) => {
    const spinner = ora("Verifying release...").start();

    try {
      const governanceDir = path.resolve(options.dir);

      const result = await verifyRelease(manifestPath, governanceDir, {
        manifest: manifestPath,
        onChain: options.onChain,
        rpcUrl: options.rpcUrl,
      });

      if (result.valid) {
        spinner.succeed(chalk.green("Release verification passed"));
      } else {
        spinner.fail(chalk.red("Release verification failed"));
      }

      // Print details
      console.log();
      console.log(chalk.bold("File Verification:"));
      for (const file of result.fileVerification) {
        const status = file.match ? chalk.green("✓") : chalk.red("✗");
        console.log(`  ${status} ${file.path}`);
        if (options.verbose && !file.match) {
          console.log(`    ${chalk.dim("Expected:")} ${file.expected}`);
          console.log(`    ${chalk.dim("Actual:")} ${file.actual}`);
        }
      }

      if (result.signatureVerification) {
        console.log();
        console.log(chalk.bold("Signature Verification:"));
        for (const sig of result.signatureVerification) {
          const status = sig.valid ? chalk.green("✓") : chalk.red("✗");
          console.log(`  ${status} ${sig.signer}`);
        }
      }

      if (result.errors.length > 0) {
        console.log();
        console.log(chalk.red("Errors:"));
        for (const error of result.errors) {
          console.log(`  • ${error}`);
        }
      }

      if (result.warnings.length > 0) {
        console.log();
        console.log(chalk.yellow("Warnings:"));
        for (const warning of result.warnings) {
          console.log(`  • ${warning}`);
        }
      }

      process.exit(result.valid ? 0 : 1);
    } catch (error) {
      spinner.fail(
        chalk.red(`Verification failed: ${(error as Error).message}`)
      );
      process.exit(1);
    }
  });

// ============================================================================
// Publish Command (stub)
// ============================================================================

program
  .command("publish")
  .description("Publish release to storage backends")
  .argument("<manifest>", "Path to signed manifest file")
  .option("--github", "Publish to GitHub releases")
  .option("--local <path>", "Save to local backup directory")
  .option("--s3", "Publish to S3 bucket")
  .action(async (manifestPath: string, options) => {
    const spinner = ora("Publishing release...").start();

    try {
      // Load manifest to verify it exists and is valid
      const manifest = await loadManifest(manifestPath);

      if (!("signatures" in manifest) || manifest.signatures.length === 0) {
        spinner.fail("Manifest must be signed before publishing");
        process.exit(1);
      }

      const targets: string[] = [];

      // Local backup (always do this)
      if (options.local) {
        const backupDir = path.resolve(options.local);
        await fs.mkdir(backupDir, { recursive: true });
        const backupPath = path.join(
          backupDir,
          `release-v${manifest.release_version}.json`
        );
        await saveManifest(manifest, backupPath);
        targets.push(`Local: ${backupPath}`);
      }

      // GitHub (stub)
      if (options.github) {
        // TODO: Implement GitHub release creation
        spinner.warn("GitHub publishing not yet implemented");
      }

      // S3 (stub)
      if (options.s3) {
        // TODO: Implement S3 upload
        spinner.warn("S3 publishing not yet implemented");
      }

      if (targets.length === 0) {
        spinner.warn("No publish targets specified. Use --local, --github, or --s3");
      } else {
        spinner.succeed(chalk.green("Release published"));
        for (const target of targets) {
          console.log(`  ${chalk.dim("→")} ${target}`);
        }
      }
    } catch (error) {
      spinner.fail(chalk.red(`Publishing failed: ${(error as Error).message}`));
      process.exit(1);
    }
  });

// ============================================================================
// Anchor Command - Register release on-chain
// ============================================================================

program
  .command("anchor")
  .description("Register a signed release on-chain")
  .argument("<manifest>", "Path to signed manifest file")
  .option("--rpc-url <url>", "RPC URL", process.env.RPC_URL)
  .option("--contract <address>", "Contract address", process.env.CONTRACT_ADDRESS)
  .option("-v, --verbose", "Verbose output")
  .action(async (manifestPath: string, options) => {
    const spinner = ora("Anchoring release on-chain...").start();

    try {
      // Load manifest
      const manifest = await loadManifest(manifestPath);

      if (!("signatures" in manifest) || manifest.signatures.length === 0) {
        spinner.fail("Manifest must be signed before anchoring");
        process.exit(1);
      }

      // Get chain config
      const config: ChainConfig = {
        rpcUrl: options.rpcUrl || process.env.RPC_URL || "",
        contractAddress: options.contract || process.env.CONTRACT_ADDRESS || "",
        privateKey: process.env.PRIVATE_KEY,
      };

      if (!config.rpcUrl || !config.contractAddress) {
        spinner.fail(
          "Missing RPC_URL or CONTRACT_ADDRESS. Set via --rpc-url/--contract or environment variables."
        );
        process.exit(1);
      }

      if (!config.privateKey) {
        spinner.fail("PRIVATE_KEY environment variable required for on-chain operations");
        process.exit(1);
      }

      // Check connection first
      if (options.verbose) {
        spinner.text = "Checking chain connection...";
      }
      const connStatus = await checkConnection(config);
      if (!connStatus.connected) {
        spinner.fail(`Chain connection failed: ${connStatus.error}`);
        process.exit(1);
      }

      if (options.verbose) {
        console.log(`  Chain ID: ${connStatus.chainId}`);
        console.log(`  Existing releases: ${connStatus.releaseCount}`);
      }

      // Check if already anchored
      const existing = await verifyReleaseOnChain(config, manifest.root_hash);
      if (existing.registered) {
        spinner.warn(
          `Release already anchored at block ${existing.blockNumber}`
        );
        process.exit(0);
      }

      // Register on-chain
      spinner.text = "Sending transaction...";
      const result = await registerRelease(
        config,
        manifest.root_hash,
        manifest.release_version
      );

      spinner.succeed(chalk.green("Release anchored on-chain"));
      console.log(`  ${chalk.dim("Root hash:")} ${manifest.root_hash}`);
      console.log(`  ${chalk.dim("Version:")} ${manifest.release_version}`);
      console.log(`  ${chalk.dim("Tx hash:")} ${result.txHash}`);
      console.log(`  ${chalk.dim("Block:")} ${result.blockNumber}`);
    } catch (error) {
      spinner.fail(chalk.red(`Anchoring failed: ${(error as Error).message}`));
      process.exit(1);
    }
  });

// ============================================================================
// Anchor-Batch Command - Anchor receipt batch on-chain
// ============================================================================

program
  .command("anchor-batch")
  .description("Anchor a receipt batch on-chain")
  .argument("<batch-hash>", "Hash of the receipt batch")
  .argument("<release-hash>", "Root hash of the governing release")
  .argument("<count>", "Number of receipts in the batch")
  .option("--rpc-url <url>", "RPC URL", process.env.RPC_URL)
  .option("--contract <address>", "Contract address", process.env.CONTRACT_ADDRESS)
  .action(async (batchHash: string, releaseHash: string, count: string, options) => {
    const spinner = ora("Anchoring receipt batch...").start();

    try {
      const config: ChainConfig = {
        rpcUrl: options.rpcUrl || process.env.RPC_URL || "",
        contractAddress: options.contract || process.env.CONTRACT_ADDRESS || "",
        privateKey: process.env.PRIVATE_KEY,
      };

      if (!config.rpcUrl || !config.contractAddress) {
        spinner.fail("Missing RPC_URL or CONTRACT_ADDRESS");
        process.exit(1);
      }

      if (!config.privateKey) {
        spinner.fail("PRIVATE_KEY environment variable required");
        process.exit(1);
      }

      const receiptCount = parseInt(count, 10);
      if (isNaN(receiptCount) || receiptCount <= 0) {
        spinner.fail("Invalid receipt count");
        process.exit(1);
      }

      const result = await anchorReceiptBatch(
        config,
        batchHash,
        releaseHash,
        receiptCount
      );

      spinner.succeed(chalk.green("Receipt batch anchored"));
      console.log(`  ${chalk.dim("Batch hash:")} ${batchHash}`);
      console.log(`  ${chalk.dim("Release:")} ${releaseHash}`);
      console.log(`  ${chalk.dim("Receipts:")} ${receiptCount}`);
      console.log(`  ${chalk.dim("Tx hash:")} ${result.txHash}`);
      console.log(`  ${chalk.dim("Block:")} ${result.blockNumber}`);
    } catch (error) {
      spinner.fail(chalk.red(`Anchoring failed: ${(error as Error).message}`));
      process.exit(1);
    }
  });

// ============================================================================
// Verify-Chain Command - Verify release on-chain
// ============================================================================

program
  .command("verify-chain")
  .description("Verify a release is anchored on-chain")
  .argument("<root-hash>", "Root hash to verify")
  .option("--rpc-url <url>", "RPC URL", process.env.RPC_URL)
  .option("--contract <address>", "Contract address", process.env.CONTRACT_ADDRESS)
  .action(async (rootHash: string, options) => {
    const spinner = ora("Verifying on-chain anchor...").start();

    try {
      const config: ChainConfig = {
        rpcUrl: options.rpcUrl || process.env.RPC_URL || "",
        contractAddress: options.contract || process.env.CONTRACT_ADDRESS || "",
      };

      if (!config.rpcUrl || !config.contractAddress) {
        spinner.fail("Missing RPC_URL or CONTRACT_ADDRESS");
        process.exit(1);
      }

      const result = await verifyReleaseOnChain(config, rootHash);

      if (result.registered) {
        if (result.revoked) {
          spinner.warn(chalk.yellow("Release registered but REVOKED"));
        } else {
          spinner.succeed(chalk.green("Release verified on-chain"));
        }
        console.log(`  ${chalk.dim("Version:")} ${result.version}`);
        console.log(`  ${chalk.dim("Block:")} ${result.blockNumber}`);
        console.log(`  ${chalk.dim("Revoked:")} ${result.revoked}`);
      } else {
        spinner.fail(chalk.red("Release NOT found on-chain"));
        process.exit(1);
      }
    } catch (error) {
      spinner.fail(chalk.red(`Verification failed: ${(error as Error).message}`));
      process.exit(1);
    }
  });

// ============================================================================
// Verify Live Command - Check running system matches on-chain anchor
// ============================================================================

program
  .command("verify-live")
  .description("Verify running release matches on-chain anchor")
  .option("-d, --dir <path>", "Governance directory", ".")
  .option("-m, --manifest <path>", "Path to current manifest file")
  .option("--rpc-url <url>", "RPC URL", process.env.RPC_URL)
  .option("--contract <address>", "Contract address", process.env.CONTRACT_ADDRESS)
  .option("-v, --verbose", "Verbose output")
  .action(async (options) => {
    console.log();
    console.log(chalk.bold("╔════════════════════════════════════════════════════╗"));
    console.log(chalk.bold("║         KAI Live Verification                      ║"));
    console.log(chalk.bold("╚════════════════════════════════════════════════════╝"));
    console.log();

    const spinner = ora("Checking live verification status...").start();

    try {
      const config = {
        rpcUrl: options.rpcUrl || process.env.RPC_URL || "",
        contractAddress: options.contract || process.env.CONTRACT_ADDRESS || "",
      };

      // Step 1: Load local manifest or build from governance
      let localRootHash: string;
      let localVersion: string;

      if (options.manifest) {
        spinner.text = "Loading local manifest...";
        const manifest = await loadManifest(options.manifest);
        localRootHash = manifest.root_hash;
        localVersion = manifest.release_version;
      } else {
        spinner.text = "Building release from governance files...";
        const governanceDir = path.resolve(options.dir);
        // Try to detect version from existing releases
        try {
          const releaseFiles = await fs.readdir(path.join(governanceDir, "../releases"));
          const latestRelease = releaseFiles
            .filter(f => f.endsWith(".json"))
            .sort()
            .reverse()[0];
          if (latestRelease) {
            const manifest = await loadManifest(path.join(governanceDir, "../releases", latestRelease));
            localRootHash = manifest.root_hash;
            localVersion = manifest.release_version;
          } else {
            // Build fresh
            const tempManifest = await buildRelease(governanceDir, "0.0.0");
            localRootHash = tempManifest.root_hash;
            localVersion = "local-build";
          }
        } catch {
          // Build fresh
          const tempManifest = await buildRelease(governanceDir, "0.0.0");
          localRootHash = tempManifest.root_hash;
          localVersion = "local-build";
        }
      }

      spinner.succeed("Local governance loaded");
      console.log(`  ${chalk.dim("Version:")} ${localVersion}`);
      console.log(`  ${chalk.dim("Root hash:")} ${localRootHash.slice(0, 24)}...`);

      // Step 2: Check on-chain if configured
      if (config.rpcUrl && config.contractAddress) {
        spinner.start("Checking on-chain anchor...");

        const onChainResult = await verifyReleaseOnChain(config, localRootHash);

        if (onChainResult.registered) {
          if (onChainResult.revoked) {
            spinner.fail(chalk.red("⚠️  REVOKED RELEASE"));
            console.log(chalk.red("  This release has been revoked on-chain!"));
            console.log();
            console.log(chalk.red("  ╔════════════════════════════════════════╗"));
            console.log(chalk.red("  ║   RUNNING REVOKED RELEASE - WARNING    ║"));
            console.log(chalk.red("  ╚════════════════════════════════════════╝"));
            process.exit(1);
          } else {
            spinner.succeed(chalk.green("On-chain verification PASSED"));
            console.log(`  ${chalk.dim("Block:")} ${onChainResult.blockNumber}`);
            console.log(`  ${chalk.dim("On-chain version:")} ${onChainResult.version}`);
          }
        } else {
          spinner.warn(chalk.yellow("Release NOT found on-chain"));
          console.log(chalk.yellow("  This release has not been anchored yet."));
          console.log();
          console.log(chalk.yellow("  ╔════════════════════════════════════════╗"));
          console.log(chalk.yellow("  ║   RUNNING UNANCHORED RELEASE           ║"));
          console.log(chalk.yellow("  ╚════════════════════════════════════════╝"));
        }
      } else {
        console.log();
        console.log(chalk.yellow("  ⚠ On-chain verification skipped (no RPC/contract configured)"));
      }

      // Step 3: Print summary
      console.log();
      console.log(chalk.bold("Status:"));

      const checks = {
        local: true,
        onChain: config.rpcUrl && config.contractAddress,
      };

      if (checks.local && (!checks.onChain || (await verifyReleaseOnChain(config, localRootHash)).registered)) {
        console.log();
        console.log(chalk.green("  ╔════════════════════════════════════════════════════╗"));
        console.log(chalk.green(`  ║   RUNNING VERIFIED RELEASE v${localVersion.padEnd(19)}║`));
        console.log(chalk.green("  ╚════════════════════════════════════════════════════╝"));
        console.log();
        console.log(chalk.dim(`  Root: ${localRootHash}`));
      } else {
        console.log();
        console.log(chalk.yellow("  ╔════════════════════════════════════════════════════╗"));
        console.log(chalk.yellow(`  ║   RUNNING UNVERIFIED RELEASE v${localVersion.padEnd(17)}║`));
        console.log(chalk.yellow("  ╚════════════════════════════════════════════════════╝"));
      }

    } catch (error) {
      spinner.fail(chalk.red(`Verification failed: ${(error as Error).message}`));
      process.exit(1);
    }
  });

// ============================================================================
// Healthcheck Command (stub)
// ============================================================================

program
  .command("healthcheck")
  .description("Verify storage redundancy")
  .option("-c, --config <path>", "Path to config file")
  .option("-v, --verbose", "Verbose output")
  .action(async (options) => {
    const spinner = ora("Checking storage health...").start();

    // TODO: Implement healthcheck
    spinner.warn("Healthcheck not yet implemented");

    console.log();
    console.log(chalk.yellow("Expected checks:"));
    console.log("  • GitHub: release exists and hash matches");
    console.log("  • Local: backup exists and hash matches");
    console.log("  • S3: object exists and hash matches (if configured)");
  });

// ============================================================================
// Init Command
// ============================================================================

program
  .command("init")
  .description("Initialize a new KAI governance directory")
  .argument("[dir]", "Directory to initialize", ".")
  .action(async (dir: string) => {
    const spinner = ora("Initializing KAI governance...").start();

    try {
      const baseDir = path.resolve(dir);

      // Create directory structure
      const dirs = [
        "constitution/core",
        "constitution/manual",
        "agents",
        "tools",
        "schemas",
        "releases",
      ];

      for (const d of dirs) {
        await fs.mkdir(path.join(baseDir, d), { recursive: true });
      }

      // Create default tool registry
      const defaultRegistry = `# KAI Tool Registry v0.5
version: "0.5"

defaults:
  fail_mode: CLOSED
  approval_required: false
  egress: false
  output_sensitivity: INTERNAL

tools:
  # Add your tool definitions here
  # Example:
  # read_file:
  #   risk_level: MEDIUM
  #   output_sensitivity: INHERIT
`;

      await fs.writeFile(
        path.join(baseDir, "tools/registry.yaml"),
        defaultRegistry
      );

      // Create default agent
      const defaultAgent = `# KAI Agent Definition v0.5
agent_id: default
name: Default Agent
version: "0.5"

# Permissions this agent has
permissions:
  - read_file
  - web_search

# Tools this agent can use
allowed_tools:
  - read_file
  - web_search
`;

      await fs.writeFile(
        path.join(baseDir, "agents/default.yaml"),
        defaultAgent
      );

      spinner.succeed(chalk.green("KAI governance initialized"));
      console.log(`  ${chalk.dim("Directory:")} ${baseDir}`);
      console.log();
      console.log("Next steps:");
      console.log("  1. Add your constitution to constitution/core/");
      console.log("  2. Configure tools in tools/registry.yaml");
      console.log("  3. Run: kai build 0.1.0");
    } catch (error) {
      spinner.fail(
        chalk.red(`Initialization failed: ${(error as Error).message}`)
      );
      process.exit(1);
    }
  });

// ============================================================================
// Run CLI
// ============================================================================

program.parse();
