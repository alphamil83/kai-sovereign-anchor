/**
 * Healthcheck
 * Ticket 8: System health verification
 *
 * Per KAI v0.5 Specification:
 * - Verify all system components are operational
 * - Check storage backends
 * - Verify chain connectivity
 * - Validate configuration
 */

import * as fs from "fs/promises";
import * as path from "path";

import type {
  KaiConfig,
  StorageConfig,
  ChainConfig,
} from "./types.js";

import {
  StorageManager,
  StorageHealth,
  LocalStorage,
} from "./storage.js";

// ============================================================================
// Types
// ============================================================================

export interface HealthcheckResult {
  healthy: boolean;
  timestamp: number;
  duration_ms: number;
  components: ComponentHealth[];
  warnings: string[];
  errors: string[];
}

export interface ComponentHealth {
  name: string;
  healthy: boolean;
  latency_ms: number;
  message?: string;
  details?: Record<string, unknown>;
}

export interface HealthcheckOptions {
  verbose?: boolean;
  skipChain?: boolean;
  skipStorage?: boolean;
  timeout?: number;
}

// ============================================================================
// Component Checks
// ============================================================================

/**
 * Check file system access
 */
async function checkFileSystem(configPath: string): Promise<ComponentHealth> {
  const start = Date.now();

  try {
    // Check config file exists
    await fs.access(configPath);

    // Check config is valid JSON
    const content = await fs.readFile(configPath, "utf-8");
    JSON.parse(content);

    return {
      name: "filesystem",
      healthy: true,
      latency_ms: Date.now() - start,
      message: "Config file accessible and valid",
      details: { configPath },
    };
  } catch (error) {
    return {
      name: "filesystem",
      healthy: false,
      latency_ms: Date.now() - start,
      message: `File system check failed: ${(error as Error).message}`,
    };
  }
}

/**
 * Check storage backends
 */
async function checkStorage(
  config: StorageConfig,
  timeout: number = 5000
): Promise<ComponentHealth[]> {
  const results: ComponentHealth[] = [];

  try {
    const manager = new StorageManager(config);
    const healthResults = await Promise.race([
      manager.healthCheckAll(),
      new Promise<StorageHealth[]>((_, reject) =>
        setTimeout(() => reject(new Error("Timeout")), timeout)
      ),
    ]);

    for (const health of healthResults) {
      results.push({
        name: `storage:${health.backend}`,
        healthy: health.healthy,
        latency_ms: health.latencyMs,
        message: health.error || "OK",
        details: health.details,
      });
    }
  } catch (error) {
    results.push({
      name: "storage",
      healthy: false,
      latency_ms: timeout,
      message: `Storage check failed: ${(error as Error).message}`,
    });
  }

  return results;
}

/**
 * Check chain connectivity
 */
async function checkChain(
  config: ChainConfig,
  timeout: number = 10000
): Promise<ComponentHealth> {
  const start = Date.now();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(config.rpc_url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "eth_blockNumber",
        params: [],
        id: 1,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();

    if (data.error) {
      throw new Error(data.error.message);
    }

    const blockNumber = parseInt(data.result, 16);

    return {
      name: "chain",
      healthy: true,
      latency_ms: Date.now() - start,
      message: `Connected to ${config.network}`,
      details: {
        network: config.network,
        rpc_url: config.rpc_url,
        block_number: blockNumber,
        contract: config.contract_address,
      },
    };
  } catch (error) {
    return {
      name: "chain",
      healthy: false,
      latency_ms: Date.now() - start,
      message: `Chain check failed: ${(error as Error).message}`,
      details: {
        network: config.network,
        rpc_url: config.rpc_url,
      },
    };
  }
}

/**
 * Check configuration validity
 */
function checkConfig(config: KaiConfig): ComponentHealth {
  const start = Date.now();
  const issues: string[] = [];

  // Check version
  if (config.version !== "0.5") {
    issues.push(`Unsupported version: ${config.version}`);
  }

  // Check approval config
  if (config.approval.max_approvals_per_hour < 1) {
    issues.push("max_approvals_per_hour must be at least 1");
  }

  if (config.approval.cooldown_after_burst < 0) {
    issues.push("cooldown_after_burst cannot be negative");
  }

  // Check storage config
  if (!config.storage.primary) {
    issues.push("Primary storage not configured");
  }

  // Check chain config
  if (!config.chain.rpc_url) {
    issues.push("Chain RPC URL not configured");
  }

  if (!config.chain.contract_address) {
    issues.push("Contract address not configured");
  }

  return {
    name: "config",
    healthy: issues.length === 0,
    latency_ms: Date.now() - start,
    message: issues.length === 0 ? "Configuration valid" : issues.join("; "),
    details: {
      version: config.version,
      release_version: config.release_version,
    },
  };
}

/**
 * Check governance directory
 */
async function checkGovernance(governanceDir: string): Promise<ComponentHealth> {
  const start = Date.now();
  const requiredFiles = [
    "tool-registry.json",
  ];
  const missingFiles: string[] = [];

  try {
    // Check directory exists
    await fs.access(governanceDir);

    // Check required files
    for (const file of requiredFiles) {
      try {
        await fs.access(path.join(governanceDir, file));
      } catch {
        missingFiles.push(file);
      }
    }

    if (missingFiles.length > 0) {
      return {
        name: "governance",
        healthy: false,
        latency_ms: Date.now() - start,
        message: `Missing required files: ${missingFiles.join(", ")}`,
        details: { governanceDir, missingFiles },
      };
    }

    return {
      name: "governance",
      healthy: true,
      latency_ms: Date.now() - start,
      message: "Governance files present",
      details: { governanceDir },
    };
  } catch (error) {
    return {
      name: "governance",
      healthy: false,
      latency_ms: Date.now() - start,
      message: `Governance check failed: ${(error as Error).message}`,
    };
  }
}

// ============================================================================
// Main Healthcheck
// ============================================================================

/**
 * Run full system healthcheck
 */
export async function runHealthcheck(
  config: KaiConfig,
  options: HealthcheckOptions = {}
): Promise<HealthcheckResult> {
  const start = Date.now();
  const components: ComponentHealth[] = [];
  const warnings: string[] = [];
  const errors: string[] = [];

  const timeout = options.timeout ?? 10000;

  // 1. Check configuration
  const configHealth = checkConfig(config);
  components.push(configHealth);
  if (!configHealth.healthy) {
    errors.push(configHealth.message || "Config validation failed");
  }

  // 2. Check governance directory
  const govHealth = await checkGovernance(config.governance_dir);
  components.push(govHealth);
  if (!govHealth.healthy) {
    warnings.push(govHealth.message || "Governance check failed");
  }

  // 3. Check storage (unless skipped)
  if (!options.skipStorage) {
    const storageHealth = await checkStorage(config.storage, timeout);
    components.push(...storageHealth);

    const unhealthyStorage = storageHealth.filter(s => !s.healthy);
    if (unhealthyStorage.length === storageHealth.length) {
      errors.push("All storage backends unhealthy");
    } else if (unhealthyStorage.length > 0) {
      warnings.push(`${unhealthyStorage.length}/${storageHealth.length} storage backends unhealthy`);
    }
  }

  // 4. Check chain (unless skipped)
  if (!options.skipChain) {
    const chainHealth = await checkChain(config.chain, timeout);
    components.push(chainHealth);
    if (!chainHealth.healthy) {
      warnings.push(chainHealth.message || "Chain connectivity issues");
    }
  }

  // Determine overall health
  const criticalUnhealthy = components.filter(
    c => !c.healthy && (c.name === "config" || c.name.startsWith("storage"))
  );

  return {
    healthy: criticalUnhealthy.length === 0,
    timestamp: Date.now(),
    duration_ms: Date.now() - start,
    components,
    warnings,
    errors,
  };
}

/**
 * Run quick healthcheck (config + local storage only)
 */
export async function runQuickHealthcheck(
  config: KaiConfig
): Promise<HealthcheckResult> {
  const start = Date.now();
  const components: ComponentHealth[] = [];

  // Check config
  const configHealth = checkConfig(config);
  components.push(configHealth);

  // Check local storage only
  if (config.storage.local) {
    const localStorage = new LocalStorage(config.storage.local.path);
    const storageHealth = await localStorage.healthCheck();
    components.push({
      name: "storage:local",
      healthy: storageHealth.healthy,
      latency_ms: storageHealth.latencyMs,
      message: storageHealth.error || "OK",
    });
  }

  return {
    healthy: components.every(c => c.healthy),
    timestamp: Date.now(),
    duration_ms: Date.now() - start,
    components,
    warnings: [],
    errors: components.filter(c => !c.healthy).map(c => c.message || c.name),
  };
}

/**
 * Format healthcheck result for display
 */
export function formatHealthcheck(result: HealthcheckResult): string {
  const lines: string[] = [];

  // Header
  const status = result.healthy ? "✅ HEALTHY" : "❌ UNHEALTHY";
  lines.push(`System Status: ${status}`);
  lines.push(`Checked at: ${new Date(result.timestamp).toISOString()}`);
  lines.push(`Duration: ${result.duration_ms}ms`);
  lines.push("");

  // Components
  lines.push("Components:");
  for (const component of result.components) {
    const icon = component.healthy ? "✓" : "✗";
    const latency = `${component.latency_ms}ms`;
    lines.push(`  ${icon} ${component.name.padEnd(20)} ${latency.padStart(8)}  ${component.message || ""}`);
  }

  // Warnings
  if (result.warnings.length > 0) {
    lines.push("");
    lines.push("Warnings:");
    for (const warning of result.warnings) {
      lines.push(`  ⚠ ${warning}`);
    }
  }

  // Errors
  if (result.errors.length > 0) {
    lines.push("");
    lines.push("Errors:");
    for (const error of result.errors) {
      lines.push(`  ✗ ${error}`);
    }
  }

  return lines.join("\n");
}

/**
 * Format healthcheck result as JSON
 */
export function healthcheckToJson(result: HealthcheckResult): string {
  return JSON.stringify(result, null, 2);
}

// ============================================================================
// Default Configuration
// ============================================================================

/**
 * Create default KAI configuration
 */
export function createDefaultConfig(
  overrides: Partial<KaiConfig> = {}
): KaiConfig {
  return {
    version: "0.5",
    release_version: "0.1.0-beta",
    governance_dir: "./governance",
    approval: {
      max_approvals_per_hour: 20,
      cooldown_after_burst: 15,
      burst_threshold: 5,
      require_summary_confirmation: true,
    },
    storage: {
      primary: "local",
      backup: [],
      local: {
        path: "./storage",
      },
    },
    chain: {
      network: "sepolia",
      rpc_url: "https://sepolia.infura.io/v3/YOUR_KEY",
      contract_address: "0x0000000000000000000000000000000000000000",
    },
    ...overrides,
  };
}

/**
 * Load configuration from file
 */
export async function loadConfig(configPath: string): Promise<KaiConfig> {
  const content = await fs.readFile(configPath, "utf-8");
  return JSON.parse(content) as KaiConfig;
}

/**
 * Save configuration to file
 */
export async function saveConfig(config: KaiConfig, configPath: string): Promise<void> {
  await fs.writeFile(configPath, JSON.stringify(config, null, 2));
}
