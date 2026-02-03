/**
 * Storage and Healthcheck Tests
 * Ticket 8: GitHub + Local + S3 storage with verification
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs/promises";
import * as path from "path";
import * as os from "os";

import {
  LocalStorage,
  StorageManager,
  storeReceipt,
  loadStoredReceipt,
  storeManifest,
  loadManifest,
} from "../src/storage.js";

import {
  runHealthcheck,
  runQuickHealthcheck,
  formatHealthcheck,
  healthcheckToJson,
  createDefaultConfig,
  loadConfig,
  saveConfig,
} from "../src/healthcheck.js";

import type { Receipt, StorageConfig, KaiConfig } from "../src/types.js";

// Helper to create temp directory
async function createTempDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "kai-storage-test-"));
}

// Helper to create mock receipt
function createMockReceipt(): Receipt {
  return {
    receipt_version: "0.5",
    receipt_id: `rcpt_${Date.now()}_test`,
    release_root_hash: "0x1234",
    session_id: "test-session",
    prev_receipt_hash: null,
    sequence_number: 0,
    tool_calls: [],
    approvals_used: [],
    session_sensitivity: "PUBLIC",
    started_at: Date.now() - 1000,
    completed_at: Date.now(),
    receipt_hash: "0xabcdef",
    signature: "0x123456",
  };
}

describe("LocalStorage", () => {
  let tmpDir: string;
  let storage: LocalStorage;

  beforeEach(async () => {
    tmpDir = await createTempDir();
    storage = new LocalStorage(tmpDir);
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  describe("Health Check", () => {
    it("should report healthy for valid directory", async () => {
      const health = await storage.healthCheck();

      expect(health.healthy).toBe(true);
      expect(health.latencyMs).toBeGreaterThanOrEqual(0);
    });
  });

  describe("Write and Read", () => {
    it("should write and read content", async () => {
      const content = JSON.stringify({ test: "data" });
      const writeResult = await storage.write("test/file.json", content);

      expect(writeResult.success).toBe(true);

      const readResult = await storage.read("test/file.json");

      expect(readResult.success).toBe(true);
      expect(readResult.data).toBe(content);
    });

    it("should create nested directories", async () => {
      const content = "nested content";
      const writeResult = await storage.write("a/b/c/file.txt", content);

      expect(writeResult.success).toBe(true);

      const readResult = await storage.read("a/b/c/file.txt");
      expect(readResult.success).toBe(true);
    });

    it("should fail reading non-existent file", async () => {
      const result = await storage.read("nonexistent.json");

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it("should verify content hash on read", async () => {
      const content = JSON.stringify({ data: "test" });
      await storage.write("hash-test.json", content);

      // Manually tamper with file (not metadata)
      const filePath = path.join(tmpDir, "hash-test.json");
      await fs.writeFile(filePath, "tampered content");

      const readResult = await storage.read("hash-test.json");
      expect(readResult.success).toBe(false);
      expect(readResult.error).toContain("hash mismatch");
    });
  });

  describe("Exists", () => {
    it("should return true for existing file", async () => {
      await storage.write("exists.txt", "content");

      const exists = await storage.exists("exists.txt");
      expect(exists).toBe(true);
    });

    it("should return false for non-existing file", async () => {
      const exists = await storage.exists("nope.txt");
      expect(exists).toBe(false);
    });
  });

  describe("Delete", () => {
    it("should delete file", async () => {
      await storage.write("to-delete.txt", "content");
      expect(await storage.exists("to-delete.txt")).toBe(true);

      const result = await storage.delete("to-delete.txt");
      expect(result.success).toBe(true);
      expect(await storage.exists("to-delete.txt")).toBe(false);
    });
  });

  describe("List", () => {
    it("should list files with prefix", async () => {
      await storage.write("prefix/a.txt", "a");
      await storage.write("prefix/b.txt", "b");
      await storage.write("other/c.txt", "c");

      const result = await storage.list("prefix");

      expect(result.success).toBe(true);
      // Should contain at least the 2 files we created
      expect(result.data?.length).toBeGreaterThanOrEqual(2);
      // And should not include files from "other" directory
      expect(result.data?.every(f => !f.includes("other"))).toBe(true);
    });

    it("should return empty for non-existent prefix", async () => {
      const result = await storage.list("nonexistent");

      expect(result.success).toBe(true);
      expect(result.data).toEqual([]);
    });
  });
});

describe("StorageManager", () => {
  let tmpDir: string;
  let config: StorageConfig;
  let manager: StorageManager;

  beforeEach(async () => {
    tmpDir = await createTempDir();
    config = {
      primary: "local",
      backup: [],
      local: { path: tmpDir },
    };
    manager = new StorageManager(config);
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  describe("Multi-Backend", () => {
    it("should write to primary", async () => {
      const result = await manager.write("test.json", "{}");
      expect(result.success).toBe(true);
    });

    it("should read from primary", async () => {
      await manager.write("test.json", "content");

      const result = await manager.read("test.json");
      expect(result.success).toBe(true);
      expect(result.data).toBe("content");
    });

    it("should check existence", async () => {
      await manager.write("exists.json", "{}");

      expect(await manager.exists("exists.json")).toBe(true);
      expect(await manager.exists("nope.json")).toBe(false);
    });
  });

  describe("Health Check", () => {
    it("should check all backends", async () => {
      const results = await manager.healthCheckAll();

      expect(results.length).toBe(1); // Just local
      expect(results[0].healthy).toBe(true);
    });
  });
});

describe("High-Level Storage Operations", () => {
  let tmpDir: string;
  let manager: StorageManager;

  beforeEach(async () => {
    tmpDir = await createTempDir();
    manager = new StorageManager({
      primary: "local",
      backup: [],
      local: { path: tmpDir },
    });
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  describe("Receipt Storage", () => {
    it("should store and load receipt", async () => {
      const receipt = createMockReceipt();

      const storeResult = await storeReceipt(manager, receipt);
      expect(storeResult.success).toBe(true);

      const loadResult = await loadStoredReceipt(
        manager,
        receipt.session_id,
        receipt.receipt_id
      );
      expect(loadResult.success).toBe(true);
      expect(loadResult.data?.receipt_id).toBe(receipt.receipt_id);
    });
  });

  describe("Manifest Storage", () => {
    it("should store and load manifest", async () => {
      const manifest = {
        manifest_version: "0.5" as const,
        release_version: "1.0.0",
        created_at: new Date().toISOString(),
        builder_info: {
          cli_version: "0.5.0",
          built_at: new Date().toISOString(),
          node_version: "20.0.0",
        },
        files: [],
        root_hash: "0xabcdef",
        signatures: [],
      };

      const storeResult = await storeManifest(manager, manifest);
      expect(storeResult.success).toBe(true);

      const loadResult = await loadManifest(manager, "1.0.0");
      expect(loadResult.success).toBe(true);
      expect(loadResult.data?.release_version).toBe("1.0.0");
    });
  });
});

describe("Healthcheck", () => {
  let tmpDir: string;
  let config: KaiConfig;

  beforeEach(async () => {
    tmpDir = await createTempDir();

    // Create governance directory with tool-registry
    const govDir = path.join(tmpDir, "governance");
    await fs.mkdir(govDir, { recursive: true });
    await fs.writeFile(
      path.join(govDir, "tool-registry.json"),
      JSON.stringify({ version: "0.5", tools: {} })
    );

    config = createDefaultConfig({
      governance_dir: govDir,
      storage: {
        primary: "local",
        backup: [],
        local: { path: path.join(tmpDir, "storage") },
      },
    });
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  describe("runHealthcheck", () => {
    it("should run full healthcheck", async () => {
      const result = await runHealthcheck(config, { skipChain: true });

      expect(result.timestamp).toBeGreaterThan(0);
      expect(result.duration_ms).toBeGreaterThanOrEqual(0);
      expect(result.components.length).toBeGreaterThan(0);
    });

    it("should report config component", async () => {
      const result = await runHealthcheck(config, { skipChain: true, skipStorage: true });

      const configComponent = result.components.find(c => c.name === "config");
      expect(configComponent).toBeDefined();
      expect(configComponent?.healthy).toBe(true);
    });

    it("should report governance component", async () => {
      const result = await runHealthcheck(config, { skipChain: true, skipStorage: true });

      const govComponent = result.components.find(c => c.name === "governance");
      expect(govComponent).toBeDefined();
      expect(govComponent?.healthy).toBe(true);
    });

    it("should report unhealthy with missing governance", async () => {
      config.governance_dir = "/nonexistent/path";

      const result = await runHealthcheck(config, { skipChain: true, skipStorage: true });

      const govComponent = result.components.find(c => c.name === "governance");
      expect(govComponent?.healthy).toBe(false);
    });
  });

  describe("runQuickHealthcheck", () => {
    it("should run quick check", async () => {
      const result = await runQuickHealthcheck(config);

      expect(result.components.length).toBeGreaterThan(0);
      expect(result.duration_ms).toBeLessThan(1000); // Should be fast
    });
  });

  describe("formatHealthcheck", () => {
    it("should format healthy result", async () => {
      const result = await runQuickHealthcheck(config);
      const formatted = formatHealthcheck(result);

      expect(formatted).toContain("System Status:");
      expect(formatted).toContain("Components:");
    });

    it("should format as JSON", async () => {
      const result = await runQuickHealthcheck(config);
      const json = healthcheckToJson(result);

      const parsed = JSON.parse(json);
      expect(parsed.healthy).toBeDefined();
      expect(parsed.components).toBeDefined();
    });
  });
});

describe("Configuration", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await createTempDir();
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  describe("createDefaultConfig", () => {
    it("should create valid default config", () => {
      const config = createDefaultConfig();

      expect(config.version).toBe("0.5");
      expect(config.storage.primary).toBe("local");
      expect(config.approval.max_approvals_per_hour).toBe(20);
    });

    it("should merge overrides", () => {
      const config = createDefaultConfig({
        release_version: "2.0.0",
      });

      expect(config.release_version).toBe("2.0.0");
      expect(config.version).toBe("0.5"); // Default preserved
    });
  });

  describe("saveConfig and loadConfig", () => {
    it("should save and load config", async () => {
      const config = createDefaultConfig();
      const configPath = path.join(tmpDir, "config.json");

      await saveConfig(config, configPath);
      const loaded = await loadConfig(configPath);

      expect(loaded.version).toBe(config.version);
      expect(loaded.storage.primary).toBe(config.storage.primary);
    });
  });
});

describe("Config Validation", () => {
  it("should fail on invalid version", async () => {
    const config = createDefaultConfig() as any;
    config.version = "1.0"; // Wrong version

    const result = await runHealthcheck(config, { skipChain: true, skipStorage: true });

    const configComponent = result.components.find(c => c.name === "config");
    expect(configComponent?.healthy).toBe(false);
    expect(configComponent?.message).toContain("Unsupported version");
  });

  it("should fail on invalid approval config", async () => {
    const config = createDefaultConfig();
    config.approval.max_approvals_per_hour = 0; // Invalid

    const result = await runHealthcheck(config, { skipChain: true, skipStorage: true });

    const configComponent = result.components.find(c => c.name === "config");
    expect(configComponent?.healthy).toBe(false);
  });
});
