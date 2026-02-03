/**
 * Storage Backend
 * Ticket 8: GitHub + Local + S3 storage with verification
 *
 * Per KAI v0.5 Specification:
 * - Multiple storage backends for redundancy
 * - Content-addressed storage using receipt hashes
 * - Verification on read
 * - Automatic failover to backups
 */

import * as fs from "fs/promises";
import * as path from "path";
import * as crypto from "crypto";

import type {
  StorageConfig,
  Receipt,
  ReleaseManifest,
  SignedRelease,
} from "./types.js";

import type { ReceiptBatch } from "./receipt-generator.js";

// ============================================================================
// Types
// ============================================================================

export type StorageType = "github" | "local" | "s3";

export interface StorageResult<T> {
  success: boolean;
  data?: T;
  error?: string;
  backend: StorageType;
}

export interface StorageHealth {
  backend: StorageType;
  healthy: boolean;
  latencyMs: number;
  error?: string;
  details?: Record<string, unknown>;
}

export interface StorageObject {
  key: string;
  content: string;
  contentType: string;
  hash: string;
  size: number;
  createdAt: number;
}

// ============================================================================
// Storage Backend Interface
// ============================================================================

export interface StorageBackend {
  type: StorageType;
  name: string;

  /**
   * Check if backend is healthy
   */
  healthCheck(): Promise<StorageHealth>;

  /**
   * Write object to storage
   */
  write(key: string, content: string, contentType?: string): Promise<StorageResult<void>>;

  /**
   * Read object from storage
   */
  read(key: string): Promise<StorageResult<string>>;

  /**
   * Check if object exists
   */
  exists(key: string): Promise<boolean>;

  /**
   * List objects with prefix
   */
  list(prefix: string): Promise<StorageResult<string[]>>;

  /**
   * Delete object
   */
  delete(key: string): Promise<StorageResult<void>>;
}

// ============================================================================
// Local Storage Backend
// ============================================================================

export class LocalStorage implements StorageBackend {
  type: StorageType = "local";
  name: string;
  private basePath: string;

  constructor(basePath: string, name: string = "local") {
    this.basePath = basePath;
    this.name = name;
  }

  async healthCheck(): Promise<StorageHealth> {
    const start = Date.now();
    try {
      // Try to ensure directory exists
      await fs.mkdir(this.basePath, { recursive: true });

      // Write and read test file
      const testFile = path.join(this.basePath, ".healthcheck");
      const testContent = Date.now().toString();
      await fs.writeFile(testFile, testContent);
      const readContent = await fs.readFile(testFile, "utf-8");
      await fs.unlink(testFile);

      if (readContent !== testContent) {
        throw new Error("Read/write verification failed");
      }

      return {
        backend: this.type,
        healthy: true,
        latencyMs: Date.now() - start,
        details: { basePath: this.basePath },
      };
    } catch (error) {
      return {
        backend: this.type,
        healthy: false,
        latencyMs: Date.now() - start,
        error: (error as Error).message,
      };
    }
  }

  async write(key: string, content: string, contentType?: string): Promise<StorageResult<void>> {
    try {
      const filePath = this.keyToPath(key);
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, content);

      // Write metadata
      const meta = {
        key,
        contentType: contentType ?? "application/json",
        hash: this.computeHash(content),
        size: Buffer.byteLength(content, "utf8"),
        createdAt: Date.now(),
      };
      await fs.writeFile(filePath + ".meta", JSON.stringify(meta, null, 2));

      return { success: true, backend: this.type };
    } catch (error) {
      return {
        success: false,
        backend: this.type,
        error: (error as Error).message,
      };
    }
  }

  async read(key: string): Promise<StorageResult<string>> {
    try {
      const filePath = this.keyToPath(key);
      const content = await fs.readFile(filePath, "utf-8");

      // Verify hash if metadata exists
      try {
        const metaContent = await fs.readFile(filePath + ".meta", "utf-8");
        const meta = JSON.parse(metaContent);
        const computedHash = this.computeHash(content);

        if (meta.hash && meta.hash !== computedHash) {
          return {
            success: false,
            backend: this.type,
            error: "Content hash mismatch",
          };
        }
      } catch {
        // Metadata doesn't exist, skip verification
      }

      return { success: true, data: content, backend: this.type };
    } catch (error) {
      return {
        success: false,
        backend: this.type,
        error: (error as Error).message,
      };
    }
  }

  async exists(key: string): Promise<boolean> {
    try {
      const filePath = this.keyToPath(key);
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }

  async list(prefix: string): Promise<StorageResult<string[]>> {
    try {
      const prefixPath = this.keyToPath(prefix);

      try {
        // Check if prefix is a directory or file
        const stat = await fs.stat(prefixPath);
        const dir = stat.isDirectory() ? prefixPath : path.dirname(prefixPath);
        const basePrefix = stat.isDirectory() ? prefix : path.dirname(prefix);

        const entries = await fs.readdir(dir, { recursive: true });
        const keys = entries
          .filter(e => typeof e === "string" && !e.endsWith(".meta"))
          .map(e => path.join(basePrefix, e as string).replace(/\\/g, "/"));

        return { success: true, data: keys, backend: this.type };
      } catch {
        return { success: true, data: [], backend: this.type };
      }
    } catch (error) {
      return {
        success: false,
        backend: this.type,
        error: (error as Error).message,
      };
    }
  }

  async delete(key: string): Promise<StorageResult<void>> {
    try {
      const filePath = this.keyToPath(key);
      await fs.unlink(filePath);

      // Also delete metadata
      try {
        await fs.unlink(filePath + ".meta");
      } catch {
        // Ignore if no metadata
      }

      return { success: true, backend: this.type };
    } catch (error) {
      return {
        success: false,
        backend: this.type,
        error: (error as Error).message,
      };
    }
  }

  private keyToPath(key: string): string {
    // Sanitize key to prevent path traversal
    const safeKey = key.replace(/\.\./g, "_").replace(/^\/+/, "");
    return path.join(this.basePath, safeKey);
  }

  private computeHash(content: string): string {
    return "0x" + crypto.createHash("sha256").update(content).digest("hex");
  }
}

// ============================================================================
// GitHub Storage Backend
// ============================================================================

export class GitHubStorage implements StorageBackend {
  type: StorageType = "github";
  name: string;
  private owner: string;
  private repo: string;
  private token: string;
  private branch: string;
  private basePath: string;

  constructor(
    owner: string,
    repo: string,
    token: string,
    branch: string = "main",
    basePath: string = "storage",
    name: string = "github"
  ) {
    this.owner = owner;
    this.repo = repo;
    this.token = token;
    this.branch = branch;
    this.basePath = basePath;
    this.name = name;
  }

  async healthCheck(): Promise<StorageHealth> {
    const start = Date.now();
    try {
      // Check repo access
      const response = await fetch(
        `https://api.github.com/repos/${this.owner}/${this.repo}`,
        {
          headers: this.getHeaders(),
        }
      );

      if (!response.ok) {
        throw new Error(`GitHub API error: ${response.status}`);
      }

      const data = await response.json();

      return {
        backend: this.type,
        healthy: true,
        latencyMs: Date.now() - start,
        details: {
          repo: `${this.owner}/${this.repo}`,
          defaultBranch: data.default_branch,
        },
      };
    } catch (error) {
      return {
        backend: this.type,
        healthy: false,
        latencyMs: Date.now() - start,
        error: (error as Error).message,
      };
    }
  }

  async write(key: string, content: string, contentType?: string): Promise<StorageResult<void>> {
    try {
      const filePath = `${this.basePath}/${key}`;

      // Check if file exists (need SHA for update)
      let sha: string | undefined;
      try {
        const existingResponse = await fetch(
          `https://api.github.com/repos/${this.owner}/${this.repo}/contents/${filePath}?ref=${this.branch}`,
          { headers: this.getHeaders() }
        );

        if (existingResponse.ok) {
          const existing = await existingResponse.json();
          sha = existing.sha;
        }
      } catch {
        // File doesn't exist, that's fine
      }

      // Create or update file
      const body: Record<string, unknown> = {
        message: `Update ${key}`,
        content: Buffer.from(content).toString("base64"),
        branch: this.branch,
      };

      if (sha) {
        body.sha = sha;
      }

      const response = await fetch(
        `https://api.github.com/repos/${this.owner}/${this.repo}/contents/${filePath}`,
        {
          method: "PUT",
          headers: this.getHeaders(),
          body: JSON.stringify(body),
        }
      );

      if (!response.ok) {
        const error = await response.json();
        throw new Error(`GitHub API error: ${error.message}`);
      }

      return { success: true, backend: this.type };
    } catch (error) {
      return {
        success: false,
        backend: this.type,
        error: (error as Error).message,
      };
    }
  }

  async read(key: string): Promise<StorageResult<string>> {
    try {
      const filePath = `${this.basePath}/${key}`;

      const response = await fetch(
        `https://api.github.com/repos/${this.owner}/${this.repo}/contents/${filePath}?ref=${this.branch}`,
        { headers: this.getHeaders() }
      );

      if (!response.ok) {
        if (response.status === 404) {
          return {
            success: false,
            backend: this.type,
            error: "File not found",
          };
        }
        throw new Error(`GitHub API error: ${response.status}`);
      }

      const data = await response.json();
      const content = Buffer.from(data.content, "base64").toString("utf-8");

      return { success: true, data: content, backend: this.type };
    } catch (error) {
      return {
        success: false,
        backend: this.type,
        error: (error as Error).message,
      };
    }
  }

  async exists(key: string): Promise<boolean> {
    const result = await this.read(key);
    return result.success;
  }

  async list(prefix: string): Promise<StorageResult<string[]>> {
    try {
      const dirPath = `${this.basePath}/${prefix}`;

      const response = await fetch(
        `https://api.github.com/repos/${this.owner}/${this.repo}/contents/${dirPath}?ref=${this.branch}`,
        { headers: this.getHeaders() }
      );

      if (!response.ok) {
        if (response.status === 404) {
          return { success: true, data: [], backend: this.type };
        }
        throw new Error(`GitHub API error: ${response.status}`);
      }

      const data = await response.json();
      const keys = Array.isArray(data)
        ? data.filter((item: any) => item.type === "file").map((item: any) => item.path)
        : [];

      return { success: true, data: keys, backend: this.type };
    } catch (error) {
      return {
        success: false,
        backend: this.type,
        error: (error as Error).message,
      };
    }
  }

  async delete(key: string): Promise<StorageResult<void>> {
    try {
      const filePath = `${this.basePath}/${key}`;

      // Get current SHA
      const getResponse = await fetch(
        `https://api.github.com/repos/${this.owner}/${this.repo}/contents/${filePath}?ref=${this.branch}`,
        { headers: this.getHeaders() }
      );

      if (!getResponse.ok) {
        throw new Error("File not found");
      }

      const { sha } = await getResponse.json();

      // Delete file
      const response = await fetch(
        `https://api.github.com/repos/${this.owner}/${this.repo}/contents/${filePath}`,
        {
          method: "DELETE",
          headers: this.getHeaders(),
          body: JSON.stringify({
            message: `Delete ${key}`,
            sha,
            branch: this.branch,
          }),
        }
      );

      if (!response.ok) {
        throw new Error(`GitHub API error: ${response.status}`);
      }

      return { success: true, backend: this.type };
    } catch (error) {
      return {
        success: false,
        backend: this.type,
        error: (error as Error).message,
      };
    }
  }

  private getHeaders(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.token}`,
      Accept: "application/vnd.github.v3+json",
      "Content-Type": "application/json",
    };
  }
}

// ============================================================================
// S3 Storage Backend (Stub - requires AWS SDK)
// ============================================================================

export class S3Storage implements StorageBackend {
  type: StorageType = "s3";
  name: string;
  private bucket: string;
  private region: string;
  private prefix: string;

  constructor(
    bucket: string,
    region: string,
    prefix: string = "",
    name: string = "s3"
  ) {
    this.bucket = bucket;
    this.region = region;
    this.prefix = prefix;
    this.name = name;
  }

  async healthCheck(): Promise<StorageHealth> {
    // S3 health check would require AWS SDK
    return {
      backend: this.type,
      healthy: false,
      latencyMs: 0,
      error: "S3 backend not implemented - requires AWS SDK",
      details: {
        bucket: this.bucket,
        region: this.region,
      },
    };
  }

  async write(key: string, content: string): Promise<StorageResult<void>> {
    return {
      success: false,
      backend: this.type,
      error: "S3 backend not implemented",
    };
  }

  async read(key: string): Promise<StorageResult<string>> {
    return {
      success: false,
      backend: this.type,
      error: "S3 backend not implemented",
    };
  }

  async exists(key: string): Promise<boolean> {
    return false;
  }

  async list(prefix: string): Promise<StorageResult<string[]>> {
    return {
      success: false,
      backend: this.type,
      error: "S3 backend not implemented",
    };
  }

  async delete(key: string): Promise<StorageResult<void>> {
    return {
      success: false,
      backend: this.type,
      error: "S3 backend not implemented",
    };
  }
}

// ============================================================================
// Multi-Backend Storage Manager
// ============================================================================

export class StorageManager {
  private primary: StorageBackend;
  private backups: StorageBackend[];
  private config: StorageConfig;

  constructor(config: StorageConfig) {
    this.config = config;
    this.primary = this.createBackend(config.primary);
    this.backups = (config.backup ?? []).map(type => this.createBackend(type));
  }

  private createBackend(type: StorageType): StorageBackend {
    switch (type) {
      case "local":
        return new LocalStorage(
          this.config.local?.path ?? "./storage"
        );

      case "github":
        if (!this.config.github) {
          throw new Error("GitHub config required");
        }
        return new GitHubStorage(
          this.config.github.owner,
          this.config.github.repo,
          this.config.github.token ?? ""
        );

      case "s3":
        if (!this.config.s3) {
          throw new Error("S3 config required");
        }
        return new S3Storage(
          this.config.s3.bucket,
          this.config.s3.region,
          this.config.s3.prefix
        );

      default:
        throw new Error(`Unknown storage type: ${type}`);
    }
  }

  /**
   * Get all backends
   */
  getBackends(): StorageBackend[] {
    return [this.primary, ...this.backups];
  }

  /**
   * Health check all backends
   */
  async healthCheckAll(): Promise<StorageHealth[]> {
    const results = await Promise.all(
      this.getBackends().map(b => b.healthCheck())
    );
    return results;
  }

  /**
   * Write to all backends (primary + backups)
   */
  async write(key: string, content: string, contentType?: string): Promise<StorageResult<void>> {
    // Write to primary first
    const primaryResult = await this.primary.write(key, content, contentType);

    if (!primaryResult.success) {
      // Try backups
      for (const backup of this.backups) {
        const backupResult = await backup.write(key, content, contentType);
        if (backupResult.success) {
          return backupResult;
        }
      }
      return primaryResult; // Return primary error
    }

    // Write to backups async (don't wait)
    for (const backup of this.backups) {
      backup.write(key, content, contentType).catch(() => {
        // Log backup write failure silently
      });
    }

    return primaryResult;
  }

  /**
   * Read from primary, fallback to backups
   */
  async read(key: string): Promise<StorageResult<string>> {
    const primaryResult = await this.primary.read(key);

    if (primaryResult.success) {
      return primaryResult;
    }

    // Try backups
    for (const backup of this.backups) {
      const backupResult = await backup.read(key);
      if (backupResult.success) {
        return backupResult;
      }
    }

    return primaryResult; // Return primary error
  }

  /**
   * Check if exists in any backend
   */
  async exists(key: string): Promise<boolean> {
    if (await this.primary.exists(key)) {
      return true;
    }

    for (const backup of this.backups) {
      if (await backup.exists(key)) {
        return true;
      }
    }

    return false;
  }

  /**
   * List from primary
   */
  async list(prefix: string): Promise<StorageResult<string[]>> {
    return this.primary.list(prefix);
  }

  /**
   * Delete from all backends
   */
  async delete(key: string): Promise<StorageResult<void>> {
    const results = await Promise.all(
      this.getBackends().map(b => b.delete(key))
    );

    // Return primary result
    return results[0];
  }
}

// ============================================================================
// High-Level Storage Operations
// ============================================================================

/**
 * Store a receipt
 */
export async function storeReceipt(
  manager: StorageManager,
  receipt: Receipt
): Promise<StorageResult<void>> {
  const key = `receipts/${receipt.session_id}/${receipt.receipt_id}.json`;
  return manager.write(key, JSON.stringify(receipt, null, 2), "application/json");
}

/**
 * Load a receipt
 */
export async function loadStoredReceipt(
  manager: StorageManager,
  sessionId: string,
  receiptId: string
): Promise<StorageResult<Receipt>> {
  const key = `receipts/${sessionId}/${receiptId}.json`;
  const result = await manager.read(key);

  if (!result.success || !result.data) {
    return {
      success: false,
      backend: result.backend,
      error: result.error,
    };
  }

  try {
    return {
      success: true,
      data: JSON.parse(result.data) as Receipt,
      backend: result.backend,
    };
  } catch (error) {
    return {
      success: false,
      backend: result.backend,
      error: `Failed to parse receipt: ${(error as Error).message}`,
    };
  }
}

/**
 * Store a receipt batch
 */
export async function storeBatch(
  manager: StorageManager,
  batch: ReceiptBatch
): Promise<StorageResult<void>> {
  const key = `batches/${batch.batch_id}.json`;
  return manager.write(key, JSON.stringify(batch, null, 2), "application/json");
}

/**
 * Store a release manifest
 */
export async function storeManifest(
  manager: StorageManager,
  manifest: SignedRelease | ReleaseManifest
): Promise<StorageResult<void>> {
  const key = `releases/${manifest.release_version}/manifest.json`;
  return manager.write(key, JSON.stringify(manifest, null, 2), "application/json");
}

/**
 * Load a release manifest
 */
export async function loadManifest(
  manager: StorageManager,
  version: string
): Promise<StorageResult<SignedRelease>> {
  const key = `releases/${version}/manifest.json`;
  const result = await manager.read(key);

  if (!result.success || !result.data) {
    return {
      success: false,
      backend: result.backend,
      error: result.error,
    };
  }

  try {
    return {
      success: true,
      data: JSON.parse(result.data) as SignedRelease,
      backend: result.backend,
    };
  } catch (error) {
    return {
      success: false,
      backend: result.backend,
      error: `Failed to parse manifest: ${(error as Error).message}`,
    };
  }
}
