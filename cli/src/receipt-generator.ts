/**
 * Receipt Generator
 * Ticket 4: WAL + chaining + anchoring
 *
 * Per KAI v0.5 Specification:
 * - Write-ahead logging ensures durability before action execution
 * - Receipts are hash-chained for tamper evidence
 * - Batch anchoring to on-chain registry
 * - Full audit trail of all tool calls
 */

import * as crypto from "crypto";
import * as fs from "fs/promises";
import * as path from "path";
import { ethers } from "ethers";

import type {
  Receipt,
  ToolCallRecord,
  SessionState,
  DataSensitivity,
  ToolCallResult,
} from "./types.js";

import { sha256, canonicalize } from "./canonical.js";

// ============================================================================
// Types
// ============================================================================

export interface WALEntry {
  wal_id: string;
  receipt_id: string;
  timestamp: number;
  status: "pending" | "committed" | "rolled_back";
  data: Partial<Receipt>;
}

export interface ReceiptBatch {
  batch_id: string;
  receipts: Receipt[];
  merkle_root: string;
  created_at: number;
  anchored_at?: number;
  tx_hash?: string;
}

export interface ReceiptChainState {
  session_id: string;
  last_receipt_hash: string | null;
  sequence_number: number;
  receipts: Receipt[];
}

// ============================================================================
// Write-Ahead Log
// ============================================================================

/**
 * Simple in-memory WAL for development
 * Production should use SQLite or file-based storage
 */
export class WriteAheadLog {
  private entries: Map<string, WALEntry> = new Map();
  private walDir: string | null = null;

  constructor(walDir?: string) {
    this.walDir = walDir ?? null;
  }

  /**
   * Generate a unique WAL entry ID
   */
  private generateWalId(): string {
    return `wal_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
  }

  /**
   * Write entry to WAL before execution
   */
  async write(receiptId: string, data: Partial<Receipt>): Promise<string> {
    const walId = this.generateWalId();
    const entry: WALEntry = {
      wal_id: walId,
      receipt_id: receiptId,
      timestamp: Date.now(),
      status: "pending",
      data,
    };

    // In-memory storage
    this.entries.set(walId, entry);

    // Optional file persistence
    if (this.walDir) {
      await this.persistEntry(entry);
    }

    return walId;
  }

  /**
   * Mark entry as committed (execution successful)
   */
  async commit(walId: string): Promise<void> {
    const entry = this.entries.get(walId);
    if (!entry) {
      throw new Error(`WAL entry not found: ${walId}`);
    }

    entry.status = "committed";

    if (this.walDir) {
      await this.persistEntry(entry);
    }
  }

  /**
   * Roll back entry (execution failed or cancelled)
   */
  async rollback(walId: string): Promise<void> {
    const entry = this.entries.get(walId);
    if (!entry) {
      throw new Error(`WAL entry not found: ${walId}`);
    }

    entry.status = "rolled_back";

    if (this.walDir) {
      await this.persistEntry(entry);
    }
  }

  /**
   * Get entry by ID
   */
  get(walId: string): WALEntry | undefined {
    return this.entries.get(walId);
  }

  /**
   * Get all pending entries (for recovery)
   */
  getPending(): WALEntry[] {
    return Array.from(this.entries.values()).filter(e => e.status === "pending");
  }

  /**
   * Clean up old committed entries
   */
  cleanup(maxAgeMs: number = 24 * 60 * 60 * 1000): number {
    const cutoff = Date.now() - maxAgeMs;
    let removed = 0;

    for (const [walId, entry] of this.entries.entries()) {
      if (entry.timestamp < cutoff && entry.status !== "pending") {
        this.entries.delete(walId);
        removed++;
      }
    }

    return removed;
  }

  /**
   * Persist entry to file (optional durability)
   */
  private async persistEntry(entry: WALEntry): Promise<void> {
    if (!this.walDir) return;

    const filePath = path.join(this.walDir, `${entry.wal_id}.json`);
    await fs.mkdir(this.walDir, { recursive: true });
    await fs.writeFile(filePath, JSON.stringify(entry, null, 2));
  }

  /**
   * Load entries from disk (recovery)
   */
  async recover(): Promise<number> {
    if (!this.walDir) return 0;

    try {
      const files = await fs.readdir(this.walDir);
      let recovered = 0;

      for (const file of files) {
        if (file.endsWith(".json")) {
          const filePath = path.join(this.walDir, file);
          const content = await fs.readFile(filePath, "utf-8");
          const entry = JSON.parse(content) as WALEntry;
          this.entries.set(entry.wal_id, entry);
          recovered++;
        }
      }

      return recovered;
    } catch {
      // Directory doesn't exist or can't be read
      return 0;
    }
  }

  /**
   * Clear all entries (for testing)
   */
  clear(): void {
    this.entries.clear();
  }
}

// ============================================================================
// Receipt Generator
// ============================================================================

/**
 * Generate unique receipt ID
 */
export function generateReceiptId(): string {
  return `rcpt_${Date.now()}_${crypto.randomBytes(8).toString("hex")}`;
}

/**
 * Create a tool call record from execution result
 */
export function createToolCallRecord(
  result: ToolCallResult,
  smugglingFlags?: string[]
): ToolCallRecord {
  return {
    tool_name: result.tool_name,
    input_hash: sha256(Buffer.from(JSON.stringify(result.decision))),
    output_hash: sha256(Buffer.from(JSON.stringify(result.output))),
    output_sensitivity: result.output_sensitivity,
    output_size: typeof result.output === "string"
      ? Buffer.byteLength(result.output, "utf8")
      : JSON.stringify(result.output).length,
    timestamp: result.timestamp,
    duration_ms: result.duration_ms,
    status: result.status,
    block_reason: result.status === "blocked" ? result.decision.reason : undefined,
    smuggling_flags: smugglingFlags,
  };
}

/**
 * Compute receipt hash
 */
export function computeReceiptHash(receipt: Omit<Receipt, "receipt_hash" | "signature">): string {
  const canonical = canonicalize(receipt);
  return sha256(Buffer.from(canonical));
}

/**
 * Create a receipt from session state
 */
export function createReceipt(
  session: SessionState,
  toolCalls: ToolCallRecord[],
  approvalsUsed: string[] = [],
  startedAt: number,
  completedAt: number = Date.now()
): Omit<Receipt, "signature"> {
  const receiptId = generateReceiptId();

  const receiptData: Omit<Receipt, "receipt_hash" | "signature"> = {
    receipt_version: "0.5",
    receipt_id: receiptId,
    release_root_hash: session.release_root_hash,
    session_id: session.session_id,
    prev_receipt_hash: session.last_receipt_hash ?? null,
    sequence_number: session.sequence_number,
    tool_calls: toolCalls,
    approvals_used: approvalsUsed,
    session_sensitivity: session.current_sensitivity,
    taint_source: session.taint_source,
    started_at: startedAt,
    completed_at: completedAt,
  };

  return {
    ...receiptData,
    receipt_hash: computeReceiptHash(receiptData),
  };
}

/**
 * Sign a receipt
 */
export async function signReceipt(
  receipt: Omit<Receipt, "signature">,
  privateKey: string
): Promise<Receipt> {
  const wallet = new ethers.Wallet(privateKey);
  const signature = await wallet.signMessage(receipt.receipt_hash);

  return {
    ...receipt,
    signature,
  };
}

/**
 * Verify receipt signature
 */
export function verifyReceiptSignature(
  receipt: Receipt,
  expectedSigner?: string
): { valid: boolean; signer: string; error?: string } {
  try {
    const signer = ethers.verifyMessage(receipt.receipt_hash, receipt.signature);

    if (expectedSigner && signer.toLowerCase() !== expectedSigner.toLowerCase()) {
      return {
        valid: false,
        signer,
        error: `Signer mismatch: expected ${expectedSigner}, got ${signer}`,
      };
    }

    return { valid: true, signer };
  } catch (error) {
    return {
      valid: false,
      signer: "",
      error: `Signature verification failed: ${(error as Error).message}`,
    };
  }
}

/**
 * Verify receipt hash integrity
 */
export function verifyReceiptHash(receipt: Receipt): boolean {
  const { receipt_hash, signature, ...receiptData } = receipt;
  const computedHash = computeReceiptHash(receiptData as Omit<Receipt, "receipt_hash" | "signature">);
  return computedHash === receipt_hash;
}

// ============================================================================
// Receipt Chain
// ============================================================================

/**
 * Receipt chain manager for a session
 */
export class ReceiptChain {
  private state: ReceiptChainState;
  private wal: WriteAheadLog;

  constructor(sessionId: string, releaseRootHash: string, wal?: WriteAheadLog) {
    this.state = {
      session_id: sessionId,
      last_receipt_hash: null,
      sequence_number: 0,
      receipts: [],
    };
    this.wal = wal ?? new WriteAheadLog();
  }

  /**
   * Get current state
   */
  getState(): ReceiptChainState {
    return { ...this.state };
  }

  /**
   * Get all receipts
   */
  getReceipts(): Receipt[] {
    return [...this.state.receipts];
  }

  /**
   * Get last receipt
   */
  getLastReceipt(): Receipt | null {
    if (this.state.receipts.length === 0) return null;
    return this.state.receipts[this.state.receipts.length - 1];
  }

  /**
   * Add a receipt to the chain
   */
  async addReceipt(
    session: SessionState,
    toolCalls: ToolCallRecord[],
    approvalsUsed: string[],
    startedAt: number,
    privateKey: string
  ): Promise<Receipt> {
    // Create unsigned receipt
    const unsignedReceipt = createReceipt(
      {
        ...session,
        last_receipt_hash: this.state.last_receipt_hash,
        sequence_number: this.state.sequence_number,
      },
      toolCalls,
      approvalsUsed,
      startedAt
    );

    // Write to WAL before signing
    const walId = await this.wal.write(unsignedReceipt.receipt_id, unsignedReceipt);

    try {
      // Sign receipt
      const receipt = await signReceipt(unsignedReceipt, privateKey);

      // Update chain state
      this.state.last_receipt_hash = receipt.receipt_hash;
      this.state.sequence_number++;
      this.state.receipts.push(receipt);

      // Commit WAL entry
      await this.wal.commit(walId);

      return receipt;
    } catch (error) {
      // Rollback on failure
      await this.wal.rollback(walId);
      throw error;
    }
  }

  /**
   * Verify chain integrity
   */
  verifyChain(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    for (let i = 0; i < this.state.receipts.length; i++) {
      const receipt = this.state.receipts[i];

      // Verify hash
      if (!verifyReceiptHash(receipt)) {
        errors.push(`Receipt ${i}: hash mismatch`);
      }

      // Verify sequence
      if (receipt.sequence_number !== i) {
        errors.push(`Receipt ${i}: sequence number mismatch (expected ${i}, got ${receipt.sequence_number})`);
      }

      // Verify chain link
      if (i === 0) {
        if (receipt.prev_receipt_hash !== null) {
          errors.push(`Receipt 0: should have null prev_receipt_hash`);
        }
      } else {
        const prevReceipt = this.state.receipts[i - 1];
        if (receipt.prev_receipt_hash !== prevReceipt.receipt_hash) {
          errors.push(`Receipt ${i}: prev_receipt_hash mismatch`);
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Export chain for persistence
   */
  export(): string {
    return JSON.stringify({
      state: this.state,
      version: "0.5",
    }, null, 2);
  }

  /**
   * Import chain from persistence
   */
  static import(json: string, wal?: WriteAheadLog): ReceiptChain {
    const data = JSON.parse(json);
    const chain = new ReceiptChain(data.state.session_id, "", wal);
    chain.state = data.state;
    return chain;
  }
}

// ============================================================================
// Batch Operations
// ============================================================================

/**
 * Compute Merkle root of receipts using Bitcoin-style duplication.
 * When there's an odd number of nodes at any level, the last node
 * is duplicated before pairing. This ensures deterministic proof
 * generation and verification for any batch size.
 */
export function computeMerkleRoot(receipts: Receipt[]): string {
  if (receipts.length === 0) {
    return sha256(Buffer.from(""));
  }

  // Get leaf hashes
  let hashes = receipts.map(r => r.receipt_hash);

  // Build tree with Bitcoin-style duplication for odd counts
  while (hashes.length > 1) {
    // If odd number of nodes, duplicate the last one (Bitcoin-style)
    if (hashes.length % 2 === 1) {
      hashes.push(hashes[hashes.length - 1]);
    }

    const nextLevel: string[] = [];
    for (let i = 0; i < hashes.length; i += 2) {
      nextLevel.push(sha256(Buffer.from(hashes[i] + hashes[i + 1])));
    }

    hashes = nextLevel;
  }

  return hashes[0];
}

/**
 * Create a batch of receipts for anchoring
 */
export function createReceiptBatch(receipts: Receipt[]): ReceiptBatch {
  return {
    batch_id: `batch_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`,
    receipts,
    merkle_root: computeMerkleRoot(receipts),
    created_at: Date.now(),
  };
}

/**
 * Generate Merkle proof for a receipt at a given index.
 * Uses Bitcoin-style duplication for odd node counts, ensuring
 * proofs work correctly for any batch size (1, 2, 3, 5, 7, etc.).
 */
export function generateMerkleProof(
  receipts: Receipt[],
  targetIndex: number
): { proof: string[]; index: number } {
  if (targetIndex < 0 || targetIndex >= receipts.length) {
    throw new Error(`Invalid index: ${targetIndex}`);
  }

  const proof: string[] = [];
  let hashes = receipts.map(r => r.receipt_hash);
  let index = targetIndex;

  while (hashes.length > 1) {
    // If odd number of nodes, duplicate the last one (Bitcoin-style)
    if (hashes.length % 2 === 1) {
      hashes.push(hashes[hashes.length - 1]);
    }

    // Find sibling for our current index
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
    proof.push(hashes[siblingIndex]);

    // Build next level
    const nextLevel: string[] = [];
    for (let i = 0; i < hashes.length; i += 2) {
      nextLevel.push(sha256(Buffer.from(hashes[i] + hashes[i + 1])));
    }

    hashes = nextLevel;
    index = Math.floor(index / 2);
  }

  return { proof, index: targetIndex };
}

/**
 * Verify a Merkle proof
 */
export function verifyMerkleProof(
  receiptHash: string,
  proof: string[],
  index: number,
  merkleRoot: string
): boolean {
  let hash = receiptHash;
  let idx = index;

  for (const sibling of proof) {
    if (idx % 2 === 0) {
      hash = sha256(Buffer.from(hash + sibling));
    } else {
      hash = sha256(Buffer.from(sibling + hash));
    }
    idx = Math.floor(idx / 2);
  }

  return hash === merkleRoot;
}

// ============================================================================
// Storage
// ============================================================================

/**
 * Save receipt to file
 */
export async function saveReceipt(receipt: Receipt, outputDir: string): Promise<string> {
  await fs.mkdir(outputDir, { recursive: true });
  const filePath = path.join(outputDir, `${receipt.receipt_id}.json`);
  await fs.writeFile(filePath, JSON.stringify(receipt, null, 2));
  return filePath;
}

/**
 * Load receipt from file
 */
export async function loadReceipt(filePath: string): Promise<Receipt> {
  const content = await fs.readFile(filePath, "utf-8");
  return JSON.parse(content) as Receipt;
}

/**
 * Save batch to file
 */
export async function saveBatch(batch: ReceiptBatch, outputDir: string): Promise<string> {
  await fs.mkdir(outputDir, { recursive: true });
  const filePath = path.join(outputDir, `${batch.batch_id}.json`);
  await fs.writeFile(filePath, JSON.stringify(batch, null, 2));
  return filePath;
}

/**
 * Load batch from file
 */
export async function loadBatch(filePath: string): Promise<ReceiptBatch> {
  const content = await fs.readFile(filePath, "utf-8");
  return JSON.parse(content) as ReceiptBatch;
}
