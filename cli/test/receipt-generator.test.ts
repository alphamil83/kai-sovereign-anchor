/**
 * Receipt Generator Tests
 * Ticket 4: WAL + chaining + anchoring
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs/promises";
import * as path from "path";
import * as os from "os";

import {
  WriteAheadLog,
  generateReceiptId,
  createToolCallRecord,
  computeReceiptHash,
  createReceipt,
  signReceipt,
  verifyReceiptSignature,
  verifyReceiptHash,
  ReceiptChain,
  computeMerkleRoot,
  createReceiptBatch,
  generateMerkleProof,
  verifyMerkleProof,
  saveReceipt,
  loadReceipt,
  saveBatch,
  loadBatch,
} from "../src/receipt-generator.js";

import type { SessionState, ToolCallResult, Receipt } from "../src/types.js";

// Test constants
const TEST_PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_ROOT_HASH = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

// Helper to create mock session
function createMockSession(overrides: Partial<SessionState> = {}): SessionState {
  return {
    session_id: "test-session",
    started_at: Date.now() - 10000,
    release_root_hash: TEST_ROOT_HASH,
    current_sensitivity: "PUBLIC",
    tool_calls: [],
    approvals_used: [],
    sequence_number: 0,
    last_receipt_hash: null,
    ...overrides,
  };
}

// Helper to create mock tool call result
function createMockToolCallResult(overrides: Partial<ToolCallResult> = {}): ToolCallResult {
  return {
    request_id: "req-1",
    tool_name: "test_tool",
    decision: {
      action: "ALLOW",
      reason: "Test",
      tool_name: "test_tool",
      risk_level: "LOW",
    },
    status: "success",
    output: { result: "test" },
    output_sensitivity: "PUBLIC",
    duration_ms: 100,
    timestamp: Date.now(),
    ...overrides,
  };
}

describe("Write-Ahead Log", () => {
  let wal: WriteAheadLog;

  beforeEach(() => {
    wal = new WriteAheadLog();
  });

  describe("Basic Operations", () => {
    it("should write and retrieve entry", async () => {
      const walId = await wal.write("rcpt-1", { receipt_id: "rcpt-1" });

      const entry = wal.get(walId);
      expect(entry).toBeDefined();
      expect(entry?.receipt_id).toBe("rcpt-1");
      expect(entry?.status).toBe("pending");
    });

    it("should commit entry", async () => {
      const walId = await wal.write("rcpt-1", {});
      await wal.commit(walId);

      const entry = wal.get(walId);
      expect(entry?.status).toBe("committed");
    });

    it("should rollback entry", async () => {
      const walId = await wal.write("rcpt-1", {});
      await wal.rollback(walId);

      const entry = wal.get(walId);
      expect(entry?.status).toBe("rolled_back");
    });

    it("should throw on unknown entry", async () => {
      await expect(wal.commit("unknown")).rejects.toThrow("not found");
    });
  });

  describe("Pending Entries", () => {
    it("should return pending entries", async () => {
      await wal.write("rcpt-1", {});
      const walId2 = await wal.write("rcpt-2", {});
      await wal.commit(walId2);
      await wal.write("rcpt-3", {});

      const pending = wal.getPending();
      expect(pending.length).toBe(2);
    });
  });

  describe("Cleanup", () => {
    it("should cleanup old committed entries", async () => {
      const walId = await wal.write("rcpt-1", {});
      await wal.commit(walId);

      // With maxAge of 1 hour, entry should not be removed
      let removed = wal.cleanup(60 * 60 * 1000);
      expect(removed).toBe(0);

      // With maxAge of -1 (everything is "old"), entry should be removed
      removed = wal.cleanup(-1);
      expect(removed).toBe(1);
    });

    it("should not cleanup pending entries", async () => {
      await wal.write("rcpt-1", {});

      // Even with 0 max age, pending should remain
      const removed = wal.cleanup(0);
      expect(removed).toBe(0);

      const pending = wal.getPending();
      expect(pending.length).toBe(1);
    });
  });
});

describe("Receipt Generation", () => {
  describe("generateReceiptId", () => {
    it("should generate unique IDs", () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(generateReceiptId());
      }
      expect(ids.size).toBe(100);
    });

    it("should have correct format", () => {
      const id = generateReceiptId();
      expect(id).toMatch(/^rcpt_\d+_[a-f0-9]{16}$/);
    });
  });

  describe("createToolCallRecord", () => {
    it("should create record from result", () => {
      const result = createMockToolCallResult();
      const record = createToolCallRecord(result);

      expect(record.tool_name).toBe("test_tool");
      expect(record.status).toBe("success");
      expect(record.duration_ms).toBe(100);
      expect(record.input_hash).toMatch(/^0x[a-f0-9]{64}$/);
      expect(record.output_hash).toMatch(/^0x[a-f0-9]{64}$/);
    });

    it("should include block reason for blocked calls", () => {
      const result = createMockToolCallResult({
        status: "blocked",
        decision: {
          action: "BLOCK",
          reason: "Forbidden path",
          tool_name: "test_tool",
          risk_level: "HIGH",
        },
      });
      const record = createToolCallRecord(result);

      expect(record.block_reason).toBe("Forbidden path");
    });

    it("should include smuggling flags", () => {
      const result = createMockToolCallResult();
      const record = createToolCallRecord(result, ["high_entropy", "secret_pattern"]);

      expect(record.smuggling_flags).toEqual(["high_entropy", "secret_pattern"]);
    });
  });

  describe("createReceipt", () => {
    it("should create receipt with correct fields", () => {
      const session = createMockSession();
      const toolCalls = [createToolCallRecord(createMockToolCallResult())];
      const startedAt = Date.now() - 1000;

      const receipt = createReceipt(session, toolCalls, [], startedAt);

      expect(receipt.receipt_version).toBe("0.5");
      expect(receipt.session_id).toBe("test-session");
      expect(receipt.release_root_hash).toBe(TEST_ROOT_HASH);
      expect(receipt.prev_receipt_hash).toBeNull();
      expect(receipt.sequence_number).toBe(0);
      expect(receipt.tool_calls).toHaveLength(1);
      expect(receipt.receipt_hash).toMatch(/^0x[a-f0-9]{64}$/);
    });

    it("should link to previous receipt", () => {
      const session = createMockSession({
        last_receipt_hash: "0xpreviousreceipthash",
        sequence_number: 5,
      });

      const receipt = createReceipt(session, [], [], Date.now());

      expect(receipt.prev_receipt_hash).toBe("0xpreviousreceipthash");
      expect(receipt.sequence_number).toBe(5);
    });
  });

  describe("computeReceiptHash", () => {
    it("should produce deterministic hash", () => {
      const session = createMockSession();
      const receipt = createReceipt(session, [], [], Date.now());

      // Recompute hash from receipt data
      const { receipt_hash, ...data } = receipt;
      const recomputed = computeReceiptHash(data as any);

      expect(recomputed).toBe(receipt_hash);
    });

    it("should change with different data", () => {
      const session1 = createMockSession({ session_id: "session-1" });
      const session2 = createMockSession({ session_id: "session-2" });
      const now = Date.now();

      const receipt1 = createReceipt(session1, [], [], now);
      const receipt2 = createReceipt(session2, [], [], now);

      expect(receipt1.receipt_hash).not.toBe(receipt2.receipt_hash);
    });
  });
});

describe("Receipt Signing", () => {
  it("should sign receipt", async () => {
    const session = createMockSession();
    const unsignedReceipt = createReceipt(session, [], [], Date.now());

    const receipt = await signReceipt(unsignedReceipt, TEST_PRIVATE_KEY);

    expect(receipt.signature).toMatch(/^0x[a-f0-9]+$/);
  });

  it("should verify valid signature", async () => {
    const session = createMockSession();
    const unsignedReceipt = createReceipt(session, [], [], Date.now());
    const receipt = await signReceipt(unsignedReceipt, TEST_PRIVATE_KEY);

    const result = verifyReceiptSignature(receipt);

    expect(result.valid).toBe(true);
    expect(result.signer).toBeTruthy();
  });

  it("should reject tampered receipt", async () => {
    const session = createMockSession();
    const unsignedReceipt = createReceipt(session, [], [], Date.now());
    const receipt = await signReceipt(unsignedReceipt, TEST_PRIVATE_KEY);

    // Tamper with receipt
    receipt.session_id = "tampered-session";

    // Hash verification should fail
    const hashValid = verifyReceiptHash(receipt);
    expect(hashValid).toBe(false);
  });
});

describe("Receipt Chain", () => {
  it("should create chain with initial state", () => {
    const chain = new ReceiptChain("test-session", TEST_ROOT_HASH);
    const state = chain.getState();

    expect(state.session_id).toBe("test-session");
    expect(state.sequence_number).toBe(0);
    expect(state.last_receipt_hash).toBeNull();
    expect(state.receipts).toHaveLength(0);
  });

  it("should add receipts to chain", async () => {
    const chain = new ReceiptChain("test-session", TEST_ROOT_HASH);
    const session = createMockSession();

    const receipt1 = await chain.addReceipt(session, [], [], Date.now() - 100, TEST_PRIVATE_KEY);
    const receipt2 = await chain.addReceipt(session, [], [], Date.now(), TEST_PRIVATE_KEY);

    expect(chain.getReceipts()).toHaveLength(2);

    // Second receipt should link to first
    expect(receipt2.prev_receipt_hash).toBe(receipt1.receipt_hash);
    expect(receipt2.sequence_number).toBe(1);
  });

  it("should verify chain integrity", async () => {
    const chain = new ReceiptChain("test-session", TEST_ROOT_HASH);
    const session = createMockSession();

    await chain.addReceipt(session, [], [], Date.now() - 200, TEST_PRIVATE_KEY);
    await chain.addReceipt(session, [], [], Date.now() - 100, TEST_PRIVATE_KEY);
    await chain.addReceipt(session, [], [], Date.now(), TEST_PRIVATE_KEY);

    const result = chain.verifyChain();

    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("should export and import chain", async () => {
    const chain = new ReceiptChain("test-session", TEST_ROOT_HASH);
    const session = createMockSession();

    await chain.addReceipt(session, [], [], Date.now(), TEST_PRIVATE_KEY);

    const exported = chain.export();
    const imported = ReceiptChain.import(exported);

    expect(imported.getState().session_id).toBe("test-session");
    expect(imported.getReceipts()).toHaveLength(1);
  });
});

describe("Merkle Tree", () => {
  let receipts: Receipt[];

  beforeEach(async () => {
    receipts = [];
    const session = createMockSession();

    for (let i = 0; i < 4; i++) {
      const unsigned = createReceipt(
        { ...session, sequence_number: i },
        [],
        [],
        Date.now() + i
      );
      receipts.push(await signReceipt(unsigned, TEST_PRIVATE_KEY));
    }
  });

  describe("computeMerkleRoot", () => {
    it("should return empty hash for empty list", () => {
      const root = computeMerkleRoot([]);
      expect(root).toMatch(/^0x[a-f0-9]{64}$/);
    });

    it("should compute root for single receipt", () => {
      const root = computeMerkleRoot([receipts[0]]);
      expect(root).toBe(receipts[0].receipt_hash);
    });

    it("should compute root for multiple receipts", () => {
      const root = computeMerkleRoot(receipts);
      expect(root).toMatch(/^0x[a-f0-9]{64}$/);
    });

    it("should be deterministic", () => {
      const root1 = computeMerkleRoot(receipts);
      const root2 = computeMerkleRoot(receipts);
      expect(root1).toBe(root2);
    });

    it("should change with different receipts", () => {
      const root1 = computeMerkleRoot(receipts.slice(0, 2));
      const root2 = computeMerkleRoot(receipts.slice(2, 4));
      expect(root1).not.toBe(root2);
    });
  });

  describe("Merkle Proofs", () => {
    it("should generate valid proof", () => {
      const { proof, index } = generateMerkleProof(receipts, 1);

      expect(proof.length).toBeGreaterThan(0);
      expect(index).toBe(1);
    });

    it("should verify valid proof", () => {
      const root = computeMerkleRoot(receipts);
      const { proof, index } = generateMerkleProof(receipts, 2);

      const valid = verifyMerkleProof(
        receipts[2].receipt_hash,
        proof,
        index,
        root
      );

      expect(valid).toBe(true);
    });

    it("should reject proof for wrong receipt", () => {
      const root = computeMerkleRoot(receipts);
      const { proof, index } = generateMerkleProof(receipts, 0);

      // Use wrong receipt hash
      const valid = verifyMerkleProof(
        receipts[1].receipt_hash, // Wrong!
        proof,
        index,
        root
      );

      expect(valid).toBe(false);
    });

    it("should throw for invalid index", () => {
      expect(() => generateMerkleProof(receipts, 10)).toThrow("Invalid index");
    });
  });

  describe("Odd Batch Size Correctness (Bitcoin-style duplication)", () => {
    // Helper to create N receipts for testing
    async function createNReceipts(n: number): Promise<Receipt[]> {
      const result: Receipt[] = [];
      const session = createMockSession();

      for (let i = 0; i < n; i++) {
        const unsigned = createReceipt(
          { ...session, sequence_number: i },
          [],
          [],
          Date.now() + i * 100
        );
        result.push(await signReceipt(unsigned, TEST_PRIVATE_KEY));
      }
      return result;
    }

    it("should handle batch size 1", async () => {
      const batch = await createNReceipts(1);
      const root = computeMerkleRoot(batch);

      // For single node, root equals the node hash
      expect(root).toBe(batch[0].receipt_hash);

      // Proof should be empty (no siblings needed)
      const { proof } = generateMerkleProof(batch, 0);
      expect(proof).toHaveLength(0);

      // Verification should work
      const valid = verifyMerkleProof(batch[0].receipt_hash, proof, 0, root);
      expect(valid).toBe(true);
    });

    it("should handle batch size 2", async () => {
      const batch = await createNReceipts(2);
      const root = computeMerkleRoot(batch);

      // Verify all proofs
      for (let i = 0; i < batch.length; i++) {
        const { proof, index } = generateMerkleProof(batch, i);
        expect(proof).toHaveLength(1); // One level
        const valid = verifyMerkleProof(batch[i].receipt_hash, proof, index, root);
        expect(valid).toBe(true);
      }
    });

    it("should handle batch size 3 (odd)", async () => {
      const batch = await createNReceipts(3);
      const root = computeMerkleRoot(batch);

      // Verify ALL proofs work correctly
      for (let i = 0; i < batch.length; i++) {
        const { proof, index } = generateMerkleProof(batch, i);
        const valid = verifyMerkleProof(batch[i].receipt_hash, proof, index, root);
        expect(valid).toBe(true);
      }
    });

    it("should handle batch size 5 (odd)", async () => {
      const batch = await createNReceipts(5);
      const root = computeMerkleRoot(batch);

      for (let i = 0; i < batch.length; i++) {
        const { proof, index } = generateMerkleProof(batch, i);
        const valid = verifyMerkleProof(batch[i].receipt_hash, proof, index, root);
        expect(valid).toBe(true);
      }
    });

    it("should handle batch size 7 (odd)", async () => {
      const batch = await createNReceipts(7);
      const root = computeMerkleRoot(batch);

      for (let i = 0; i < batch.length; i++) {
        const { proof, index } = generateMerkleProof(batch, i);
        const valid = verifyMerkleProof(batch[i].receipt_hash, proof, index, root);
        expect(valid).toBe(true);
      }
    });

    it("should handle batch size 9 (odd)", async () => {
      const batch = await createNReceipts(9);
      const root = computeMerkleRoot(batch);

      for (let i = 0; i < batch.length; i++) {
        const { proof, index } = generateMerkleProof(batch, i);
        const valid = verifyMerkleProof(batch[i].receipt_hash, proof, index, root);
        expect(valid).toBe(true);
      }
    });

    it("should produce deterministic roots for odd batches", async () => {
      const batch = await createNReceipts(5);

      const root1 = computeMerkleRoot(batch);
      const root2 = computeMerkleRoot(batch);
      const root3 = computeMerkleRoot(batch);

      expect(root1).toBe(root2);
      expect(root2).toBe(root3);
    });

    it("should reject tampered proof for odd batch", async () => {
      const batch = await createNReceipts(5);
      const root = computeMerkleRoot(batch);

      // Generate proof for index 2
      const { proof, index } = generateMerkleProof(batch, 2);

      // Try to verify with wrong receipt hash
      const valid = verifyMerkleProof(
        batch[3].receipt_hash, // Wrong receipt!
        proof,
        index,
        root
      );
      expect(valid).toBe(false);
    });

    it("should handle last element in odd batch correctly", async () => {
      // This was the edge case that originally broke: verifying the last
      // element when it gets duplicated during tree construction
      const batch = await createNReceipts(3);
      const root = computeMerkleRoot(batch);

      // Specifically test index 2 (the one that would be duplicated)
      const { proof, index } = generateMerkleProof(batch, 2);
      const valid = verifyMerkleProof(batch[2].receipt_hash, proof, index, root);
      expect(valid).toBe(true);
    });
  });
});

describe("Receipt Batch", () => {
  let receipts: Receipt[];

  beforeEach(async () => {
    receipts = [];
    const session = createMockSession();

    for (let i = 0; i < 3; i++) {
      const unsigned = createReceipt(session, [], [], Date.now() + i);
      receipts.push(await signReceipt(unsigned, TEST_PRIVATE_KEY));
    }
  });

  it("should create batch", () => {
    const batch = createReceiptBatch(receipts);

    expect(batch.batch_id).toMatch(/^batch_\d+_[a-f0-9]+$/);
    expect(batch.receipts).toHaveLength(3);
    expect(batch.merkle_root).toMatch(/^0x[a-f0-9]{64}$/);
    expect(batch.created_at).toBeLessThanOrEqual(Date.now());
  });

  it("should have correct merkle root", () => {
    const batch = createReceiptBatch(receipts);
    const expectedRoot = computeMerkleRoot(receipts);

    expect(batch.merkle_root).toBe(expectedRoot);
  });
});

describe("Storage", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "receipt-test-"));
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("should save and load receipt", async () => {
    const session = createMockSession();
    const unsigned = createReceipt(session, [], [], Date.now());
    const receipt = await signReceipt(unsigned, TEST_PRIVATE_KEY);

    const filePath = await saveReceipt(receipt, tmpDir);
    const loaded = await loadReceipt(filePath);

    expect(loaded.receipt_id).toBe(receipt.receipt_id);
    expect(loaded.receipt_hash).toBe(receipt.receipt_hash);
  });

  it("should save and load batch", async () => {
    const session = createMockSession();
    const unsigned = createReceipt(session, [], [], Date.now());
    const receipt = await signReceipt(unsigned, TEST_PRIVATE_KEY);
    const batch = createReceiptBatch([receipt]);

    const filePath = await saveBatch(batch, tmpDir);
    const loaded = await loadBatch(filePath);

    expect(loaded.batch_id).toBe(batch.batch_id);
    expect(loaded.merkle_root).toBe(batch.merkle_root);
    expect(loaded.receipts).toHaveLength(1);
  });
});

describe("WAL with File Persistence", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "wal-test-"));
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("should persist entries to disk", async () => {
    const wal = new WriteAheadLog(tmpDir);
    await wal.write("rcpt-1", { receipt_id: "rcpt-1" });

    // Check file exists
    const files = await fs.readdir(tmpDir);
    expect(files.length).toBe(1);
    expect(files[0]).toMatch(/^wal_/);
  });

  it("should recover entries from disk", async () => {
    const wal1 = new WriteAheadLog(tmpDir);
    await wal1.write("rcpt-1", { receipt_id: "rcpt-1" });

    // Create new WAL and recover
    const wal2 = new WriteAheadLog(tmpDir);
    const recovered = await wal2.recover();

    expect(recovered).toBe(1);
    expect(wal2.getPending().length).toBe(1);
  });
});
