/**
 * Approval Tokens Tests
 * Ticket 3: Nonce-based replay prevention
 */

import { describe, it, expect, beforeEach } from "vitest";
import { ethers } from "ethers";

import {
  NonceDatabase,
  generateNonce,
  createApprovalRequest,
  createApprovalToken,
  verifyTokenSignature,
  validateApprovalToken,
  consumeToken,
  serializeToken,
  deserializeToken,
  generateSummary,
  verifySummaryHash,
} from "../src/approval-tokens.js";

import { computeActionHash, sha256 } from "../src/canonical.js";

import type { ToolCallRequest, SessionState } from "../src/types.js";

// Test constants
const TEST_ROOT_HASH = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const TEST_PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

describe("Nonce Database", () => {
  let db: NonceDatabase;

  beforeEach(() => {
    db = new NonceDatabase();
  });

  it("should start empty", () => {
    expect(db.size()).toBe(0);
  });

  it("should mark nonce as spent", () => {
    const nonce = generateNonce();
    expect(db.isSpent(nonce)).toBe(false);

    db.spend(nonce, "session-1");
    expect(db.isSpent(nonce)).toBe(true);
  });

  it("should throw on double spend", () => {
    const nonce = generateNonce();
    db.spend(nonce, "session-1");

    expect(() => db.spend(nonce, "session-2")).toThrow("replay");
  });

  it("should track nonce info", () => {
    const nonce = generateNonce();
    db.spend(nonce, "session-123");

    const info = db.getNonceInfo(nonce);
    expect(info).toBeDefined();
    expect(info?.session_id).toBe("session-123");
  });

  it("should clear on request", () => {
    db.spend(generateNonce(), "s1");
    db.spend(generateNonce(), "s2");
    expect(db.size()).toBe(2);

    db.clear();
    expect(db.size()).toBe(0);
  });
});

describe("Nonce Generation", () => {
  it("should generate 32-byte hex nonces", () => {
    const nonce = generateNonce();
    expect(nonce).toMatch(/^0x[a-f0-9]{64}$/);
  });

  it("should generate unique nonces", () => {
    const nonces = new Set<string>();
    for (let i = 0; i < 100; i++) {
      nonces.add(generateNonce());
    }
    expect(nonces.size).toBe(100);
  });
});

describe("Approval Request Creation", () => {
  it("should create approval request with correct fields", () => {
    const request: ToolCallRequest = {
      request_id: "req-1",
      tool_name: "send_email",
      parameters: { to: "test@example.com", body: "Hello" },
      timestamp: Date.now(),
    };

    const session: SessionState = {
      session_id: "sess-123",
      started_at: Date.now() - 1000,
      release_root_hash: TEST_ROOT_HASH,
      current_sensitivity: "PUBLIC",
      tool_calls: [],
      approvals_used: [],
      sequence_number: 5,
    };

    const summary = "Send email to test@example.com";
    const approval = createApprovalRequest(TEST_ROOT_HASH, request, session, summary);

    expect(approval.release_root_hash).toBe(TEST_ROOT_HASH);
    expect(approval.tool_name).toBe("send_email");
    expect(approval.session_id).toBe("sess-123");
    expect(approval.sequence_number).toBe(5);
    expect(approval.summary).toBe(summary);
    expect(approval.expires_at).toBeGreaterThan(Date.now());
  });
});

describe("Approval Token Creation and Signing", () => {
  it("should create signed token", async () => {
    const request: ToolCallRequest = {
      request_id: "req-1",
      tool_name: "send_email",
      parameters: { to: "test@example.com" },
      timestamp: Date.now(),
    };

    const session: SessionState = {
      session_id: "sess-123",
      started_at: Date.now(),
      release_root_hash: TEST_ROOT_HASH,
      current_sensitivity: "PUBLIC",
      tool_calls: [],
      approvals_used: [],
      sequence_number: 0,
    };

    const summary = "Test summary";
    const approvalRequest = createApprovalRequest(TEST_ROOT_HASH, request, session, summary);
    const token = await createApprovalToken(approvalRequest, TEST_PRIVATE_KEY);

    expect(token.token_version).toBe("0.5");
    expect(token.release_root_hash).toBe(TEST_ROOT_HASH);
    expect(token.tool_name).toBe("send_email");
    expect(token.nonce).toMatch(/^0x[a-f0-9]{64}$/);
    expect(token.signature).toMatch(/^0x[a-f0-9]+$/);
  });

  it("should set correct approver pubkey", async () => {
    const wallet = new ethers.Wallet(TEST_PRIVATE_KEY);

    const request: ToolCallRequest = {
      request_id: "req-1",
      tool_name: "send_email",
      parameters: {},
      timestamp: Date.now(),
    };

    const session: SessionState = {
      session_id: "sess-123",
      started_at: Date.now(),
      release_root_hash: TEST_ROOT_HASH,
      current_sensitivity: "PUBLIC",
      tool_calls: [],
      approvals_used: [],
      sequence_number: 0,
    };

    const approvalRequest = createApprovalRequest(TEST_ROOT_HASH, request, session, "test");
    const token = await createApprovalToken(approvalRequest, TEST_PRIVATE_KEY);

    expect(token.approver_pubkey.toLowerCase()).toBe(wallet.address.toLowerCase());
  });
});

describe("Token Signature Verification", () => {
  it("should verify valid signature", async () => {
    const request: ToolCallRequest = {
      request_id: "req-1",
      tool_name: "test_tool",
      parameters: {},
      timestamp: Date.now(),
    };

    const session: SessionState = {
      session_id: "sess-123",
      started_at: Date.now(),
      release_root_hash: TEST_ROOT_HASH,
      current_sensitivity: "PUBLIC",
      tool_calls: [],
      approvals_used: [],
      sequence_number: 0,
    };

    const approvalRequest = createApprovalRequest(TEST_ROOT_HASH, request, session, "test");
    const token = await createApprovalToken(approvalRequest, TEST_PRIVATE_KEY);

    const result = verifyTokenSignature(token);

    expect(result.valid).toBe(true);
    expect(result.recoveredAddress?.toLowerCase()).toBe(token.approver_pubkey.toLowerCase());
  });

  it("should reject tampered token", async () => {
    const request: ToolCallRequest = {
      request_id: "req-1",
      tool_name: "test_tool",
      parameters: {},
      timestamp: Date.now(),
    };

    const session: SessionState = {
      session_id: "sess-123",
      started_at: Date.now(),
      release_root_hash: TEST_ROOT_HASH,
      current_sensitivity: "PUBLIC",
      tool_calls: [],
      approvals_used: [],
      sequence_number: 0,
    };

    const approvalRequest = createApprovalRequest(TEST_ROOT_HASH, request, session, "test");
    const token = await createApprovalToken(approvalRequest, TEST_PRIVATE_KEY);

    // Tamper with the token
    token.tool_name = "different_tool";

    const result = verifyTokenSignature(token);
    expect(result.valid).toBe(false);
  });
});

describe("Full Token Validation", () => {
  it("should validate correct token", async () => {
    const request: ToolCallRequest = {
      request_id: "req-1",
      tool_name: "test_tool",
      parameters: { key: "value" },
      timestamp: Date.now(),
    };

    const session: SessionState = {
      session_id: "sess-123",
      started_at: Date.now(),
      release_root_hash: TEST_ROOT_HASH,
      current_sensitivity: "PUBLIC",
      tool_calls: [],
      approvals_used: [],
      sequence_number: 5,
    };

    const approvalRequest = createApprovalRequest(TEST_ROOT_HASH, request, session, "test");
    const token = await createApprovalToken(approvalRequest, TEST_PRIVATE_KEY);

    const actionHash = computeActionHash(TEST_ROOT_HASH, "test_tool", request.parameters);
    const nonceDb = new NonceDatabase();

    const result = validateApprovalToken(
      token,
      TEST_ROOT_HASH,
      "sess-123",
      5,
      "test_tool",
      actionHash,
      nonceDb
    );

    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("should reject expired token", async () => {
    const request: ToolCallRequest = {
      request_id: "req-1",
      tool_name: "test_tool",
      parameters: {},
      timestamp: Date.now(),
    };

    const session: SessionState = {
      session_id: "sess-123",
      started_at: Date.now(),
      release_root_hash: TEST_ROOT_HASH,
      current_sensitivity: "PUBLIC",
      tool_calls: [],
      approvals_used: [],
      sequence_number: 0,
    };

    // Create with very short expiry
    const approvalRequest = createApprovalRequest(TEST_ROOT_HASH, request, session, "test", 1);
    const token = await createApprovalToken(approvalRequest, TEST_PRIVATE_KEY);

    // Wait for expiry
    await new Promise(resolve => setTimeout(resolve, 10));

    const actionHash = computeActionHash(TEST_ROOT_HASH, "test_tool", {});
    const nonceDb = new NonceDatabase();

    const result = validateApprovalToken(
      token,
      TEST_ROOT_HASH,
      "sess-123",
      0,
      "test_tool",
      actionHash,
      nonceDb
    );

    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes("expired"))).toBe(true);
  });

  it("should reject replayed nonce", async () => {
    const request: ToolCallRequest = {
      request_id: "req-1",
      tool_name: "test_tool",
      parameters: {},
      timestamp: Date.now(),
    };

    const session: SessionState = {
      session_id: "sess-123",
      started_at: Date.now(),
      release_root_hash: TEST_ROOT_HASH,
      current_sensitivity: "PUBLIC",
      tool_calls: [],
      approvals_used: [],
      sequence_number: 0,
    };

    const approvalRequest = createApprovalRequest(TEST_ROOT_HASH, request, session, "test");
    const token = await createApprovalToken(approvalRequest, TEST_PRIVATE_KEY);

    const actionHash = computeActionHash(TEST_ROOT_HASH, "test_tool", {});
    const nonceDb = new NonceDatabase();

    // First use - should be valid
    const result1 = validateApprovalToken(
      token,
      TEST_ROOT_HASH,
      "sess-123",
      0,
      "test_tool",
      actionHash,
      nonceDb
    );
    expect(result1.valid).toBe(true);

    // Consume the token
    consumeToken(token, nonceDb);

    // Second use - should be rejected
    const result2 = validateApprovalToken(
      token,
      TEST_ROOT_HASH,
      "sess-123",
      0,
      "test_tool",
      actionHash,
      nonceDb
    );
    expect(result2.valid).toBe(false);
    expect(result2.errors.some(e => e.includes("replay"))).toBe(true);
  });

  it("should reject wrong session", async () => {
    const request: ToolCallRequest = {
      request_id: "req-1",
      tool_name: "test_tool",
      parameters: {},
      timestamp: Date.now(),
    };

    const session: SessionState = {
      session_id: "sess-123",
      started_at: Date.now(),
      release_root_hash: TEST_ROOT_HASH,
      current_sensitivity: "PUBLIC",
      tool_calls: [],
      approvals_used: [],
      sequence_number: 0,
    };

    const approvalRequest = createApprovalRequest(TEST_ROOT_HASH, request, session, "test");
    const token = await createApprovalToken(approvalRequest, TEST_PRIVATE_KEY);

    const actionHash = computeActionHash(TEST_ROOT_HASH, "test_tool", {});
    const nonceDb = new NonceDatabase();

    const result = validateApprovalToken(
      token,
      TEST_ROOT_HASH,
      "different-session",  // Wrong session
      0,
      "test_tool",
      actionHash,
      nonceDb
    );

    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes("Session"))).toBe(true);
  });
});

describe("Token Serialization", () => {
  it("should serialize and deserialize token", async () => {
    const request: ToolCallRequest = {
      request_id: "req-1",
      tool_name: "test_tool",
      parameters: { key: "value" },
      timestamp: Date.now(),
    };

    const session: SessionState = {
      session_id: "sess-123",
      started_at: Date.now(),
      release_root_hash: TEST_ROOT_HASH,
      current_sensitivity: "PUBLIC",
      tool_calls: [],
      approvals_used: [],
      sequence_number: 0,
    };

    const approvalRequest = createApprovalRequest(TEST_ROOT_HASH, request, session, "test");
    const token = await createApprovalToken(approvalRequest, TEST_PRIVATE_KEY);

    const json = serializeToken(token);
    const restored = deserializeToken(json);

    expect(restored.nonce).toBe(token.nonce);
    expect(restored.signature).toBe(token.signature);
    expect(restored.tool_name).toBe(token.tool_name);
  });
});

describe("Summary Generation", () => {
  it("should generate readable summary", () => {
    const summary = generateSummary(
      "send_email",
      { to: "test@example.com", body: "Hello" },
      "HIGH",
      true
    );

    expect(summary).toContain("send_email");
    expect(summary).toContain("HIGH");
    expect(summary).toContain("test@example.com");
    expect(summary).toContain("externally");
  });

  it("should verify summary hash", async () => {
    const summary = "Test summary for approval";

    const request: ToolCallRequest = {
      request_id: "req-1",
      tool_name: "test_tool",
      parameters: {},
      timestamp: Date.now(),
    };

    const session: SessionState = {
      session_id: "sess-123",
      started_at: Date.now(),
      release_root_hash: TEST_ROOT_HASH,
      current_sensitivity: "PUBLIC",
      tool_calls: [],
      approvals_used: [],
      sequence_number: 0,
    };

    const approvalRequest = createApprovalRequest(TEST_ROOT_HASH, request, session, summary);
    const token = await createApprovalToken(approvalRequest, TEST_PRIVATE_KEY);

    expect(verifySummaryHash(token, summary)).toBe(true);
    expect(verifySummaryHash(token, "Different summary")).toBe(false);
  });
});
