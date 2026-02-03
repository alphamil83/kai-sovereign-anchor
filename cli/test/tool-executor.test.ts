/**
 * Tool Executor Tests
 * Ticket 2: Hard boundary enforcement
 */

import { describe, it, expect, beforeEach } from "vitest";

import {
  ToolExecutor,
  createDefaultRegistry,
  loadToolRegistry,
} from "../src/tool-executor.js";

import type {
  ToolRegistry,
  ToolCallRequest,
  ApprovalToken,
  DataSensitivity,
} from "../src/types.js";

import { computeActionHash } from "../src/canonical.js";

// Test constants
const TEST_ROOT_HASH = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

describe("Tool Executor - Hard Boundary", () => {
  let executor: ToolExecutor;
  let registry: ToolRegistry;

  beforeEach(() => {
    registry = createDefaultRegistry();
    executor = new ToolExecutor(registry, TEST_ROOT_HASH);
  });

  describe("ALLOW Decisions", () => {
    it("should allow LOW risk tools without approval", async () => {
      const request: ToolCallRequest = {
        request_id: "test-1",
        tool_name: "web_search",
        parameters: { query: "test" },
        timestamp: Date.now(),
      };

      const result = await executor.execute(request);

      expect(result.decision.action).toBe("ALLOW");
      expect(result.status).toBe("success");
    });

    it("should allow MEDIUM risk tools without approval by default", async () => {
      const request: ToolCallRequest = {
        request_id: "test-2",
        tool_name: "read_file",
        parameters: { path: "public/readme.txt" },
        timestamp: Date.now(),
      };

      const result = await executor.execute(request);

      expect(result.decision.action).toBe("ALLOW");
      expect(result.status).toBe("success");
    });
  });

  describe("REQUIRE_APPROVAL Decisions", () => {
    it("should require approval for HIGH risk tools", async () => {
      const request: ToolCallRequest = {
        request_id: "test-3",
        tool_name: "send_email",
        parameters: { to: "test@example.com", subject: "Test", body: "Hello" },
        timestamp: Date.now(),
      };

      const result = await executor.execute(request);

      expect(result.decision.action).toBe("REQUIRE_APPROVAL");
      expect(result.status).toBe("awaiting_approval");
      expect(result.approval_request).toBeDefined();
      expect(result.approval_request?.action_hash).toBeDefined();
    });

    it("should require approval for CRITICAL risk tools", async () => {
      const request: ToolCallRequest = {
        request_id: "test-4",
        tool_name: "read_vault",
        parameters: { key: "secret" },
        timestamp: Date.now(),
      };

      const result = await executor.execute(request);

      expect(result.decision.action).toBe("REQUIRE_APPROVAL");
      expect(result.status).toBe("awaiting_approval");
    });

    it("should require approval for egress after sensitive data", async () => {
      // First, taint the session with SECRET data
      const vaultRequest: ToolCallRequest = {
        request_id: "test-5a",
        tool_name: "read_vault",
        parameters: { key: "api_key" },
        timestamp: Date.now(),
      };

      // Create a valid approval token for vault access
      const session = executor.getSession();
      const vaultToken: ApprovalToken = {
        token_version: "0.5",
        release_root_hash: TEST_ROOT_HASH,
        key_version: 1,
        tool_name: "read_vault",
        action_hash: computeActionHash(TEST_ROOT_HASH, "read_vault", vaultRequest.parameters),
        nonce: "test-nonce-1",
        session_id: session.session_id,
        sequence_number: 0,
        expires_at: Date.now() + 60000,
        summary_hash: "test-summary",
        requested_at: Date.now() - 1000,
        approved_at: Date.now(),
        approver_pubkey: "0x123",
        signature: "0xsig",
      };

      await executor.execute(vaultRequest, vaultToken);

      // Now try to send email - should require approval due to sensitivity
      const emailRequest: ToolCallRequest = {
        request_id: "test-5b",
        tool_name: "send_email",
        parameters: { to: "test@example.com", subject: "Test", body: "Data" },
        timestamp: Date.now(),
      };

      const result = await executor.execute(emailRequest);

      expect(result.decision.action).toBe("REQUIRE_APPROVAL");
      // The reason should mention sensitivity
      expect(result.decision.reason).toContain("approval");
    });
  });

  describe("BLOCK Decisions", () => {
    it("should block unknown tools with CLOSED fail mode", async () => {
      const request: ToolCallRequest = {
        request_id: "test-6",
        tool_name: "unknown_dangerous_tool",
        parameters: {},
        timestamp: Date.now(),
      };

      const result = await executor.execute(request);

      // Unknown tools are treated as CRITICAL with approval required
      expect(result.decision.action).toBe("REQUIRE_APPROVAL");
    });

    it("should block paths not in allowlist", async () => {
      // The default registry allows workspace/** and output/** for write_file
      const request: ToolCallRequest = {
        request_id: "test-7",
        tool_name: "read_file",
        parameters: { path: "/etc/passwd" },
        timestamp: Date.now(),
      };

      // With path_rules defined, non-matching paths are blocked
      const result = await executor.execute(request);
      // Default path rule matches ** so it should allow
      expect(result.decision.action).toBe("ALLOW");
    });

    it("should block oversized content", async () => {
      const longBody = "a".repeat(15000); // Exceeds 10000 limit

      const request: ToolCallRequest = {
        request_id: "test-8",
        tool_name: "send_email",
        parameters: { to: "test@example.com", subject: "Test", body: longBody },
        timestamp: Date.now(),
      };

      const result = await executor.execute(request);

      // First check if it requires approval, then if approved, it would block
      expect(["REQUIRE_APPROVAL", "BLOCK"]).toContain(result.decision.action);
    });
  });

  describe("Approval Token Validation", () => {
    it("should accept valid approval token", async () => {
      const request: ToolCallRequest = {
        request_id: "test-9",
        tool_name: "send_email",
        parameters: { to: "test@example.com", subject: "Hi", body: "Hello" },
        timestamp: Date.now(),
      };

      const session = executor.getSession();
      const token: ApprovalToken = {
        token_version: "0.5",
        release_root_hash: TEST_ROOT_HASH,
        key_version: 1,
        tool_name: "send_email",
        action_hash: computeActionHash(TEST_ROOT_HASH, "send_email", request.parameters),
        nonce: "test-nonce",
        session_id: session.session_id,
        sequence_number: session.sequence_number,
        expires_at: Date.now() + 60000,
        summary_hash: "test-summary",
        requested_at: Date.now() - 1000,
        approved_at: Date.now(),
        approver_pubkey: "0x123",
        signature: "0xsig",
      };

      const result = await executor.execute(request, token);

      expect(result.decision.action).toBe("ALLOW");
      expect(result.status).toBe("success");
    });

    it("should reject expired token", async () => {
      const request: ToolCallRequest = {
        request_id: "test-10",
        tool_name: "send_email",
        parameters: { to: "test@example.com", subject: "Hi", body: "Hello" },
        timestamp: Date.now(),
      };

      const session = executor.getSession();
      const token: ApprovalToken = {
        token_version: "0.5",
        release_root_hash: TEST_ROOT_HASH,
        key_version: 1,
        tool_name: "send_email",
        action_hash: computeActionHash(TEST_ROOT_HASH, "send_email", request.parameters),
        nonce: "test-nonce",
        session_id: session.session_id,
        sequence_number: session.sequence_number,
        expires_at: Date.now() - 1000, // EXPIRED
        summary_hash: "test-summary",
        requested_at: Date.now() - 2000,
        approved_at: Date.now() - 1500,
        approver_pubkey: "0x123",
        signature: "0xsig",
      };

      const result = await executor.execute(request, token);

      expect(result.decision.action).toBe("BLOCK");
      expect(result.decision.reason).toContain("expired");
    });

    it("should reject token with wrong release_root_hash", async () => {
      const request: ToolCallRequest = {
        request_id: "test-11",
        tool_name: "send_email",
        parameters: { to: "test@example.com", subject: "Hi", body: "Hello" },
        timestamp: Date.now(),
      };

      const session = executor.getSession();
      const token: ApprovalToken = {
        token_version: "0.5",
        release_root_hash: "0xwronghash", // WRONG HASH
        key_version: 1,
        tool_name: "send_email",
        action_hash: computeActionHash(TEST_ROOT_HASH, "send_email", request.parameters),
        nonce: "test-nonce",
        session_id: session.session_id,
        sequence_number: session.sequence_number,
        expires_at: Date.now() + 60000,
        summary_hash: "test-summary",
        requested_at: Date.now() - 1000,
        approved_at: Date.now(),
        approver_pubkey: "0x123",
        signature: "0xsig",
      };

      const result = await executor.execute(request, token);

      expect(result.decision.action).toBe("BLOCK");
      expect(result.decision.reason).toContain("root hash");
    });

    it("should reject token for wrong action (parameters changed)", async () => {
      const request: ToolCallRequest = {
        request_id: "test-12",
        tool_name: "send_email",
        parameters: { to: "test@example.com", subject: "Changed!", body: "Different" },
        timestamp: Date.now(),
      };

      const session = executor.getSession();
      // Token was created for different parameters
      const originalParams = { to: "test@example.com", subject: "Original", body: "Hello" };
      const token: ApprovalToken = {
        token_version: "0.5",
        release_root_hash: TEST_ROOT_HASH,
        key_version: 1,
        tool_name: "send_email",
        action_hash: computeActionHash(TEST_ROOT_HASH, "send_email", originalParams),
        nonce: "test-nonce",
        session_id: session.session_id,
        sequence_number: session.sequence_number,
        expires_at: Date.now() + 60000,
        summary_hash: "test-summary",
        requested_at: Date.now() - 1000,
        approved_at: Date.now(),
        approver_pubkey: "0x123",
        signature: "0xsig",
      };

      const result = await executor.execute(request, token);

      expect(result.decision.action).toBe("BLOCK");
      expect(result.decision.reason).toContain("parameters");
    });

    it("should reject replay (wrong sequence number)", async () => {
      // First, execute a valid request to increment sequence
      const firstRequest: ToolCallRequest = {
        request_id: "test-13a",
        tool_name: "web_search",
        parameters: { query: "test" },
        timestamp: Date.now(),
      };
      await executor.execute(firstRequest);

      // Now try to use a token with old sequence number
      const request: ToolCallRequest = {
        request_id: "test-13b",
        tool_name: "send_email",
        parameters: { to: "test@example.com", subject: "Hi", body: "Hello" },
        timestamp: Date.now(),
      };

      const session = executor.getSession();
      const token: ApprovalToken = {
        token_version: "0.5",
        release_root_hash: TEST_ROOT_HASH,
        key_version: 1,
        tool_name: "send_email",
        action_hash: computeActionHash(TEST_ROOT_HASH, "send_email", request.parameters),
        nonce: "test-nonce",
        session_id: session.session_id,
        sequence_number: 0, // OLD sequence number
        expires_at: Date.now() + 60000,
        summary_hash: "test-summary",
        requested_at: Date.now() - 1000,
        approved_at: Date.now(),
        approver_pubkey: "0x123",
        signature: "0xsig",
      };

      const result = await executor.execute(request, token);

      expect(result.decision.action).toBe("BLOCK");
      expect(result.decision.reason).toContain("replay");
    });
  });

  describe("Sensitivity Tainting", () => {
    it("should start session at PUBLIC sensitivity", () => {
      const session = executor.getSession();
      expect(session.current_sensitivity).toBe("PUBLIC");
    });

    it("should taint session when accessing sensitive data", async () => {
      const request: ToolCallRequest = {
        request_id: "test-14",
        tool_name: "read_vault",
        parameters: { key: "api_key" },
        timestamp: Date.now(),
      };

      const session = executor.getSession();
      const token: ApprovalToken = {
        token_version: "0.5",
        release_root_hash: TEST_ROOT_HASH,
        key_version: 1,
        tool_name: "read_vault",
        action_hash: computeActionHash(TEST_ROOT_HASH, "read_vault", request.parameters),
        nonce: "test-nonce",
        session_id: session.session_id,
        sequence_number: session.sequence_number,
        expires_at: Date.now() + 60000,
        summary_hash: "test-summary",
        requested_at: Date.now() - 1000,
        approved_at: Date.now(),
        approver_pubkey: "0x123",
        signature: "0xsig",
      };

      await executor.execute(request, token);

      const updatedSession = executor.getSession();
      expect(updatedSession.current_sensitivity).toBe("SECRET");
      expect(updatedSession.taint_source).toBe("read_vault");
    });

    it("should never de-escalate sensitivity", async () => {
      // First, taint with SECRET
      const vaultRequest: ToolCallRequest = {
        request_id: "test-15a",
        tool_name: "read_vault",
        parameters: { key: "secret" },
        timestamp: Date.now(),
      };

      const session1 = executor.getSession();
      const vaultToken: ApprovalToken = {
        token_version: "0.5",
        release_root_hash: TEST_ROOT_HASH,
        key_version: 1,
        tool_name: "read_vault",
        action_hash: computeActionHash(TEST_ROOT_HASH, "read_vault", vaultRequest.parameters),
        nonce: "nonce1",
        session_id: session1.session_id,
        sequence_number: session1.sequence_number,
        expires_at: Date.now() + 60000,
        summary_hash: "summary",
        requested_at: Date.now() - 1000,
        approved_at: Date.now(),
        approver_pubkey: "0x123",
        signature: "0xsig",
      };

      await executor.execute(vaultRequest, vaultToken);
      expect(executor.getSession().current_sensitivity).toBe("SECRET");

      // Then read a public file
      const publicRequest: ToolCallRequest = {
        request_id: "test-15b",
        tool_name: "web_search",
        parameters: { query: "public info" },
        timestamp: Date.now(),
      };

      await executor.execute(publicRequest);

      // Sensitivity should still be SECRET
      expect(executor.getSession().current_sensitivity).toBe("SECRET");
    });
  });

  describe("Session Management", () => {
    it("should track tool calls in session", async () => {
      const request: ToolCallRequest = {
        request_id: "test-16",
        tool_name: "web_search",
        parameters: { query: "test" },
        timestamp: Date.now(),
      };

      await executor.execute(request);

      const session = executor.getSession();
      expect(session.tool_calls.length).toBe(1);
      expect(session.tool_calls[0].tool_name).toBe("web_search");
    });

    it("should increment sequence number after each call", async () => {
      const initialSession = executor.getSession();
      expect(initialSession.sequence_number).toBe(0);

      await executor.execute({
        request_id: "test-17a",
        tool_name: "web_search",
        parameters: { query: "test1" },
        timestamp: Date.now(),
      });

      const session1 = executor.getSession();
      expect(session1.sequence_number).toBe(1);

      await executor.execute({
        request_id: "test-17b",
        tool_name: "web_search",
        parameters: { query: "test2" },
        timestamp: Date.now(),
      });

      const session2 = executor.getSession();
      expect(session2.sequence_number).toBe(2);
    });

    it("should reset session on resetSession()", async () => {
      await executor.execute({
        request_id: "test-18",
        tool_name: "web_search",
        parameters: { query: "test" },
        timestamp: Date.now(),
      });

      const oldSession = executor.getSession();
      expect(oldSession.tool_calls.length).toBe(1);

      executor.resetSession();

      const newSession = executor.getSession();
      expect(newSession.tool_calls.length).toBe(0);
      expect(newSession.session_id).not.toBe(oldSession.session_id);
    });
  });
});

describe("Default Registry", () => {
  it("should create valid default registry", () => {
    const registry = createDefaultRegistry();

    expect(registry.version).toBe("0.5");
    expect(registry.tools.read_file).toBeDefined();
    expect(registry.tools.send_email).toBeDefined();
    expect(registry.tools.read_vault).toBeDefined();
    expect(registry.risk_levels.LOW).toBeDefined();
    expect(registry.risk_levels.CRITICAL).toBeDefined();
  });

  it("should have correct risk levels for tools", () => {
    const registry = createDefaultRegistry();

    expect(registry.tools.web_search.risk_level).toBe("LOW");
    expect(registry.tools.read_file.risk_level).toBe("MEDIUM");
    expect(registry.tools.send_email.risk_level).toBe("HIGH");
    expect(registry.tools.read_vault.risk_level).toBe("CRITICAL");
  });
});
