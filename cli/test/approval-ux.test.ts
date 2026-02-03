/**
 * Approval UX Tests
 * Ticket 5: Rate limiting, cooldowns, and summaries
 */

import { describe, it, expect, beforeEach } from "vitest";

import {
  ApprovalTracker,
  DEFAULT_APPROVAL_CONFIG,
  generateApprovalSummary,
  formatSummaryForDisplay,
  formatSummaryAsJson,
  getApprovalTracker,
  clearApprovalTracker,
  preflightApprovalCheck,
  recordApproval,
  formatMetrics,
} from "../src/approval-ux.js";

import type { ToolDefinition, DataSensitivity } from "../src/types.js";

describe("ApprovalTracker", () => {
  let tracker: ApprovalTracker;

  beforeEach(() => {
    tracker = new ApprovalTracker();
  });

  describe("Basic Operations", () => {
    it("should start with empty metrics", () => {
      const metrics = tracker.getMetrics();

      expect(metrics.approvalsThisHour).toBe(0);
      expect(metrics.lastApprovalTime).toBeNull();
      expect(metrics.inCooldown).toBe(false);
    });

    it("should allow approval initially", () => {
      const decision = tracker.canApprove();

      expect(decision.allowed).toBe(true);
    });

    it("should track approvals", () => {
      const requestTime = Date.now() - 1000;
      tracker.recordApproval(requestTime);

      const metrics = tracker.getMetrics();
      expect(metrics.approvalsThisHour).toBe(1);
      expect(metrics.lastApprovalTime).toBeGreaterThan(0);
    });
  });

  describe("Hourly Rate Limit", () => {
    it("should block after hourly limit exceeded", () => {
      const config = { max_approvals_per_hour: 5 };
      const limitedTracker = new ApprovalTracker(config);

      // Use up all approvals
      for (let i = 0; i < 5; i++) {
        expect(limitedTracker.canApprove().allowed).toBe(true);
        limitedTracker.recordApproval(Date.now() - 1000);
      }

      // Should be blocked now
      const decision = limitedTracker.canApprove();
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain("Hourly approval limit");
    });

    it("should warn when approaching limit", () => {
      const config = { max_approvals_per_hour: 5 };
      const limitedTracker = new ApprovalTracker(config);

      // Use 80% of limit (4 of 5)
      for (let i = 0; i < 4; i++) {
        limitedTracker.recordApproval(Date.now() - 1000);
      }

      const decision = limitedTracker.canApprove();
      expect(decision.allowed).toBe(true);
      expect(decision.warningMessage).toContain("Approaching");
    });
  });

  describe("Burst Protection", () => {
    it("should trigger cooldown after burst", () => {
      const config = {
        burst_threshold: 3,
        cooldown_after_burst: 5, // 5 minutes
      };
      const burstTracker = new ApprovalTracker(config);

      // Rapid approvals within 5 minutes
      for (let i = 0; i < 3; i++) {
        burstTracker.canApprove(); // Check allows recording
        burstTracker.recordApproval(Date.now() - 1000);
      }

      // Next attempt should trigger cooldown
      const decision = burstTracker.canApprove();
      expect(decision.allowed).toBe(false);
      expect(decision.requiresCooldown).toBe(true);
      expect(decision.cooldownUntil).toBeDefined();
    });

    it("should respect cooldown period", () => {
      tracker.triggerCooldown(1); // 1 minute cooldown

      expect(tracker.isInCooldown()).toBe(true);

      const decision = tracker.canApprove();
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain("cooldown");
    });

    it("should allow clearing cooldown manually", () => {
      tracker.triggerCooldown(60);
      expect(tracker.isInCooldown()).toBe(true);

      tracker.clearCooldown();
      expect(tracker.isInCooldown()).toBe(false);
    });
  });

  describe("Response Time Analysis", () => {
    it("should track response times", () => {
      const requestTime = Date.now() - 2000;
      tracker.recordApproval(requestTime);

      const metrics = tracker.getMetrics();
      expect(metrics.avgResponseTimeMs).toBeGreaterThan(0);
    });

    it("should flag suspiciously fast responses", () => {
      const requestTime = Date.now() - 100; // Only 100ms ago
      const result = tracker.recordApproval(requestTime);

      expect(result.isSuspiciouslyFast).toBe(true);
    });

    it("should flag suspiciously slow responses", () => {
      const requestTime = Date.now() - (6 * 60 * 1000); // 6 minutes ago
      const result = tracker.recordApproval(requestTime);

      expect(result.isSuspiciouslySlow).toBe(true);
    });
  });

  describe("Session State", () => {
    it("should update session state", () => {
      const session = {
        session_id: "test-session",
        started_at: Date.now(),
        release_root_hash: "0x1234",
        current_sensitivity: "PUBLIC" as DataSensitivity,
        tool_calls: [],
        approvals_used: [],
        sequence_number: 0,
      };

      tracker.recordApproval(Date.now() - 1000);
      tracker.updateSessionState(session);

      expect(session.approvals_this_hour).toBe(1);
      expect(session.last_approval_time).toBeDefined();
    });
  });
});

describe("Summary Generation", () => {
  describe("generateApprovalSummary", () => {
    it("should generate summary for email tool", () => {
      const toolDef: ToolDefinition = {
        name: "send_email",
        risk_level: "HIGH",
        egress: true,
      };

      const params = {
        to: "test@example.com",
        subject: "Test Subject",
        body: "Test body content",
      };

      const summary = generateApprovalSummary(
        "send_email",
        toolDef,
        params,
        "PUBLIC"
      );

      expect(summary.headline).toContain("test@example.com");
      expect(summary.isEgress).toBe(true);
      expect(summary.riskLevel).toBe("HIGH");
      expect(summary.warnings.length).toBeGreaterThan(0);
    });

    it("should generate summary for file write", () => {
      const toolDef: ToolDefinition = {
        name: "write_file",
        risk_level: "MEDIUM",
      };

      const params = {
        path: "/etc/config.json",
        content: "{ \"key\": \"value\" }",
      };

      const summary = generateApprovalSummary(
        "write_file",
        toolDef,
        params,
        "INTERNAL"
      );

      expect(summary.headline).toContain("/etc/config.json");
      expect(summary.toolName).toBe("write_file");
    });

    it("should mask sensitive parameters", () => {
      const toolDef: ToolDefinition = {
        name: "api_call",
        risk_level: "HIGH",
      };

      const params = {
        url: "https://api.example.com",
        api_key: "secret-api-key-12345",
        password: "supersecret",
      };

      const summary = generateApprovalSummary(
        "api_call",
        toolDef,
        params,
        "PUBLIC"
      );

      // Should not contain full secrets
      expect(summary.parameterSummary).not.toContain("secret-api-key-12345");
      expect(summary.parameterSummary).not.toContain("supersecret");
      // Should contain masked values
      expect(summary.parameterSummary).toContain("****");
    });

    it("should warn about SECRET data", () => {
      const toolDef: ToolDefinition = {
        name: "send_data",
        risk_level: "HIGH",
        egress: true,
      };

      const summary = generateApprovalSummary(
        "send_data",
        toolDef,
        { data: "test" },
        "SECRET"
      );

      expect(summary.warnings.some(w => w.includes("SECRET"))).toBe(true);
    });

    it("should warn about external URLs", () => {
      const toolDef: ToolDefinition = {
        name: "http_post",
        risk_level: "HIGH",
        egress: true,
      };

      const params = {
        url: "https://unknown-external-site.com/api",
        data: "test",
      };

      const summary = generateApprovalSummary(
        "http_post",
        toolDef,
        params,
        "PUBLIC"
      );

      expect(summary.warnings.some(w => w.includes("External URL"))).toBe(true);
    });

    it("should include hash for binding", () => {
      const summary = generateApprovalSummary(
        "test_tool",
        undefined,
        { key: "value" },
        "PUBLIC"
      );

      expect(summary.hash).toMatch(/^0x[a-f0-9]{64}$/);
    });
  });

  describe("formatSummaryForDisplay", () => {
    it("should format summary for terminal", () => {
      const summary = generateApprovalSummary(
        "send_email",
        { name: "send_email", risk_level: "HIGH", egress: true },
        { to: "test@example.com" },
        "PUBLIC"
      );

      const display = formatSummaryForDisplay(summary);

      expect(display).toContain("APPROVAL REQUIRED");
      expect(display).toContain("send_email");
      expect(display).toContain("HIGH");
    });

    it("should show warnings in display", () => {
      const summary = generateApprovalSummary(
        "http_post",
        { name: "http_post", risk_level: "CRITICAL", egress: true },
        { url: "https://malicious.example.com" },
        "SECRET"
      );

      const display = formatSummaryForDisplay(summary);

      expect(display).toContain("Warnings");
      expect(display).toContain("SECRET");
    });
  });

  describe("formatSummaryAsJson", () => {
    it("should produce valid JSON", () => {
      const summary = generateApprovalSummary(
        "test_tool",
        { name: "test_tool", risk_level: "LOW" },
        { param: "value" },
        "PUBLIC"
      );

      const json = formatSummaryAsJson(summary);
      const parsed = JSON.parse(json);

      expect(parsed.tool).toBe("test_tool");
      expect(parsed.risk_level).toBe("LOW");
    });
  });
});

describe("Session Tracker Management", () => {
  beforeEach(() => {
    clearApprovalTracker("test-session");
  });

  it("should create tracker per session", () => {
    const tracker1 = getApprovalTracker("session-1");
    const tracker2 = getApprovalTracker("session-2");

    tracker1.recordApproval(Date.now() - 1000);

    expect(tracker1.getMetrics().approvalsThisHour).toBe(1);
    expect(tracker2.getMetrics().approvalsThisHour).toBe(0);
  });

  it("should return same tracker for same session", () => {
    const tracker1 = getApprovalTracker("same-session");
    tracker1.recordApproval(Date.now() - 1000);

    const tracker2 = getApprovalTracker("same-session");
    expect(tracker2.getMetrics().approvalsThisHour).toBe(1);
  });

  it("should clear tracker on cleanup", () => {
    const tracker = getApprovalTracker("cleanup-session");
    tracker.recordApproval(Date.now() - 1000);

    clearApprovalTracker("cleanup-session");

    const newTracker = getApprovalTracker("cleanup-session");
    expect(newTracker.getMetrics().approvalsThisHour).toBe(0);
  });
});

describe("Approval Flow Helpers", () => {
  beforeEach(() => {
    clearApprovalTracker("flow-test");
  });

  it("should perform preflight check", () => {
    const decision = preflightApprovalCheck("flow-test");
    expect(decision.allowed).toBe(true);
  });

  it("should record approval through helper", () => {
    const requestTime = Date.now() - 2000;
    const metrics = recordApproval("flow-test", requestTime);

    expect(metrics.responseMs).toBeGreaterThanOrEqual(2000);
  });
});

describe("Metrics Formatting", () => {
  it("should format metrics nicely", () => {
    const tracker = new ApprovalTracker();
    tracker.recordApproval(Date.now() - 2000);

    const metrics = tracker.getMetrics();
    const formatted = formatMetrics(metrics);

    expect(formatted).toContain("Approvals this hour: 1");
    expect(formatted).toContain("Last approval:");
  });

  it("should show cooldown in metrics", () => {
    const tracker = new ApprovalTracker();
    tracker.triggerCooldown(5);

    const metrics = tracker.getMetrics();
    const formatted = formatMetrics(metrics);

    expect(formatted).toContain("In cooldown until");
  });
});

describe("Edge Cases", () => {
  it("should handle undefined tool definition", () => {
    const summary = generateApprovalSummary(
      "unknown_tool",
      undefined,
      { key: "value" },
      "PUBLIC"
    );

    expect(summary.riskLevel).toBe("HIGH"); // Default to HIGH for unknown
    expect(summary.headline).toContain("unknown_tool");
  });

  it("should handle empty parameters", () => {
    const summary = generateApprovalSummary(
      "no_params_tool",
      { name: "no_params_tool", risk_level: "LOW" },
      {},
      "PUBLIC"
    );

    expect(summary.parameterSummary).toBe("No parameters");
  });

  it("should truncate long parameter values", () => {
    const longValue = "a".repeat(100);
    const summary = generateApprovalSummary(
      "test_tool",
      undefined,
      { long_param: longValue },
      "PUBLIC"
    );

    expect(summary.parameterSummary).toContain("...");
    expect(summary.parameterSummary.length).toBeLessThan(longValue.length);
  });

  it("should handle array parameters", () => {
    const summary = generateApprovalSummary(
      "test_tool",
      undefined,
      { items: [1, 2, 3, 4, 5] },
      "PUBLIC"
    );

    expect(summary.parameterSummary).toContain("array: 5 items");
  });

  it("should handle object parameters", () => {
    const summary = generateApprovalSummary(
      "test_tool",
      undefined,
      { config: { a: 1, b: 2 } },
      "PUBLIC"
    );

    expect(summary.parameterSummary).toContain("object: 2 keys");
  });

  it("should handle invalid URLs gracefully", () => {
    const summary = generateApprovalSummary(
      "http_post",
      { name: "http_post", risk_level: "HIGH", egress: true },
      { url: "not-a-valid-url" },
      "PUBLIC"
    );

    expect(summary.warnings.some(w => w.includes("Invalid"))).toBe(true);
  });
});
