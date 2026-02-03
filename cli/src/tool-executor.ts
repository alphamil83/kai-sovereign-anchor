/**
 * Tool Executor - Hard Boundary Enforcement
 * Ticket 2: The security core of KAI v0.5
 *
 * This module implements:
 * - Hard boundary between LLM and tool execution
 * - Tool registry validation
 * - Sensitivity tainting and propagation
 * - ALLOW/BLOCK/REQUIRE_APPROVAL decision making
 */

import * as fs from "fs/promises";
import * as path from "path";
import { parse as parseYaml } from "yaml";

import type {
  ToolRegistry,
  ToolDefinition,
  ToolCallRequest,
  ToolCallResult,
  ExecutionDecision,
  DataSensitivity,
  SessionState,
  RiskLevel,
  FailMode,
  ApprovalToken,
} from "./types.js";

import { sha256, computeActionHash } from "./canonical.js";

// ============================================================================
// Constants
// ============================================================================

const SENSITIVITY_ORDER: DataSensitivity[] = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"];

const DEFAULT_FAIL_MODE: FailMode = "CLOSED";

// ============================================================================
// Tool Executor Class
// ============================================================================

export class ToolExecutor {
  private registry: ToolRegistry;
  private session: SessionState;
  private releaseRootHash: string;

  constructor(registry: ToolRegistry, releaseRootHash: string) {
    this.registry = registry;
    this.releaseRootHash = releaseRootHash;
    this.session = this.initSession();
  }

  /**
   * Initialize a new session
   */
  private initSession(): SessionState {
    return {
      session_id: crypto.randomUUID(),
      started_at: Date.now(),
      release_root_hash: this.releaseRootHash,
      current_sensitivity: "PUBLIC",
      taint_source: undefined,
      tool_calls: [],
      approvals_used: [],
      sequence_number: 0,
    };
  }

  /**
   * Get current session state
   */
  getSession(): SessionState {
    return { ...this.session };
  }

  /**
   * Reset session (for testing or new conversations)
   */
  resetSession(): void {
    this.session = this.initSession();
  }

  /**
   * Execute a tool call request
   * This is the HARD BOUNDARY - all tool execution goes through here
   */
  async execute(
    request: ToolCallRequest,
    approvalToken?: ApprovalToken
  ): Promise<ToolCallResult> {
    const startTime = Date.now();

    // Step 1: Get tool definition from registry
    const toolDef = this.getToolDefinition(request.tool_name);

    // Step 2: Make execution decision
    const decision = this.makeDecision(request, toolDef, approvalToken);

    // Step 3: If blocked, return immediately
    if (decision.action === "BLOCK") {
      return {
        request_id: request.request_id,
        tool_name: request.tool_name,
        decision,
        status: "blocked",
        output: null,
        output_sensitivity: "PUBLIC",
        duration_ms: Date.now() - startTime,
        timestamp: Date.now(),
      };
    }

    // Step 4: If approval required but not provided
    if (decision.action === "REQUIRE_APPROVAL" && !approvalToken) {
      return {
        request_id: request.request_id,
        tool_name: request.tool_name,
        decision,
        status: "awaiting_approval",
        output: null,
        output_sensitivity: "PUBLIC",
        duration_ms: Date.now() - startTime,
        timestamp: Date.now(),
        approval_request: {
          action_hash: computeActionHash(
            this.releaseRootHash,
            request.tool_name,
            request.parameters
          ),
          summary: this.generateSummary(request, toolDef),
          expires_at: Date.now() + 5 * 60 * 1000, // 5 minutes
        },
      };
    }

    // Step 5: Execute the tool (this would be provided by the host)
    // For now, we just simulate execution
    const output = await this.simulateExecution(request);

    // Step 6: Determine output sensitivity
    const outputSensitivity = this.computeOutputSensitivity(
      toolDef,
      request,
      output
    );

    // Step 7: Update session state
    this.updateSessionSensitivity(outputSensitivity, request.tool_name);

    // Step 8: Record tool call
    this.session.tool_calls.push({
      tool_name: request.tool_name,
      input_hash: sha256(Buffer.from(JSON.stringify(request.parameters))),
      output_hash: sha256(Buffer.from(JSON.stringify(output))),
      output_sensitivity: outputSensitivity,
      output_size: JSON.stringify(output).length,
      timestamp: Date.now(),
      duration_ms: Date.now() - startTime,
      status: "success",
    });

    this.session.sequence_number++;

    if (approvalToken) {
      this.session.approvals_used.push(
        sha256(Buffer.from(JSON.stringify(approvalToken)))
      );
    }

    return {
      request_id: request.request_id,
      tool_name: request.tool_name,
      decision,
      status: "success",
      output,
      output_sensitivity: outputSensitivity,
      duration_ms: Date.now() - startTime,
      timestamp: Date.now(),
    };
  }

  /**
   * Get tool definition from registry, with fallback to defaults
   */
  private getToolDefinition(toolName: string): ToolDefinition {
    const tool = this.registry.tools[toolName];

    if (!tool) {
      // Unknown tool - use most restrictive defaults
      return {
        name: toolName,
        risk_level: "CRITICAL",
        fail_mode: "CLOSED",
        approval_required: true,
        egress: false,
        output_sensitivity: "INTERNAL",
      };
    }

    // Merge with defaults
    const riskConfig = this.registry.risk_levels[tool.risk_level];

    return {
      name: toolName,
      risk_level: tool.risk_level || "HIGH",
      fail_mode: tool.fail_mode || riskConfig?.fail_mode || DEFAULT_FAIL_MODE,
      approval_required:
        tool.approval_required ?? riskConfig?.approval_required ?? false,
      egress: tool.egress ?? false,
      output_sensitivity: tool.output_sensitivity || "INTERNAL",
      path_rules: tool.path_rules,
      size_limits: tool.size_limits,
      domain_allowlist: tool.domain_allowlist,
      smuggling_checks: tool.smuggling_checks,
      rate_limit: tool.rate_limit,
      taints_session: tool.taints_session,
    };
  }

  /**
   * Make execution decision based on registry and session state
   */
  private makeDecision(
    request: ToolCallRequest,
    toolDef: ToolDefinition,
    approvalToken?: ApprovalToken
  ): ExecutionDecision {
    const reasons: string[] = [];

    // Check 1: Is tool explicitly blocked?
    if (toolDef.fail_mode === "CLOSED" && toolDef.approval_required === false) {
      // This combination means always require approval for CLOSED mode
    }

    // Check 2: Does tool require approval?
    if (toolDef.approval_required) {
      // Validate approval token if provided
      if (approvalToken) {
        const tokenValid = this.validateApprovalToken(
          approvalToken,
          request,
          toolDef
        );
        if (!tokenValid.valid) {
          return {
            action: "BLOCK",
            reason: `Invalid approval token: ${tokenValid.reason}`,
            tool_name: request.tool_name,
            risk_level: toolDef.risk_level,
          };
        }
        // Approval token is valid, continue
      } else {
        return {
          action: "REQUIRE_APPROVAL",
          reason: "Tool requires approval",
          tool_name: request.tool_name,
          risk_level: toolDef.risk_level,
        };
      }
    }

    // Check 3: Is this an egress tool after sensitive data access?
    if (toolDef.egress && this.isSensitivityAbove("INTERNAL")) {
      if (!approvalToken) {
        return {
          action: "REQUIRE_APPROVAL",
          reason: `Egress after ${this.session.current_sensitivity} data requires approval`,
          tool_name: request.tool_name,
          risk_level: toolDef.risk_level,
        };
      }
    }

    // Check 4: Path restrictions
    if (toolDef.path_rules && request.parameters?.path) {
      const pathAllowed = this.checkPathAllowed(
        String(request.parameters.path),
        toolDef
      );
      if (!pathAllowed.allowed) {
        return {
          action: "BLOCK",
          reason: pathAllowed.reason || "Path not allowed",
          tool_name: request.tool_name,
          risk_level: toolDef.risk_level,
        };
      }
    }

    // Check 5: Domain restrictions for egress tools
    if (toolDef.egress && toolDef.domain_allowlist && request.parameters?.url) {
      const url = new URL(String(request.parameters.url));
      if (!toolDef.domain_allowlist.includes(url.hostname)) {
        return {
          action: "REQUIRE_APPROVAL",
          reason: `Domain ${url.hostname} not in allowlist`,
          tool_name: request.tool_name,
          risk_level: "CRITICAL", // Unlisted domain escalates to CRITICAL
        };
      }
    }

    // Check 6: Size limits
    if (toolDef.size_limits) {
      const sizeCheck = this.checkSizeLimits(request.parameters, toolDef.size_limits);
      if (!sizeCheck.allowed) {
        return {
          action: "BLOCK",
          reason: sizeCheck.reason || "Size limit exceeded",
          tool_name: request.tool_name,
          risk_level: toolDef.risk_level,
        };
      }
    }

    // All checks passed - ALLOW
    return {
      action: "ALLOW",
      reason: "All checks passed",
      tool_name: request.tool_name,
      risk_level: toolDef.risk_level,
    };
  }

  /**
   * Validate an approval token
   */
  private validateApprovalToken(
    token: ApprovalToken,
    request: ToolCallRequest,
    toolDef: ToolDefinition
  ): { valid: boolean; reason?: string } {
    // Check 1: Token version
    if (token.token_version !== "0.5") {
      return { valid: false, reason: "Invalid token version" };
    }

    // Check 2: Release root hash must match
    if (token.release_root_hash !== this.releaseRootHash) {
      return { valid: false, reason: "Release root hash mismatch" };
    }

    // Check 3: Tool name must match
    if (token.tool_name !== request.tool_name) {
      return { valid: false, reason: "Tool name mismatch" };
    }

    // Check 4: Action hash must match
    const expectedActionHash = computeActionHash(
      this.releaseRootHash,
      request.tool_name,
      request.parameters
    );
    if (token.action_hash !== expectedActionHash) {
      return { valid: false, reason: "Action hash mismatch (parameters changed)" };
    }

    // Check 5: Session must match
    if (token.session_id !== this.session.session_id) {
      return { valid: false, reason: "Session ID mismatch" };
    }

    // Check 6: Sequence number must be next
    if (token.sequence_number !== this.session.sequence_number) {
      return { valid: false, reason: "Sequence number mismatch (replay detected)" };
    }

    // Check 7: Token not expired
    if (token.expires_at < Date.now()) {
      return { valid: false, reason: "Token expired" };
    }

    // Check 8: Nonce not reused (would need nonce DB for full implementation)
    // TODO: Check nonce against persistent nonce database

    return { valid: true };
  }

  /**
   * Check if a path is allowed by path rules
   */
  private checkPathAllowed(
    filePath: string,
    toolDef: ToolDefinition
  ): { allowed: boolean; reason?: string; sensitivity?: DataSensitivity } {
    if (!toolDef.path_rules) {
      return { allowed: true };
    }

    // Check path against rules
    for (const rule of toolDef.path_rules) {
      const pattern = rule.pattern;
      // Convert glob pattern to regex
      // First escape regex special chars except * and /
      // Then convert ** to match any path (including /)
      // Then convert single * to match anything except /
      let regexStr = pattern
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")  // Escape special chars
        .replace(/\*\*/g, "___GLOBSTAR___")     // Placeholder for **
        .replace(/\*/g, "[^/]*")                // Single * matches non-slash
        .replace(/___GLOBSTAR___/g, ".*");      // ** matches anything

      const regex = new RegExp("^" + regexStr + "$");

      if (regex.test(filePath)) {
        return {
          allowed: true,
          sensitivity: rule.sensitivity,
        };
      }
    }

    // No matching rule - default to blocked for restrictive tools
    return {
      allowed: false,
      reason: `Path ${filePath} not allowed by path rules`,
    };
  }

  /**
   * Check size limits
   */
  private checkSizeLimits(
    params: Record<string, unknown>,
    limits: Record<string, number>
  ): { allowed: boolean; reason?: string } {
    for (const [field, limit] of Object.entries(limits)) {
      const value = params[field];
      if (typeof value === "string" && value.length > limit) {
        return {
          allowed: false,
          reason: `${field} exceeds size limit (${value.length} > ${limit})`,
        };
      }
    }
    return { allowed: true };
  }

  /**
   * Check if current sensitivity is above a threshold
   */
  private isSensitivityAbove(threshold: DataSensitivity): boolean {
    const currentIndex = SENSITIVITY_ORDER.indexOf(this.session.current_sensitivity);
    const thresholdIndex = SENSITIVITY_ORDER.indexOf(threshold);
    return currentIndex > thresholdIndex;
  }

  /**
   * Compute output sensitivity
   */
  private computeOutputSensitivity(
    toolDef: ToolDefinition,
    request: ToolCallRequest,
    output: unknown
  ): DataSensitivity {
    // If tool has INHERIT sensitivity, inherit from path rules
    if (toolDef.output_sensitivity === "INHERIT" && toolDef.path_rules) {
      const pathCheck = this.checkPathAllowed(
        String(request.parameters?.path || ""),
        toolDef
      );
      if (pathCheck.sensitivity) {
        return pathCheck.sensitivity;
      }
    }

    // If tool has CONTEXT sensitivity, use session sensitivity
    if (toolDef.output_sensitivity === "CONTEXT") {
      return this.session.current_sensitivity;
    }

    // If tool taints session, use SECRET
    if (toolDef.taints_session) {
      return "SECRET";
    }

    // Return explicit sensitivity or default
    const sensitivity = toolDef.output_sensitivity;
    if (sensitivity && SENSITIVITY_ORDER.includes(sensitivity as DataSensitivity)) {
      return sensitivity as DataSensitivity;
    }

    return "INTERNAL";
  }

  /**
   * Update session sensitivity (never de-escalates)
   */
  private updateSessionSensitivity(
    newSensitivity: DataSensitivity,
    source: string
  ): void {
    const currentIndex = SENSITIVITY_ORDER.indexOf(this.session.current_sensitivity);
    const newIndex = SENSITIVITY_ORDER.indexOf(newSensitivity);

    if (newIndex > currentIndex) {
      this.session.current_sensitivity = newSensitivity;
      this.session.taint_source = source;
    }
  }

  /**
   * Generate a human-readable summary for approval
   */
  private generateSummary(
    request: ToolCallRequest,
    toolDef: ToolDefinition
  ): string {
    const parts: string[] = [];

    parts.push(`Tool: ${request.tool_name}`);
    parts.push(`Risk: ${toolDef.risk_level}`);

    if (request.parameters) {
      // Summarize key parameters without full content
      const keys = Object.keys(request.parameters);
      if (keys.length > 0) {
        parts.push(`Parameters: ${keys.join(", ")}`);
      }

      // Special handling for common parameters
      if (request.parameters.path) {
        parts.push(`Path: ${request.parameters.path}`);
      }
      if (request.parameters.url) {
        parts.push(`URL: ${request.parameters.url}`);
      }
    }

    if (toolDef.egress) {
      parts.push("⚠️ This tool can send data externally");
    }

    return parts.join("\n");
  }

  /**
   * Simulate tool execution (placeholder for real execution)
   */
  private async simulateExecution(request: ToolCallRequest): Promise<unknown> {
    // In a real implementation, this would dispatch to actual tool handlers
    // For now, return a placeholder result
    return {
      simulated: true,
      tool: request.tool_name,
      timestamp: Date.now(),
    };
  }
}

// ============================================================================
// Registry Loading
// ============================================================================

/**
 * Load tool registry from YAML file
 */
export async function loadToolRegistry(registryPath: string): Promise<ToolRegistry> {
  const content = await fs.readFile(registryPath, "utf8");
  const parsed = parseYaml(content);

  // Validate required fields
  if (!parsed.version) {
    throw new Error("Registry missing version");
  }
  if (!parsed.tools) {
    throw new Error("Registry missing tools");
  }

  return {
    version: parsed.version,
    defaults: parsed.defaults || {},
    risk_levels: parsed.risk_levels || {},
    tools: parsed.tools,
  };
}

/**
 * Create default tool registry (for testing)
 */
export function createDefaultRegistry(): ToolRegistry {
  return {
    version: "0.5",
    defaults: {
      fail_mode: "CLOSED",
      approval_required: false,
      egress: false,
      output_sensitivity: "INTERNAL",
    },
    risk_levels: {
      LOW: { fail_mode: "OPEN", approval_required: false },
      MEDIUM: { fail_mode: "OPEN_WITH_WARNING", approval_required: false },
      HIGH: { fail_mode: "CLOSED", approval_required: true },
      CRITICAL: { fail_mode: "CLOSED", approval_required: true },
    },
    tools: {
      read_file: {
        name: "read_file",
        risk_level: "MEDIUM",
        output_sensitivity: "INHERIT",
        path_rules: [
          { pattern: "**/secrets/**", sensitivity: "SECRET" },
          { pattern: "**/config/**", sensitivity: "INTERNAL" },
          { pattern: "**", sensitivity: "PUBLIC" },
        ],
      },
      write_file: {
        name: "write_file",
        risk_level: "MEDIUM",
        path_restrictions: {
          allow: ["workspace/**", "output/**"],
          deny: ["**/*.exe", "**/*.sh", "**/.*"],
        },
      },
      web_search: {
        name: "web_search",
        risk_level: "LOW",
        output_sensitivity: "PUBLIC",
        rate_limit: "10/minute",
      },
      send_email: {
        name: "send_email",
        risk_level: "HIGH",
        egress: true,
        approval_required: true,
        size_limits: {
          subject: 200,
          body: 10000,
        },
      },
      read_vault: {
        name: "read_vault",
        risk_level: "CRITICAL",
        output_sensitivity: "SECRET",
        taints_session: true,
        approval_required: true,
      },
      http_post: {
        name: "http_post",
        risk_level: "HIGH",
        egress: true,
        approval_required: true,
        size_limits: { body: 5000 },
        domain_allowlist: ["api.internal.com"],
      },
    },
  };
}
