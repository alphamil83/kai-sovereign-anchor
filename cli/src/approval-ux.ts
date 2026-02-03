/**
 * Approval UX
 * Ticket 5: Rate limiting, cooldowns, and human-readable summaries
 *
 * Per KAI v0.5 Specification:
 * - Rate limit approvals to prevent fatigue attacks
 * - Cooldown after burst prevents rapid approval sequences
 * - Summaries must be human-readable and accurate
 * - Approval response time metrics for anomaly detection
 */

import type {
  ApprovalConfig,
  SessionState,
  ToolDefinition,
  DataSensitivity,
  RiskLevel,
} from "./types.js";

// ============================================================================
// Types
// ============================================================================

export interface ApprovalMetrics {
  approvalsThisHour: number;
  lastApprovalTime: number | null;
  avgResponseTimeMs: number;
  fastestResponseMs: number;
  slowestResponseMs: number;
  inCooldown: boolean;
  cooldownUntil: number | null;
}

export interface ApprovalDecision {
  allowed: boolean;
  reason: string;
  requiresCooldown: boolean;
  cooldownUntil?: number;
  warningMessage?: string;
}

export interface ApprovalSummary {
  headline: string;
  toolName: string;
  riskLevel: RiskLevel;
  isEgress: boolean;
  sensitivity: DataSensitivity;
  parameterSummary: string;
  warnings: string[];
  hash: string;
}

export interface ApprovalResponseMetrics {
  requestTime: number;
  approvalTime: number;
  responseMs: number;
  isSuspiciouslyFast: boolean;
  isSuspiciouslySlow: boolean;
}

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_APPROVAL_CONFIG: ApprovalConfig = {
  max_approvals_per_hour: 20,
  cooldown_after_burst: 15, // minutes
  burst_threshold: 5, // approvals in 5 minutes triggers cooldown
  require_summary_confirmation: true,
};

// Response time thresholds (milliseconds)
const MIN_REASONABLE_RESPONSE_MS = 500; // Too fast = automated?
const MAX_REASONABLE_RESPONSE_MS = 5 * 60 * 1000; // 5 minutes = user distracted?

// ============================================================================
// Approval Tracker
// ============================================================================

/**
 * Track and manage approval state for a session
 */
export class ApprovalTracker {
  private config: ApprovalConfig;
  private approvalTimes: number[] = [];
  private responseTimes: number[] = [];
  private cooldownUntil: number | null = null;

  constructor(config: Partial<ApprovalConfig> = {}) {
    this.config = { ...DEFAULT_APPROVAL_CONFIG, ...config };
  }

  /**
   * Get current metrics
   */
  getMetrics(): ApprovalMetrics {
    this.cleanupOldApprovals();

    const approvalsThisHour = this.approvalTimes.length;
    const lastApprovalTime = this.approvalTimes.length > 0
      ? this.approvalTimes[this.approvalTimes.length - 1]
      : null;

    let avgResponseTimeMs = 0;
    let fastestResponseMs = 0;
    let slowestResponseMs = 0;

    if (this.responseTimes.length > 0) {
      avgResponseTimeMs = this.responseTimes.reduce((a, b) => a + b, 0) / this.responseTimes.length;
      fastestResponseMs = Math.min(...this.responseTimes);
      slowestResponseMs = Math.max(...this.responseTimes);
    }

    return {
      approvalsThisHour,
      lastApprovalTime,
      avgResponseTimeMs,
      fastestResponseMs,
      slowestResponseMs,
      inCooldown: this.isInCooldown(),
      cooldownUntil: this.cooldownUntil,
    };
  }

  /**
   * Check if more approvals are allowed
   */
  canApprove(): ApprovalDecision {
    this.cleanupOldApprovals();

    // Check cooldown
    if (this.isInCooldown()) {
      return {
        allowed: false,
        reason: `In cooldown until ${new Date(this.cooldownUntil!).toLocaleTimeString()}`,
        requiresCooldown: true,
        cooldownUntil: this.cooldownUntil!,
      };
    }

    // Check hourly limit
    if (this.approvalTimes.length >= this.config.max_approvals_per_hour) {
      const oldestApproval = this.approvalTimes[0];
      const resetTime = oldestApproval + 60 * 60 * 1000;
      return {
        allowed: false,
        reason: `Hourly approval limit (${this.config.max_approvals_per_hour}) reached`,
        requiresCooldown: false,
        warningMessage: `Limit resets at ${new Date(resetTime).toLocaleTimeString()}`,
      };
    }

    // Check burst pattern
    const burstCount = this.countRecentApprovals(5 * 60 * 1000); // 5 minute window
    if (burstCount >= this.config.burst_threshold) {
      // Trigger cooldown
      this.cooldownUntil = Date.now() + this.config.cooldown_after_burst * 60 * 1000;
      return {
        allowed: false,
        reason: `Burst limit (${this.config.burst_threshold} in 5 min) reached`,
        requiresCooldown: true,
        cooldownUntil: this.cooldownUntil,
        warningMessage: "Automatic cooldown triggered to prevent approval fatigue",
      };
    }

    // Warning if getting close to limits
    let warningMessage: string | undefined;
    if (this.approvalTimes.length >= this.config.max_approvals_per_hour * 0.8) {
      warningMessage = `Approaching hourly limit (${this.approvalTimes.length}/${this.config.max_approvals_per_hour})`;
    } else if (burstCount >= this.config.burst_threshold - 1) {
      warningMessage = "Approaching burst limit - consider slowing down";
    }

    return {
      allowed: true,
      reason: "Approval allowed",
      requiresCooldown: false,
      warningMessage,
    };
  }

  /**
   * Record an approval
   */
  recordApproval(requestTime: number, approvalTime: number = Date.now()): ApprovalResponseMetrics {
    const responseMs = approvalTime - requestTime;

    this.approvalTimes.push(approvalTime);
    this.responseTimes.push(responseMs);

    // Keep response times bounded
    if (this.responseTimes.length > 100) {
      this.responseTimes = this.responseTimes.slice(-100);
    }

    return this.analyzeResponseTime(requestTime, approvalTime, responseMs);
  }

  /**
   * Check if currently in cooldown
   */
  isInCooldown(): boolean {
    if (!this.cooldownUntil) return false;
    if (Date.now() >= this.cooldownUntil) {
      this.cooldownUntil = null;
      return false;
    }
    return true;
  }

  /**
   * Manually trigger cooldown
   */
  triggerCooldown(durationMinutes?: number): void {
    const minutes = durationMinutes ?? this.config.cooldown_after_burst;
    this.cooldownUntil = Date.now() + minutes * 60 * 1000;
  }

  /**
   * Clear cooldown (admin override)
   */
  clearCooldown(): void {
    this.cooldownUntil = null;
  }

  /**
   * Cleanup old approvals outside the hour window
   */
  private cleanupOldApprovals(): void {
    const oneHourAgo = Date.now() - 60 * 60 * 1000;
    this.approvalTimes = this.approvalTimes.filter(t => t > oneHourAgo);
  }

  /**
   * Count approvals in recent time window
   */
  private countRecentApprovals(windowMs: number): number {
    const cutoff = Date.now() - windowMs;
    return this.approvalTimes.filter(t => t > cutoff).length;
  }

  /**
   * Analyze response time for anomalies
   */
  private analyzeResponseTime(
    requestTime: number,
    approvalTime: number,
    responseMs: number
  ): ApprovalResponseMetrics {
    return {
      requestTime,
      approvalTime,
      responseMs,
      isSuspiciouslyFast: responseMs < MIN_REASONABLE_RESPONSE_MS,
      isSuspiciouslySlow: responseMs > MAX_REASONABLE_RESPONSE_MS,
    };
  }

  /**
   * Update session state with approval tracking info
   */
  updateSessionState(session: SessionState): void {
    session.approvals_this_hour = this.approvalTimes.length;
    session.last_approval_time = this.approvalTimes.length > 0
      ? this.approvalTimes[this.approvalTimes.length - 1]
      : undefined;
    session.in_cooldown = this.isInCooldown();
    session.cooldown_until = this.cooldownUntil ?? undefined;
  }

  /**
   * Load state from session
   */
  loadFromSession(session: SessionState): void {
    if (session.cooldown_until) {
      this.cooldownUntil = session.cooldown_until;
    }
    // Note: approval times can't be fully restored from session
    // This is acceptable as it's per-session tracking
  }
}

// ============================================================================
// Summary Generation
// ============================================================================

import { sha256 } from "./canonical.js";

/**
 * Generate human-readable approval summary
 */
export function generateApprovalSummary(
  toolName: string,
  toolDef: ToolDefinition | undefined,
  parameters: Record<string, unknown>,
  sessionSensitivity: DataSensitivity
): ApprovalSummary {
  const riskLevel = toolDef?.risk_level ?? "HIGH";
  const isEgress = toolDef?.egress ?? false;

  // Generate headline
  const headline = generateHeadline(toolName, parameters, isEgress);

  // Generate parameter summary
  const parameterSummary = summarizeParameters(toolName, parameters);

  // Collect warnings
  const warnings = collectWarnings(toolDef, parameters, sessionSensitivity);

  // Compute hash for binding
  const summaryText = [headline, parameterSummary, ...warnings].join("\n");
  const hash = sha256(Buffer.from(summaryText));

  return {
    headline,
    toolName,
    riskLevel,
    isEgress,
    sensitivity: sessionSensitivity,
    parameterSummary,
    warnings,
    hash,
  };
}

/**
 * Generate a clear headline for the approval
 */
function generateHeadline(
  toolName: string,
  parameters: Record<string, unknown>,
  isEgress: boolean
): string {
  // Tool-specific headlines
  switch (toolName) {
    case "send_email":
      return `Send email to ${parameters.to || "unknown recipient"}`;

    case "http_post":
      return `POST data to ${parameters.url || "unknown URL"}`;

    case "write_file":
      return `Write to file: ${parameters.path || "unknown path"}`;

    case "delete_file":
      return `DELETE file: ${parameters.path || "unknown path"}`;

    case "execute_command":
      return `Execute shell command`;

    case "read_vault":
      return `Read secret: ${parameters.key || "unknown key"}`;

    default:
      if (isEgress) {
        return `Execute ${toolName} (sends data externally)`;
      }
      return `Execute ${toolName}`;
  }
}

/**
 * Create a readable summary of parameters
 */
function summarizeParameters(
  toolName: string,
  parameters: Record<string, unknown>
): string {
  const entries = Object.entries(parameters);
  if (entries.length === 0) {
    return "No parameters";
  }

  const summaryParts: string[] = [];

  for (const [key, value] of entries) {
    // Mask sensitive parameter values
    const displayValue = shouldMaskValue(key, toolName)
      ? maskParameterValue(value)
      : truncateValue(value);

    summaryParts.push(`  ${key}: ${displayValue}`);
  }

  return summaryParts.join("\n");
}

/**
 * Check if a parameter value should be masked
 */
function shouldMaskValue(key: string, toolName: string): boolean {
  const sensitiveKeys = [
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "auth",
    "credential",
    "private_key",
    "content", // email/message content
    "body",    // request body
  ];

  return sensitiveKeys.some(
    sk => key.toLowerCase().includes(sk)
  );
}

/**
 * Mask a parameter value for display
 */
function maskParameterValue(value: unknown): string {
  if (typeof value === "string") {
    if (value.length <= 4) {
      return "****";
    }
    return value.slice(0, 2) + "****" + value.slice(-2);
  }
  if (typeof value === "object") {
    return "<object>";
  }
  return "<value>";
}

/**
 * Truncate long values for display
 */
function truncateValue(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) return "undefined";

  if (typeof value === "string") {
    if (value.length > 50) {
      return `"${value.slice(0, 47)}..."`;
    }
    return `"${value}"`;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }

  if (Array.isArray(value)) {
    return `[array: ${value.length} items]`;
  }

  if (typeof value === "object") {
    const keys = Object.keys(value);
    return `{object: ${keys.length} keys}`;
  }

  return String(value);
}

/**
 * Collect all warnings for an approval
 */
function collectWarnings(
  toolDef: ToolDefinition | undefined,
  parameters: Record<string, unknown>,
  sessionSensitivity: DataSensitivity
): string[] {
  const warnings: string[] = [];

  // Egress warning
  if (toolDef?.egress) {
    warnings.push("This action sends data outside the system");
  }

  // High/Critical risk warning
  if (toolDef?.risk_level === "HIGH" || toolDef?.risk_level === "CRITICAL") {
    warnings.push(`Risk level: ${toolDef.risk_level}`);
  }

  // Sensitivity warning
  if (sessionSensitivity === "SECRET" || sessionSensitivity === "CONFIDENTIAL") {
    warnings.push(`Session contains ${sessionSensitivity} data`);
  }

  // Tainting warning
  if (toolDef?.taints_session) {
    warnings.push("This action will increase session sensitivity");
  }

  // Size warning
  if (typeof parameters.content === "string" && parameters.content.length > 10000) {
    warnings.push(`Large content: ${(parameters.content.length / 1024).toFixed(1)}KB`);
  }

  // External URL warning
  if (parameters.url && typeof parameters.url === "string") {
    try {
      const url = new URL(parameters.url as string);
      if (!isKnownSafeHost(url.hostname)) {
        warnings.push(`External URL: ${url.hostname}`);
      }
    } catch {
      // Invalid URL
      warnings.push("Invalid or suspicious URL");
    }
  }

  return warnings;
}

/**
 * Check if host is known safe (internal or allowlisted)
 */
function isKnownSafeHost(hostname: string): boolean {
  const safeHosts = [
    "localhost",
    "127.0.0.1",
    "api.github.com",
    "github.com",
  ];
  return safeHosts.some(safe =>
    hostname === safe || hostname.endsWith("." + safe)
  );
}

// ============================================================================
// Display Formatting
// ============================================================================

/**
 * Format approval summary for terminal display
 */
export function formatSummaryForDisplay(summary: ApprovalSummary): string {
  const lines: string[] = [];

  // Header
  lines.push("┌─────────────────────────────────────────────────────┐");
  lines.push("│  🔐 APPROVAL REQUIRED                               │");
  lines.push("├─────────────────────────────────────────────────────┤");

  // Headline
  lines.push(`│  ${summary.headline.padEnd(51)}│`);
  lines.push("├─────────────────────────────────────────────────────┤");

  // Tool info
  lines.push(`│  Tool: ${summary.toolName.padEnd(44)}│`);
  lines.push(`│  Risk: ${summary.riskLevel.padEnd(44)}│`);

  if (summary.isEgress) {
    lines.push("│  ⚠️  EGRESS: Sends data externally                  │");
  }

  // Parameters
  lines.push("├─────────────────────────────────────────────────────┤");
  lines.push("│  Parameters:                                        │");
  for (const line of summary.parameterSummary.split("\n")) {
    lines.push(`│  ${line.padEnd(51)}│`);
  }

  // Warnings
  if (summary.warnings.length > 0) {
    lines.push("├─────────────────────────────────────────────────────┤");
    lines.push("│  ⚠️  Warnings:                                       │");
    for (const warning of summary.warnings) {
      lines.push(`│    • ${warning.padEnd(47)}│`);
    }
  }

  // Footer
  lines.push("├─────────────────────────────────────────────────────┤");
  lines.push("│  Type 'yes' to approve or 'no' to reject            │");
  lines.push("└─────────────────────────────────────────────────────┘");

  return lines.join("\n");
}

/**
 * Format approval summary as JSON for programmatic use
 */
export function formatSummaryAsJson(summary: ApprovalSummary): string {
  return JSON.stringify({
    headline: summary.headline,
    tool: summary.toolName,
    risk_level: summary.riskLevel,
    egress: summary.isEgress,
    sensitivity: summary.sensitivity,
    parameters: summary.parameterSummary,
    warnings: summary.warnings,
    hash: summary.hash,
  }, null, 2);
}

// ============================================================================
// Session Integration
// ============================================================================

/**
 * Create or get approval tracker for session
 */
const sessionTrackers = new Map<string, ApprovalTracker>();

export function getApprovalTracker(
  sessionId: string,
  config?: Partial<ApprovalConfig>
): ApprovalTracker {
  let tracker = sessionTrackers.get(sessionId);
  if (!tracker) {
    tracker = new ApprovalTracker(config);
    sessionTrackers.set(sessionId, tracker);
  }
  return tracker;
}

/**
 * Clean up tracker when session ends
 */
export function clearApprovalTracker(sessionId: string): void {
  sessionTrackers.delete(sessionId);
}

// ============================================================================
// Approval Flow Helpers
// ============================================================================

export interface ApprovalFlowResult {
  approved: boolean;
  summary: ApprovalSummary;
  metrics?: ApprovalResponseMetrics;
  rejection_reason?: string;
}

/**
 * Check if approval can proceed (pre-flight check)
 */
export function preflightApprovalCheck(
  sessionId: string,
  config?: Partial<ApprovalConfig>
): ApprovalDecision {
  const tracker = getApprovalTracker(sessionId, config);
  return tracker.canApprove();
}

/**
 * Record successful approval
 */
export function recordApproval(
  sessionId: string,
  requestTime: number,
  approvalTime?: number
): ApprovalResponseMetrics {
  const tracker = getApprovalTracker(sessionId);
  return tracker.recordApproval(requestTime, approvalTime);
}

/**
 * Format metrics for logging
 */
export function formatMetrics(metrics: ApprovalMetrics): string {
  const lines: string[] = [];

  lines.push(`Approvals this hour: ${metrics.approvalsThisHour}`);
  if (metrics.lastApprovalTime) {
    lines.push(`Last approval: ${new Date(metrics.lastApprovalTime).toLocaleTimeString()}`);
  }
  if (metrics.avgResponseTimeMs > 0) {
    lines.push(`Avg response time: ${(metrics.avgResponseTimeMs / 1000).toFixed(1)}s`);
  }
  if (metrics.inCooldown && metrics.cooldownUntil) {
    lines.push(`In cooldown until: ${new Date(metrics.cooldownUntil).toLocaleTimeString()}`);
  }

  return lines.join("\n");
}
