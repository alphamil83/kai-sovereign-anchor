/**
 * KAI v0.5 Type Definitions
 * Per KAI_v0.5_FINAL_BUILD.md specification
 */

// ============================================================================
// Data Sensitivity (U9: Executor-assigned)
// ============================================================================

export type DataSensitivity = "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "SECRET";

// ============================================================================
// Risk Levels
// ============================================================================

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type FailMode = "OPEN" | "OPEN_WITH_WARNING" | "CLOSED";

// ============================================================================
// Execution Decision
// ============================================================================

export type ExecutionAction = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";

export interface ExecutionDecision {
  action: ExecutionAction;
  reason: string;
  tool_name: string;
  risk_level: RiskLevel;
}

// ============================================================================
// Release Manifest (Ticket 1)
// ============================================================================

export interface FileEntry {
  path: string;
  sha256: string;
  size: number;
}

export interface BuilderInfo {
  cli_version: string;
  git_commit?: string;
  built_at: string;
  node_version: string;
}

export interface ReleaseManifest {
  manifest_version: "0.5";
  release_version: string;           // semver
  created_at: string;                // ISO 8601
  builder_info: BuilderInfo;
  files: FileEntry[];
  root_hash: string;                 // H(canonical(manifest without root_hash))
}

export interface SignedRelease extends ReleaseManifest {
  signatures: ReleaseSignature[];
}

export interface ReleaseSignature {
  signer_address: string;
  signature: string;
  signed_at: string;
  key_version: number;
}

// ============================================================================
// Tool Registry (Ticket 2)
// ============================================================================

export interface PathRule {
  pattern: string;
  sensitivity: DataSensitivity;
}

export interface PathRestrictions {
  allow: string[];
  deny: string[];
}

export interface SizeLimits {
  [field: string]: number;
}

export interface SmugglingChecks {
  entropy_threshold?: number;
  secret_patterns?: boolean;
  size_limit?: number;
}

export interface ToolDefinition {
  name: string;
  risk_level: RiskLevel;
  fail_mode?: FailMode;
  approval_required?: boolean;
  egress?: boolean;
  output_sensitivity?: DataSensitivity | "INHERIT" | "CONTEXT";
  taints_session?: boolean;
  path_rules?: PathRule[];
  path_restrictions?: PathRestrictions;
  size_limits?: SizeLimits;
  smuggling_checks?: SmugglingChecks;
  rate_limit?: string;
  domain_allowlist?: string[];
}

export interface RiskLevelConfig {
  fail_mode: FailMode;
  approval_required: boolean;
  multi_party?: boolean;
}

export interface ToolRegistry {
  version: string;
  defaults: {
    fail_mode?: FailMode;
    approval_required?: boolean;
    egress?: boolean;
    output_sensitivity?: DataSensitivity;
  };
  risk_levels: Record<RiskLevel, RiskLevelConfig>;
  tools: Record<string, ToolDefinition>;
  egress_tools?: string[];
}

// ============================================================================
// Tool Call Request/Response (Ticket 2)
// ============================================================================

export interface ToolCallRequest {
  request_id: string;
  tool_name: string;
  parameters: Record<string, unknown>;
  timestamp: number;
}

export interface ApprovalRequest {
  action_hash: string;
  summary: string;
  expires_at: number;
}

export type ToolCallStatus = "success" | "blocked" | "error" | "awaiting_approval";

export interface ToolCallResult {
  request_id: string;
  tool_name: string;
  decision: ExecutionDecision;
  status: ToolCallStatus;
  output: unknown;
  output_sensitivity: DataSensitivity;
  duration_ms: number;
  timestamp: number;
  approval_request?: ApprovalRequest;
  error?: string;
}

// ============================================================================
// Approval Tokens (Ticket 3)
// ============================================================================

export interface ApprovalToken {
  token_version: "0.5";

  // Identity binding
  release_root_hash: string;
  key_version: number;

  // Action binding
  tool_name: string;
  action_hash: string;

  // Replay prevention
  nonce: string;
  session_id: string;
  sequence_number: number;
  expires_at: number;               // Block height

  // Fatigue defense
  summary_hash: string;
  requested_at: number;
  approved_at: number;

  // Signature
  approver_pubkey: string;
  signature: string;
}

// ============================================================================
// Receipts (Ticket 4)
// ============================================================================

export interface ToolCallRecord {
  tool_name: string;
  input_hash: string;
  output_hash: string;
  output_sensitivity: DataSensitivity;
  output_size: number;
  timestamp: number;
  duration_ms: number;
  status: ToolCallStatus;
  block_reason?: string;
  smuggling_flags?: string[];
}

export interface Receipt {
  receipt_version: "0.5";
  receipt_id: string;
  release_root_hash: string;
  session_id: string;

  // Chain
  prev_receipt_hash: string | null;
  sequence_number: number;

  // Content
  tool_calls: ToolCallRecord[];
  approvals_used: string[];
  session_sensitivity: DataSensitivity;
  taint_source?: string;

  // Timing
  started_at: number;
  completed_at: number;

  // Integrity
  receipt_hash: string;
  signature: string;
}

// ============================================================================
// Session State (Ticket 2/5)
// ============================================================================

export interface SessionState {
  session_id: string;
  started_at: number;
  release_root_hash: string;

  // Sensitivity taint (U9: never de-escalates)
  current_sensitivity: DataSensitivity;
  taint_source?: string;

  // Tool call tracking
  tool_calls: ToolCallRecord[];
  approvals_used: string[];
  sequence_number: number;

  // Approval tracking (Ticket 5)
  approvals_this_hour?: number;
  last_approval_time?: number;
  in_cooldown?: boolean;
  cooldown_until?: number;

  // Nonce tracking
  spent_nonces?: Set<string>;

  // Receipt chain
  last_receipt_hash?: string | null;
  receipt_count?: number;
}

// ============================================================================
// Configuration
// ============================================================================

export interface ApprovalConfig {
  max_approvals_per_hour: number;
  cooldown_after_burst: number;      // minutes
  burst_threshold: number;
  require_summary_confirmation: boolean;
}

export interface StorageConfig {
  primary: "github" | "local" | "s3";
  backup: ("github" | "local" | "s3")[];
  github?: {
    owner: string;
    repo: string;
    token?: string;
  };
  s3?: {
    bucket: string;
    region: string;
    prefix?: string;
  };
  local?: {
    path: string;
  };
}

export interface ChainConfig {
  network: "sepolia" | "mainnet" | "localhost";
  rpc_url: string;
  contract_address: string;
  private_key?: string;              // Deprecated: use keychain
}

export interface KaiConfig {
  version: "0.5";
  release_version: string;
  governance_dir: string;
  approval: ApprovalConfig;
  storage: StorageConfig;
  chain: ChainConfig;
}

// ============================================================================
// CLI Commands
// ============================================================================

export interface BuildOptions {
  config?: string;
  output?: string;
  verbose?: boolean;
}

export interface SignOptions {
  manifest: string;
  keychain?: boolean;
  keyFile?: string;
}

export interface VerifyOptions {
  manifest?: string;
  onChain?: boolean;
  rpcUrl?: string;
}

export interface PublishOptions {
  manifest: string;
  targets?: string[];
}

export interface HealthcheckOptions {
  config?: string;
  verbose?: boolean;
}
