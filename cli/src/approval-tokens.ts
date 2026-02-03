/**
 * Approval Tokens
 * Ticket 3: Nonce-based replay prevention with session binding
 *
 * Per KAI v0.5 Specification:
 * - Nonces are cryptographically random and never reused
 * - Tokens are bound to specific session + sequence
 * - Expiry prevents stale approvals
 * - Summary hash ensures user saw what they approved
 */

import * as crypto from "crypto";
import { ethers } from "ethers";

import type {
  ApprovalToken,
  ToolCallRequest,
  SessionState,
} from "./types.js";

import { sha256, canonicalize, computeActionHash } from "./canonical.js";

// ============================================================================
// Nonce Database
// ============================================================================

/**
 * In-memory nonce database for development/testing
 * Production should use SQLite or similar persistent storage
 */
export class NonceDatabase {
  private spentNonces: Map<string, { timestamp: number; session_id: string }> = new Map();
  private maxAge: number; // milliseconds

  constructor(maxAgeMs: number = 24 * 60 * 60 * 1000) {
    this.maxAge = maxAgeMs;
  }

  /**
   * Check if a nonce has been used
   */
  isSpent(nonce: string): boolean {
    this.cleanup();
    return this.spentNonces.has(nonce);
  }

  /**
   * Mark a nonce as spent
   */
  spend(nonce: string, sessionId: string): void {
    if (this.isSpent(nonce)) {
      throw new Error("Nonce already spent (replay attack detected)");
    }
    this.spentNonces.set(nonce, {
      timestamp: Date.now(),
      session_id: sessionId,
    });
  }

  /**
   * Get info about a spent nonce
   */
  getNonceInfo(nonce: string): { timestamp: number; session_id: string } | undefined {
    return this.spentNonces.get(nonce);
  }

  /**
   * Remove old nonces to prevent memory bloat
   */
  private cleanup(): void {
    const cutoff = Date.now() - this.maxAge;
    for (const [nonce, info] of this.spentNonces.entries()) {
      if (info.timestamp < cutoff) {
        this.spentNonces.delete(nonce);
      }
    }
  }

  /**
   * Get count of stored nonces
   */
  size(): number {
    return this.spentNonces.size;
  }

  /**
   * Clear all nonces (for testing)
   */
  clear(): void {
    this.spentNonces.clear();
  }
}

// Global nonce database instance
let globalNonceDb: NonceDatabase | null = null;

export function getNonceDatabase(): NonceDatabase {
  if (!globalNonceDb) {
    globalNonceDb = new NonceDatabase();
  }
  return globalNonceDb;
}

// ============================================================================
// Token Creation
// ============================================================================

/**
 * Generate a cryptographically secure nonce
 */
export function generateNonce(): string {
  return "0x" + crypto.randomBytes(32).toString("hex");
}

/**
 * Create an approval request (unsigned token data)
 */
export interface ApprovalRequest {
  release_root_hash: string;
  tool_name: string;
  action_hash: string;
  session_id: string;
  sequence_number: number;
  summary: string;
  expires_at: number;
  requested_at: number;
}

export function createApprovalRequest(
  releaseRootHash: string,
  request: ToolCallRequest,
  session: SessionState,
  summary: string,
  expiryMs: number = 5 * 60 * 1000 // 5 minutes default
): ApprovalRequest {
  return {
    release_root_hash: releaseRootHash,
    tool_name: request.tool_name,
    action_hash: computeActionHash(releaseRootHash, request.tool_name, request.parameters),
    session_id: session.session_id,
    sequence_number: session.sequence_number,
    summary,
    expires_at: Date.now() + expiryMs,
    requested_at: Date.now(),
  };
}

/**
 * Create a complete approval token (with signature)
 */
export async function createApprovalToken(
  approvalRequest: ApprovalRequest,
  privateKey: string,
  keyVersion: number = 1
): Promise<ApprovalToken> {
  const nonce = generateNonce();
  const approvedAt = Date.now();
  const summaryHash = sha256(Buffer.from(approvalRequest.summary));

  // Create wallet for signing
  const wallet = new ethers.Wallet(privateKey);

  // Create the token data to sign
  const tokenData = {
    token_version: "0.5",
    release_root_hash: approvalRequest.release_root_hash,
    key_version: keyVersion,
    tool_name: approvalRequest.tool_name,
    action_hash: approvalRequest.action_hash,
    nonce,
    session_id: approvalRequest.session_id,
    sequence_number: approvalRequest.sequence_number,
    expires_at: approvalRequest.expires_at,
    summary_hash: summaryHash,
    requested_at: approvalRequest.requested_at,
    approved_at: approvedAt,
  };

  // Sign the canonical representation
  const canonicalData = canonicalize(tokenData);
  const signature = await wallet.signMessage(canonicalData);

  return {
    token_version: "0.5",
    release_root_hash: approvalRequest.release_root_hash,
    key_version: keyVersion,
    tool_name: approvalRequest.tool_name,
    action_hash: approvalRequest.action_hash,
    nonce,
    session_id: approvalRequest.session_id,
    sequence_number: approvalRequest.sequence_number,
    expires_at: approvalRequest.expires_at,
    summary_hash: summaryHash,
    requested_at: approvalRequest.requested_at,
    approved_at: approvedAt,
    approver_pubkey: wallet.address,
    signature,
  };
}

// ============================================================================
// Token Verification
// ============================================================================

export interface TokenVerificationResult {
  valid: boolean;
  error?: string;
  recoveredAddress?: string;
}

/**
 * Verify an approval token's signature
 */
export function verifyTokenSignature(token: ApprovalToken): TokenVerificationResult {
  try {
    // Reconstruct the data that was signed
    const tokenData = {
      token_version: token.token_version,
      release_root_hash: token.release_root_hash,
      key_version: token.key_version,
      tool_name: token.tool_name,
      action_hash: token.action_hash,
      nonce: token.nonce,
      session_id: token.session_id,
      sequence_number: token.sequence_number,
      expires_at: token.expires_at,
      summary_hash: token.summary_hash,
      requested_at: token.requested_at,
      approved_at: token.approved_at,
    };

    const canonicalData = canonicalize(tokenData);
    const recoveredAddress = ethers.verifyMessage(canonicalData, token.signature);

    if (recoveredAddress.toLowerCase() !== token.approver_pubkey.toLowerCase()) {
      return {
        valid: false,
        error: "Signature does not match approver pubkey",
        recoveredAddress,
      };
    }

    return {
      valid: true,
      recoveredAddress,
    };
  } catch (error) {
    return {
      valid: false,
      error: `Signature verification failed: ${(error as Error).message}`,
    };
  }
}

/**
 * Full token validation including nonce check
 */
export interface FullValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export function validateApprovalToken(
  token: ApprovalToken,
  expectedReleaseHash: string,
  expectedSessionId: string,
  expectedSequence: number,
  expectedToolName: string,
  expectedActionHash: string,
  nonceDb: NonceDatabase = getNonceDatabase()
): FullValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // 1. Version check
  if (token.token_version !== "0.5") {
    errors.push(`Invalid token version: ${token.token_version}`);
  }

  // 2. Release hash binding
  if (token.release_root_hash !== expectedReleaseHash) {
    errors.push("Release root hash mismatch");
  }

  // 3. Session binding
  if (token.session_id !== expectedSessionId) {
    errors.push("Session ID mismatch");
  }

  // 4. Sequence number (replay prevention)
  if (token.sequence_number !== expectedSequence) {
    errors.push(`Sequence number mismatch: expected ${expectedSequence}, got ${token.sequence_number}`);
  }

  // 5. Tool name match
  if (token.tool_name !== expectedToolName) {
    errors.push(`Tool name mismatch: expected ${expectedToolName}, got ${token.tool_name}`);
  }

  // 6. Action hash (parameters haven't changed)
  if (token.action_hash !== expectedActionHash) {
    errors.push("Action hash mismatch (parameters may have changed)");
  }

  // 7. Expiry check
  if (token.expires_at < Date.now()) {
    errors.push("Token has expired");
  }

  // 8. Nonce check (not already spent)
  if (nonceDb.isSpent(token.nonce)) {
    const info = nonceDb.getNonceInfo(token.nonce);
    errors.push(`Nonce already used (replay attack) - originally used at ${info?.timestamp}`);
  }

  // 9. Timing sanity checks
  if (token.approved_at < token.requested_at) {
    warnings.push("Token approved before it was requested (clock skew?)");
  }

  if (token.approved_at > Date.now() + 60000) {
    warnings.push("Token approved in the future (clock skew?)");
  }

  // 10. Signature verification
  const sigResult = verifyTokenSignature(token);
  if (!sigResult.valid) {
    errors.push(sigResult.error || "Invalid signature");
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Mark token nonce as spent after successful use
 */
export function consumeToken(
  token: ApprovalToken,
  nonceDb: NonceDatabase = getNonceDatabase()
): void {
  nonceDb.spend(token.nonce, token.session_id);
}

// ============================================================================
// Serialization
// ============================================================================

/**
 * Serialize token to JSON
 */
export function serializeToken(token: ApprovalToken): string {
  return JSON.stringify(token, null, 2);
}

/**
 * Deserialize token from JSON
 */
export function deserializeToken(json: string): ApprovalToken {
  const parsed = JSON.parse(json);

  // Basic validation
  if (!parsed.token_version || parsed.token_version !== "0.5") {
    throw new Error("Invalid token format");
  }

  return parsed as ApprovalToken;
}

// ============================================================================
// Summary Generation
// ============================================================================

/**
 * Generate a human-readable summary for an approval request
 * This summary is shown to the user before they approve
 */
export function generateSummary(
  toolName: string,
  parameters: Record<string, unknown>,
  riskLevel: string,
  isEgress: boolean
): string {
  const lines: string[] = [];

  lines.push(`🔧 Tool: ${toolName}`);
  lines.push(`⚠️ Risk Level: ${riskLevel}`);

  // Summarize parameters without showing full content
  const paramKeys = Object.keys(parameters);
  if (paramKeys.length > 0) {
    lines.push(`📋 Parameters: ${paramKeys.join(", ")}`);
  }

  // Show specific parameter hints
  if (parameters.path) {
    lines.push(`📂 Path: ${parameters.path}`);
  }
  if (parameters.url) {
    lines.push(`🌐 URL: ${parameters.url}`);
  }
  if (parameters.to) {
    lines.push(`📧 Recipient: ${parameters.to}`);
  }

  // Egress warning
  if (isEgress) {
    lines.push("");
    lines.push("⚠️ WARNING: This action can send data externally");
  }

  return lines.join("\n");
}

/**
 * Verify summary hash matches
 */
export function verifySummaryHash(token: ApprovalToken, expectedSummary: string): boolean {
  const expectedHash = sha256(Buffer.from(expectedSummary));
  return token.summary_hash === expectedHash;
}
