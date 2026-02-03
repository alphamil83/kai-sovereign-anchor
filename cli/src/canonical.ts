/**
 * Canonical JSON Serialization
 * Per KAI v0.5 Specification
 *
 * Guarantees:
 * - Deterministic output across all implementations
 * - Recursive key sorting at ALL levels
 * - No whitespace between tokens
 * - UTF-8 encoding
 * - Strict type handling
 *
 * This is THE authoritative implementation used by:
 * - Release builder (manifest hashing)
 * - Approval tokens (action_hash)
 * - Receipts (receipt_hash)
 * - Verification (hash comparison)
 */

import * as crypto from "crypto";

/**
 * Recursively sorts object keys and serializes to canonical JSON.
 * Handles: objects, arrays, strings, numbers, booleans, null
 *
 * Rules:
 * - Keys sorted alphabetically (Unicode code point order)
 * - No whitespace
 * - Numbers: no leading zeros, no trailing zeros after decimal
 * - Strings: escape quotes and control characters
 * - Undefined values: omit key entirely
 * - Arrays: preserve order
 */
export function canonicalize(value: unknown): string {
  if (value === null) {
    return "null";
  }

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("Cannot canonicalize Infinity or NaN");
    }
    // JSON.stringify handles -0, exponents correctly
    return JSON.stringify(value);
  }

  if (typeof value === "string") {
    // JSON.stringify handles escaping quotes and control characters
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    // Arrays: preserve order, canonicalize each element
    const elements = value.map((el) => canonicalize(el));
    return "[" + elements.join(",") + "]";
  }

  if (typeof value === "object") {
    // Objects: sort keys alphabetically, canonicalize each value
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const pairs = keys
      .filter((key) => obj[key] !== undefined) // Skip undefined
      .map((key) => JSON.stringify(key) + ":" + canonicalize(obj[key]));
    return "{" + pairs.join(",") + "}";
  }

  throw new Error(`Cannot canonicalize type: ${typeof value}`);
}

/**
 * Computes SHA-256 hash of canonical JSON representation.
 * Returns hex string with 0x prefix.
 */
export function sha256(data: string | Buffer): string {
  const hash = crypto.createHash("sha256");
  hash.update(data);
  return "0x" + hash.digest("hex");
}

/**
 * Computes canonical hash of an object.
 * Optionally excludes specified fields (e.g., exclude the hash field itself).
 */
export function computeCanonicalHash(
  data: Record<string, unknown>,
  excludeFields: string[] = []
): string {
  // Create copy without excluded fields
  const filtered: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data)) {
    if (!excludeFields.includes(key)) {
      filtered[key] = value;
    }
  }

  const canonical = canonicalize(filtered);
  return sha256(canonical);
}

/**
 * Computes the action hash for an approval token.
 * action_hash = H(release_root_hash || tool_name || canonical(params))
 */
export function computeActionHash(
  releaseRootHash: string,
  toolName: string,
  params: Record<string, unknown>
): string {
  const canonicalParams = canonicalize(params);
  const preimage = `${releaseRootHash}||${toolName}||${canonicalParams}`;
  return sha256(preimage);
}

/**
 * Verifies that a stored hash matches the computed hash.
 */
export function verifyCanonicalHash(
  data: Record<string, unknown>,
  storedHash: string,
  hashField: string
): {
  match: boolean;
  storedHash: string;
  computedHash: string;
  canonicalJson: string;
} {
  const computedHash = computeCanonicalHash(data, [hashField]);
  const filtered = Object.fromEntries(
    Object.entries(data).filter(([k]) => k !== hashField)
  );

  return {
    match: computedHash.toLowerCase() === storedHash.toLowerCase(),
    storedHash,
    computedHash,
    canonicalJson: canonicalize(filtered),
  };
}

/**
 * Computes SHA-256 hash of a file's contents.
 */
export async function hashFile(filePath: string): Promise<string> {
  const fs = await import("fs/promises");
  const content = await fs.readFile(filePath);
  return sha256(content);
}

/**
 * Normalizes line endings to \n for consistent hashing.
 */
export function normalizeLineEndings(text: string): string {
  return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
}
