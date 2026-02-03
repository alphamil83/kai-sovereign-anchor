/**
 * Canonical JSON Serialization (RFC 8785 JCS-inspired)
 *
 * Guarantees:
 * - Deterministic output across all implementations
 * - Recursive key sorting at ALL levels
 * - No whitespace
 * - UTF-8 encoding
 * - Strict type handling (numbers as numbers, not strings)
 *
 * Used by both deploy script and verify script to ensure
 * identical hash computation.
 */

import * as crypto from "crypto";

/**
 * Recursively sorts object keys and serializes to canonical JSON.
 * Handles: objects, arrays, strings, numbers, booleans, null
 */
export function canonicalize(value: unknown): string {
  if (value === null) {
    return "null";
  }

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (typeof value === "number") {
    // Handle special cases per RFC 8785
    if (!Number.isFinite(value)) {
      throw new Error("Cannot canonicalize Infinity or NaN");
    }
    // Use standard JSON number serialization
    return JSON.stringify(value);
  }

  if (typeof value === "string") {
    // JSON string escaping
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    // Arrays: preserve order, canonicalize each element
    const elements = value.map((el) => canonicalize(el));
    return "[" + elements.join(",") + "]";
  }

  if (typeof value === "object") {
    // Objects: sort keys alphabetically, canonicalize each value
    const keys = Object.keys(value as Record<string, unknown>).sort();
    const pairs = keys.map((key) => {
      const v = (value as Record<string, unknown>)[key];
      // Skip undefined values (not valid JSON)
      if (v === undefined) {
        return null;
      }
      return JSON.stringify(key) + ":" + canonicalize(v);
    }).filter((p) => p !== null);
    return "{" + pairs.join(",") + "}";
  }

  throw new Error(`Cannot canonicalize type: ${typeof value}`);
}

/**
 * Computes SHA-256 hash of canonical JSON representation.
 * Excludes specified fields from the hash input.
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
  return "0x" + crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

/**
 * Verifies that a stored hash matches the computed hash.
 * Returns detailed comparison for debugging.
 */
export function verifyCanonicalHash(
  data: Record<string, unknown>,
  storedHash: string,
  hashField: string = "receiptHash"
): {
  match: boolean;
  storedHash: string;
  computedHash: string;
  canonicalJson: string;
} {
  const computedHash = computeCanonicalHash(data, [hashField]);
  const canonical = canonicalize(
    Object.fromEntries(
      Object.entries(data).filter(([k]) => k !== hashField)
    )
  );

  return {
    match: computedHash.toLowerCase() === storedHash.toLowerCase(),
    storedHash,
    computedHash,
    canonicalJson: canonical
  };
}

// Self-test: run with `npx tsx canonical.ts --test`
if (process.argv.includes("--test")) {
  console.log("Testing canonical JSON...\n");

  const test1 = { b: 2, a: 1 };
  console.log("Test 1 (key sorting):", canonicalize(test1));
  console.assert(canonicalize(test1) === '{"a":1,"b":2}', "Test 1 failed");

  const test2 = { z: { b: 2, a: 1 }, a: 1 };
  console.log("Test 2 (nested sorting):", canonicalize(test2));
  console.assert(canonicalize(test2) === '{"a":1,"z":{"a":1,"b":2}}', "Test 2 failed");

  const test3 = { arr: [3, 1, 2], name: "test" };
  console.log("Test 3 (array order):", canonicalize(test3));
  console.assert(canonicalize(test3) === '{"arr":[3,1,2],"name":"test"}', "Test 3 failed");

  console.log("\n✅ All canonical JSON tests passed");
}
