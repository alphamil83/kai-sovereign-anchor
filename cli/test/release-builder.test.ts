/**
 * Release Builder Tests
 * Ticket 1: Build, sign, verify, publish governance releases
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "fs/promises";
import * as path from "path";
import { ethers } from "ethers";

import {
  buildRelease,
  signRelease,
  verifyRelease,
  saveManifest,
  loadManifest,
  validateVersion,
  getDefaultManifestPath,
} from "../src/release-builder.js";

import {
  canonicalize,
  sha256,
  computeCanonicalHash,
} from "../src/canonical.js";

// Test fixtures
const TEST_DIR = "/tmp/kai-test-governance";
const TEST_MANIFEST_PATH = "/tmp/kai-test-manifest.json";
const TEST_PRIVATE_KEY =
  "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

describe("Canonical JSON", () => {
  it("should produce deterministic output for objects", () => {
    const obj1 = { b: 2, a: 1 };
    const obj2 = { a: 1, b: 2 };
    expect(canonicalize(obj1)).toBe(canonicalize(obj2));
    expect(canonicalize(obj1)).toBe('{"a":1,"b":2}');
  });

  it("should sort keys alphabetically at all levels", () => {
    const nested = {
      z: { b: 2, a: 1 },
      a: { y: 3, x: 4 },
    };
    expect(canonicalize(nested)).toBe(
      '{"a":{"x":4,"y":3},"z":{"a":1,"b":2}}'
    );
  });

  it("should omit undefined values", () => {
    const obj = { a: 1, b: undefined, c: 3 };
    expect(canonicalize(obj)).toBe('{"a":1,"c":3}');
  });

  it("should handle arrays in order", () => {
    const arr = [3, 1, 2];
    expect(canonicalize(arr)).toBe("[3,1,2]");
  });

  it("should handle null", () => {
    expect(canonicalize(null)).toBe("null");
  });

  it("should handle booleans", () => {
    expect(canonicalize(true)).toBe("true");
    expect(canonicalize(false)).toBe("false");
  });

  it("should escape strings properly", () => {
    expect(canonicalize('hello "world"')).toBe('"hello \\"world\\""');
  });

  it("should throw on Infinity/NaN", () => {
    expect(() => canonicalize(Infinity)).toThrow();
    expect(() => canonicalize(NaN)).toThrow();
  });
});

describe("SHA256 Hashing", () => {
  it("should produce correct hash for string", () => {
    const hash = sha256(Buffer.from("hello"));
    expect(hash).toBe(
      "0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
  });

  it("should produce deterministic hashes", () => {
    const data = Buffer.from("test data");
    expect(sha256(data)).toBe(sha256(data));
  });
});

describe("Release Builder", () => {
  beforeAll(async () => {
    // Create test governance directory
    await fs.mkdir(TEST_DIR, { recursive: true });
    await fs.mkdir(path.join(TEST_DIR, "constitution", "core"), {
      recursive: true,
    });
    await fs.mkdir(path.join(TEST_DIR, "agents"), { recursive: true });

    // Create test files
    await fs.writeFile(
      path.join(TEST_DIR, "constitution", "core", "test.yaml"),
      "version: 1.0\nrules:\n  - test rule"
    );
    await fs.writeFile(
      path.join(TEST_DIR, "agents", "test-agent.yaml"),
      "name: test-agent\nversion: 1.0"
    );
  });

  afterAll(async () => {
    // Cleanup
    await fs.rm(TEST_DIR, { recursive: true, force: true });
    await fs.rm(TEST_MANIFEST_PATH, { force: true });
    await fs.rm(TEST_MANIFEST_PATH.replace(".json", "-signed.json"), {
      force: true,
    });
  });

  describe("buildRelease", () => {
    it("should build a manifest from governance files", async () => {
      const manifest = await buildRelease(TEST_DIR, "1.0.0");

      expect(manifest.manifest_version).toBe("0.5");
      expect(manifest.release_version).toBe("1.0.0");
      expect(manifest.files.length).toBe(2);
      expect(manifest.root_hash).toMatch(/^0x[a-f0-9]{64}$/);
    });

    it("should sort files alphabetically", async () => {
      const manifest = await buildRelease(TEST_DIR, "1.0.0");

      const paths = manifest.files.map((f) => f.path);
      const sorted = [...paths].sort();
      expect(paths).toEqual(sorted);
    });

    it("should include file hashes and sizes", async () => {
      const manifest = await buildRelease(TEST_DIR, "1.0.0");

      for (const file of manifest.files) {
        expect(file.sha256).toMatch(/^0x[a-f0-9]{64}$/);
        expect(file.size).toBeGreaterThan(0);
      }
    });

    it("should throw for empty directory", async () => {
      const emptyDir = "/tmp/kai-empty-test";
      await fs.mkdir(emptyDir, { recursive: true });

      await expect(buildRelease(emptyDir, "1.0.0")).rejects.toThrow(
        /No governance files found/
      );

      await fs.rm(emptyDir, { recursive: true, force: true });
    });
  });

  describe("signRelease", () => {
    it("should sign a manifest", async () => {
      const manifest = await buildRelease(TEST_DIR, "1.0.0");
      const signed = await signRelease(manifest, TEST_PRIVATE_KEY);

      expect(signed.signatures).toHaveLength(1);
      expect(signed.signatures[0].signer_address).toMatch(/^0x[a-fA-F0-9]{40}$/);
      expect(signed.signatures[0].signature).toMatch(/^0x[a-f0-9]+$/);
      expect(signed.signatures[0].key_version).toBe(1);
    });

    it("should produce valid signature", async () => {
      const manifest = await buildRelease(TEST_DIR, "1.0.0");
      const signed = await signRelease(manifest, TEST_PRIVATE_KEY);

      // Verify signature
      const recoveredAddress = ethers.verifyMessage(
        manifest.root_hash,
        signed.signatures[0].signature
      );

      expect(recoveredAddress.toLowerCase()).toBe(
        signed.signatures[0].signer_address.toLowerCase()
      );
    });
  });

  describe("verifyRelease", () => {
    it("should verify a valid manifest", async () => {
      const manifest = await buildRelease(TEST_DIR, "1.0.0");
      await saveManifest(manifest, TEST_MANIFEST_PATH);

      const result = await verifyRelease(TEST_MANIFEST_PATH, TEST_DIR);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it("should verify signatures", async () => {
      const manifest = await buildRelease(TEST_DIR, "1.0.0");
      const signed = await signRelease(manifest, TEST_PRIVATE_KEY);
      const signedPath = TEST_MANIFEST_PATH.replace(".json", "-signed.json");
      await saveManifest(signed, signedPath);

      const result = await verifyRelease(signedPath, TEST_DIR);

      expect(result.valid).toBe(true);
      expect(result.signatureVerification).toHaveLength(1);
      expect(result.signatureVerification![0].valid).toBe(true);
    });

    it("should detect file tampering", async () => {
      const manifest = await buildRelease(TEST_DIR, "1.0.0");
      await saveManifest(manifest, TEST_MANIFEST_PATH);

      // Tamper with a file
      const filePath = path.join(
        TEST_DIR,
        "constitution",
        "core",
        "test.yaml"
      );
      await fs.appendFile(filePath, "\n# tampered");

      const result = await verifyRelease(TEST_MANIFEST_PATH, TEST_DIR);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("hash mismatch"))).toBe(true);

      // Restore file
      await fs.writeFile(filePath, "version: 1.0\nrules:\n  - test rule");
    });
  });

  describe("loadManifest", () => {
    it("should load a saved manifest", async () => {
      const manifest = await buildRelease(TEST_DIR, "1.0.0");
      await saveManifest(manifest, TEST_MANIFEST_PATH);

      const loaded = await loadManifest(TEST_MANIFEST_PATH);

      expect(loaded.release_version).toBe("1.0.0");
      expect(loaded.root_hash).toBe(manifest.root_hash);
    });
  });
});

describe("Utility Functions", () => {
  describe("validateVersion", () => {
    it("should accept valid semver", () => {
      expect(validateVersion("1.0.0")).toBe(true);
      expect(validateVersion("0.1.0")).toBe(true);
      expect(validateVersion("10.20.30")).toBe(true);
      expect(validateVersion("1.0.0-alpha")).toBe(true);
      expect(validateVersion("1.0.0-beta.1")).toBe(true);
    });

    it("should reject invalid semver", () => {
      expect(validateVersion("1.0")).toBe(false);
      expect(validateVersion("v1.0.0")).toBe(false);
      expect(validateVersion("1.0.0.0")).toBe(false);
      expect(validateVersion("latest")).toBe(false);
    });
  });

  describe("getDefaultManifestPath", () => {
    it("should generate path with version and date", () => {
      const path = getDefaultManifestPath("1.0.0");
      expect(path).toMatch(/^releases\/v1\.0\.0-\d{8}\.json$/);
    });
  });
});

describe("Determinism", () => {
  const DETERM_DIR = "/tmp/kai-determinism-test";

  beforeAll(async () => {
    await fs.mkdir(DETERM_DIR, { recursive: true });
    await fs.mkdir(path.join(DETERM_DIR, "constitution", "core"), {
      recursive: true,
    });
    await fs.writeFile(
      path.join(DETERM_DIR, "constitution", "core", "test.yaml"),
      "version: 1.0\nrules:\n  - test rule"
    );
  });

  afterAll(async () => {
    await fs.rm(DETERM_DIR, { recursive: true, force: true });
  });

  it("should produce identical root_hash for same content (timestamps excluded)", async () => {
    // Build twice - may have different timestamps
    const manifest1 = await buildRelease(DETERM_DIR, "1.0.0");

    // Wait a moment to ensure different timestamp
    await new Promise(resolve => setTimeout(resolve, 10));

    const manifest2 = await buildRelease(DETERM_DIR, "1.0.0");

    // Timestamps SHOULD differ (proves the test is valid)
    expect(manifest1.created_at).not.toBe(manifest2.created_at);
    expect(manifest1.builder_info.built_at).not.toBe(manifest2.builder_info.built_at);

    // But root_hash MUST be identical (timestamps are NOT part of the hash)
    expect(manifest1.root_hash).toBe(manifest2.root_hash);

    // Files should also match exactly
    expect(manifest1.files).toEqual(manifest2.files);
  });

  it("should produce identical file hashes for same input", async () => {
    const manifest1 = await buildRelease(DETERM_DIR, "1.0.0");
    const manifest2 = await buildRelease(DETERM_DIR, "1.0.0");

    // Verify each file hash matches
    for (let i = 0; i < manifest1.files.length; i++) {
      expect(manifest1.files[i].sha256).toBe(manifest2.files[i].sha256);
      expect(manifest1.files[i].path).toBe(manifest2.files[i].path);
    }
  });

  it("should produce same hash for equivalent objects", () => {
    const obj1 = { files: [{ a: 1 }], version: "1.0" };
    const obj2 = { version: "1.0", files: [{ a: 1 }] };

    const hash1 = computeCanonicalHash(obj1, []);
    const hash2 = computeCanonicalHash(obj2, []);

    expect(hash1).toBe(hash2);
  });
});
