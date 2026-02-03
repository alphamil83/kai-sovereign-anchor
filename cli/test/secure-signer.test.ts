/**
 * Secure Signer Tests
 * Ticket 10: External Signer / Key Isolation
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { ethers } from "ethers";

import {
  SecureSigner,
  createDevSigner,
  isValidKeyRole,
  getAllKeyRoles,
  roleRequiresApproval,
  type KeyRole,
} from "../src/secure-signer.js";

// Test constants
const TEST_PASSWORD = "test-password-123!";
const TEST_PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_ADDRESS = new ethers.Wallet(TEST_PRIVATE_KEY).address;

// Use unique service name per test run to ensure isolation
const TEST_SERVICE_NAME = `kai-test-${Date.now()}-${Math.random().toString(36).slice(2)}`;

/**
 * Helper to clean up all keys from a signer
 */
async function cleanupAllKeys(signer: SecureSigner): Promise<void> {
  const keys = await signer.listKeys();
  for (const key of keys) {
    await signer.deleteKey(key.role, key.address);
  }
}

describe("SecureSigner", () => {
  let signer: SecureSigner;

  beforeEach(async () => {
    // Use unique service name to avoid cross-test pollution
    signer = new SecureSigner(TEST_SERVICE_NAME);
    await signer.initialize();
  });

  afterEach(async () => {
    // Clean up all keys after each test
    if (signer) {
      await cleanupAllKeys(signer);
    }
  });

  describe("Initialization", () => {
    it("should initialize without error", async () => {
      const newSigner = new SecureSigner(TEST_SERVICE_NAME + "-init");
      await newSigner.initialize();
      // Should not throw
    });

    it("should detect backend type correctly", async () => {
      // isUsingOSKeychain returns true if keytar is available on the system,
      // false if falling back to memory backend
      // Either is acceptable - we just verify the method works
      const usesKeychain = signer.isUsingOSKeychain();
      expect(typeof usesKeychain).toBe("boolean");
    });
  });

  describe("Key Generation", () => {
    it("should generate a new key", async () => {
      const { address, mnemonic } = await signer.generateKey("receipt", TEST_PASSWORD);

      expect(address).toMatch(/^0x[a-fA-F0-9]{40}$/);
      expect(mnemonic.split(" ").length).toBe(12);
    });

    it("should generate different keys for different roles", async () => {
      const receipt = await signer.generateKey("receipt", TEST_PASSWORD);
      const release = await signer.generateKey("release", TEST_PASSWORD);

      expect(receipt.address).not.toBe(release.address);
    });
  });

  describe("Key Import", () => {
    it("should import an existing key", async () => {
      const address = await signer.importKey("receipt", TEST_PRIVATE_KEY, TEST_PASSWORD);

      expect(address).toBe(TEST_ADDRESS);
    });

    it("should be able to retrieve imported key address", async () => {
      await signer.importKey("receipt", TEST_PRIVATE_KEY, TEST_PASSWORD);

      const address = await signer.getAddress("receipt");
      expect(address).toBe(TEST_ADDRESS);
    });
  });

  describe("Signing", () => {
    beforeEach(async () => {
      await signer.importKey("receipt", TEST_PRIVATE_KEY, TEST_PASSWORD);
    });

    it("should sign a message", async () => {
      const message = "Test message to sign";
      const result = await signer.sign("receipt", message, TEST_PASSWORD);

      expect(result.signature).toMatch(/^0x[a-fA-F0-9]+$/);
      expect(result.signer).toBe(TEST_ADDRESS);
      expect(result.keyRole).toBe("receipt");
      expect(result.timestamp).toBeLessThanOrEqual(Date.now());
    });

    it("should produce verifiable signatures", async () => {
      const message = "Verify this message";
      const result = await signer.sign("receipt", message, TEST_PASSWORD);

      const recoveredAddress = signer.verifySignature(message, result.signature);
      expect(recoveredAddress).toBe(TEST_ADDRESS);
    });

    it("should fail with wrong password", async () => {
      await expect(
        signer.sign("receipt", "test", "wrong-password")
      ).rejects.toThrow("Invalid password");
    });

    it("should fail for role without key", async () => {
      await expect(
        signer.sign("release", "test", TEST_PASSWORD)
      ).rejects.toThrow("No key configured for role");
    });
  });

  describe("Hash Signing", () => {
    beforeEach(async () => {
      await signer.importKey("receipt", TEST_PRIVATE_KEY, TEST_PASSWORD);
    });

    it("should sign a hash", async () => {
      const hash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
      const result = await signer.signHash("receipt", hash, TEST_PASSWORD);

      expect(result.signature).toMatch(/^0x[a-fA-F0-9]+$/);
      expect(result.signer).toBe(TEST_ADDRESS);
    });
  });

  describe("Key Listing", () => {
    it("should list all keys", async () => {
      await signer.generateKey("receipt", TEST_PASSWORD);
      await signer.generateKey("release", TEST_PASSWORD);

      const keys = await signer.listKeys();

      expect(keys.length).toBe(2);
      expect(keys.some(k => k.role === "receipt")).toBe(true);
      expect(keys.some(k => k.role === "release")).toBe(true);
    });
  });

  describe("Key Deletion", () => {
    it("should delete a key", async () => {
      const { address } = await signer.generateKey("receipt", TEST_PASSWORD);

      const deleted = await signer.deleteKey("receipt", address);
      expect(deleted).toBe(true);

      const keys = await signer.listKeys();
      expect(keys.find(k => k.address === address)).toBeUndefined();
    });
  });
});

describe("Key Role Utilities", () => {
  describe("isValidKeyRole", () => {
    it("should validate valid roles", () => {
      expect(isValidKeyRole("release")).toBe(true);
      expect(isValidKeyRole("receipt")).toBe(true);
      expect(isValidKeyRole("approver")).toBe(true);
    });

    it("should reject invalid roles", () => {
      expect(isValidKeyRole("invalid")).toBe(false);
      expect(isValidKeyRole("")).toBe(false);
      expect(isValidKeyRole("admin")).toBe(false);
    });
  });

  describe("getAllKeyRoles", () => {
    it("should return all roles", () => {
      const roles = getAllKeyRoles();

      expect(roles).toContain("release");
      expect(roles).toContain("receipt");
      expect(roles).toContain("approver");
      expect(roles.length).toBe(3);
    });
  });

  describe("roleRequiresApproval", () => {
    it("should return true for release and approver", () => {
      expect(roleRequiresApproval("release")).toBe(true);
      expect(roleRequiresApproval("approver")).toBe(true);
    });

    it("should return false for receipt", () => {
      expect(roleRequiresApproval("receipt")).toBe(false);
    });
  });
});

describe("Key Role Separation", () => {
  it("should maintain separate keys for each role", async () => {
    const signer = new SecureSigner(TEST_SERVICE_NAME + "-role-sep-1");
    await signer.initialize();

    // Import different keys for each role
    const key1 = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const key2 = "0x2222222222222222222222222222222222222222222222222222222222222222";
    const key3 = "0x3333333333333333333333333333333333333333333333333333333333333333";

    await signer.importKey("release", key1, TEST_PASSWORD);
    await signer.importKey("receipt", key2, TEST_PASSWORD);
    await signer.importKey("approver", key3, TEST_PASSWORD);

    // Each role should have its own address
    const releaseAddr = await signer.getAddress("release");
    const receiptAddr = await signer.getAddress("receipt");
    const approverAddr = await signer.getAddress("approver");

    expect(releaseAddr).not.toBe(receiptAddr);
    expect(receiptAddr).not.toBe(approverAddr);
    expect(releaseAddr).not.toBe(approverAddr);

    // Cleanup
    await cleanupAllKeys(signer);
  });

  it("should sign with correct role key", async () => {
    const signer = new SecureSigner(TEST_SERVICE_NAME + "-role-sep-2");
    await signer.initialize();

    const key1 = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const key2 = "0x2222222222222222222222222222222222222222222222222222222222222222";

    await signer.importKey("release", key1, TEST_PASSWORD);
    await signer.importKey("receipt", key2, TEST_PASSWORD);

    const message = "Test message";

    const releaseSig = await signer.sign("release", message, TEST_PASSWORD);
    const receiptSig = await signer.sign("receipt", message, TEST_PASSWORD);

    // Signatures should come from different keys
    expect(releaseSig.signer).not.toBe(receiptSig.signer);
    expect(releaseSig.signature).not.toBe(receiptSig.signature);

    // Verify each signature
    expect(signer.verifySignature(message, releaseSig.signature)).toBe(releaseSig.signer);
    expect(signer.verifySignature(message, receiptSig.signature)).toBe(receiptSig.signer);

    // Cleanup
    await cleanupAllKeys(signer);
  });
});

describe("Security Properties", () => {
  it("should not expose private key after import", async () => {
    const signer = new SecureSigner(TEST_SERVICE_NAME + "-sec-1");
    await signer.initialize();

    await signer.importKey("receipt", TEST_PRIVATE_KEY, TEST_PASSWORD);

    // The signer object should not have any property containing the raw key
    const signerStr = JSON.stringify(signer);
    expect(signerStr).not.toContain(TEST_PRIVATE_KEY.slice(2)); // Remove 0x prefix

    // Cleanup
    await cleanupAllKeys(signer);
  });

  it("should require password for each sign operation", async () => {
    const signer = new SecureSigner(TEST_SERVICE_NAME + "-sec-2");
    await signer.initialize();

    await signer.importKey("receipt", TEST_PRIVATE_KEY, TEST_PASSWORD);

    // First sign works
    await signer.sign("receipt", "test", TEST_PASSWORD);

    // Second sign still requires password
    await expect(
      signer.sign("receipt", "test", "wrong")
    ).rejects.toThrow();

    // Cleanup
    await cleanupAllKeys(signer);
  });
});
