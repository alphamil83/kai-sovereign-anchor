/**
 * Key Management Tests
 * Ticket 6: File-based key storage with seed backup
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs/promises";
import * as path from "path";
import * as os from "os";
import { ethers } from "ethers";

import {
  encryptPrivateKey,
  decryptPrivateKey,
  generateMnemonic,
  deriveKeyFromMnemonic,
  validateMnemonic,
  getAddressFromMnemonic,
  generateKeyPair,
  getAddressFromPrivateKey,
  KeychainManager,
  signMessage,
  signHash,
  verifySignature,
  createWallet,
  generateRandomPassword,
  isPrivateKey,
  isAddress,
} from "../src/key-management.js";

// Test constants
const TEST_PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_PASSWORD = "test-password-123";

// Helper to create temp directory
async function createTempDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "kai-key-test-"));
}

describe("Encryption and Decryption", () => {
  it("should encrypt and decrypt private key", () => {
    const encrypted = encryptPrivateKey(TEST_PRIVATE_KEY, TEST_PASSWORD);
    const decrypted = decryptPrivateKey(encrypted, TEST_PASSWORD);

    expect(decrypted).toBe(TEST_PRIVATE_KEY);
  });

  it("should fail with wrong password", () => {
    const encrypted = encryptPrivateKey(TEST_PRIVATE_KEY, TEST_PASSWORD);

    expect(() => decryptPrivateKey(encrypted, "wrong-password")).toThrow();
  });

  it("should include correct metadata", () => {
    const encrypted = encryptPrivateKey(TEST_PRIVATE_KEY, TEST_PASSWORD);

    expect(encrypted.metadata.algorithm).toBe("aes-256-gcm");
    expect(encrypted.metadata.kdf).toBe("pbkdf2");
    expect(encrypted.metadata.version).toBe(1);
    expect(encrypted.metadata.address).toBeTruthy();
  });

  it("should produce different ciphertext for same key", () => {
    const encrypted1 = encryptPrivateKey(TEST_PRIVATE_KEY, TEST_PASSWORD);
    const encrypted2 = encryptPrivateKey(TEST_PRIVATE_KEY, TEST_PASSWORD);

    // Same key encrypted twice should have different IV/salt
    expect(encrypted1.iv).not.toBe(encrypted2.iv);
    expect(encrypted1.salt).not.toBe(encrypted2.salt);
    expect(encrypted1.encrypted).not.toBe(encrypted2.encrypted);
  });
});

describe("Mnemonic Operations", () => {
  describe("generateMnemonic", () => {
    it("should generate 12-word mnemonic", () => {
      const mnemonic = generateMnemonic();
      const words = mnemonic.split(" ");

      expect(words.length).toBe(12);
    });

    it("should generate unique mnemonics", () => {
      const mnemonic1 = generateMnemonic();
      const mnemonic2 = generateMnemonic();

      expect(mnemonic1).not.toBe(mnemonic2);
    });

    it("should generate valid mnemonic", () => {
      const mnemonic = generateMnemonic();
      expect(validateMnemonic(mnemonic)).toBe(true);
    });
  });

  describe("validateMnemonic", () => {
    it("should validate correct mnemonic", () => {
      const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
      expect(validateMnemonic(mnemonic)).toBe(true);
    });

    it("should reject invalid mnemonic", () => {
      expect(validateMnemonic("invalid mnemonic phrase")).toBe(false);
      expect(validateMnemonic("")).toBe(false);
    });
  });

  describe("deriveKeyFromMnemonic", () => {
    const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    it("should derive consistent key", () => {
      const key1 = deriveKeyFromMnemonic(testMnemonic, 0);
      const key2 = deriveKeyFromMnemonic(testMnemonic, 0);

      expect(key1).toBe(key2);
    });

    it("should derive different keys for different indices", () => {
      const key0 = deriveKeyFromMnemonic(testMnemonic, 0);
      const key1 = deriveKeyFromMnemonic(testMnemonic, 1);

      expect(key0).not.toBe(key1);
    });

    it("should derive valid private key", () => {
      const key = deriveKeyFromMnemonic(testMnemonic, 0);
      expect(isPrivateKey(key)).toBe(true);
    });
  });

  describe("getAddressFromMnemonic", () => {
    const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    it("should get valid address", () => {
      const address = getAddressFromMnemonic(testMnemonic, 0);
      expect(isAddress(address)).toBe(true);
    });

    it("should be consistent with key derivation", () => {
      const key = deriveKeyFromMnemonic(testMnemonic, 0);
      const addressFromKey = getAddressFromPrivateKey(key);
      const addressFromMnemonic = getAddressFromMnemonic(testMnemonic, 0);

      expect(addressFromKey).toBe(addressFromMnemonic);
    });
  });
});

describe("Key Generation", () => {
  describe("generateKeyPair", () => {
    it("should generate complete key pair", () => {
      const { privateKey, address, mnemonic } = generateKeyPair();

      expect(isPrivateKey(privateKey)).toBe(true);
      expect(isAddress(address)).toBe(true);
      expect(validateMnemonic(mnemonic)).toBe(true);
    });

    it("should generate unique key pairs", () => {
      const pair1 = generateKeyPair();
      const pair2 = generateKeyPair();

      expect(pair1.privateKey).not.toBe(pair2.privateKey);
      expect(pair1.address).not.toBe(pair2.address);
    });

    it("should derive address from key", () => {
      const { privateKey, address, mnemonic } = generateKeyPair();
      const derivedAddress = getAddressFromPrivateKey(privateKey);

      expect(derivedAddress).toBe(address);
    });
  });

  describe("getAddressFromPrivateKey", () => {
    it("should get correct address", () => {
      const wallet = new ethers.Wallet(TEST_PRIVATE_KEY);
      const address = getAddressFromPrivateKey(TEST_PRIVATE_KEY);

      expect(address).toBe(wallet.address);
    });
  });
});

describe("KeychainManager", () => {
  let tmpDir: string;
  let manager: KeychainManager;

  beforeEach(async () => {
    tmpDir = await createTempDir();
    manager = new KeychainManager(tmpDir);
    await manager.initialize();
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  describe("Initialization", () => {
    it("should initialize with empty state", () => {
      const state = manager.getState();

      expect(state?.current_version).toBe(0);
      expect(state?.keys).toHaveLength(0);
    });

    it("should create keychain directory", async () => {
      const stat = await fs.stat(tmpDir);
      expect(stat.isDirectory()).toBe(true);
    });
  });

  describe("Key Generation", () => {
    it("should generate and store key", async () => {
      const { address, mnemonic, version } = await manager.generateKey(TEST_PASSWORD);

      expect(isAddress(address)).toBe(true);
      expect(validateMnemonic(mnemonic)).toBe(true);
      expect(version).toBe(1);
    });

    it("should increment version", async () => {
      await manager.generateKey(TEST_PASSWORD);
      const { version } = await manager.generateKey(TEST_PASSWORD);

      expect(version).toBe(2);
    });

    it("should update current address", async () => {
      const { address } = await manager.generateKey(TEST_PASSWORD);

      expect(manager.getCurrentAddress()).toBe(address);
    });
  });

  describe("Key Import", () => {
    it("should import private key", async () => {
      const { address, version } = await manager.importKey(TEST_PRIVATE_KEY, TEST_PASSWORD);

      expect(address).toBeTruthy();
      expect(version).toBe(1);
    });

    it("should import from mnemonic", async () => {
      const mnemonic = generateMnemonic();
      const { address } = await manager.importFromMnemonic(mnemonic, TEST_PASSWORD);

      expect(isAddress(address)).toBe(true);
    });

    it("should reject invalid mnemonic", async () => {
      await expect(
        manager.importFromMnemonic("invalid mnemonic", TEST_PASSWORD)
      ).rejects.toThrow("Invalid mnemonic");
    });
  });

  describe("Key Loading", () => {
    it("should load key by version", async () => {
      await manager.importKey(TEST_PRIVATE_KEY, TEST_PASSWORD);

      const loaded = await manager.loadKey(1, TEST_PASSWORD);

      expect(loaded).toBe(TEST_PRIVATE_KEY);
    });

    it("should load current key", async () => {
      await manager.importKey(TEST_PRIVATE_KEY, TEST_PASSWORD);

      const loaded = await manager.loadCurrentKey(TEST_PASSWORD);

      expect(loaded).toBe(TEST_PRIVATE_KEY);
    });

    it("should fail with wrong password", async () => {
      await manager.importKey(TEST_PRIVATE_KEY, TEST_PASSWORD);

      await expect(
        manager.loadKey(1, "wrong-password")
      ).rejects.toThrow();
    });

    it("should fail for non-existent version", async () => {
      await expect(
        manager.loadKey(99, TEST_PASSWORD)
      ).rejects.toThrow("not found");
    });
  });

  describe("Key Listing", () => {
    it("should list all keys", async () => {
      await manager.generateKey(TEST_PASSWORD);
      await manager.generateKey(TEST_PASSWORD);

      const keys = manager.listKeys();

      expect(keys.length).toBe(2);
      expect(keys[0].version).toBe(1);
      expect(keys[1].version).toBe(2);
    });

    it("should mark current key", async () => {
      await manager.generateKey(TEST_PASSWORD);
      await manager.generateKey(TEST_PASSWORD);

      const keys = manager.listKeys();
      const current = keys.find(k => k.is_current);

      expect(current?.version).toBe(2);
    });
  });

  describe("Password Operations", () => {
    it("should verify correct password", async () => {
      await manager.importKey(TEST_PRIVATE_KEY, TEST_PASSWORD);

      const valid = await manager.verifyPassword(1, TEST_PASSWORD);

      expect(valid).toBe(true);
    });

    it("should reject wrong password", async () => {
      await manager.importKey(TEST_PRIVATE_KEY, TEST_PASSWORD);

      const valid = await manager.verifyPassword(1, "wrong");

      expect(valid).toBe(false);
    });

    it("should change password", async () => {
      await manager.importKey(TEST_PRIVATE_KEY, TEST_PASSWORD);

      const newPassword = "new-password-456";
      await manager.changePassword(1, TEST_PASSWORD, newPassword);

      // Old password should fail
      const oldValid = await manager.verifyPassword(1, TEST_PASSWORD);
      expect(oldValid).toBe(false);

      // New password should work
      const newValid = await manager.verifyPassword(1, newPassword);
      expect(newValid).toBe(true);
    });
  });

  describe("Key Deletion", () => {
    it("should delete key", async () => {
      await manager.generateKey(TEST_PASSWORD);
      await manager.generateKey(TEST_PASSWORD);

      await manager.deleteKey(1, TEST_PASSWORD);

      const keys = manager.listKeys();
      expect(keys.length).toBe(1);
      expect(keys[0].version).toBe(2);
    });

    it("should not delete only key", async () => {
      await manager.generateKey(TEST_PASSWORD);

      await expect(
        manager.deleteKey(1, TEST_PASSWORD)
      ).rejects.toThrow("Cannot delete the only key");
    });

    it("should require correct password", async () => {
      await manager.generateKey(TEST_PASSWORD);
      await manager.generateKey(TEST_PASSWORD);

      await expect(
        manager.deleteKey(1, "wrong-password")
      ).rejects.toThrow("Invalid password");
    });
  });

  describe("Key Info", () => {
    it("should get key metadata", async () => {
      await manager.importKey(TEST_PRIVATE_KEY, TEST_PASSWORD);

      const info = await manager.getKeyInfo(1);

      expect(info?.version).toBe(1);
      expect(info?.address).toBeTruthy();
      expect(info?.algorithm).toBe("aes-256-gcm");
    });

    it("should return null for non-existent key", async () => {
      const info = await manager.getKeyInfo(99);
      expect(info).toBeNull();
    });
  });
});

describe("Signing Utilities", () => {
  describe("signMessage", () => {
    it("should sign message", async () => {
      const message = "Hello, World!";
      const signature = await signMessage(TEST_PRIVATE_KEY, message);

      expect(signature).toMatch(/^0x[a-f0-9]+$/);
    });

    it("should produce verifiable signature", async () => {
      const message = "Test message";
      const signature = await signMessage(TEST_PRIVATE_KEY, message);
      const recoveredAddress = verifySignature(message, signature);

      const wallet = new ethers.Wallet(TEST_PRIVATE_KEY);
      expect(recoveredAddress.toLowerCase()).toBe(wallet.address.toLowerCase());
    });
  });

  describe("signHash", () => {
    it("should sign hash", async () => {
      const hash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
      const signature = await signHash(TEST_PRIVATE_KEY, hash);

      expect(signature).toMatch(/^0x[a-f0-9]+$/);
    });
  });

  describe("createWallet", () => {
    it("should create wallet from private key", () => {
      const wallet = createWallet(TEST_PRIVATE_KEY);

      expect(wallet.address).toBeTruthy();
      expect(wallet.privateKey).toBe(TEST_PRIVATE_KEY);
    });
  });
});

describe("Utility Functions", () => {
  describe("generateRandomPassword", () => {
    it("should generate password of specified length", () => {
      const password = generateRandomPassword(16);
      expect(password.length).toBe(16);
    });

    it("should generate unique passwords", () => {
      const p1 = generateRandomPassword();
      const p2 = generateRandomPassword();

      expect(p1).not.toBe(p2);
    });
  });

  describe("isPrivateKey", () => {
    it("should validate correct private key", () => {
      expect(isPrivateKey(TEST_PRIVATE_KEY)).toBe(true);
      expect(isPrivateKey("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")).toBe(true);
    });

    it("should reject invalid private key", () => {
      expect(isPrivateKey("not-a-key")).toBe(false);
      expect(isPrivateKey("0x1234")).toBe(false);
      expect(isPrivateKey("")).toBe(false);
    });
  });

  describe("isAddress", () => {
    it("should validate correct address", () => {
      const wallet = new ethers.Wallet(TEST_PRIVATE_KEY);
      expect(isAddress(wallet.address)).toBe(true);
    });

    it("should reject invalid address", () => {
      expect(isAddress("not-an-address")).toBe(false);
      expect(isAddress("0x1234")).toBe(false);
      expect(isAddress("")).toBe(false);
    });
  });
});

describe("Persistence", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await createTempDir();
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("should persist and reload state", async () => {
    // Create manager and add keys
    const manager1 = new KeychainManager(tmpDir);
    await manager1.initialize();
    const { address: addr1 } = await manager1.generateKey(TEST_PASSWORD);
    const { address: addr2 } = await manager1.generateKey(TEST_PASSWORD);

    // Create new manager and reload
    const manager2 = new KeychainManager(tmpDir);
    await manager2.initialize();

    const keys = manager2.listKeys();
    expect(keys.length).toBe(2);
    expect(keys[0].address).toBe(addr1);
    expect(keys[1].address).toBe(addr2);
  });

  it("should load keys after restart", async () => {
    const manager1 = new KeychainManager(tmpDir);
    await manager1.initialize();
    await manager1.importKey(TEST_PRIVATE_KEY, TEST_PASSWORD);

    const manager2 = new KeychainManager(tmpDir);
    await manager2.initialize();

    const loaded = await manager2.loadKey(1, TEST_PASSWORD);
    expect(loaded).toBe(TEST_PRIVATE_KEY);
  });
});
