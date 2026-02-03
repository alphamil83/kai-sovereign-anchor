/**
 * Key Management
 * Ticket 6: File-based key storage with seed backup
 *
 * Per KAI v0.5 Specification:
 * - Secure file-based key storage with encryption
 * - BIP39 mnemonic seed backup
 * - Support for multiple key versions
 * - Key rotation capabilities
 */

import * as crypto from "crypto";
import * as fs from "fs/promises";
import * as path from "path";
import { ethers } from "ethers";

// ============================================================================
// Types
// ============================================================================

export interface KeyMetadata {
  version: number;
  address: string;
  created_at: string;
  algorithm: string;
  kdf: string;
  iterations: number;
}

export interface EncryptedKey {
  metadata: KeyMetadata;
  encrypted: string;
  iv: string;
  salt: string;
  tag: string;
}

export interface KeyInfo {
  version: number;
  address: string;
  created_at: string;
  is_current: boolean;
}

export interface KeychainState {
  current_version: number;
  keys: KeyInfo[];
}

// ============================================================================
// Constants
// ============================================================================

const ALGORITHM = "aes-256-gcm";
const KDF = "pbkdf2";
const KDF_ITERATIONS = 100000;
const SALT_LENGTH = 32;
const IV_LENGTH = 16;
const KEY_LENGTH = 32;

// ============================================================================
// Encryption/Decryption
// ============================================================================

/**
 * Derive encryption key from password
 */
function deriveKey(password: string, salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(password, salt, KDF_ITERATIONS, KEY_LENGTH, "sha256");
}

/**
 * Encrypt private key with password
 */
export function encryptPrivateKey(privateKey: string, password: string): EncryptedKey {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = deriveKey(password, salt);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(privateKey, "utf8", "hex");
  encrypted += cipher.final("hex");

  const tag = cipher.getAuthTag();
  const wallet = new ethers.Wallet(privateKey);

  return {
    metadata: {
      version: 1,
      address: wallet.address,
      created_at: new Date().toISOString(),
      algorithm: ALGORITHM,
      kdf: KDF,
      iterations: KDF_ITERATIONS,
    },
    encrypted,
    iv: iv.toString("hex"),
    salt: salt.toString("hex"),
    tag: tag.toString("hex"),
  };
}

/**
 * Decrypt private key with password
 */
export function decryptPrivateKey(encryptedKey: EncryptedKey, password: string): string {
  const salt = Buffer.from(encryptedKey.salt, "hex");
  const iv = Buffer.from(encryptedKey.iv, "hex");
  const tag = Buffer.from(encryptedKey.tag, "hex");
  const key = deriveKey(password, salt);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(encryptedKey.encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}

// ============================================================================
// Mnemonic / Seed
// ============================================================================

/**
 * Generate a new random mnemonic
 */
export function generateMnemonic(): string {
  const wallet = ethers.Wallet.createRandom();
  if (!wallet.mnemonic) {
    throw new Error("Failed to generate mnemonic");
  }
  return wallet.mnemonic.phrase;
}

/**
 * Derive private key from mnemonic
 */
export function deriveKeyFromMnemonic(mnemonic: string, index: number = 0): string {
  // In ethers v6, fromPhrase accepts an optional path parameter
  const path = `m/44'/60'/0'/0/${index}`;
  const hdNode = ethers.HDNodeWallet.fromPhrase(mnemonic, undefined, path);
  return hdNode.privateKey;
}

/**
 * Validate mnemonic phrase
 */
export function validateMnemonic(mnemonic: string): boolean {
  try {
    ethers.Mnemonic.fromPhrase(mnemonic);
    return true;
  } catch {
    return false;
  }
}

/**
 * Get address from mnemonic
 */
export function getAddressFromMnemonic(mnemonic: string, index: number = 0): string {
  const privateKey = deriveKeyFromMnemonic(mnemonic, index);
  const wallet = new ethers.Wallet(privateKey);
  return wallet.address;
}

// ============================================================================
// Key Generation
// ============================================================================

/**
 * Generate a new key pair
 */
export function generateKeyPair(): { privateKey: string; address: string; mnemonic: string } {
  const mnemonic = generateMnemonic();
  const privateKey = deriveKeyFromMnemonic(mnemonic);
  const wallet = new ethers.Wallet(privateKey);

  return {
    privateKey,
    address: wallet.address,
    mnemonic,
  };
}

/**
 * Get address from private key
 */
export function getAddressFromPrivateKey(privateKey: string): string {
  const wallet = new ethers.Wallet(privateKey);
  return wallet.address;
}

// ============================================================================
// Keychain Manager
// ============================================================================

/**
 * Manage multiple versioned keys
 */
export class KeychainManager {
  private basePath: string;
  private state: KeychainState | null = null;

  constructor(basePath: string) {
    this.basePath = basePath;
  }

  /**
   * Initialize keychain directory
   */
  async initialize(): Promise<void> {
    await fs.mkdir(this.basePath, { recursive: true });
    await this.loadState();
  }

  /**
   * Load keychain state
   */
  private async loadState(): Promise<void> {
    const statePath = path.join(this.basePath, "keychain.json");

    try {
      const content = await fs.readFile(statePath, "utf-8");
      this.state = JSON.parse(content);
    } catch {
      // Initialize empty state
      this.state = {
        current_version: 0,
        keys: [],
      };
    }
  }

  /**
   * Save keychain state
   */
  private async saveState(): Promise<void> {
    if (!this.state) return;

    const statePath = path.join(this.basePath, "keychain.json");
    await fs.writeFile(statePath, JSON.stringify(this.state, null, 2));
  }

  /**
   * Get current state
   */
  getState(): KeychainState | null {
    return this.state;
  }

  /**
   * Generate and store a new key
   */
  async generateKey(password: string): Promise<{
    address: string;
    mnemonic: string;
    version: number;
  }> {
    if (!this.state) {
      await this.initialize();
    }

    const { privateKey, address, mnemonic } = generateKeyPair();
    const version = this.state!.current_version + 1;

    // Encrypt and save key
    const encryptedKey = encryptPrivateKey(privateKey, password);
    encryptedKey.metadata.version = version;

    const keyPath = path.join(this.basePath, `key-v${version}.json`);
    await fs.writeFile(keyPath, JSON.stringify(encryptedKey, null, 2));

    // Update state
    this.state!.keys.push({
      version,
      address,
      created_at: encryptedKey.metadata.created_at,
      is_current: true,
    });

    // Mark previous keys as not current
    for (const key of this.state!.keys) {
      if (key.version !== version) {
        key.is_current = false;
      }
    }

    this.state!.current_version = version;
    await this.saveState();

    return { address, mnemonic, version };
  }

  /**
   * Import key from private key
   */
  async importKey(privateKey: string, password: string): Promise<{
    address: string;
    version: number;
  }> {
    if (!this.state) {
      await this.initialize();
    }

    const version = this.state!.current_version + 1;
    const encryptedKey = encryptPrivateKey(privateKey, password);
    encryptedKey.metadata.version = version;

    const keyPath = path.join(this.basePath, `key-v${version}.json`);
    await fs.writeFile(keyPath, JSON.stringify(encryptedKey, null, 2));

    // Update state
    this.state!.keys.push({
      version,
      address: encryptedKey.metadata.address,
      created_at: encryptedKey.metadata.created_at,
      is_current: true,
    });

    // Mark previous keys as not current
    for (const key of this.state!.keys) {
      if (key.version !== version) {
        key.is_current = false;
      }
    }

    this.state!.current_version = version;
    await this.saveState();

    return { address: encryptedKey.metadata.address, version };
  }

  /**
   * Import key from mnemonic
   */
  async importFromMnemonic(
    mnemonic: string,
    password: string,
    index: number = 0
  ): Promise<{ address: string; version: number }> {
    if (!validateMnemonic(mnemonic)) {
      throw new Error("Invalid mnemonic phrase");
    }

    const privateKey = deriveKeyFromMnemonic(mnemonic, index);
    return this.importKey(privateKey, password);
  }

  /**
   * Load key by version
   */
  async loadKey(version: number, password: string): Promise<string> {
    const keyPath = path.join(this.basePath, `key-v${version}.json`);

    try {
      const content = await fs.readFile(keyPath, "utf-8");
      const encryptedKey: EncryptedKey = JSON.parse(content);
      return decryptPrivateKey(encryptedKey, password);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        throw new Error(`Key version ${version} not found`);
      }
      throw error;
    }
  }

  /**
   * Load current key
   */
  async loadCurrentKey(password: string): Promise<string> {
    if (!this.state || this.state.current_version === 0) {
      throw new Error("No keys available");
    }

    return this.loadKey(this.state.current_version, password);
  }

  /**
   * Get key info
   */
  async getKeyInfo(version: number): Promise<KeyMetadata | null> {
    const keyPath = path.join(this.basePath, `key-v${version}.json`);

    try {
      const content = await fs.readFile(keyPath, "utf-8");
      const encryptedKey: EncryptedKey = JSON.parse(content);
      return encryptedKey.metadata;
    } catch {
      return null;
    }
  }

  /**
   * List all keys
   */
  listKeys(): KeyInfo[] {
    return this.state?.keys ?? [];
  }

  /**
   * Get current key address
   */
  getCurrentAddress(): string | null {
    if (!this.state) return null;

    const current = this.state.keys.find(k => k.is_current);
    return current?.address ?? null;
  }

  /**
   * Verify password is correct
   */
  async verifyPassword(version: number, password: string): Promise<boolean> {
    try {
      await this.loadKey(version, password);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Change password for a key
   */
  async changePassword(
    version: number,
    oldPassword: string,
    newPassword: string
  ): Promise<void> {
    const privateKey = await this.loadKey(version, oldPassword);
    const encryptedKey = encryptPrivateKey(privateKey, newPassword);
    encryptedKey.metadata.version = version;

    const keyPath = path.join(this.basePath, `key-v${version}.json`);
    await fs.writeFile(keyPath, JSON.stringify(encryptedKey, null, 2));
  }

  /**
   * Export key as mnemonic (if available)
   * Note: Only works for keys generated with mnemonic
   */
  async exportMnemonic(version: number, password: string): Promise<string | null> {
    // We don't store mnemonics, so this returns null
    // Users should have backed up their mnemonic at generation time
    return null;
  }

  /**
   * Delete a key (dangerous!)
   */
  async deleteKey(version: number, password: string): Promise<void> {
    // Verify password first
    if (!await this.verifyPassword(version, password)) {
      throw new Error("Invalid password");
    }

    // Don't delete current key if it's the only one
    if (this.state?.keys.length === 1) {
      throw new Error("Cannot delete the only key");
    }

    const keyPath = path.join(this.basePath, `key-v${version}.json`);
    await fs.unlink(keyPath);

    // Update state
    if (this.state) {
      this.state.keys = this.state.keys.filter(k => k.version !== version);

      // If deleted key was current, make newest remaining key current
      if (this.state.current_version === version) {
        const newest = this.state.keys.reduce((a, b) =>
          a.version > b.version ? a : b
        );
        newest.is_current = true;
        this.state.current_version = newest.version;
      }

      await this.saveState();
    }
  }
}

// ============================================================================
// Signing Utilities
// ============================================================================

/**
 * Sign a message with a private key
 */
export async function signMessage(privateKey: string, message: string): Promise<string> {
  const wallet = new ethers.Wallet(privateKey);
  return wallet.signMessage(message);
}

/**
 * Sign data hash with a private key
 */
export async function signHash(privateKey: string, hash: string): Promise<string> {
  const wallet = new ethers.Wallet(privateKey);
  return wallet.signMessage(ethers.getBytes(hash));
}

/**
 * Verify a message signature
 */
export function verifySignature(message: string, signature: string): string {
  return ethers.verifyMessage(message, signature);
}

/**
 * Create a wallet from private key
 */
export function createWallet(privateKey: string): ethers.Wallet {
  return new ethers.Wallet(privateKey);
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Generate a random password (for testing)
 */
export function generateRandomPassword(length: number = 32): string {
  return crypto.randomBytes(length).toString("base64").slice(0, length);
}

/**
 * Check if a string looks like a private key
 */
export function isPrivateKey(value: string): boolean {
  // Ethereum private keys are 32 bytes = 64 hex chars
  return /^(0x)?[a-fA-F0-9]{64}$/.test(value);
}

/**
 * Check if a string looks like an Ethereum address
 */
export function isAddress(value: string): boolean {
  return ethers.isAddress(value);
}
