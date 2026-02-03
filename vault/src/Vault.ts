/**
 * KAI Encrypted Vault
 * Local-first encrypted storage for sensitive data
 *
 * Features:
 * - AES-256-GCM encryption at rest
 * - Export/import for portability
 * - No secrets stored unencrypted
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

// ═══════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════

export interface VaultConfig {
  vaultPath: string;
  keyDerivationIterations: number;
}

export interface Guardian {
  fingerprint: string;
  rank: "G1" | "G2" | "G3";
  status: "ACTIVE" | "DEPRECATED" | "REVOKED";
  effectiveDate: string;
  revokedDate?: string;
  reasonCategory?: string;
}

export interface SecondChannel {
  type: "EMAIL" | "PHONE" | "DISCORD" | "SLACK" | "LOCAL_DEVICE" | "HARDWARE_KEY";
  identifier: string;
  confirmationRule: string;
}

export interface SuccessionSettings {
  inactivityThreshold: number; // days
  coolingPeriod: number; // days
  safeModeExitCondition: string;
}

export interface VerificationMode {
  passphraseEnabled: boolean;
  passphraseRotationDays: number;
  lastRotation?: string;
  secondChannelEnabled: boolean;
  guardianCosignRequired: string[]; // list of action types
}

export interface Receipt {
  id: string;
  type: "REGISTRATION" | "ROTATION" | "REVOCATION" | "ACTIVITY" | "SUCCESSION" | "SAFE_MODE";
  timestamp: string;
  data: Record<string, unknown>;
  hash: string;
}

export interface LivingAppendix {
  version: string;
  lastUpdated: string;
  guardians: Guardian[];
  secondChannels: SecondChannel[];
  verification: VerificationMode;
  succession: SuccessionSettings;
  receipts: Receipt[];
  customData: Record<string, unknown>;
}

export interface EncryptedPayload {
  iv: string;
  authTag: string;
  ciphertext: string;
  salt: string;
  version: number;
}

export interface ExportPackage {
  version: number;
  exportedAt: string;
  coreHash: string;
  encryptedAppendix: EncryptedPayload;
  receiptsHash: string;
}

// ═══════════════════════════════════════════════════════════════
// VAULT CLASS
// ═══════════════════════════════════════════════════════════════

export class Vault {
  private config: VaultConfig;
  private derivedKey: Buffer | null = null;
  private appendix: LivingAppendix | null = null;

  private static readonly ALGORITHM = "aes-256-gcm";
  private static readonly KEY_LENGTH = 32;
  private static readonly IV_LENGTH = 16;
  private static readonly SALT_LENGTH = 32;
  private static readonly AUTH_TAG_LENGTH = 16;
  private static readonly VERSION = 1;

  constructor(config: VaultConfig) {
    this.config = config;
  }

  // ═══════════════════════════════════════════════════════════════
  // INITIALIZATION
  // ═══════════════════════════════════════════════════════════════

  /**
   * Initialize vault with password
   * Creates new vault if doesn't exist, loads existing if it does
   */
  public async initialize(password: string): Promise<boolean> {
    const vaultFile = path.join(this.config.vaultPath, "vault.enc");

    if (fs.existsSync(vaultFile)) {
      return this.unlock(password);
    } else {
      return this.create(password);
    }
  }

  /**
   * Create new vault
   */
  private async create(password: string): Promise<boolean> {
    // Ensure directory exists
    if (!fs.existsSync(this.config.vaultPath)) {
      fs.mkdirSync(this.config.vaultPath, { recursive: true });
    }

    // Generate salt and derive key
    const salt = crypto.randomBytes(Vault.SALT_LENGTH);
    this.derivedKey = this.deriveKey(password, salt);

    // Create empty appendix
    this.appendix = this.createEmptyAppendix();

    // Encrypt and save
    const encrypted = this.encrypt(JSON.stringify(this.appendix), salt);
    fs.writeFileSync(
      path.join(this.config.vaultPath, "vault.enc"),
      JSON.stringify(encrypted, null, 2)
    );

    return true;
  }

  /**
   * Unlock existing vault
   */
  public async unlock(password: string): Promise<boolean> {
    const vaultFile = path.join(this.config.vaultPath, "vault.enc");

    if (!fs.existsSync(vaultFile)) {
      throw new Error("Vault file not found");
    }

    const encrypted: EncryptedPayload = JSON.parse(fs.readFileSync(vaultFile, "utf8"));
    const salt = Buffer.from(encrypted.salt, "hex");

    this.derivedKey = this.deriveKey(password, salt);

    try {
      const decrypted = this.decrypt(encrypted);
      this.appendix = JSON.parse(decrypted);
      return true;
    } catch (error) {
      this.derivedKey = null;
      throw new Error("Invalid password or corrupted vault");
    }
  }

  /**
   * Lock vault (clear derived key from memory)
   */
  public lock(): void {
    if (this.derivedKey) {
      this.derivedKey.fill(0); // Zero out key
    }
    this.derivedKey = null;
    this.appendix = null;
  }

  /**
   * Check if vault is unlocked
   */
  public isUnlocked(): boolean {
    return this.derivedKey !== null && this.appendix !== null;
  }

  // ═══════════════════════════════════════════════════════════════
  // GUARDIAN MANAGEMENT
  // ═══════════════════════════════════════════════════════════════

  /**
   * Register a guardian
   */
  public registerGuardian(guardian: Guardian): Receipt {
    this.ensureUnlocked();

    // Check for duplicate fingerprint
    const existing = this.appendix!.guardians.find(g => g.fingerprint === guardian.fingerprint);
    if (existing) {
      throw new Error("Guardian with this fingerprint already exists");
    }

    this.appendix!.guardians.push(guardian);

    const receipt = this.createReceipt("REGISTRATION", {
      guardian: guardian.fingerprint,
      rank: guardian.rank,
      effectiveDate: guardian.effectiveDate,
    });

    this.appendix!.receipts.push(receipt);
    this.save();

    return receipt;
  }

  /**
   * Rotate guardian key
   */
  public rotateGuardianKey(oldFingerprint: string, newFingerprint: string): Receipt {
    this.ensureUnlocked();

    const guardian = this.appendix!.guardians.find(g => g.fingerprint === oldFingerprint);
    if (!guardian) {
      throw new Error("Guardian not found");
    }

    if (guardian.status !== "ACTIVE") {
      throw new Error("Can only rotate active guardian keys");
    }

    // Deprecate old
    guardian.status = "DEPRECATED";

    // Create new with same rank
    const newGuardian: Guardian = {
      fingerprint: newFingerprint,
      rank: guardian.rank,
      status: "ACTIVE",
      effectiveDate: new Date().toISOString(),
    };

    this.appendix!.guardians.push(newGuardian);

    const receipt = this.createReceipt("ROTATION", {
      oldFingerprint,
      newFingerprint,
      rank: guardian.rank,
    });

    this.appendix!.receipts.push(receipt);
    this.save();

    return receipt;
  }

  /**
   * Revoke guardian immediately
   */
  public revokeGuardian(fingerprint: string, reason: string): Receipt {
    this.ensureUnlocked();

    const guardian = this.appendix!.guardians.find(g => g.fingerprint === fingerprint);
    if (!guardian) {
      throw new Error("Guardian not found");
    }

    guardian.status = "REVOKED";
    guardian.revokedDate = new Date().toISOString();
    guardian.reasonCategory = reason;

    const receipt = this.createReceipt("REVOCATION", {
      fingerprint,
      reason,
      revokedAt: guardian.revokedDate,
    });

    this.appendix!.receipts.push(receipt);
    this.save();

    return receipt;
  }

  /**
   * Get all guardians
   */
  public getGuardians(): Guardian[] {
    this.ensureUnlocked();
    return [...this.appendix!.guardians];
  }

  /**
   * Get active guardian by rank
   */
  public getActiveGuardian(rank: "G1" | "G2" | "G3"): Guardian | undefined {
    this.ensureUnlocked();
    return this.appendix!.guardians.find(g => g.rank === rank && g.status === "ACTIVE");
  }

  // ═══════════════════════════════════════════════════════════════
  // SECOND CHANNEL MANAGEMENT
  // ═══════════════════════════════════════════════════════════════

  /**
   * Add second channel
   */
  public addSecondChannel(channel: SecondChannel): void {
    this.ensureUnlocked();
    this.appendix!.secondChannels.push(channel);
    this.save();
  }

  /**
   * Remove second channel
   */
  public removeSecondChannel(type: string, identifier: string): boolean {
    this.ensureUnlocked();
    const index = this.appendix!.secondChannels.findIndex(
      c => c.type === type && c.identifier === identifier
    );
    if (index === -1) return false;
    this.appendix!.secondChannels.splice(index, 1);
    this.save();
    return true;
  }

  /**
   * Get second channels
   */
  public getSecondChannels(): SecondChannel[] {
    this.ensureUnlocked();
    return [...this.appendix!.secondChannels];
  }

  // ═══════════════════════════════════════════════════════════════
  // SUCCESSION SETTINGS
  // ═══════════════════════════════════════════════════════════════

  /**
   * Update succession settings
   */
  public updateSuccessionSettings(settings: Partial<SuccessionSettings>): void {
    this.ensureUnlocked();
    this.appendix!.succession = { ...this.appendix!.succession, ...settings };
    this.save();
  }

  /**
   * Get succession settings
   */
  public getSuccessionSettings(): SuccessionSettings {
    this.ensureUnlocked();
    return { ...this.appendix!.succession };
  }

  // ═══════════════════════════════════════════════════════════════
  // VERIFICATION MODE
  // ═══════════════════════════════════════════════════════════════

  /**
   * Update verification mode
   */
  public updateVerificationMode(mode: Partial<VerificationMode>): void {
    this.ensureUnlocked();
    this.appendix!.verification = { ...this.appendix!.verification, ...mode };
    this.save();
  }

  /**
   * Get verification mode
   */
  public getVerificationMode(): VerificationMode {
    this.ensureUnlocked();
    return { ...this.appendix!.verification };
  }

  // ═══════════════════════════════════════════════════════════════
  // RECEIPTS
  // ═══════════════════════════════════════════════════════════════

  /**
   * Get all receipts
   */
  public getReceipts(): Receipt[] {
    this.ensureUnlocked();
    return [...this.appendix!.receipts];
  }

  /**
   * Add activity receipt
   */
  public recordActivity(verificationHash: string): Receipt {
    this.ensureUnlocked();

    const receipt = this.createReceipt("ACTIVITY", {
      verificationHash,
      recordedAt: new Date().toISOString(),
    });

    this.appendix!.receipts.push(receipt);
    this.save();

    return receipt;
  }

  // ═══════════════════════════════════════════════════════════════
  // EXPORT / IMPORT
  // ═══════════════════════════════════════════════════════════════

  /**
   * Export vault for portability
   */
  public export(password: string, coreHash: string): ExportPackage {
    this.ensureUnlocked();

    // Re-encrypt with provided password
    const salt = crypto.randomBytes(Vault.SALT_LENGTH);
    const key = this.deriveKey(password, salt);
    const encryptedAppendix = this.encryptWithKey(JSON.stringify(this.appendix), salt, key);

    // Hash receipts for integrity
    const receiptsHash = crypto
      .createHash("sha256")
      .update(JSON.stringify(this.appendix!.receipts))
      .digest("hex");

    return {
      version: Vault.VERSION,
      exportedAt: new Date().toISOString(),
      coreHash,
      encryptedAppendix,
      receiptsHash,
    };
  }

  /**
   * Import vault from export package
   */
  public async import(pkg: ExportPackage, password: string): Promise<boolean> {
    const salt = Buffer.from(pkg.encryptedAppendix.salt, "hex");
    const key = this.deriveKey(password, salt);

    try {
      const decrypted = this.decryptWithKey(pkg.encryptedAppendix, key);
      const appendix: LivingAppendix = JSON.parse(decrypted);

      // Verify receipts hash
      const receiptsHash = crypto
        .createHash("sha256")
        .update(JSON.stringify(appendix.receipts))
        .digest("hex");

      if (receiptsHash !== pkg.receiptsHash) {
        throw new Error("Receipts integrity check failed");
      }

      this.appendix = appendix;
      this.derivedKey = key;
      this.save();

      return true;
    } catch (error) {
      throw new Error("Import failed: invalid password or corrupted package");
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // CUSTOM DATA
  // ═══════════════════════════════════════════════════════════════

  /**
   * Set custom data
   */
  public setCustomData(key: string, value: unknown): void {
    this.ensureUnlocked();
    this.appendix!.customData[key] = value;
    this.save();
  }

  /**
   * Get custom data
   */
  public getCustomData(key: string): unknown {
    this.ensureUnlocked();
    return this.appendix!.customData[key];
  }

  // ═══════════════════════════════════════════════════════════════
  // CRYPTO HELPERS
  // ═══════════════════════════════════════════════════════════════

  private deriveKey(password: string, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(
      password,
      salt,
      this.config.keyDerivationIterations,
      Vault.KEY_LENGTH,
      "sha512"
    );
  }

  private encrypt(plaintext: string, salt: Buffer): EncryptedPayload {
    return this.encryptWithKey(plaintext, salt, this.derivedKey!);
  }

  private encryptWithKey(plaintext: string, salt: Buffer, key: Buffer): EncryptedPayload {
    const iv = crypto.randomBytes(Vault.IV_LENGTH);
    const cipher = crypto.createCipheriv(Vault.ALGORITHM, key, iv);

    let ciphertext = cipher.update(plaintext, "utf8", "hex");
    ciphertext += cipher.final("hex");

    const authTag = cipher.getAuthTag();

    return {
      iv: iv.toString("hex"),
      authTag: authTag.toString("hex"),
      ciphertext,
      salt: salt.toString("hex"),
      version: Vault.VERSION,
    };
  }

  private decrypt(payload: EncryptedPayload): string {
    return this.decryptWithKey(payload, this.derivedKey!);
  }

  private decryptWithKey(payload: EncryptedPayload, key: Buffer): string {
    const iv = Buffer.from(payload.iv, "hex");
    const authTag = Buffer.from(payload.authTag, "hex");

    const decipher = crypto.createDecipheriv(Vault.ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    let plaintext = decipher.update(payload.ciphertext, "hex", "utf8");
    plaintext += decipher.final("utf8");

    return plaintext;
  }

  // ═══════════════════════════════════════════════════════════════
  // HELPERS
  // ═══════════════════════════════════════════════════════════════

  private ensureUnlocked(): void {
    if (!this.isUnlocked()) {
      throw new Error("Vault is locked");
    }
  }

  private save(): void {
    this.ensureUnlocked();

    const vaultFile = path.join(this.config.vaultPath, "vault.enc");
    const existingData: EncryptedPayload = JSON.parse(fs.readFileSync(vaultFile, "utf8"));
    const salt = Buffer.from(existingData.salt, "hex");

    const encrypted = this.encrypt(JSON.stringify(this.appendix), salt);
    fs.writeFileSync(vaultFile, JSON.stringify(encrypted, null, 2));

    this.appendix!.lastUpdated = new Date().toISOString();
  }

  private createEmptyAppendix(): LivingAppendix {
    return {
      version: "1.4",
      lastUpdated: new Date().toISOString(),
      guardians: [],
      secondChannels: [],
      verification: {
        passphraseEnabled: true,
        passphraseRotationDays: 90,
        secondChannelEnabled: true,
        guardianCosignRequired: ["money_moves", "public_posting", "credentials"],
      },
      succession: {
        inactivityThreshold: 180,
        coolingPeriod: 7,
        safeModeExitCondition: "verified_kamil_only",
      },
      receipts: [],
      customData: {},
    };
  }

  private createReceipt(
    type: Receipt["type"],
    data: Record<string, unknown>
  ): Receipt {
    const receipt: Omit<Receipt, "hash"> = {
      id: crypto.randomUUID(),
      type,
      timestamp: new Date().toISOString(),
      data,
    };

    const hash = crypto
      .createHash("sha256")
      .update(JSON.stringify(receipt))
      .digest("hex");

    return { ...receipt, hash };
  }
}
