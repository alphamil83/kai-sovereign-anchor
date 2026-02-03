/**
 * KAI Encrypted Vault
 * Entry point and exports
 */

export * from "./Vault";

import { Vault, VaultConfig } from "./Vault";

// Default configuration
export const DEFAULT_VAULT_CONFIG: VaultConfig = {
  vaultPath: "./.kai-vault",
  keyDerivationIterations: 100000,
};

// Factory function
export function createVault(config?: Partial<VaultConfig>): Vault {
  return new Vault({ ...DEFAULT_VAULT_CONFIG, ...config });
}
