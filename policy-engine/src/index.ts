/**
 * KAI Policy Engine
 * Entry point and exports
 */

export * from "./types";
export * from "./PolicyEngine";

import { PolicyEngine } from "./PolicyEngine";
import { PolicyConfig, SecondChannelType } from "./types";

// Default configuration
export const DEFAULT_CONFIG: PolicyConfig = {
  impiredStateHours: { start: 23, end: 6 }, // 11pm to 6am
  highStakesFinancialThreshold: 500,
  successionThresholdDays: 180,
  coolingPeriodDays: 7,
  passphraseRotationDays: 90,
  approvedSecondChannels: [
    {
      type: SecondChannelType.LOCAL_DEVICE,
      identifier: "local",
      confirmationRule: "Device confirmation prompt",
    },
  ],
};

// Factory function
export function createPolicyEngine(config?: Partial<PolicyConfig>): PolicyEngine {
  return new PolicyEngine({ ...DEFAULT_CONFIG, ...config });
}
