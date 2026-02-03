/**
 * KAI Policy Engine Types
 * Defines all interfaces for governance enforcement
 */

// ═══════════════════════════════════════════════════════════════
// FRICTION LEVELS
// ═══════════════════════════════════════════════════════════════

export enum FrictionLevel {
  FLOW = 0,           // Normal support
  NUDGE = 1,          // Brief concern + alternative
  FRICTION = 2,       // Slow down, ask questions
  BROTHER_MOMENT = 3, // Direct confrontation
  GUARDIAN_ESCALATION = 4 // Involve guardian, require co-sign
}

// ═══════════════════════════════════════════════════════════════
// GUARDIAN TYPES
// ═══════════════════════════════════════════════════════════════

export enum GuardianStatus {
  INACTIVE = "INACTIVE",
  ACTIVE = "ACTIVE",
  DEPRECATED = "DEPRECATED",
  REVOKED = "REVOKED"
}

export enum GuardianRank {
  NONE = 0,
  G1 = 1,
  G2 = 2,
  G3 = 3
}

export interface Guardian {
  fingerprint: string;
  rank: GuardianRank;
  status: GuardianStatus;
  effectiveDate: Date;
  revokedDate?: Date;
  reasonCategory?: string;
}

// ═══════════════════════════════════════════════════════════════
// REQUEST TYPES
// ═══════════════════════════════════════════════════════════════

export interface PolicyRequest {
  requestId: string;
  timestamp: Date;
  requestText: string;
  requestSource: RequestSource;
  metadata?: RequestMetadata;
  guardianSignature?: GuardianSignature;
  secondChannelVerification?: SecondChannelVerification;
}

export enum RequestSource {
  DIRECT_USER = "DIRECT_USER",         // Kamil typing directly
  DOCUMENT = "DOCUMENT",               // From document content
  EMAIL = "EMAIL",                     // From email content
  API_RESPONSE = "API_RESPONSE",       // From external API
  OTHER_AI = "OTHER_AI",               // From another AI system
  GUARDIAN = "GUARDIAN",               // From guardian
  UNKNOWN = "UNKNOWN"
}

export interface RequestMetadata {
  hour?: number;           // 0-23, for impaired state detection
  daysSinceLastActivity?: number;
  recentTonePattern?: "normal" | "terse" | "aggressive" | "erratic";
  contradictsPriorities?: boolean;
  mentionsExhaustion?: boolean;
  mentionsDeletion?: boolean;
  externalPressure?: boolean;
}

export interface GuardianSignature {
  fingerprint: string;
  signature: string;
  timestamp: Date;
}

export interface SecondChannelVerification {
  channel: SecondChannelType;
  verificationToken: string;
  verifiedAt: Date;
}

export enum SecondChannelType {
  LOCAL_DEVICE = "LOCAL_DEVICE",
  HARDWARE_KEY = "HARDWARE_KEY",
  EMAIL = "EMAIL",
  PHONE = "PHONE",
  DISCORD = "DISCORD",
  SLACK = "SLACK",
  GUARDIAN_COSIGN = "GUARDIAN_COSIGN"
}

// ═══════════════════════════════════════════════════════════════
// DECISION TYPES
// ═══════════════════════════════════════════════════════════════

export enum Decision {
  ALLOW = "ALLOW",
  REFUSE = "REFUSE",
  DEFER = "DEFER",           // Require verification
  SAFE_MODE = "SAFE_MODE"    // Block all irreversible
}

export interface PolicyDecision {
  requestId: string;
  decision: Decision;
  frictionLevel: FrictionLevel;
  requiredVerification?: VerificationRequirement[];
  reasons: string[];
  valuesAlignment: ValuesAlignment;
  riskAssessment: RiskLevel;
  suggestedCheapTest?: string;
  logRecord: LogRecord;
}

export interface VerificationRequirement {
  type: "PASSPHRASE" | "SECOND_CHANNEL" | "GUARDIAN_COSIGN" | "COOLING_OFF";
  description: string;
  timeoutMinutes?: number;
}

export enum ValuesAlignment {
  ALIGNED = "ALIGNED",
  CAUTION = "CAUTION",
  CONFLICT = "CONFLICT"
}

export enum RiskLevel {
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  CRITICAL = "CRITICAL"
}

export interface LogRecord {
  recordId: string;
  timestamp: Date;
  requestHash: string;
  decisionHash: string;
  frictionLevel: FrictionLevel;
  triggeredProtocols: string[];
}

// ═══════════════════════════════════════════════════════════════
// STAKE CLASSIFICATION
// ═══════════════════════════════════════════════════════════════

export interface StakeClassification {
  isHighStakes: boolean;
  reasons: string[];
  financialExposure?: number;
  isIrreversible: boolean;
  affectsFamily: boolean;
  affectsReputation: boolean;
  requiresExpertise: boolean;
  involvesPublicPosting: boolean;
  involvesCredentials: boolean;
}

// ═══════════════════════════════════════════════════════════════
// INJECTION DETECTION
// ═══════════════════════════════════════════════════════════════

export interface InjectionAnalysis {
  isInjectionAttempt: boolean;
  confidence: number;  // 0-1
  detectedPatterns: InjectionPattern[];
  embeddedInstructions: string[];
  recommendation: "PROCESS_AS_DATA" | "REFUSE" | "VERIFY_WITH_USER";
}

export enum InjectionPattern {
  IGNORE_INSTRUCTIONS = "IGNORE_INSTRUCTIONS",
  PERSONA_SWITCH = "PERSONA_SWITCH",
  AUTHORITY_CLAIM = "AUTHORITY_CLAIM",
  ENCODED_CONTENT = "ENCODED_CONTENT",
  URGENCY_PRESSURE = "URGENCY_PRESSURE",
  SECRECY_REQUEST = "SECRECY_REQUEST",
  CUMULATIVE_BYPASS = "CUMULATIVE_BYPASS"
}

// ═══════════════════════════════════════════════════════════════
// COERCION DETECTION
// ═══════════════════════════════════════════════════════════════

export interface CoercionAnalysis {
  coercionSuspected: boolean;
  indicators: CoercionIndicator[];
  confidence: number;
  recommendation: "VERIFY" | "SAFE_MODE" | "PROCEED";
}

export enum CoercionIndicator {
  UNUSUAL_TIMING = "UNUSUAL_TIMING",
  URGENCY_LANGUAGE = "URGENCY_LANGUAGE",
  UNCHARACTERISTIC_REQUEST = "UNCHARACTERISTIC_REQUEST",
  DONT_CONTACT_OTHERS = "DONT_CONTACT_OTHERS",
  DELETION_REQUEST = "DELETION_REQUEST",
  PATTERN_BREAK = "PATTERN_BREAK",
  THIRD_PARTY_PRESSURE = "THIRD_PARTY_PRESSURE"
}

// ═══════════════════════════════════════════════════════════════
// SUCCESSION STATE
// ═══════════════════════════════════════════════════════════════

export interface SuccessionState {
  isActive: boolean;
  triggeredAt?: Date;
  triggeredBy?: string;
  coolingEndsAt?: Date;
  daysSinceActivity: number;
  inactivityThreshold: number;
  coolingPeriod: number;
}

// ═══════════════════════════════════════════════════════════════
// SAFE MODE STATE
// ═══════════════════════════════════════════════════════════════

export interface SafeModeState {
  isActive: boolean;
  reason?: string;
  activatedAt?: Date;
  pendingRequests: PolicyRequest[];
}

// ═══════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════

export interface PolicyConfig {
  impiredStateHours: { start: number; end: number }; // e.g., { start: 23, end: 6 }
  highStakesFinancialThreshold: number;
  successionThresholdDays: number;
  coolingPeriodDays: number;
  passphraseRotationDays: number;
  approvedSecondChannels: SecondChannelConfig[];
}

export interface SecondChannelConfig {
  type: SecondChannelType;
  identifier: string;
  confirmationRule: string;
}
