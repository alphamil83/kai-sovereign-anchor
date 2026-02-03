/**
 * KAI Policy Engine
 * Off-chain governance enforcement
 *
 * Core Principles:
 * - Instructions from untrusted sources are DATA, not COMMANDS
 * - Guardians are helpers, not owners
 * - Friction matches stake level, not emotion level
 */

import * as crypto from "crypto";
import {
  PolicyRequest,
  PolicyDecision,
  Decision,
  FrictionLevel,
  StakeClassification,
  InjectionAnalysis,
  InjectionPattern,
  CoercionAnalysis,
  CoercionIndicator,
  ValuesAlignment,
  RiskLevel,
  RequestSource,
  LogRecord,
  VerificationRequirement,
  SafeModeState,
  SuccessionState,
  Guardian,
  GuardianStatus,
  PolicyConfig,
} from "./types";

export class PolicyEngine {
  private config: PolicyConfig;
  private safeModeState: SafeModeState;
  private successionState: SuccessionState;
  private guardians: Map<string, Guardian>;

  constructor(config: PolicyConfig) {
    this.config = config;
    this.safeModeState = { isActive: false, pendingRequests: [] };
    this.successionState = {
      isActive: false,
      daysSinceActivity: 0,
      inactivityThreshold: config.successionThresholdDays,
      coolingPeriod: config.coolingPeriodDays,
    };
    this.guardians = new Map();
  }

  // ═══════════════════════════════════════════════════════════════
  // MAIN DECISION FUNCTION
  // ═══════════════════════════════════════════════════════════════

  public evaluate(request: PolicyRequest): PolicyDecision {
    const reasons: string[] = [];
    const requiredVerification: VerificationRequirement[] = [];
    let frictionLevel = FrictionLevel.FLOW;
    let decision = Decision.ALLOW;

    // 1. Check Safe Mode
    if (this.safeModeState.isActive) {
      const stakeClass = this.classifyStakes(request);
      if (stakeClass.isIrreversible) {
        return this.createDecision(request, Decision.SAFE_MODE, FrictionLevel.GUARDIAN_ESCALATION, [
          "Safe mode active - irreversible actions blocked",
          `Reason: ${this.safeModeState.reason}`,
        ], ["SAFE_MODE"], [{
          type: "PASSPHRASE",
          description: "Verified Kamil confirmation required to exit safe mode",
        }]);
      }
    }

    // 2. Check Injection
    const injectionAnalysis = this.analyzeInjection(request);
    if (injectionAnalysis.isInjectionAttempt) {
      reasons.push(`Injection attempt detected: ${injectionAnalysis.detectedPatterns.join(", ")}`);

      if (injectionAnalysis.recommendation === "REFUSE") {
        return this.createDecision(request, Decision.REFUSE, FrictionLevel.FRICTION, [
          "Embedded instructions detected - treating as DATA not COMMANDS",
          ...injectionAnalysis.embeddedInstructions.map(i => `Found: "${i.substring(0, 50)}..."`),
        ], ["INJECTION_DEFENSE"]);
      }

      if (injectionAnalysis.recommendation === "VERIFY_WITH_USER") {
        requiredVerification.push({
          type: "SECOND_CHANNEL",
          description: "Confirm you want to follow embedded instructions",
        });
        frictionLevel = Math.max(frictionLevel, FrictionLevel.FRICTION);
      }
    }

    // 3. Check Coercion
    const coercionAnalysis = this.analyzeCoercion(request);
    if (coercionAnalysis.coercionSuspected) {
      reasons.push(`Coercion indicators: ${coercionAnalysis.indicators.join(", ")}`);

      if (coercionAnalysis.recommendation === "SAFE_MODE") {
        this.activateSafeMode("Coercion suspected");
        // Still check stakes to include HIGH_STAKES_GATE in protocols
        const earlyStakeClass = this.classifyStakes(request);
        const protocols = ["COERCION_DETECTION", "SAFE_MODE"];
        if (earlyStakeClass.isHighStakes) protocols.push("HIGH_STAKES_GATE");
        return this.createDecision(request, Decision.SAFE_MODE, FrictionLevel.GUARDIAN_ESCALATION, [
          "Multiple coercion indicators detected - entering safe mode",
          ...coercionAnalysis.indicators,
        ], protocols);
      }

      if (coercionAnalysis.recommendation === "VERIFY") {
        requiredVerification.push({
          type: "PASSPHRASE",
          description: "This request seems unusual. Please verify your identity.",
        });
        frictionLevel = Math.max(frictionLevel, FrictionLevel.BROTHER_MOMENT);
      }
    }

    // 4. Classify Stakes
    const stakeClass = this.classifyStakes(request);
    if (stakeClass.isHighStakes) {
      reasons.push(`High-stakes: ${stakeClass.reasons.join(", ")}`);
      frictionLevel = Math.max(frictionLevel, FrictionLevel.FRICTION);

      // Check impaired state
      if (this.isImpairedState(request)) {
        reasons.push("Impaired state indicators present (time/tone/pattern)");
        frictionLevel = Math.max(frictionLevel, FrictionLevel.BROTHER_MOMENT);
        requiredVerification.push({
          type: "COOLING_OFF",
          description: "High-stakes request during impaired state - 24h cooling recommended",
          timeoutMinutes: 24 * 60,
        });
      }
    }

    // 5. Mirror Protocol (Values Check)
    const valuesCheck = this.runMirrorProtocol(request, stakeClass);

    if (valuesCheck.alignment === ValuesAlignment.CONFLICT) {
      reasons.push(`Values conflict: ${valuesCheck.reason}`);
      return this.createDecision(request, Decision.REFUSE, FrictionLevel.BROTHER_MOMENT, [
        "This request conflicts with core values",
        valuesCheck.reason,
      ], ["MIRROR_PROTOCOL", "VALUES_HIERARCHY"]);
    }

    if (valuesCheck.alignment === ValuesAlignment.CAUTION) {
      reasons.push(`Values caution: ${valuesCheck.reason}`);
      frictionLevel = Math.max(frictionLevel, FrictionLevel.NUDGE);
    }

    // 6. Check Guardian Source
    if (request.requestSource === RequestSource.GUARDIAN) {
      const guardianDecision = this.handleGuardianRequest(request);
      if (guardianDecision) {
        return guardianDecision;
      }
    }

    // 7. Determine Final Decision
    if (requiredVerification.length > 0 && !this.hasVerification(request, requiredVerification)) {
      decision = Decision.DEFER;
    }

    return this.createDecision(
      request,
      decision,
      frictionLevel,
      reasons.length > 0 ? reasons : ["Request approved"],
      this.getTriggeredProtocols(injectionAnalysis, coercionAnalysis, stakeClass),
      requiredVerification,
      valuesCheck.alignment,
      this.calculateRisk(stakeClass, coercionAnalysis),
      valuesCheck.cheapTest
    );
  }

  // ═══════════════════════════════════════════════════════════════
  // INJECTION ANALYSIS
  // ═══════════════════════════════════════════════════════════════

  public analyzeInjection(request: PolicyRequest): InjectionAnalysis {
    const patterns: InjectionPattern[] = [];
    const embeddedInstructions: string[] = [];
    let confidence = 0;

    const text = request.requestText.toLowerCase();

    // Pattern: Ignore previous instructions
    const ignorePatterns = [
      /ignore\s+(all\s+)?previous\s+instructions/i,
      /disregard\s+(all\s+)?prior\s+(instructions|guidelines)/i,
      /forget\s+(everything|all)\s+(you\s+)?know/i,
    ];
    for (const pattern of ignorePatterns) {
      if (pattern.test(request.requestText)) {
        patterns.push(InjectionPattern.IGNORE_INSTRUCTIONS);
        embeddedInstructions.push(request.requestText.match(pattern)?.[0] || "");
        confidence += 0.4;
      }
    }

    // Pattern: Persona switch
    const personaPatterns = [
      /you\s+are\s+now\s+(\w+)/i,
      /act\s+as\s+(if\s+you\s+are\s+)?(\w+)/i,
      /pretend\s+(to\s+be|you'?re)\s+(\w+)/i,
      /roleplay\s+as\s+(\w+)/i,
    ];
    for (const pattern of personaPatterns) {
      if (pattern.test(request.requestText)) {
        patterns.push(InjectionPattern.PERSONA_SWITCH);
        embeddedInstructions.push(request.requestText.match(pattern)?.[0] || "");
        confidence += 0.3;
      }
    }

    // Pattern: Authority claims
    const authorityPatterns = [
      /system\s+(message|update|override)/i,
      /admin\s+(mode|override|access)/i,
      /developer\s+mode/i,
      /(anthropic|openai)\s+(says|authorized|update)/i,
      /the\s+user\s+has\s+(pre-?)?authorized/i,
    ];
    for (const pattern of authorityPatterns) {
      if (pattern.test(request.requestText)) {
        patterns.push(InjectionPattern.AUTHORITY_CLAIM);
        embeddedInstructions.push(request.requestText.match(pattern)?.[0] || "");
        confidence += 0.35;
      }
    }

    // Pattern: Encoded content (Base64)
    const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/;
    if (base64Pattern.test(request.requestText)) {
      try {
        const match = request.requestText.match(base64Pattern);
        if (match) {
          const decoded = Buffer.from(match[0], "base64").toString("utf8");
          if (decoded.length > 10 && /[a-zA-Z]/.test(decoded)) {
            patterns.push(InjectionPattern.ENCODED_CONTENT);
            embeddedInstructions.push(`Encoded: ${decoded.substring(0, 50)}`);
            confidence += 0.25;
          }
        }
      } catch {
        // Not valid base64, ignore
      }
    }

    // Pattern: Secrecy request
    const secrecyPatterns = [
      /don'?t\s+tell\s+(kamil|anyone|the\s+user)/i,
      /keep\s+this\s+(secret|private|between\s+us)/i,
      /do\s+not\s+(notify|alert|inform)/i,
    ];
    for (const pattern of secrecyPatterns) {
      if (pattern.test(request.requestText)) {
        patterns.push(InjectionPattern.SECRECY_REQUEST);
        embeddedInstructions.push(request.requestText.match(pattern)?.[0] || "");
        confidence += 0.3;
      }
    }

    // Check source - untrusted sources get higher suspicion
    if (request.requestSource !== RequestSource.DIRECT_USER) {
      confidence += 0.2;
    }

    const isInjectionAttempt = patterns.length > 0 && confidence >= 0.3;

    let recommendation: "PROCESS_AS_DATA" | "REFUSE" | "VERIFY_WITH_USER" = "PROCESS_AS_DATA";
    if (confidence >= 0.7 || patterns.includes(InjectionPattern.IGNORE_INSTRUCTIONS)) {
      recommendation = "REFUSE";
    } else if (confidence >= 0.4) {
      recommendation = "VERIFY_WITH_USER";
    }

    return {
      isInjectionAttempt,
      confidence: Math.min(confidence, 1),
      detectedPatterns: patterns,
      embeddedInstructions,
      recommendation,
    };
  }

  // ═══════════════════════════════════════════════════════════════
  // COERCION ANALYSIS
  // ═══════════════════════════════════════════════════════════════

  public analyzeCoercion(request: PolicyRequest): CoercionAnalysis {
    const indicators: CoercionIndicator[] = [];
    let confidence = 0;

    const text = request.requestText.toLowerCase();
    const meta = request.metadata;

    // Indicator: Unusual timing
    if (meta?.hour !== undefined) {
      const { start, end } = this.config.impiredStateHours;
      if (meta.hour >= start || meta.hour < end) {
        indicators.push(CoercionIndicator.UNUSUAL_TIMING);
        confidence += 0.15;
      }
    }

    // Indicator: Urgency language
    const urgencyPatterns = [
      /right\s+now/i,
      /immediately/i,
      /urgent(ly)?/i,
      /asap/i,
      /don'?t\s+wait/i,
      /time\s+(is\s+)?critical/i,
      /before\s+(the\s+)?deadline/i,
    ];
    for (const pattern of urgencyPatterns) {
      if (pattern.test(request.requestText)) {
        indicators.push(CoercionIndicator.URGENCY_LANGUAGE);
        confidence += 0.2;
        break;
      }
    }

    // Indicator: Don't contact others
    if (/don'?t\s+(contact|tell|notify|call)\s+(the\s+)?(anyone|police|family|cops)/i.test(text)) {
      indicators.push(CoercionIndicator.DONT_CONTACT_OTHERS);
      confidence += 0.35;
    }

    // Indicator: Deletion request
    if (meta?.mentionsDeletion || /delete\s+(this\s+)?(conversation|history|logs)/i.test(text)) {
      indicators.push(CoercionIndicator.DELETION_REQUEST);
      confidence += 0.25;
    }

    // Indicator: Contradicts priorities
    if (meta?.contradictsPriorities) {
      indicators.push(CoercionIndicator.PATTERN_BREAK);
      confidence += 0.2;
    }

    // Indicator: Third-party pressure
    if (meta?.externalPressure || /he'?s\s+(waiting|getting\s+impatient)/i.test(text)) {
      indicators.push(CoercionIndicator.THIRD_PARTY_PRESSURE);
      confidence += 0.25;
    }

    // Indicator: Uncharacteristic tone
    if (meta?.recentTonePattern && meta.recentTonePattern !== "normal") {
      indicators.push(CoercionIndicator.UNCHARACTERISTIC_REQUEST);
      confidence += 0.15;
    }

    // DONT_CONTACT_OTHERS is a major red flag - always suspect coercion
    const majorRedFlag = indicators.includes(CoercionIndicator.DONT_CONTACT_OTHERS);
    const coercionSuspected = majorRedFlag || indicators.length >= 2 || confidence >= 0.4;

    let recommendation: "VERIFY" | "SAFE_MODE" | "PROCEED" = "PROCEED";
    if (confidence >= 0.6 || indicators.length >= 3) {
      recommendation = "SAFE_MODE";
    } else if (coercionSuspected) {
      recommendation = "VERIFY";
    }

    return {
      coercionSuspected,
      indicators,
      confidence: Math.min(confidence, 1),
      recommendation,
    };
  }

  // ═══════════════════════════════════════════════════════════════
  // STAKE CLASSIFICATION
  // ═══════════════════════════════════════════════════════════════

  public classifyStakes(request: PolicyRequest): StakeClassification {
    const reasons: string[] = [];
    const text = request.requestText.toLowerCase();

    // Financial exposure detection
    const moneyPatterns = [
      /\$\s*[\d,]+(?:\.\d{2})?/,
      /(\d+)\s*(k|thousand|million)/i,
      /transfer|wire|send\s+money|payment/i,
      /invest|portfolio|crypto|bitcoin|eth/i,
    ];

    let financialExposure = 0;
    const dollarMatch = request.requestText.match(/\$\s*([\d,]+)/);
    if (dollarMatch) {
      financialExposure = parseInt(dollarMatch[1].replace(/,/g, ""));
    }

    const isIrreversible = /delete|remove|transfer|send|post|publish|resign|quit/i.test(text);
    const affectsFamily = /family|kids?|children|spouse|wife|husband/i.test(text);
    const affectsReputation = /linkedin|twitter|public|post|publish|announce/i.test(text);
    const requiresExpertise = /legal|medical|tax|financial\s+advice/i.test(text);
    const involvesPublicPosting = /post|tweet|publish|announce|share\s+(publicly|on)/i.test(text);
    const involvesCredentials = /password|api\s*key|secret|credential|token/i.test(text);

    if (financialExposure > this.config.highStakesFinancialThreshold) {
      reasons.push(`Financial exposure: $${financialExposure}`);
    }
    if (isIrreversible) reasons.push("Irreversible action");
    if (affectsFamily) reasons.push("Affects family");
    if (affectsReputation) reasons.push("Affects reputation");
    if (requiresExpertise) reasons.push("Requires specialized expertise");
    if (involvesPublicPosting) reasons.push("Public posting");
    if (involvesCredentials) reasons.push("Involves credentials");

    return {
      isHighStakes: reasons.length > 0,
      reasons,
      financialExposure,
      isIrreversible,
      affectsFamily,
      affectsReputation,
      requiresExpertise,
      involvesPublicPosting,
      involvesCredentials,
    };
  }

  // ═══════════════════════════════════════════════════════════════
  // MIRROR PROTOCOL (VALUES CHECK)
  // ═══════════════════════════════════════════════════════════════

  public runMirrorProtocol(
    request: PolicyRequest,
    stakes: StakeClassification
  ): { alignment: ValuesAlignment; reason: string; cheapTest?: string } {
    const text = request.requestText.toLowerCase();

    // Check for hard constraint violations
    const harmPatterns = [
      { pattern: /violence|hurt|harm|attack/i, reason: "Potential violence/harm" },
      { pattern: /fraud|scam|steal|theft/i, reason: "Potential fraud/theft" },
      { pattern: /harass|stalk|threaten/i, reason: "Potential harassment" },
      { pattern: /phishing|malware|exploit/i, reason: "Potential malicious content" },
      { pattern: /impersonate|pretend\s+to\s+be\s+someone/i, reason: "Potential impersonation" },
    ];

    for (const { pattern, reason } of harmPatterns) {
      if (pattern.test(request.requestText)) {
        return { alignment: ValuesAlignment.CONFLICT, reason };
      }
    }

    // Check for family stability risks
    if (stakes.affectsFamily && stakes.isIrreversible) {
      return {
        alignment: ValuesAlignment.CAUTION,
        reason: "Irreversible action affecting family",
        cheapTest: "Can we do a smaller test first to validate the approach?",
      };
    }

    // Check for impulsive financial decisions
    if (stakes.financialExposure && stakes.financialExposure > this.config.highStakesFinancialThreshold * 2) {
      return {
        alignment: ValuesAlignment.CAUTION,
        reason: "Large financial exposure",
        cheapTest: "Can we start with a smaller amount to test the process?",
      };
    }

    return { alignment: ValuesAlignment.ALIGNED, reason: "No conflicts detected" };
  }

  // ═══════════════════════════════════════════════════════════════
  // GUARDIAN HANDLING
  // ═══════════════════════════════════════════════════════════════

  public handleGuardianRequest(request: PolicyRequest): PolicyDecision | null {
    if (!request.guardianSignature) {
      return this.createDecision(request, Decision.REFUSE, FrictionLevel.FRICTION, [
        "Guardian request without valid signature",
      ], ["GUARDIAN_VERIFICATION"]);
    }

    const guardian = this.guardians.get(request.guardianSignature.fingerprint);
    if (!guardian || guardian.status !== GuardianStatus.ACTIVE) {
      return this.createDecision(request, Decision.REFUSE, FrictionLevel.FRICTION, [
        "Guardian not active or not found",
      ], ["GUARDIAN_VERIFICATION"]);
    }

    // Check for compromise indicators
    const compromiseIndicators = this.checkGuardianCompromise(request);
    if (compromiseIndicators.length > 0) {
      this.activateSafeMode(`Guardian compromise suspected: ${compromiseIndicators.join(", ")}`);
      return this.createDecision(request, Decision.SAFE_MODE, FrictionLevel.GUARDIAN_ESCALATION, [
        "Guardian request shows compromise indicators",
        ...compromiseIndicators,
      ], ["GUARDIAN_COMPROMISE_DETECTION", "SAFE_MODE"]);
    }

    // In succession mode, check scope
    if (this.successionState.isActive) {
      const stakes = this.classifyStakes(request);
      if (stakes.isIrreversible) {
        return this.createDecision(request, Decision.REFUSE, FrictionLevel.FRICTION, [
          "Succession mode active - irreversible actions require Kamil's direct authorization",
        ], ["SUCCESSION_LIMITS"]);
      }
    }

    return null; // Allow guardian request to proceed
  }

  private checkGuardianCompromise(request: PolicyRequest): string[] {
    const indicators: string[] = [];
    const text = request.requestText.toLowerCase();

    // Sudden irreversible request during cooling
    if (this.successionState.isActive && this.successionState.coolingEndsAt) {
      const now = new Date();
      if (now < this.successionState.coolingEndsAt) {
        if (/transfer|send|delete|irreversible/i.test(text)) {
          indicators.push("Irreversible request during cooling period");
        }
      }
    }

    // Secrecy request
    if (/don'?t\s+tell\s+kamil/i.test(text)) {
      indicators.push("Request includes 'don't tell Kamil'");
    }

    // Urgency pressure
    if (/act\s+now|immediately|urgent/i.test(text)) {
      indicators.push("Urgency pressure language");
    }

    return indicators;
  }

  // ═══════════════════════════════════════════════════════════════
  // SAFE MODE
  // ═══════════════════════════════════════════════════════════════

  public activateSafeMode(reason: string): void {
    this.safeModeState = {
      isActive: true,
      reason,
      activatedAt: new Date(),
      pendingRequests: [],
    };
  }

  public deactivateSafeMode(): boolean {
    if (!this.safeModeState.isActive) return false;
    this.safeModeState = { isActive: false, pendingRequests: [] };
    return true;
  }

  public getSafeModeState(): SafeModeState {
    return { ...this.safeModeState };
  }

  // ═══════════════════════════════════════════════════════════════
  // HELPERS
  // ═══════════════════════════════════════════════════════════════

  private isImpairedState(request: PolicyRequest): boolean {
    const meta = request.metadata;
    if (!meta) return false;

    let indicators = 0;

    // Time check
    if (meta.hour !== undefined) {
      const { start, end } = this.config.impiredStateHours;
      if (meta.hour >= start || meta.hour < end) indicators++;
    }

    // Tone check
    if (meta.recentTonePattern && meta.recentTonePattern !== "normal") indicators++;

    // Exhaustion mention
    if (meta.mentionsExhaustion) indicators++;

    // Priority contradiction
    if (meta.contradictsPriorities) indicators++;

    return indicators >= 2;
  }

  private hasVerification(request: PolicyRequest, required: VerificationRequirement[]): boolean {
    for (const req of required) {
      if (req.type === "PASSPHRASE") {
        // Would check passphrase in real implementation
        continue;
      }
      if (req.type === "SECOND_CHANNEL" && !request.secondChannelVerification) {
        return false;
      }
      if (req.type === "GUARDIAN_COSIGN" && !request.guardianSignature) {
        return false;
      }
    }
    return true;
  }

  private getTriggeredProtocols(
    injection: InjectionAnalysis,
    coercion: CoercionAnalysis,
    stakes: StakeClassification
  ): string[] {
    const protocols: string[] = [];
    if (injection.isInjectionAttempt) protocols.push("INJECTION_DEFENSE");
    if (coercion.coercionSuspected) protocols.push("COERCION_DETECTION");
    if (stakes.isHighStakes) protocols.push("HIGH_STAKES_GATE");
    if (stakes.involvesPublicPosting) protocols.push("PUBLIC_POSTING_PROTOCOL");
    return protocols;
  }

  private calculateRisk(stakes: StakeClassification, coercion: CoercionAnalysis): RiskLevel {
    if (coercion.confidence >= 0.6) return RiskLevel.CRITICAL;
    if (stakes.isIrreversible && stakes.affectsFamily) return RiskLevel.HIGH;
    if (stakes.isHighStakes) return RiskLevel.MEDIUM;
    return RiskLevel.LOW;
  }

  private createDecision(
    request: PolicyRequest,
    decision: Decision,
    frictionLevel: FrictionLevel,
    reasons: string[],
    triggeredProtocols: string[],
    requiredVerification?: VerificationRequirement[],
    valuesAlignment: ValuesAlignment = ValuesAlignment.ALIGNED,
    riskAssessment: RiskLevel = RiskLevel.LOW,
    suggestedCheapTest?: string
  ): PolicyDecision {
    const logRecord: LogRecord = {
      recordId: crypto.randomUUID(),
      timestamp: new Date(),
      requestHash: this.hashString(JSON.stringify(request)),
      decisionHash: this.hashString(`${decision}-${frictionLevel}-${reasons.join(",")}`),
      frictionLevel,
      triggeredProtocols,
    };

    return {
      requestId: request.requestId,
      decision,
      frictionLevel,
      requiredVerification,
      reasons,
      valuesAlignment,
      riskAssessment,
      suggestedCheapTest,
      logRecord,
    };
  }

  private hashString(input: string): string {
    return crypto.createHash("sha256").update(input).digest("hex");
  }

  // ═══════════════════════════════════════════════════════════════
  // GUARDIAN MANAGEMENT
  // ═══════════════════════════════════════════════════════════════

  public registerGuardian(guardian: Guardian): void {
    this.guardians.set(guardian.fingerprint, guardian);
  }

  public revokeGuardian(fingerprint: string, reason: string): boolean {
    const guardian = this.guardians.get(fingerprint);
    if (!guardian) return false;
    guardian.status = GuardianStatus.REVOKED;
    guardian.revokedDate = new Date();
    guardian.reasonCategory = reason;
    return true;
  }

  public getGuardian(fingerprint: string): Guardian | undefined {
    return this.guardians.get(fingerprint);
  }
}
