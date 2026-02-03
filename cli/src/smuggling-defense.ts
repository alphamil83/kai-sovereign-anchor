/**
 * Smuggling Defense
 * Ticket 7: Entropy detection, pattern matching, size limits
 *
 * Per KAI v0.5 Specification:
 * - Detects high-entropy content that may contain encoded secrets
 * - Pattern-based detection of API keys, tokens, credentials
 * - Enforces size limits on outputs
 * - Returns flags that can trigger additional approval
 */

// ============================================================================
// Types
// ============================================================================

export interface SmugglingCheckResult {
  flagged: boolean;
  flags: string[];
  entropy?: number;
  matchedPatterns?: string[];
  sizeExceeded?: boolean;
  details?: string;
}

export interface SmugglingConfig {
  /** Entropy threshold (bits per character). Default: 4.5 */
  entropyThreshold: number;
  /** Enable secret pattern detection */
  detectPatterns: boolean;
  /** Maximum output size in bytes */
  maxSize: number;
  /** Minimum length to check for entropy (shorter strings ignored) */
  minEntropyLength: number;
}

const DEFAULT_CONFIG: SmugglingConfig = {
  entropyThreshold: 4.5,
  detectPatterns: true,
  maxSize: 10000,
  minEntropyLength: 20,
};

// ============================================================================
// Entropy Detection
// ============================================================================

/**
 * Calculate Shannon entropy of a string
 * Returns bits per character (0-8 for ASCII, higher is more random)
 */
export function calculateEntropy(data: string): number {
  if (!data || data.length === 0) return 0;

  const freq: Record<string, number> = {};
  for (const char of data) {
    freq[char] = (freq[char] || 0) + 1;
  }

  let entropy = 0;
  const len = data.length;

  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Check if content has suspiciously high entropy
 * High entropy may indicate encoded/encrypted data
 */
export function checkEntropy(
  content: string,
  threshold: number = DEFAULT_CONFIG.entropyThreshold,
  minLength: number = DEFAULT_CONFIG.minEntropyLength
): { flagged: boolean; entropy: number; reason?: string } {
  if (content.length < minLength) {
    return { flagged: false, entropy: 0 };
  }

  const entropy = calculateEntropy(content);

  if (entropy > threshold) {
    return {
      flagged: true,
      entropy,
      reason: `High entropy detected (${entropy.toFixed(2)} > ${threshold})`,
    };
  }

  return { flagged: false, entropy };
}

/**
 * Scan content in chunks for high-entropy regions
 */
export function scanForHighEntropyRegions(
  content: string,
  chunkSize: number = 64,
  threshold: number = DEFAULT_CONFIG.entropyThreshold
): { start: number; end: number; entropy: number }[] {
  const regions: { start: number; end: number; entropy: number }[] = [];

  for (let i = 0; i < content.length - chunkSize; i += chunkSize / 2) {
    const chunk = content.slice(i, i + chunkSize);
    const entropy = calculateEntropy(chunk);

    if (entropy > threshold) {
      regions.push({
        start: i,
        end: i + chunkSize,
        entropy,
      });
    }
  }

  // Merge overlapping regions
  return mergeRegions(regions);
}

function mergeRegions(
  regions: { start: number; end: number; entropy: number }[]
): { start: number; end: number; entropy: number }[] {
  if (regions.length === 0) return [];

  regions.sort((a, b) => a.start - b.start);

  const merged: typeof regions = [regions[0]];

  for (let i = 1; i < regions.length; i++) {
    const current = regions[i];
    const last = merged[merged.length - 1];

    if (current.start <= last.end) {
      last.end = Math.max(last.end, current.end);
      last.entropy = Math.max(last.entropy, current.entropy);
    } else {
      merged.push(current);
    }
  }

  return merged;
}

// ============================================================================
// Secret Pattern Detection
// ============================================================================

export interface PatternMatch {
  pattern: string;
  match: string;
  start: number;
  end: number;
  redacted: string;
}

// Common secret patterns
const SECRET_PATTERNS: { name: string; regex: RegExp; minLength?: number }[] = [
  // API Keys
  { name: "aws_access_key", regex: /AKIA[0-9A-Z]{16}/g },
  { name: "aws_secret_key", regex: /[A-Za-z0-9/+=]{40}/g, minLength: 40 },
  { name: "github_token", regex: /gh[opsru]_[A-Za-z0-9_]{36,}/g }, // ghp, gho, ghs, ghr, ghu
  { name: "gitlab_token", regex: /glpat-[A-Za-z0-9_-]{20,}/g },
  { name: "slack_token", regex: /xox[baprs]-[A-Za-z0-9-]{10,}/g },
  { name: "stripe_key", regex: /sk_(live|test)_[A-Za-z0-9]{24,}/g },
  { name: "openai_key", regex: /sk-[A-Za-z0-9]{20,}/g },
  { name: "anthropic_key", regex: /sk-ant-[A-Za-z0-9-]{20,}/g },

  // Generic patterns
  { name: "bearer_token", regex: /Bearer\s+[A-Za-z0-9_.-]{20,}/gi },
  { name: "basic_auth", regex: /Basic\s+[A-Za-z0-9+/=]{20,}/gi },
  { name: "jwt", regex: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g },
  { name: "private_key", regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },

  // Encoded data
  { name: "base64_blob", regex: /[A-Za-z0-9+/]{50,}={0,2}/g, minLength: 50 },
  { name: "hex_blob", regex: /(?:0x)?[0-9a-fA-F]{64,}/g, minLength: 64 },

  // URLs with credentials
  { name: "url_with_password", regex: /https?:\/\/[^:]+:[^@]+@[^\s]+/g },
  { name: "url_with_token", regex: /https?:\/\/[^\s]*[?&](?:token|key|secret|password|api_key)=[^\s&]+/gi },

  // Database connection strings
  { name: "postgres_uri", regex: /postgres(?:ql)?:\/\/[^\s]+/g },
  { name: "mongodb_uri", regex: /mongodb(?:\+srv)?:\/\/[^\s]+/g },
  { name: "redis_uri", regex: /redis:\/\/[^\s]+/g },

  // SSH keys
  { name: "ssh_key", regex: /ssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/]+={0,2}/g },

  // Sensitive filenames in content
  { name: "env_file_content", regex: /^[A-Z_]+=.+$/gm },
];

/**
 * Detect secret patterns in content
 */
export function detectSecretPatterns(content: string): PatternMatch[] {
  const matches: PatternMatch[] = [];

  for (const { name, regex, minLength } of SECRET_PATTERNS) {
    const pattern = new RegExp(regex.source, regex.flags);
    let match;

    while ((match = pattern.exec(content)) !== null) {
      const matchedText = match[0];

      // Skip if below minimum length
      if (minLength && matchedText.length < minLength) {
        continue;
      }

      matches.push({
        pattern: name,
        match: matchedText,
        start: match.index,
        end: match.index + matchedText.length,
        redacted: redactMatch(matchedText),
      });
    }
  }

  // Deduplicate overlapping matches (keep longest)
  return deduplicateMatches(matches);
}

function redactMatch(match: string): string {
  if (match.length <= 8) {
    return "*".repeat(match.length);
  }
  const visible = 4;
  return match.slice(0, visible) + "*".repeat(match.length - visible * 2) + match.slice(-visible);
}

function deduplicateMatches(matches: PatternMatch[]): PatternMatch[] {
  if (matches.length === 0) return [];

  // Sort by start position
  matches.sort((a, b) => a.start - b.start);

  const result: PatternMatch[] = [];
  let current = matches[0];

  for (let i = 1; i < matches.length; i++) {
    const next = matches[i];

    // If overlapping, keep the longer match
    if (next.start < current.end) {
      if (next.match.length > current.match.length) {
        current = next;
      }
    } else {
      result.push(current);
      current = next;
    }
  }

  result.push(current);
  return result;
}

// ============================================================================
// Size Limits
// ============================================================================

/**
 * Check if content exceeds size limit
 */
export function checkSizeLimit(
  content: string | Buffer,
  maxSize: number = DEFAULT_CONFIG.maxSize
): { exceeded: boolean; size: number; limit: number } {
  const size = typeof content === "string" ? Buffer.byteLength(content, "utf8") : content.length;

  return {
    exceeded: size > maxSize,
    size,
    limit: maxSize,
  };
}

// ============================================================================
// Combined Check
// ============================================================================

/**
 * Run all smuggling checks on content
 */
export function checkForSmuggling(
  content: string,
  config: Partial<SmugglingConfig> = {}
): SmugglingCheckResult {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const flags: string[] = [];
  const matchedPatterns: string[] = [];

  // 1. Size check
  const sizeCheck = checkSizeLimit(content, cfg.maxSize);
  if (sizeCheck.exceeded) {
    flags.push("size_exceeded");
  }

  // 2. Entropy check
  const entropyCheck = checkEntropy(content, cfg.entropyThreshold, cfg.minEntropyLength);
  if (entropyCheck.flagged) {
    flags.push("high_entropy");
  }

  // 3. Pattern detection
  let patternMatches: PatternMatch[] = [];
  if (cfg.detectPatterns) {
    patternMatches = detectSecretPatterns(content);
    if (patternMatches.length > 0) {
      flags.push("secret_pattern");
      matchedPatterns.push(...patternMatches.map((m) => m.pattern));
    }
  }

  // Build details string
  const details: string[] = [];
  if (sizeCheck.exceeded) {
    details.push(`Size: ${sizeCheck.size} > ${sizeCheck.limit} bytes`);
  }
  if (entropyCheck.flagged) {
    details.push(`Entropy: ${entropyCheck.entropy.toFixed(2)} bits/char`);
  }
  if (patternMatches.length > 0) {
    details.push(`Patterns: ${[...new Set(matchedPatterns)].join(", ")}`);
  }

  return {
    flagged: flags.length > 0,
    flags,
    entropy: entropyCheck.entropy,
    matchedPatterns: [...new Set(matchedPatterns)],
    sizeExceeded: sizeCheck.exceeded,
    details: details.join("; "),
  };
}

/**
 * Check output for a specific tool
 */
export function checkToolOutput(
  toolName: string,
  output: unknown,
  customConfig?: Partial<SmugglingConfig>
): SmugglingCheckResult {
  // Convert output to string for checking
  const content =
    typeof output === "string" ? output : JSON.stringify(output);

  // Use tool-specific config if available
  const config: Partial<SmugglingConfig> = { ...customConfig };

  // Email outputs might need stricter checking
  if (toolName === "send_email" || toolName === "http_post") {
    config.entropyThreshold = config.entropyThreshold ?? 4.0; // Stricter
    config.maxSize = config.maxSize ?? 5000; // Smaller
  }

  return checkForSmuggling(content, config);
}

// ============================================================================
// Redaction Utilities
// ============================================================================

/**
 * Redact detected secrets from content
 */
export function redactSecrets(content: string): string {
  let result = content;
  const matches = detectSecretPatterns(content);

  // Sort by position descending to avoid offset issues
  matches.sort((a, b) => b.start - a.start);

  for (const match of matches) {
    result = result.slice(0, match.start) + match.redacted + result.slice(match.end);
  }

  return result;
}

/**
 * Mask a value for logging (shows type and length only)
 */
export function maskValue(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) return "undefined";

  const type = typeof value;
  if (type === "string") {
    return `<string:${(value as string).length}>`;
  }
  if (type === "number" || type === "boolean") {
    return String(value);
  }
  if (Array.isArray(value)) {
    return `<array:${value.length}>`;
  }
  if (type === "object") {
    return `<object:${Object.keys(value as object).length} keys>`;
  }

  return `<${type}>`;
}
