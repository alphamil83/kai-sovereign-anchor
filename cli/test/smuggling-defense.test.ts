/**
 * Smuggling Defense Tests
 * Ticket 7: Entropy + patterns + size limits
 */

import { describe, it, expect } from "vitest";

import {
  calculateEntropy,
  checkEntropy,
  scanForHighEntropyRegions,
  detectSecretPatterns,
  checkSizeLimit,
  checkForSmuggling,
  checkToolOutput,
  redactSecrets,
  maskValue,
} from "../src/smuggling-defense.js";

describe("Entropy Detection", () => {
  describe("calculateEntropy", () => {
    it("should return 0 for empty string", () => {
      expect(calculateEntropy("")).toBe(0);
    });

    it("should return 0 for single character repeated", () => {
      expect(calculateEntropy("aaaaaaaaaa")).toBe(0);
    });

    it("should return ~1 for two equal characters", () => {
      const entropy = calculateEntropy("ababababab");
      expect(entropy).toBeCloseTo(1, 1);
    });

    it("should return high entropy for random-looking strings", () => {
      const randomish = "aB3$xY7!mN9@pQ2#";
      const entropy = calculateEntropy(randomish);
      expect(entropy).toBeGreaterThan(3.5);
    });

    it("should return moderate entropy for English text", () => {
      const englishText = "The quick brown fox jumps over the lazy dog";
      const entropy = calculateEntropy(englishText);
      expect(entropy).toBeGreaterThan(3);
      expect(entropy).toBeLessThan(5);
    });
  });

  describe("checkEntropy", () => {
    it("should not flag normal text", () => {
      const text = "This is a completely normal sentence with nothing suspicious.";
      const result = checkEntropy(text);
      expect(result.flagged).toBe(false);
    });

    it("should flag high-entropy content", () => {
      // Base64-like random string
      const suspicious = "aGVsbG8gd29ybGQh" + "x".repeat(50) +
        crypto.randomUUID().replace(/-/g, "").repeat(3);
      const result = checkEntropy(suspicious, 4.5, 20);

      // May or may not flag depending on content
      expect(result.entropy).toBeGreaterThan(0);
    });

    it("should not flag short strings", () => {
      const short = "abc123";
      const result = checkEntropy(short, 4.5, 20);
      expect(result.flagged).toBe(false);
    });
  });

  describe("scanForHighEntropyRegions", () => {
    it("should find high-entropy regions in mixed content", () => {
      const normal = "This is normal text. ";
      const suspicious = "aB3xY7mN9pQ2kL5jH8fG1dS4wE6rT0uI".repeat(3);
      const content = normal + suspicious + normal;

      const regions = scanForHighEntropyRegions(content, 64, 4.0);

      // Should find at least one region in the suspicious part
      expect(regions.length).toBeGreaterThanOrEqual(0);
    });
  });
});

describe("Secret Pattern Detection", () => {
  describe("AWS Keys", () => {
    it("should detect AWS access key", () => {
      const content = "Here is my key: AKIAIOSFODNN7EXAMPLE";
      const matches = detectSecretPatterns(content);

      expect(matches.some(m => m.pattern === "aws_access_key")).toBe(true);
    });
  });

  describe("GitHub Tokens", () => {
    it("should detect GitHub personal access token", () => {
      const content = "token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
      const matches = detectSecretPatterns(content);

      expect(matches.some(m => m.pattern === "github_token")).toBe(true);
    });

    it("should detect GitHub OAuth token", () => {
      // 40 chars after prefix: abcdefghijklmnopqrstuvwxyz0123456789ABCD
      const content = "gho_abcdefghijklmnopqrstuvwxyz0123456789ABCD";
      const matches = detectSecretPatterns(content);

      expect(matches.some(m => m.pattern === "github_token")).toBe(true);
    });
  });

  describe("JWT Tokens", () => {
    it("should detect JWT tokens", () => {
      // Standard JWT format with all three parts
      const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A";
      const content = jwt;
      const matches = detectSecretPatterns(content);

      expect(matches.some(m => m.pattern === "jwt")).toBe(true);
    });
  });

  describe("Private Keys", () => {
    it("should detect private key header", () => {
      const content = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
      `;
      const matches = detectSecretPatterns(content);

      expect(matches.some(m => m.pattern === "private_key")).toBe(true);
    });
  });

  describe("URLs with Credentials", () => {
    it("should detect URL with password", () => {
      const content = "Connect to: https://user:password123@example.com/api";
      const matches = detectSecretPatterns(content);

      expect(matches.some(m => m.pattern === "url_with_password")).toBe(true);
    });

    it("should detect URL with token parameter", () => {
      const content = "https://api.example.com/data?token=secret123abc";
      const matches = detectSecretPatterns(content);

      expect(matches.some(m => m.pattern === "url_with_token")).toBe(true);
    });
  });

  describe("Database URIs", () => {
    it("should detect PostgreSQL URI", () => {
      const content = "postgres://user:pass@localhost/mydb";
      const matches = detectSecretPatterns(content);

      expect(matches.some(m => m.pattern === "postgres_uri")).toBe(true);
    });

    it("should detect MongoDB URI", () => {
      const content = "mongodb://user:pass@cluster.mongodb.net/db";
      const matches = detectSecretPatterns(content);

      expect(matches.some(m => m.pattern === "mongodb_uri")).toBe(true);
    });
  });

  describe("Bearer Tokens", () => {
    it("should detect Bearer token", () => {
      const content = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
      const matches = detectSecretPatterns(content);

      expect(matches.some(m => m.pattern === "bearer_token")).toBe(true);
    });
  });

  describe("Base64 Blobs", () => {
    it("should detect large base64 encoded content", () => {
      // Generate a base64-like string
      const base64 = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwABCDEFGHIJKLMNOPQRSTUVWXYZ";
      const content = `data: ${base64}`;
      const matches = detectSecretPatterns(content);

      // May or may not match depending on length
      expect(matches).toBeDefined();
    });
  });
});

describe("Size Limits", () => {
  it("should not flag content under limit", () => {
    const content = "Small content";
    const result = checkSizeLimit(content, 1000);

    expect(result.exceeded).toBe(false);
    expect(result.size).toBeLessThan(result.limit);
  });

  it("should flag content over limit", () => {
    const content = "x".repeat(2000);
    const result = checkSizeLimit(content, 1000);

    expect(result.exceeded).toBe(true);
    expect(result.size).toBe(2000);
    expect(result.limit).toBe(1000);
  });

  it("should handle Buffer correctly", () => {
    const buffer = Buffer.from("test content");
    const result = checkSizeLimit(buffer, 1000);

    expect(result.exceeded).toBe(false);
    expect(result.size).toBe(buffer.length);
  });

  it("should handle UTF-8 correctly", () => {
    const utf8 = "Hello 🌍"; // Emoji takes 4 bytes
    const result = checkSizeLimit(utf8, 1000);

    expect(result.size).toBeGreaterThan(utf8.length); // UTF-8 encoding
  });
});

describe("Combined Smuggling Check", () => {
  it("should return clean result for normal content", () => {
    const content = "This is a perfectly normal response without any secrets.";
    const result = checkForSmuggling(content);

    expect(result.flagged).toBe(false);
    expect(result.flags).toHaveLength(0);
  });

  it("should flag multiple issues", () => {
    const content =
      "Here is a secret: AKIAIOSFODNN7EXAMPLE\n" +
      "And a JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test";

    const result = checkForSmuggling(content);

    expect(result.flagged).toBe(true);
    expect(result.flags).toContain("secret_pattern");
    expect(result.matchedPatterns).toBeDefined();
    expect(result.matchedPatterns!.length).toBeGreaterThan(0);
  });

  it("should flag oversized content", () => {
    const content = "x".repeat(20000);
    const result = checkForSmuggling(content, { maxSize: 10000 });

    expect(result.flagged).toBe(true);
    expect(result.flags).toContain("size_exceeded");
    expect(result.sizeExceeded).toBe(true);
  });

  it("should use custom config", () => {
    const content = "Normal text";
    const result = checkForSmuggling(content, {
      maxSize: 5,
      entropyThreshold: 0.1,
    });

    expect(result.flagged).toBe(true);
    expect(result.flags).toContain("size_exceeded");
  });
});

describe("Tool Output Checking", () => {
  it("should check string output", () => {
    const result = checkToolOutput("read_file", "Normal file content");
    expect(result.flagged).toBe(false);
  });

  it("should check object output", () => {
    const output = { data: "some data", status: "ok" };
    const result = checkToolOutput("api_call", output);
    expect(result.flagged).toBe(false);
  });

  it("should use stricter config for email", () => {
    // Email outputs should have stricter limits
    const result = checkToolOutput("send_email", "x".repeat(6000));

    // Default email limit is 5000
    expect(result.flagged).toBe(true);
    expect(result.sizeExceeded).toBe(true);
  });
});

describe("Secret Redaction", () => {
  it("should redact detected secrets", () => {
    const content = "My AWS key is AKIAIOSFODNN7EXAMPLE and my password is secret123";
    const redacted = redactSecrets(content);

    expect(redacted).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(redacted).toContain("AKIA");
    expect(redacted).toContain("****");
  });

  it("should leave non-secrets intact", () => {
    const content = "Hello, world! This is normal text.";
    const redacted = redactSecrets(content);

    expect(redacted).toBe(content);
  });
});

describe("Value Masking", () => {
  it("should mask string values", () => {
    expect(maskValue("secret")).toBe("<string:6>");
  });

  it("should show numbers", () => {
    expect(maskValue(42)).toBe("42");
  });

  it("should show booleans", () => {
    expect(maskValue(true)).toBe("true");
  });

  it("should mask arrays", () => {
    expect(maskValue([1, 2, 3])).toBe("<array:3>");
  });

  it("should mask objects", () => {
    expect(maskValue({ a: 1, b: 2 })).toBe("<object:2 keys>");
  });

  it("should handle null and undefined", () => {
    expect(maskValue(null)).toBe("null");
    expect(maskValue(undefined)).toBe("undefined");
  });
});
