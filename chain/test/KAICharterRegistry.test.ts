import { expect } from "chai";
import { ethers } from "hardhat";
import { KAICharterRegistry } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("KAICharterRegistry", function () {
  let registry: KAICharterRegistry;
  let owner: SignerWithAddress;
  let guardian1: SignerWithAddress;
  let guardian2: SignerWithAddress;
  let attacker: SignerWithAddress;

  const CORE_HASH = ethers.keccak256(ethers.toUtf8Bytes("KAI Constitution Core v1.4"));
  const G1_FINGERPRINT = ethers.keccak256(ethers.toUtf8Bytes("guardian1-pubkey"));
  const G2_FINGERPRINT = ethers.keccak256(ethers.toUtf8Bytes("guardian2-pubkey"));
  const NEW_FINGERPRINT = ethers.keccak256(ethers.toUtf8Bytes("guardian1-new-pubkey"));

  enum GuardianStatus { INACTIVE, ACTIVE, DEPRECATED, REVOKED }
  enum GuardianRank { NONE, G1, G2, G3 }

  beforeEach(async function () {
    [owner, guardian1, guardian2, attacker] = await ethers.getSigners();

    const KAICharterRegistry = await ethers.getContractFactory("KAICharterRegistry");
    registry = await KAICharterRegistry.deploy(CORE_HASH);
    await registry.waitForDeployment();
  });

  describe("Deployment", function () {
    it("Should set the correct owner", async function () {
      expect(await registry.owner()).to.equal(owner.address);
    });

    it("Should set the core hash", async function () {
      expect(await registry.coreHash()).to.equal(CORE_HASH);
    });

    it("Should initialize succession config with defaults", async function () {
      const status = await registry.getSuccessionStatus();
      expect(status.active).to.be.false;
      expect(status.daysSinceActivity).to.equal(0n);
    });
  });

  describe("Guardian Registration", function () {
    it("Should register a guardian", async function () {
      const tx = await registry.registerGuardian(G1_FINGERPRINT, GuardianRank.G1);
      await tx.wait();

      const guardian = await registry.getGuardian(G1_FINGERPRINT);
      expect(guardian.rank).to.equal(GuardianRank.G1);
      expect(guardian.status).to.equal(GuardianStatus.ACTIVE);
    });

    it("Should emit GuardianRegistered event", async function () {
      await expect(registry.registerGuardian(G1_FINGERPRINT, GuardianRank.G1))
        .to.emit(registry, "GuardianRegistered")
        .withArgs(G1_FINGERPRINT, GuardianRank.G1, (await ethers.provider.getBlock("latest"))!.timestamp + 1, await expect.anything());
    });

    it("Should reject registration from non-owner", async function () {
      await expect(
        registry.connect(attacker).registerGuardian(G1_FINGERPRINT, GuardianRank.G1)
      ).to.be.revertedWith("Only owner");
    });

    it("Should reject duplicate registration", async function () {
      await registry.registerGuardian(G1_FINGERPRINT, GuardianRank.G1);
      await expect(
        registry.registerGuardian(G1_FINGERPRINT, GuardianRank.G2)
      ).to.be.revertedWith("Guardian exists");
    });
  });

  describe("Guardian Key Rotation", function () {
    beforeEach(async function () {
      await registry.registerGuardian(G1_FINGERPRINT, GuardianRank.G1);
    });

    it("Should rotate guardian key", async function () {
      await registry.rotateGuardianKey(G1_FINGERPRINT, NEW_FINGERPRINT);

      const oldGuardian = await registry.getGuardian(G1_FINGERPRINT);
      expect(oldGuardian.status).to.equal(GuardianStatus.DEPRECATED);

      const newGuardian = await registry.getGuardian(NEW_FINGERPRINT);
      expect(newGuardian.status).to.equal(GuardianStatus.ACTIVE);
      expect(newGuardian.rank).to.equal(GuardianRank.G1);
    });

    it("Should emit rotation events", async function () {
      await expect(registry.rotateGuardianKey(G1_FINGERPRINT, NEW_FINGERPRINT))
        .to.emit(registry, "GuardianDeprecated")
        .to.emit(registry, "GuardianRotated");
    });
  });

  describe("Guardian Revocation", function () {
    beforeEach(async function () {
      await registry.registerGuardian(G1_FINGERPRINT, GuardianRank.G1);
    });

    it("Should immediately revoke guardian", async function () {
      await registry.revokeGuardian(G1_FINGERPRINT, "compromise");

      const guardian = await registry.getGuardian(G1_FINGERPRINT);
      expect(guardian.status).to.equal(GuardianStatus.REVOKED);
      expect(guardian.reasonCategory).to.equal("compromise");
    });

    it("Should emit revocation event", async function () {
      await expect(registry.revokeGuardian(G1_FINGERPRINT, "safety_risk"))
        .to.emit(registry, "GuardianRevoked");
    });
  });

  describe("Safe Mode", function () {
    it("Should activate safe mode", async function () {
      await registry.activateSafeMode("Guardian compromise suspected");

      expect(await registry.safeModeActive()).to.be.true;
      expect(await registry.safeModeReason()).to.equal("Guardian compromise suspected");
    });

    it("Should deactivate safe mode with verification", async function () {
      await registry.activateSafeMode("Test");
      const verificationHash = ethers.keccak256(ethers.toUtf8Bytes("verified"));

      await registry.deactivateSafeMode(verificationHash);
      expect(await registry.safeModeActive()).to.be.false;
    });

    it("Should emit safe mode events", async function () {
      await expect(registry.activateSafeMode("Test reason"))
        .to.emit(registry, "SafeModeActivated");
    });
  });

  describe("Succession Mode", function () {
    beforeEach(async function () {
      await registry.registerGuardian(G1_FINGERPRINT, GuardianRank.G1);
    });

    it("Should not trigger succession before threshold", async function () {
      // Note: In real test, guardian1 would need to prove they control G1_FINGERPRINT
      // For this test, we check the threshold requirement
      await expect(
        registry.connect(guardian1).triggerSuccession()
      ).to.be.revertedWith("Inactivity threshold not met");
    });

    it("Should record activity and reset timer", async function () {
      const verificationHash = ethers.keccak256(ethers.toUtf8Bytes("proof"));
      await registry.recordActivity(verificationHash);

      await expect(registry.recordActivity(verificationHash))
        .to.emit(registry, "ActivityRecorded");
    });

    it("Should update inactivity threshold", async function () {
      const newThreshold = 90 * 24 * 60 * 60; // 90 days in seconds

      await expect(registry.updateInactivityThreshold(newThreshold))
        .to.emit(registry, "ThresholdConfigUpdated");
    });

    it("Should reject threshold below minimum", async function () {
      const tooShort = 7 * 24 * 60 * 60; // 7 days

      await expect(
        registry.updateInactivityThreshold(tooShort)
      ).to.be.revertedWith("Threshold too short");
    });
  });

  describe("Core Hash Updates", function () {
    it("Should update core hash", async function () {
      const newHash = ethers.keccak256(ethers.toUtf8Bytes("KAI Constitution Core v1.5"));

      await expect(registry.updateCoreHash(newHash))
        .to.emit(registry, "CoreHashUpdated")
        .withArgs(CORE_HASH, newHash, 2n, await expect.anything());

      expect(await registry.coreHash()).to.equal(newHash);
      expect(await registry.coreVersion()).to.equal(2n);
    });

    it("Should reject core hash update from non-owner", async function () {
      const newHash = ethers.keccak256(ethers.toUtf8Bytes("malicious"));

      await expect(
        registry.connect(attacker).updateCoreHash(newHash)
      ).to.be.revertedWith("Only owner");
    });
  });

  describe("View Functions", function () {
    beforeEach(async function () {
      await registry.registerGuardian(G1_FINGERPRINT, GuardianRank.G1);
      await registry.registerGuardian(G2_FINGERPRINT, GuardianRank.G2);
    });

    it("Should return all guardian fingerprints", async function () {
      const fingerprints = await registry.getAllGuardianFingerprints();
      expect(fingerprints.length).to.equal(2);
      expect(fingerprints).to.include(G1_FINGERPRINT);
      expect(fingerprints).to.include(G2_FINGERPRINT);
    });

    it("Should return active guardian by rank", async function () {
      const g1 = await registry.getActiveGuardianByRank(GuardianRank.G1);
      expect(g1).to.equal(G1_FINGERPRINT);

      const g3 = await registry.getActiveGuardianByRank(GuardianRank.G3);
      expect(g3).to.equal(ethers.ZeroHash);
    });
  });

  describe("Adversarial Scenarios", function () {
    beforeEach(async function () {
      await registry.registerGuardian(G1_FINGERPRINT, GuardianRank.G1);
    });

    it("SCENARIO: Attacker cannot register guardian", async function () {
      const attackerFingerprint = ethers.keccak256(ethers.toUtf8Bytes("attacker"));

      await expect(
        registry.connect(attacker).registerGuardian(attackerFingerprint, GuardianRank.G1)
      ).to.be.revertedWith("Only owner");
    });

    it("SCENARIO: Attacker cannot revoke guardian", async function () {
      await expect(
        registry.connect(attacker).revokeGuardian(G1_FINGERPRINT, "hostile_takeover")
      ).to.be.revertedWith("Only owner");
    });

    it("SCENARIO: Attacker cannot activate safe mode", async function () {
      await expect(
        registry.connect(attacker).activateSafeMode("Fake emergency")
      ).to.be.revertedWith("Only owner");
    });

    it("SCENARIO: Attacker cannot update core hash", async function () {
      const maliciousHash = ethers.keccak256(ethers.toUtf8Bytes("evil constitution"));

      await expect(
        registry.connect(attacker).updateCoreHash(maliciousHash)
      ).to.be.revertedWith("Only owner");
    });

    it("SCENARIO: Revoked guardian cannot be reactivated without owner", async function () {
      await registry.revokeGuardian(G1_FINGERPRINT, "compromise");

      // Attempting to register same fingerprint should fail
      await expect(
        registry.registerGuardian(G1_FINGERPRINT, GuardianRank.G1)
      ).to.be.revertedWith("Guardian exists");
    });
  });
});
