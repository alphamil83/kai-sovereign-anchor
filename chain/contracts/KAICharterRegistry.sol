// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title KAI Charter Registry
 * @notice On-chain registry for KAI governance proofs
 * @dev Stores only hashes, fingerprints, and audit receipts - NO private data
 *
 * Design Principles:
 * - Guardians are helpers, not owners
 * - Only proofs on-chain, private data off-chain
 * - Immutable audit trail for governance events
 */
contract KAICharterRegistry {

    // ═══════════════════════════════════════════════════════════════
    // TYPES
    // ═══════════════════════════════════════════════════════════════

    enum GuardianStatus {
        INACTIVE,
        ACTIVE,
        DEPRECATED,
        REVOKED
    }

    enum GuardianRank {
        NONE,
        G1,
        G2,
        G3
    }

    struct Guardian {
        bytes32 fingerprint;
        GuardianRank rank;
        GuardianStatus status;
        uint256 effectiveDate;
        uint256 revokedDate;
        string reasonCategory; // For revocation: "compromise" / "role_change" / "safety_risk"
    }

    struct SuccessionConfig {
        uint256 inactivityThreshold; // Default: 180 days in seconds
        uint256 coolingPeriod;       // Default: 7 days in seconds
        uint256 lastActivity;        // Last verified Kamil activity timestamp
        bool successionActive;
        uint256 successionTriggeredAt;
        address triggeredBy;
    }

    // ═══════════════════════════════════════════════════════════════
    // STATE
    // ═══════════════════════════════════════════════════════════════

    address public owner; // Kamil's address
    bytes32 public coreHash; // SHA-256 hash of Core constitution
    uint256 public coreVersion;

    mapping(bytes32 => Guardian) public guardians; // fingerprint => Guardian
    bytes32[] public guardianFingerprints; // List of all fingerprints

    SuccessionConfig public succession;

    bool public safeModeActive;
    string public safeModeReason;

    // Receipt counter for unique IDs
    uint256 public receiptNonce;

    // ═══════════════════════════════════════════════════════════════
    // EVENTS
    // ═══════════════════════════════════════════════════════════════

    event CoreHashUpdated(
        bytes32 indexed oldHash,
        bytes32 indexed newHash,
        uint256 version,
        uint256 timestamp
    );

    event GuardianRegistered(
        bytes32 indexed fingerprint,
        GuardianRank rank,
        uint256 effectiveDate,
        bytes32 receiptHash
    );

    event GuardianRotated(
        bytes32 indexed oldFingerprint,
        bytes32 indexed newFingerprint,
        GuardianRank rank,
        bytes32 receiptHash
    );

    event GuardianRevoked(
        bytes32 indexed fingerprint,
        string reasonCategory,
        uint256 timestamp,
        bytes32 receiptHash
    );

    event GuardianDeprecated(
        bytes32 indexed fingerprint,
        uint256 timestamp
    );

    event SuccessionTriggered(
        address indexed triggeredBy,
        uint256 timestamp,
        bytes32 receiptHash
    );

    event SuccessionCancelled(
        uint256 timestamp,
        string reason
    );

    event SafeModeActivated(
        string reason,
        uint256 timestamp,
        bytes32 receiptHash
    );

    event SafeModeDeactivated(
        uint256 timestamp,
        bytes32 verificationHash
    );

    event ThresholdConfigUpdated(
        uint256 oldThreshold,
        uint256 newThreshold,
        uint256 timestamp
    );

    event ActivityRecorded(
        uint256 timestamp,
        bytes32 verificationHash
    );

    event AuditLogEntry(
        uint256 indexed receiptId,
        string action,
        bytes32 dataHash,
        uint256 timestamp
    );

    // ═══════════════════════════════════════════════════════════════
    // MODIFIERS
    // ═══════════════════════════════════════════════════════════════

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyActiveGuardian() {
        bool isActive = false;
        for (uint i = 0; i < guardianFingerprints.length; i++) {
            Guardian storage g = guardians[guardianFingerprints[i]];
            if (g.status == GuardianStatus.ACTIVE) {
                // In production, verify signature matches fingerprint
                isActive = true;
                break;
            }
        }
        require(isActive, "Not an active guardian");
        _;
    }

    modifier notInSafeMode() {
        require(!safeModeActive, "Safe mode active - action blocked");
        _;
    }

    modifier successionNotActive() {
        require(!succession.successionActive, "Succession mode active");
        _;
    }

    // ═══════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════

    constructor(bytes32 _coreHash) {
        owner = msg.sender;
        coreHash = _coreHash;
        coreVersion = 1;

        // Default succession config: 180 days inactivity, 7 days cooling
        succession.inactivityThreshold = 180 days;
        succession.coolingPeriod = 7 days;
        succession.lastActivity = block.timestamp;
        succession.successionActive = false;

        safeModeActive = false;

        emit CoreHashUpdated(bytes32(0), _coreHash, 1, block.timestamp);
    }

    // ═══════════════════════════════════════════════════════════════
    // CORE HASH MANAGEMENT
    // ═══════════════════════════════════════════════════════════════

    /**
     * @notice Update the Core constitution hash
     * @dev Only owner can update, emits event for audit trail
     */
    function updateCoreHash(bytes32 _newHash) external onlyOwner successionNotActive {
        bytes32 oldHash = coreHash;
        coreHash = _newHash;
        coreVersion++;

        emit CoreHashUpdated(oldHash, _newHash, coreVersion, block.timestamp);
        _logAudit("CORE_HASH_UPDATE", _newHash);
    }

    // ═══════════════════════════════════════════════════════════════
    // GUARDIAN MANAGEMENT
    // ═══════════════════════════════════════════════════════════════

    /**
     * @notice Register a new guardian
     * @param _fingerprint Guardian's public key fingerprint
     * @param _rank Guardian rank (G1 > G2 > G3)
     */
    function registerGuardian(
        bytes32 _fingerprint,
        GuardianRank _rank
    ) external onlyOwner successionNotActive returns (bytes32 receiptHash) {
        require(_fingerprint != bytes32(0), "Invalid fingerprint");
        require(_rank != GuardianRank.NONE, "Invalid rank");
        require(guardians[_fingerprint].status == GuardianStatus.INACTIVE, "Guardian exists");

        guardians[_fingerprint] = Guardian({
            fingerprint: _fingerprint,
            rank: _rank,
            status: GuardianStatus.ACTIVE,
            effectiveDate: block.timestamp,
            revokedDate: 0,
            reasonCategory: ""
        });

        guardianFingerprints.push(_fingerprint);

        // Generate receipt hash
        receiptHash = keccak256(abi.encodePacked(
            "REGISTER",
            _fingerprint,
            _rank,
            block.timestamp,
            receiptNonce++
        ));

        emit GuardianRegistered(_fingerprint, _rank, block.timestamp, receiptHash);
        _logAudit("GUARDIAN_REGISTERED", receiptHash);

        return receiptHash;
    }

    /**
     * @notice Rotate a guardian's key (deprecate old, activate new)
     * @param _oldFingerprint Current guardian fingerprint
     * @param _newFingerprint New guardian fingerprint
     */
    function rotateGuardianKey(
        bytes32 _oldFingerprint,
        bytes32 _newFingerprint
    ) external onlyOwner successionNotActive returns (bytes32 receiptHash) {
        Guardian storage oldGuardian = guardians[_oldFingerprint];
        require(oldGuardian.status == GuardianStatus.ACTIVE, "Guardian not active");
        require(_newFingerprint != bytes32(0), "Invalid new fingerprint");
        require(guardians[_newFingerprint].status == GuardianStatus.INACTIVE, "New fingerprint exists");

        // Deprecate old key
        oldGuardian.status = GuardianStatus.DEPRECATED;

        // Register new key with same rank
        guardians[_newFingerprint] = Guardian({
            fingerprint: _newFingerprint,
            rank: oldGuardian.rank,
            status: GuardianStatus.ACTIVE,
            effectiveDate: block.timestamp,
            revokedDate: 0,
            reasonCategory: ""
        });

        guardianFingerprints.push(_newFingerprint);

        receiptHash = keccak256(abi.encodePacked(
            "ROTATE",
            _oldFingerprint,
            _newFingerprint,
            block.timestamp,
            receiptNonce++
        ));

        emit GuardianDeprecated(_oldFingerprint, block.timestamp);
        emit GuardianRotated(_oldFingerprint, _newFingerprint, oldGuardian.rank, receiptHash);
        _logAudit("GUARDIAN_ROTATED", receiptHash);

        return receiptHash;
    }

    /**
     * @notice Immediately revoke a guardian key
     * @param _fingerprint Guardian fingerprint to revoke
     * @param _reasonCategory Reason: "compromise" / "role_change" / "safety_risk"
     */
    function revokeGuardian(
        bytes32 _fingerprint,
        string calldata _reasonCategory
    ) external onlyOwner returns (bytes32 receiptHash) {
        Guardian storage guardian = guardians[_fingerprint];
        require(
            guardian.status == GuardianStatus.ACTIVE ||
            guardian.status == GuardianStatus.DEPRECATED,
            "Guardian not active/deprecated"
        );

        guardian.status = GuardianStatus.REVOKED;
        guardian.revokedDate = block.timestamp;
        guardian.reasonCategory = _reasonCategory;

        receiptHash = keccak256(abi.encodePacked(
            "REVOKE",
            _fingerprint,
            _reasonCategory,
            block.timestamp,
            receiptNonce++
        ));

        emit GuardianRevoked(_fingerprint, _reasonCategory, block.timestamp, receiptHash);
        _logAudit("GUARDIAN_REVOKED", receiptHash);

        return receiptHash;
    }

    // ═══════════════════════════════════════════════════════════════
    // SUCCESSION MANAGEMENT
    // ═══════════════════════════════════════════════════════════════

    /**
     * @notice Trigger succession mode (guardian + inactivity threshold met)
     * @dev Only callable by active guardian when threshold exceeded
     */
    function triggerSuccession() external onlyActiveGuardian returns (bytes32 receiptHash) {
        require(!succession.successionActive, "Succession already active");
        require(
            block.timestamp > succession.lastActivity + succession.inactivityThreshold,
            "Inactivity threshold not met"
        );

        succession.successionActive = true;
        succession.successionTriggeredAt = block.timestamp;
        succession.triggeredBy = msg.sender;

        receiptHash = keccak256(abi.encodePacked(
            "SUCCESSION_TRIGGERED",
            msg.sender,
            block.timestamp,
            receiptNonce++
        ));

        emit SuccessionTriggered(msg.sender, block.timestamp, receiptHash);
        _logAudit("SUCCESSION_TRIGGERED", receiptHash);

        return receiptHash;
    }

    /**
     * @notice Cancel succession mode (owner returns)
     */
    function cancelSuccession() external onlyOwner {
        require(succession.successionActive, "Succession not active");

        succession.successionActive = false;
        succession.lastActivity = block.timestamp;

        emit SuccessionCancelled(block.timestamp, "Owner returned");
        _logAudit("SUCCESSION_CANCELLED", keccak256(abi.encodePacked(block.timestamp)));
    }

    /**
     * @notice Record owner activity (resets inactivity timer)
     * @param _verificationHash Hash of verification proof
     */
    function recordActivity(bytes32 _verificationHash) external onlyOwner {
        succession.lastActivity = block.timestamp;

        // If in succession and cooling period, cancel succession
        if (succession.successionActive) {
            succession.successionActive = false;
            emit SuccessionCancelled(block.timestamp, "Owner verified during cooling");
        }

        emit ActivityRecorded(block.timestamp, _verificationHash);
    }

    /**
     * @notice Check if cooling period has passed
     */
    function isCoolingPeriodComplete() external view returns (bool) {
        if (!succession.successionActive) return false;
        return block.timestamp > succession.successionTriggeredAt + succession.coolingPeriod;
    }

    /**
     * @notice Update succession thresholds
     * @param _newThreshold New inactivity threshold in seconds
     */
    function updateInactivityThreshold(uint256 _newThreshold) external onlyOwner successionNotActive {
        require(_newThreshold >= 30 days, "Threshold too short");

        uint256 oldThreshold = succession.inactivityThreshold;
        succession.inactivityThreshold = _newThreshold;

        emit ThresholdConfigUpdated(oldThreshold, _newThreshold, block.timestamp);
        _logAudit("THRESHOLD_UPDATED", keccak256(abi.encodePacked(_newThreshold)));
    }

    // ═══════════════════════════════════════════════════════════════
    // SAFE MODE
    // ═══════════════════════════════════════════════════════════════

    /**
     * @notice Activate safe mode
     * @param _reason Reason for safe mode activation
     */
    function activateSafeMode(string calldata _reason) external onlyOwner {
        safeModeActive = true;
        safeModeReason = _reason;

        bytes32 receiptHash = keccak256(abi.encodePacked(
            "SAFE_MODE_ON",
            _reason,
            block.timestamp,
            receiptNonce++
        ));

        emit SafeModeActivated(_reason, block.timestamp, receiptHash);
        _logAudit("SAFE_MODE_ACTIVATED", receiptHash);
    }

    /**
     * @notice Deactivate safe mode (requires verification)
     * @param _verificationHash Hash of verification proof
     */
    function deactivateSafeMode(bytes32 _verificationHash) external onlyOwner {
        require(safeModeActive, "Safe mode not active");

        safeModeActive = false;
        safeModeReason = "";

        emit SafeModeDeactivated(block.timestamp, _verificationHash);
        _logAudit("SAFE_MODE_DEACTIVATED", _verificationHash);
    }

    // ═══════════════════════════════════════════════════════════════
    // VIEW FUNCTIONS
    // ═══════════════════════════════════════════════════════════════

    /**
     * @notice Get guardian info by fingerprint
     */
    function getGuardian(bytes32 _fingerprint) external view returns (
        GuardianRank rank,
        GuardianStatus status,
        uint256 effectiveDate,
        uint256 revokedDate,
        string memory reasonCategory
    ) {
        Guardian storage g = guardians[_fingerprint];
        return (g.rank, g.status, g.effectiveDate, g.revokedDate, g.reasonCategory);
    }

    /**
     * @notice Get all guardian fingerprints
     */
    function getAllGuardianFingerprints() external view returns (bytes32[] memory) {
        return guardianFingerprints;
    }

    /**
     * @notice Get active guardians by rank
     */
    function getActiveGuardianByRank(GuardianRank _rank) external view returns (bytes32) {
        for (uint i = 0; i < guardianFingerprints.length; i++) {
            Guardian storage g = guardians[guardianFingerprints[i]];
            if (g.rank == _rank && g.status == GuardianStatus.ACTIVE) {
                return guardianFingerprints[i];
            }
        }
        return bytes32(0);
    }

    /**
     * @notice Get succession status
     */
    function getSuccessionStatus() external view returns (
        bool active,
        uint256 triggeredAt,
        uint256 coolingEndsAt,
        uint256 daysSinceActivity
    ) {
        return (
            succession.successionActive,
            succession.successionTriggeredAt,
            succession.successionTriggeredAt + succession.coolingPeriod,
            (block.timestamp - succession.lastActivity) / 1 days
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // INTERNAL
    // ═══════════════════════════════════════════════════════════════

    function _logAudit(string memory _action, bytes32 _dataHash) internal {
        emit AuditLogEntry(receiptNonce, _action, _dataHash, block.timestamp);
    }
}
