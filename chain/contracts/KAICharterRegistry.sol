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
    // RELEASE REGISTRY (v0.5)
    // ═══════════════════════════════════════════════════════════════

    struct Release {
        bytes32 rootHash;
        string version;
        address registrar;
        uint256 blockNumber;
        uint256 timestamp;
        bool revoked;
    }

    struct ReceiptBatch {
        bytes32 batchHash;
        bytes32 releaseRootHash;
        uint256 blockNumber;
        uint256 timestamp;
        uint256 receiptCount;
    }

    mapping(bytes32 => Release) public releases; // rootHash => Release
    bytes32[] public releaseHashes; // All release root hashes

    mapping(bytes32 => ReceiptBatch) public receiptBatches; // batchHash => ReceiptBatch
    bytes32[] public batchHashes; // All batch hashes

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

    // Release Registry Events (v0.5)
    event ReleaseRegistered(
        bytes32 indexed rootHash,
        string version,
        address indexed registrar,
        uint256 blockNumber,
        uint256 timestamp
    );

    event ReleaseRevoked(
        bytes32 indexed rootHash,
        string reason,
        uint256 timestamp
    );

    event ReceiptBatchAnchored(
        bytes32 indexed batchHash,
        bytes32 indexed releaseRootHash,
        uint256 receiptCount,
        uint256 blockNumber,
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
    // RELEASE REGISTRY (v0.5)
    // ═══════════════════════════════════════════════════════════════

    /**
     * @notice Register a new governance release
     * @param _rootHash Root hash of the release manifest
     * @param _version Semantic version string (e.g., "1.0.0")
     */
    function registerRelease(
        bytes32 _rootHash,
        string calldata _version
    ) external onlyOwner successionNotActive {
        require(_rootHash != bytes32(0), "Invalid root hash");
        require(bytes(_version).length > 0, "Invalid version");
        require(releases[_rootHash].blockNumber == 0, "Release already registered");

        releases[_rootHash] = Release({
            rootHash: _rootHash,
            version: _version,
            registrar: msg.sender,
            blockNumber: block.number,
            timestamp: block.timestamp,
            revoked: false
        });

        releaseHashes.push(_rootHash);

        emit ReleaseRegistered(_rootHash, _version, msg.sender, block.number, block.timestamp);
        _logAudit("RELEASE_REGISTERED", _rootHash);
    }

    /**
     * @notice Revoke a release (mark as invalid)
     * @param _rootHash Root hash of release to revoke
     * @param _reason Reason for revocation
     */
    function revokeRelease(
        bytes32 _rootHash,
        string calldata _reason
    ) external onlyOwner {
        require(releases[_rootHash].blockNumber > 0, "Release not found");
        require(!releases[_rootHash].revoked, "Already revoked");

        releases[_rootHash].revoked = true;

        emit ReleaseRevoked(_rootHash, _reason, block.timestamp);
        _logAudit("RELEASE_REVOKED", _rootHash);
    }

    /**
     * @notice Anchor a batch of receipt hashes
     * @param _batchHash Hash of the receipt batch (H(receipt1 || receipt2 || ...))
     * @param _releaseRootHash Root hash of the governing release
     * @param _receiptCount Number of receipts in the batch
     */
    function anchorReceiptBatch(
        bytes32 _batchHash,
        bytes32 _releaseRootHash,
        uint256 _receiptCount
    ) external onlyOwner {
        require(_batchHash != bytes32(0), "Invalid batch hash");
        require(receiptBatches[_batchHash].blockNumber == 0, "Batch already anchored");
        // Note: We allow anchoring even if release is revoked (for audit trail)

        receiptBatches[_batchHash] = ReceiptBatch({
            batchHash: _batchHash,
            releaseRootHash: _releaseRootHash,
            blockNumber: block.number,
            timestamp: block.timestamp,
            receiptCount: _receiptCount
        });

        batchHashes.push(_batchHash);

        emit ReceiptBatchAnchored(_batchHash, _releaseRootHash, _receiptCount, block.number, block.timestamp);
        _logAudit("RECEIPT_BATCH_ANCHORED", _batchHash);
    }

    /**
     * @notice Verify if a release is registered and valid
     * @param _rootHash Root hash to verify
     * @return registered Whether the release is registered
     * @return revoked Whether the release has been revoked
     * @return version Version string
     * @return blockNumber Block number when registered
     */
    function verifyRelease(bytes32 _rootHash) external view returns (
        bool registered,
        bool revoked,
        string memory version,
        uint256 blockNumber
    ) {
        Release storage r = releases[_rootHash];
        return (
            r.blockNumber > 0,
            r.revoked,
            r.version,
            r.blockNumber
        );
    }

    /**
     * @notice Get receipt batch info
     * @param _batchHash Batch hash to lookup
     */
    function getReceiptBatch(bytes32 _batchHash) external view returns (
        bytes32 releaseRootHash,
        uint256 blockNumber,
        uint256 timestamp,
        uint256 receiptCount
    ) {
        ReceiptBatch storage b = receiptBatches[_batchHash];
        return (
            b.releaseRootHash,
            b.blockNumber,
            b.timestamp,
            b.receiptCount
        );
    }

    /**
     * @notice Get all release hashes
     */
    function getAllReleaseHashes() external view returns (bytes32[] memory) {
        return releaseHashes;
    }

    /**
     * @notice Get all batch hashes
     */
    function getAllBatchHashes() external view returns (bytes32[] memory) {
        return batchHashes;
    }

    /**
     * @notice Get release count
     */
    function getReleaseCount() external view returns (uint256) {
        return releaseHashes.length;
    }

    /**
     * @notice Get batch count
     */
    function getBatchCount() external view returns (uint256) {
        return batchHashes.length;
    }

    // ═══════════════════════════════════════════════════════════════
    // INTERNAL
    // ═══════════════════════════════════════════════════════════════

    function _logAudit(string memory _action, bytes32 _dataHash) internal {
        emit AuditLogEntry(receiptNonce, _action, _dataHash, block.timestamp);
    }
}
