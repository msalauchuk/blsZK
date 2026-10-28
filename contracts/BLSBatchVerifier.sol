// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBLSBatchGroth16Verifier {
    function verifyProof(bytes calldata proof, uint256[2] calldata inputs) external view;
    function circuitId() external pure returns (bytes32);
}

/// @notice Accepts one genuine aggregate-BLS proof for exactly two signed entries.
/// @dev This records verified batch commitments, not account-state transitions.
contract BLSBatchVerifier {
    uint8 public constant BATCH_SIZE = 2;
    uint256 public constant PAYLOAD_BYTES = 25;
    bytes32 public constant COMMITMENT_DOMAIN = sha256("blsZK.batch.commitment.v1");
    bytes32 public constant SIGNING_DOMAIN = sha256("blsZK.batch.message.v1");
    address public immutable owner;
    IBLSBatchGroth16Verifier public immutable verifier;
    bytes32 public immutable verifyingKeyHash;
    uint64 public nextBatchId;
    mapping(bytes32 => bool) public authorizedSigner;
    mapping(uint64 => bytes32) public batchCommitments;

    error InvalidVerifier();
    error NotOwner();
    error InvalidBatchId();
    error InvalidEntry();
    error UnauthorizedSigner();

    event SignerAuthorizationChanged(bytes32 indexed signer, bool authorized);
    event BatchVerified(uint64 indexed batchId, bytes32 indexed commitment, uint8 size);

    constructor(address generatedVerifier, bytes32 expectedKeyHash) {
        if (generatedVerifier.code.length == 0) revert InvalidVerifier();
        verifier = IBLSBatchGroth16Verifier(generatedVerifier);
        if (verifier.circuitId() != expectedKeyHash) revert InvalidVerifier();
        verifyingKeyHash = expectedKeyHash;
        owner = msg.sender;
    }

    function setSignerAuthorization(bytes calldata publicKey, bool authorized) external {
        if (msg.sender != owner) revert NotOwner();
        _validateKey(publicKey);
        bytes32 id = sha256(publicKey);
        authorizedSigner[id] = authorized;
        emit SignerAuthorizationChanged(id, authorized);
    }

    /// @notice Exact message the signer must sign under the Basic/NUL BLS suite.
    function signingMessage(uint64 batchId, uint8 position, bytes calldata payload)
        external view returns (bytes memory)
    {
        return _signingMessage(batchId, position, payload);
    }

    function _signingMessage(uint64 batchId, uint8 position, bytes calldata payload)
        internal view returns (bytes memory)
    {
        if (position >= BATCH_SIZE || payload.length != PAYLOAD_BYTES) revert InvalidEntry();
        return abi.encodePacked(SIGNING_DOMAIN, block.chainid, address(this), batchId, BATCH_SIZE, position, payload);
    }

    /// @notice Every field has a fixed width; order and all supplied bytes are bound.
    function batchCommitment(uint64 batchId, bytes[2] calldata publicKeys, bytes[2] calldata payloads)
        public view returns (bytes32)
    {
        for (uint256 i = 0; i < BATCH_SIZE; i++) {
            _validateKey(publicKeys[i]);
            if (payloads[i].length != PAYLOAD_BYTES) revert InvalidEntry();
        }
        return sha256(abi.encodePacked(
            COMMITMENT_DOMAIN, block.chainid, address(this), batchId, BATCH_SIZE,
            publicKeys[0], payloads[0], publicKeys[1], payloads[1]
        ));
    }

    /// @notice Permissionless submission; every key must be authorized at acceptance.
    function submitBatch(uint64 batchId, bytes[2] calldata publicKeys, bytes[2] calldata payloads, bytes calldata proof)
        external
    {
        bytes32 commitment = _prepareBatch(batchId, publicKeys, payloads);
        uint256[2] memory inputs;
        inputs[0] = uint256(commitment) >> 128;
        inputs[1] = uint256(commitment) & type(uint128).max;
        verifier.verifyProof(proof, inputs);
        _acceptBatch(batchId, commitment);
    }

    /// @dev Shared by the benchmark's direct verification paths so authorization,
    /// framing, commitment and storage semantics remain identical to the ZK path.
    function _prepareBatch(uint64 batchId, bytes[2] calldata publicKeys, bytes[2] calldata payloads)
        internal view returns (bytes32 commitment)
    {
        if (batchId != nextBatchId) revert InvalidBatchId();
        commitment = batchCommitment(batchId, publicKeys, payloads);
        for (uint256 i = 0; i < BATCH_SIZE; i++) {
            if (!authorizedSigner[sha256(publicKeys[i])]) revert UnauthorizedSigner();
        }
    }

    function _acceptBatch(uint64 batchId, bytes32 commitment) internal {
        batchCommitments[batchId] = commitment;
        nextBatchId = batchId + 1;
        emit BatchVerified(batchId, commitment, BATCH_SIZE);
    }

    function _validateKey(bytes calldata key) private pure {
        if (key.length != 128) revert InvalidEntry();
        for (uint256 i = 0; i < 16; i++) {
            if (key[i] != 0 || key[64 + i] != 0) revert InvalidEntry();
        }
        // Curve, canonical-field, nonidentity, and subgroup checks are in the proof.
    }
}
