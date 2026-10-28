// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BLSBatchVerifier.sol";
import "../BLS12381Verifier.sol";

/// @notice Research harness: three verifiers share one address and state policy.
/// @dev Inherits the actual ZK submission path; direct paths use the same
/// preparation and acceptance helpers. This is not a minimal deployment for
/// either production alternative. Deployment costs are reported separately.
contract BLSBatchBenchmark is BLSBatchVerifier {
    BLS12381Verifier public immutable directVerifier;
    error InvalidBLSSignature();

    constructor(address generatedVerifier, bytes32 expectedKeyHash, address direct)
        BLSBatchVerifier(generatedVerifier, expectedKeyHash)
    {
        if (direct.code.length == 0) revert InvalidVerifier();
        directVerifier = BLS12381Verifier(direct);
    }

    function submitAggregate(
        uint64 batchId, bytes[2] calldata publicKeys, bytes[2] calldata payloads,
        bytes calldata signature
    ) external {
        bytes32 commitment = _prepareBatch(batchId, publicKeys, payloads);
        bytes[2] memory messages;
        for (uint8 i = 0; i < BATCH_SIZE; i++) messages[i] = _signingMessage(batchId, i, payloads[i]);
        if (!directVerifier.verifyAggregate(messages, publicKeys, signature)) revert InvalidBLSSignature();
        _acceptBatch(batchId, commitment);
    }

    function submitIndividual(
        uint64 batchId, bytes[2] calldata publicKeys, bytes[2] calldata payloads,
        bytes[2] calldata signatures
    ) external {
        bytes32 commitment = _prepareBatch(batchId, publicKeys, payloads);
        for (uint8 i = 0; i < BATCH_SIZE; i++) {
            if (!directVerifier.verify(_signingMessage(batchId, i, payloads[i]), publicKeys[i], signatures[i])) {
                revert InvalidBLSSignature();
            }
        }
        _acceptBatch(batchId, commitment);
    }
}
