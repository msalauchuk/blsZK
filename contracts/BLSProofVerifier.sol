// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBLSGroth16Verifier {
    function verifyProof(bytes calldata proof, uint256[37] calldata inputs) external view;
    function circuitId() external pure returns (bytes32);
}

/// @notice Verifies knowledge of a valid Basic/min-pk BLS12-381 signature.
/// @dev First circuit version supports exactly 25 message bytes. The signature
/// is private to the prover. Every public message byte and G1 coordinate is
/// reconstructed here and bound to the generated Groth16 verifier's inputs.
contract BLSProofVerifier {
    uint256 public constant MESSAGE_BYTES = 25;
    IBLSGroth16Verifier public immutable verifier;
    bytes32 public immutable verifyingKeyHash;

    error InvalidStatementLength();
    error NonCanonicalPublicKey();
    error InvalidVerifier();

    constructor(address generatedVerifier, bytes32 expectedKeyHash) {
        if (generatedVerifier.code.length == 0) revert InvalidVerifier();
        verifier = IBLSGroth16Verifier(generatedVerifier);
        if (verifier.circuitId() != expectedKeyHash) revert InvalidVerifier();
        verifyingKeyHash = expectedKeyHash;
    }

    /// @notice Success returns normally; invalid proofs revert.
    /// @param message The raw 25-byte message signed by the BLS key.
    /// @param publicKey G1 x || y, each a 64-byte big-endian EIP-2537 coordinate.
    /// @param proof gnark's full Solidity proof encoding, including commitments.
    function verifyProof(
        bytes calldata message, bytes calldata publicKey, bytes calldata proof
    ) external view {
        verifier.verifyProof(proof, statementInputs(message, publicKey));
    }

    function statementInputs(
        bytes calldata message, bytes calldata publicKey
    ) public pure returns (uint256[37] memory inputs) {
        if (message.length != MESSAGE_BYTES || publicKey.length != 128) {
            revert InvalidStatementLength();
        }
        // High padding must be zero, so no public-key bytes are ignored.
        for (uint256 i = 0; i < 16; i++) {
            if (publicKey[i] != 0 || publicKey[64 + i] != 0) revert NonCanonicalPublicKey();
        }
        // gnark's canonical Fp representation uses six little-endian 64-bit
        // limbs for each 381-bit coordinate. The wire encoding is big-endian.
        for (uint256 coordinate = 0; coordinate < 2; coordinate++) {
            for (uint256 limb = 0; limb < 6; limb++) {
                uint256 offset = 64 * (coordinate + 1) - 8 * (limb + 1);
                uint64 value;
                for (uint256 j = 0; j < 8; j++) {
                    value = (value << 8) | uint64(uint8(publicKey[offset + j]));
                }
                inputs[coordinate * 6 + limb] = uint256(value);
            }
        }
        for (uint256 i = 0; i < MESSAGE_BYTES; i++) inputs[12 + i] = uint8(message[i]);
    }
}
