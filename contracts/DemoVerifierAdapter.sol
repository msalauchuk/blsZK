// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IDemoGroth16Verifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[4] calldata publicSignals
    ) external view returns (bool);
}

/// @notice Connects the single-tuple Poseidon DEMO to the rollup interface.
/// @dev This adapter does not verify BLS signatures or batch state transitions.
contract DemoVerifierAdapter {
    IDemoGroth16Verifier public immutable verifier;

    constructor(address generatedVerifier) {
        require(generatedVerifier.code.length > 0, "Verifier must be a contract");
        verifier = IDemoGroth16Verifier(generatedVerifier);
    }

    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata inputs
    ) external view returns (bool) {
        // Exactly one tuple: messageHash, publicKeyX, publicKeyY.
        if (inputs.length != 3) return false;
        uint256[4] memory signals = [uint256(1), inputs[0], inputs[1], inputs[2]];
        return verifier.verifyProof(a, b, c, signals);
    }
}
