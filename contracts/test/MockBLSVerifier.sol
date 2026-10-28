// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Test double for rollup bookkeeping tests. It performs no cryptography.
contract MockBLSVerifier {
    bool public shouldVerify = true;

    function setShouldVerify(bool value) external {
        shouldVerify = value;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[] calldata
    ) external view returns (bool) {
        return shouldVerify;
    }
}
