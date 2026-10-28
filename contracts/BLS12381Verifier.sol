// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Direct on-chain BLS12-381 Basic/min-pk reference verifier.
/// @dev Uses EIP-2537 (Prague or later). This is NOT a SNARK verifier.
/// Keys/signatures use the uncompressed EIP-2537 representation, not IETF
/// compressed encodings. Raw message bytes are hashed to G2 inside this contract.
contract BLS12381Verifier {
    string public constant CIPHERSUITE = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    bytes internal constant FP_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    bytes internal constant NEGATIVE_G1 =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        hex"00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    error PrecompileFailed(address target);

    /// @param message Arbitrary message bytes, without an off-chain prehash.
    /// @param publicKey G1 x || y, each a 64-byte big-endian field element.
    /// @param signature G2 x.c0 || x.c1 || y.c0 || y.c1, each 64 bytes.
    function verify(
        bytes calldata message,
        bytes calldata publicKey,
        bytes calldata signature
    ) external view returns (bool) {
        if (publicKey.length != 128 || signature.length != 256) return false;
        if (_isZero(publicKey) || _isZero(signature)) return false;

        bytes memory messagePoint = _hashToG2(message);
        // e(pk, H(message)) * e(-G1, signature) == 1.
        // Pairing checks canonical coordinates, curve and subgroup membership.
        (bool success, bytes memory result) = address(0x0f).staticcall{gas: 200_000}(
            abi.encodePacked(publicKey, messagePoint, NEGATIVE_G1, signature)
        );
        return success && result.length == 32 && abi.decode(result, (uint256)) == 1;
    }

    /// @notice Basic aggregate verification for exactly two DISTINCT messages.
    /// @dev Hashes both messages on-chain and checks one three-pair pairing.
    /// Pairing validation applies to each supplied point, not just their sum.
    function verifyAggregate(
        bytes[2] calldata messages,
        bytes[2] calldata publicKeys,
        bytes calldata signature
    ) external view returns (bool) {
        if (signature.length != 256 || _isZero(signature)) return false;
        // Basic/NUL requires distinct complete signed messages. The batch
        // consumer's position framing guarantees this, and the standalone API
        // enforces it for arbitrary callers too.
        if (keccak256(messages[0]) == keccak256(messages[1])) return false;
        bytes memory pairs;
        for (uint256 i = 0; i < 2; i++) {
            if (publicKeys[i].length != 128 || _isZero(publicKeys[i])) return false;
            pairs = abi.encodePacked(pairs, publicKeys[i], _hashToG2(messages[i]));
        }
        // EIP-2537: 37,700 + 32,600 * 3 = 135,500 precompile gas.
        (bool success, bytes memory result) = address(0x0f).staticcall{gas: 200_000}(
            abi.encodePacked(pairs, NEGATIVE_G1, signature)
        );
        return success && result.length == 32 && abi.decode(result, (uint256)) == 1;
    }

    /// @notice RFC 9380 hash-to-G2 with this contract's fixed BLS signature DST.
    /// @dev Exposed to test interoperability; callers cannot supply a hash to verify().
    function hashToG2(bytes calldata message) external view returns (bytes memory) {
        return _hashToG2(message);
    }

    function _hashToG2(bytes calldata message) internal view returns (bytes memory) {
        // hash_to_field: count=2, extension degree m=2, L=64 => 256 bytes.
        bytes32[8] memory uniform = _expandMessage(message);
        bytes memory u0 = abi.encodePacked(
            _reduce(uniform[0], uniform[1]), _reduce(uniform[2], uniform[3])
        );
        bytes memory u1 = abi.encodePacked(
            _reduce(uniform[4], uniform[5]), _reduce(uniform[6], uniform[7])
        );
        // EIP-2537 map includes SWU, isogeny, and cofactor clearing. Clearing
        // each point before addition equals clearing their sum in RFC 9380.
        bytes memory q0 = _call(address(0x11), u0, 256, 50_000);
        bytes memory q1 = _call(address(0x11), u1, 256, 50_000);
        return _call(address(0x0d), abi.encodePacked(q0, q1), 256, 10_000);
    }

    function _expandMessage(bytes calldata message) internal pure returns (bytes32[8] memory b) {
        bytes memory dstPrime = abi.encodePacked(CIPHERSUITE, uint8(bytes(CIPHERSUITE).length));
        bytes32 b0 = sha256(abi.encodePacked(
            new bytes(64), message, uint16(256), uint8(0), dstPrime
        ));
        b[0] = sha256(abi.encodePacked(b0, uint8(1), dstPrime));
        for (uint256 i = 1; i < 8; i++) {
            b[i] = sha256(abi.encodePacked(b0 ^ b[i - 1], uint8(i + 1), dstPrime));
        }
    }

    function _reduce(bytes32 high, bytes32 low) internal view returns (bytes memory) {
        // OS2IP(64 bytes) mod p using MODEXP with exponent 1. No lossy uint256 cast.
        bytes memory result = _call(address(0x05), abi.encodePacked(
            uint256(64), uint256(1), uint256(48), high, low, bytes1(0x01), FP_MODULUS
        ), 48, 20_000);
        return abi.encodePacked(bytes16(0), result);
    }

    function _call(
        address target, bytes memory input, uint256 outputLength, uint256 gasBudget
    ) internal view returns (bytes memory result) {
        bool success;
        (success, result) = target.staticcall{gas: gasBudget}(input);
        // An unavailable precompile can return success with empty data.
        if (!success || result.length != outputLength) revert PrecompileFailed(target);
    }

    function _isZero(bytes calldata point) internal pure returns (bool) {
        for (uint256 i = 0; i < point.length; i++) {
            if (point[i] != 0) return false;
        }
        return true;
    }
}
