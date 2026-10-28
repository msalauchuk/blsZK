# BLS12-381 reference specification

This reference defines the BLS verification behavior used by the proof circuits. Native and direct on-chain verification are implemented. Genuine Groth16 proofs are implemented for the [one-signature reference](BLS_PROOF.md) and [two-entry aggregate batch](BLS_BATCH.md).

## Fixed scheme

| Parameter | Value |
| --- | --- |
| Curve | BLS12-381 |
| Scheme | Basic, minimal public keys |
| Public key | G1, 48-byte compressed encoding in JSON |
| Signature | G2, 96-byte compressed encoding in JSON |
| Message | Arbitrary bytes, hex-encoded in JSON |
| Ciphersuite / DST | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` |
| Hash to curve | SHA-256 XMD, hash to Fp2, SWU, isogeny, cofactor clearing |
| Hash-to-field parameters | `count = 2`, `m = 2`, `L = 64` |

The scheme follows the [CFRG BLS draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature#section-3.1) and [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html). Its signature curve is independent of the existing demo's BN254 Groth16 proof curve.

Verification checks `e(publicKey, H(message)) = e(G1, signature)`. Both key and signature must have valid canonical encodings, lie in the correct prime-order subgroup, and differ from infinity. The DST is fixed in code; a JSON statement selecting another suite is rejected.

The Rust CLI below verifies individual signatures. The Solidity reference also exposes `verifyAggregate` for exactly two distinct complete messages; it hashes both on-chain and performs one three-pair pairing check. The [batch proof backend](BLS_BATCH.md) verifies a Basic aggregate over distinct framed messages; its fixed position bytes enforce that requirement. Shared-message aggregation would require a different, explicitly specified rogue-key defence and suite.

## Native Rust reference

[src/bls.rs](../src/bls.rs) uses the pinned `blst` dependency for decoding, subgroup checks, hashing and verification. The CLI is separate from the demo prover:

```sh
cargo run --locked --bin bls-reference -- verify \
  --input test/fixtures/bls12_381_basic.json

cargo run --locked --bin bls-reference -- fixture \
  --message "blsZK BLS12-381 reference" --output /tmp/blszk-statement.json
```

`fixture` signs using the publicly known test IKM `[0x42; 32]`. It produces reproducible test data, without exporting a private key. It is not a wallet/key-management command.

The input format has exactly four required string fields: `ciphersuite`, `message`, `publicKey`, and `signature`. See the [committed fixture](../test/fixtures/bls12_381_basic.json). Hex strings allow an optional lowercase `0x` prefix. Unknown JSON fields, malformed hex, wrong point lengths and unsupported suites cause an error. Well-formed invalid signatures return failure. CLI failures have a nonzero exit status.

## Direct Solidity reference

[BLS12381Verifier.sol](../contracts/BLS12381Verifier.sol) uses Prague's [EIP-2537 precompiles](https://eips.ethereum.org/EIPS/eip-2537). The Hardhat network is explicitly configured for Prague.

`verify(message, publicKey, signature)` takes raw message bytes and uncompressed EIP-2537 points:

| Input | Encoding |
| --- | --- |
| G1 public key | `x || y`, 128 bytes total |
| G2 signature | `x.c0 || x.c1 || y.c0 || y.c1`, 256 bytes total |
| Each Fp coordinate | 64-byte big-endian integer; first 16 bytes zero; value below p |

The contract computes SHA-256 XMD expansion and hash-to-field itself. It uses MODEXP with exponent 1 to reduce full 512-bit values modulo the 381-bit field modulus, avoiding truncation to `uint256`. EIP-2537 performs the field-to-G2 mapping, cofactor clearing, G2 addition, and pairing check. The public `hashToG2` function exposes the intermediate point for interoperability tests; `verify` always computes it from the supplied message bytes.

Invalid point lengths or infinity return `false`. Pairing failures return `false`. Required hash-to-curve precompile failures revert, including empty responses on an unsupported fork. Gas forwarded to curve precompiles is bounded.

This reference has no signer registry, replay policy, account state, batch commitment, or rollup integration. Applications must define their signed message encoding and authorization separately. The legacy adapter remains a Poseidon demo. The [real BLS proof consumer](../contracts/BLSProofVerifier.sol) is a separate implementation for the supported one-signature circuit.

## Validation

```sh
npm run test:bls
cargo test --locked
```

Tests compare Rust/blst signatures, independent noble-curves signatures, and Solidity verification. Hash-to-curve results are compared for empty, binary, and boundary-length messages. Rejection coverage includes changed messages/keys/signatures, a different DST, invalid lengths and coordinates, infinity, and on-curve points outside the relevant subgroup. Test fixtures contain no private user data.

These tests establish a development reference, not an audit or a proof-system soundness claim.
