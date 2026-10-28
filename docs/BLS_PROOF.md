# Proof of real BLS verification

The [gnark backend](../proofs/gnark/) generates a genuine BN254 Groth16 proof of Basic/min-pk BLS12-381 verification. It has been tested with the committed blst signature fixture, native proof verification, and a transaction invoking the Solidity proof consumer on Hardhat's local Ethereum VM.

## Scope and statement

This first circuit supports **one signature over exactly 25 message bytes**. The [reference fixture](../test/fixtures/bls12_381_basic.json) signs the UTF-8 message `blsZK BLS12-381 reference`. Other messages of the same byte length and other valid keys/signatures use the same circuit and setup. The byte length is a circuit parameter, not a padding convention; the circuit does not silently pad or prehash user messages.

The fixed ciphersuite is `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`. The signature is a private G2 witness. Public inputs are:

1. Six little-endian 64-bit limbs for the G1 public key's canonical x coordinate.
2. Six limbs for its canonical y coordinate.
3. All 25 message bytes, in order.

All 37 public values are bound to the proof. The circuit constrains message bytes, canonical field values, nonidentity points, curve/subgroup membership, SHA-256 XMD expansion, hash-to-field, mapping/cofactor clearing to G2, and the BLS pairing equation. There is no public `isValid = false` success path.

The JSON input uses compressed IETF key/signature encodings, which the Go host decodes into affine coordinates. The circuit independently validates those coordinates. Host-side decoding is not a substitute for the in-circuit signature checks. It accepts no caller-supplied message hash or precomputed pairing lines.

## Run

Install Node.js/npm and Go **1.26.8 or newer**, then run from the repository root:

```sh
npm ci
npm run test:bls:proof
```

The command builds the pinned backend, runs its adversarial witness tests, creates development keys if missing/stale, proves the fixture, verifies it natively, exports/compiles the Solidity verifier, and tests it on the local EVM.

On the development Mac, a fresh setup took about six minutes. Circuit/key caches are reused when the embedded source/dependency fingerprint matches. Changing the circuit/backend or its dependency files invalidates the cache. A source fingerprint is a cache check; trusted setup and review of the actual generated verifier remain necessary.

Useful commands:

```sh
npm run bls:proof:inspect
npm run bls:proof:setup
npm run bls:proof:prove -- test/fixtures/bls12_381_basic.json
```

`setup` explicitly regenerates keys. Redeploy the verifier and regenerate proofs afterward. The setup is a single-machine development setup, not a production ceremony.

The backend uses four Go execution workers and a 3 GiB Go heap GC target. This is not a hard total-process memory limit. Local generation succeeded on the development 8 GB Mac; this is not a guarantee for every environment or larger circuit.

## Files and encoding

Generated artifacts are ignored under `proofs/gnark/build/`:

| File | Purpose |
| --- | --- |
| `circuit.r1cs` | Full BLS constraint system |
| `proving.key`, `verifying.key` | Development Groth16 keys |
| `circuit.json` | Schema, source fingerprint, constraint/input counts, verifying-key hash |
| `BLSGroth16Verifier.sol` | Solidity verifier exported from the actual verifying key |
| `proof.json` | Public statement, proof bytes, public inputs, and proving time |
| `evm-verification.json` | Local verification transaction measurements |

The exported Solidity source is copied into `contracts/generated/`. The proof artifact exposes the public message and uncompressed EIP-2537 G1 key encoding; it does not include the signature witness.

Use the entire `proof` byte string. In the current circuit it is **384 bytes**, including gnark's Pedersen commitment and proof of knowledge. Its encoding differs from the legacy snarkjs demo's proof JSON and 256-byte coordinate layout.

## Solidity consumer

[BLSProofVerifier.sol](../contracts/BLSProofVerifier.sol) rebuilds all public inputs from the submitted message and 128-byte EIP-2537 public key. It enforces zero high padding so no supplied key bytes are ignored. Its generated verifier address and expected verifying-key hash are immutable. Successful `verifyProof` calls return normally; invalid proofs revert.

```js
await verifier.verifyProof(artifact.message, artifact.publicKey, artifact.proof);
```

For a persistent local deployment, generate keys and run a local node:

```sh
npm run bls:proof:setup
npm run node
```

In another terminal:

```sh
npm run bls:proof:deploy
```

This deploys the actual generated verifier and its statement-binding consumer. The legacy `npm run deploy` continues to deploy the separate Poseidon bookkeeping demo.

This consumer is stateless: it does not authorize keys, prevent replay, aggregate signatures, or prove account-state transitions. Those are subsequent roadmap items. The generated verifier is a trusted deployment dependency; its self-reported key identifier is not independent bytecode attestation.

## Validation and measurements

The Go tests bypass JSON/native validation to inject adversarial witnesses into the circuit. They reject changed messages, keys and signatures, identity/non-subgroup keys, out-of-range message bytes, and noncanonical coordinate aliases. The EVM tests verify a genuine proof, compare all reconstructed public inputs, submit a transaction, and reject changes to any message byte, another key, noncanonical padding, malformed proofs, and a mismatched verifier key. They also check the standard Ethereum deployed-code size limit.

One development run recorded **2,090,737 constraints**, **384 proof bytes**, approximately **12.7 seconds** in `groth16.Prove`, and **713,281 gas** for the complete local verification transaction. Proving time excludes compilation, setup, artifact loading, and Solidity compilation. Keys/proofs are randomized, so transaction gas can vary slightly with calldata bytes. These are prototype observations, not comparative BLS savings or throughput results.
