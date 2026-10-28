# blsZK

An experimental project proving BLS signature validity off-chain and checking the resulting Groth16 proof on Ethereum.

**Working milestone:** one real BLS12-381 Basic/min-pk signature over a **25-byte message** is verified inside a gnark circuit, proved with BN254 Groth16, and accepted by a Solidity consumer on a local Ethereum VM. The signature is a private witness. Batch proofs, signer authorization, replay protection, and rollup state transitions remain to be implemented.

## Why use this project?

- Generate a genuine proof covering BLS hash-to-curve, point/subgroup validation, and the pairing equation.
- Bind every public message byte and public-key coordinate to on-chain verification.
- Cross-check the signature scheme using independent Rust/blst, JavaScript, and direct Solidity implementations.
- Inspect acceptance and adversarial-witness tests alongside local gas measurements.
- Extend the prototype toward batch proofs and compare off-chain computation with direct Ethereum verification. See the [roadmap](docs/ROADMAP.md).

The repository also retains its earlier Circom/snarkjs **Poseidon demo** as a separate workflow. That circuit does not verify BLS signatures.

## Getting started

### Prerequisites

- Node.js 22 or newer and npm 9 or newer; [.nvmrc](.nvmrc) records Node.js 22.
- **Go 1.26.8 or newer** for the real BLS proof backend.
- A Bash-compatible shell. No global Circom, snarkjs, Docker, or zkVM installation is required for the proof workflow.
- Rust/Cargo with Rust 2021 support, plus a C compiler such as Clang/GCC, for the native blst reference and legacy Rust CLI. These are optional for the Go proof quick start.

```sh
git clone https://github.com/msalauchuk/blsZK.git
cd blsZK
npm ci
npm run test:bls:proof
```

The command builds the pinned Go backend, tests the circuit with adversarial witnesses, generates development keys if needed, proves the committed BLS fixture, verifies the proof natively, compiles the exported Solidity verifier, and submits a local EVM verification transaction. It also tests rejection of altered statements and proofs.

Fresh key generation took about six minutes on the development Mac; later runs reuse compatible circuit/key artifacts. The proving process uses four Go workers and a 3 GiB Go heap GC target, which is not a hard process-memory cap. Local generation was validated on an 8 GB Mac.

The setup is a single-machine **development ceremony**. Production use requires an appropriate trusted setup and review. Generated keys, proofs, and Solidity exports are ignored by Git.

### Commands

Run these from the repository root:

| Command | Purpose |
| --- | --- |
| `npm run test:bls:proof` | Full real-BLS proof and local-EVM acceptance/rejection workflow |
| `npm run bls:proof:inspect` | Compile the BLS circuit and report its size |
| `npm run bls:proof:setup` | Explicitly regenerate the BLS circuit's development keys and verifier |
| `npm run bls:proof:prove -- statement.json` | Prove a supported BLS statement using existing/current setup artifacts |
| `npm run test:bls` | Rust/JavaScript/direct-Solidity reference verification, without a ZK proof |
| `npm test` | Mock bookkeeping and direct Solidity BLS tests |
| `cargo test --locked` | Native BLS, parser, artifact-loading, and CLI tests |
| `cargo clippy --all-targets --locked -- -D warnings` | Rust warning checks |

The first circuit accepts exactly 25 raw message bytes, with the fixed ciphersuite `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`. The committed fixture signs `blsZK BLS12-381 reference`. Other valid statements of the same byte length use the same circuit/key. See the [proof workflow](docs/BLS_PROOF.md) for its statement, encoding, cache behavior, and measurements.

### Local deployment and verification

Generate keys and start a persistent local node:

```sh
npm run bls:proof:setup
npm run node
```

In another terminal at the repository root:

```sh
npm run bls:proof:deploy
```

This deploys the generated BLS Groth16 verifier and [BLSProofVerifier](contracts/BLSProofVerifier.sol), which pins the verifying-key hash and reconstructs all 37 public inputs from the submitted message and key. Addresses are saved to `deployments/<network>-bls-proof.json`.

The generated `proofs/gnark/build/proof.json` exposes `message`, `publicKey`, and `proof` for verification:

```js
await verifier.verifyProof(artifact.message, artifact.publicKey, artifact.proof);
```

Success returns normally; invalid proofs revert. Use the full proof byte string, including gnark's commitments and proof of knowledge. The current encoding is **384 bytes**, distinct from the legacy snarkjs proof JSON/coordinate encoding. Regenerating keys requires new proofs and a new verifier deployment.

This consumer is stateless. It does not authorize signers or enforce account-state transitions or replay protection.

## Native and direct BLS references

The selected scheme uses BLS12-381 with 48-byte compressed G1 public keys, 96-byte compressed G2 signatures, and SHA-256 XMD hash-to-curve. [src/bls.rs](src/bls.rs) verifies it using pinned blst; [BLS12381Verifier](contracts/BLS12381Verifier.sol) computes hash-to-curve and verifies it directly through Prague's EIP-2537 precompiles.

```sh
cargo run --locked --bin bls-reference -- verify \
  --input test/fixtures/bls12_381_basic.json
```

`bls-reference fixture` generates deterministic statements using a publicly known test key. Its `--message` argument is UTF-8 text; verification JSON accepts arbitrary hex-encoded message bytes. The native/direct references support more message lengths than the first proof circuit. See the [reference specification](docs/BLS_REFERENCE.md) for formats and tests.

## Legacy Poseidon demo

The original Circom/snarkjs pipeline enforces:

```text
Poseidon(messageHash, signatureX, signatureY, publicKeyX)
    == publicKeyX + publicKeyY
```

It constrains `isValid` to `1`, but contains no BLS curve operations. Its named key/signature inputs are demo field values. The sample generator constructs a satisfying relation.

| Command | Purpose |
| --- | --- |
| `npm run test:proof` | Build and test the legacy Poseidon Groth16 pipeline |
| `npm run circuit:compile` | Generate the demo's R1CS, WASM, development keys, and verifier |
| `npm run circuit:prove` | Generate a satisfying demo fixture and proof |
| `npm run prover:build` | Build the Rust CLIs in release mode |
| `npm run full:setup` | Set up the legacy circuit, release CLI, and contracts |
| `npm run deploy` | Deploy the legacy Poseidon adapter and bookkeeping contract locally |
| `npm run prover:bench` | Time repeated legacy demo proofs; generate its fixture first |

The `bls-prover` Rust CLI orchestrates local snarkjs. Its `setup` subcommand loads existing artifacts; it does not perform a ceremony. Run `cargo run --locked -- --help` for options. Its default circuit path is `./circuits`.

The library's `BatchProver` still generates independent proofs sequentially; concatenating their bytes is not proof aggregation. The legacy rollup records a sequencer-supplied state root that is not proven by its circuit. Its mock bookkeeping gas tests do not establish BLS verification savings.

## Project layout

| Path | Purpose |
| --- | --- |
| [proofs/gnark/](proofs/gnark/) | Full BLS circuit, prover, development setup, and adversarial witness tests |
| [contracts/BLSProofVerifier.sol](contracts/BLSProofVerifier.sol) | Real BLS proof consumer with public-statement/key binding |
| [integration/BLSProof.test.js](integration/BLSProof.test.js) | Genuine BLS proof acceptance, transaction, and tampering tests |
| [src/bls.rs](src/bls.rs) | Native BLS12-381 reference verification |
| [src/bin/bls-reference.rs](src/bin/bls-reference.rs) | Native reference CLI |
| [contracts/BLS12381Verifier.sol](contracts/BLS12381Verifier.sol) | Direct on-chain BLS baseline |
| [circuits/bls_verify.circom](circuits/bls_verify.circom) | Legacy Poseidon demo |
| [src/lib.rs](src/lib.rs), [src/main.rs](src/main.rs) | Legacy snarkjs orchestration/CLI and reference module exports |
| [contracts/ZKRollupBLS.sol](contracts/ZKRollupBLS.sol) | Experimental bookkeeping/state tracking |
| [scripts/](scripts/) | Setup, proving, and deployment workflows |
| [test/](test/), [integration/](integration/) | Reference, mock bookkeeping, and proof tests |

Generated artifacts live under `proofs/gnark/build/`, `circuits/build/`, and `contracts/generated/`. Manifests and dependency lockfiles are tracked.

## Help and documentation

Use the repository's **Issues** tab for questions and reproducible bug reports. Include tool versions, commands, and output. Start with the [BLS proof guide](docs/BLS_PROOF.md), [BLS scheme reference](docs/BLS_REFERENCE.md), [backend rationale](docs/BLS_PROVING.md), and [roadmap](docs/ROADMAP.md).

Upstream references: [gnark](https://github.com/Consensys-Incorporated/gnark), [blst](https://github.com/supranational/blst), [Circom](https://github.com/iden3/circom), [snarkjs](https://github.com/iden3/snarkjs), and [Hardhat 2](https://v2.hardhat.org/hardhat-runner/docs/getting-started).

## Maintainers and contributions

[Cargo.toml](Cargo.toml) lists **ZK-Rollup** as the author. Coordinate maintenance through repository issues and pull requests; no dedicated maintenance contact or separate contribution guide is supplied.

Create a focused branch and open a pull request describing the behavior change and checks performed. Run relevant Rust, reference, circuit, and proof tests listed above. Circuit changes require fresh keys/proofs and rejection tests. For native Go checks, use `go -C proofs/gnark test ./...` and `go -C proofs/gnark vet ./...`. Keep `.env`, private user data, generated proofs, and keys out of commits.

## License

The manifests declare **MIT**, and Solidity sources carry MIT SPDX labels. A standalone `LICENSE` file has not yet been supplied.
