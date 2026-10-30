# blsZK

blsZK verifies BLS signature batches off-chain and submits a Groth16 proof to Ethereum. It combines BLS12-381 signature aggregation, gnark circuits, and Solidity verification to compare L1 gas costs with direct on-chain BLS verification.

The current circuit verifies an aggregate of two BLS12-381 Basic/min-pk signatures in one BN254 Groth16 proof. Each entry carries a 25-byte payload, signed together with its chain, contract, batch number, size, and position. The Solidity consumer checks authorized keys, rejects replayed batches, and records a verified batch commitment. It does not execute payloads or prove account-state transitions. The earlier one-signature proof is retained as a separate reference.

The repository includes reproducible benchmarks, tests, and local deployment scripts. See the [benchmark guide](docs/BENCHMARKS.md) for measurements and the [roadmap](docs/ROADMAP.md) for completed milestones and possible extensions.

## Why use this project?

- Generate a genuine proof covering BLS hash-to-curve, point/subgroup validation, and the pairing equation.
- Bind all batch entries and their signed submission context to a canonical SHA-256 commitment.
- Enforce signer authorization and sequential batch IDs on-chain.
- Cross-check the signature scheme using independent Rust/blst, JavaScript, and direct Solidity implementations.
- Inspect acceptance and adversarial-witness tests alongside local gas measurements.
- Extend batch capacity and compare off-chain computation with direct Ethereum verification. See the [roadmap](docs/ROADMAP.md).

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
npm run test:bls:batch
```

The command builds the pinned Go backend, tests adversarial witnesses, generates development keys if needed, and deploys the actual exported Solidity verifier locally. It signs the deployment context with deterministic test keys, produces one genuine aggregate-BLS proof, verifies it natively, and submits a local EVM transaction. It also tests altered entries, authorization, and replay rejection.

Fresh batch key generation took about 13 minutes on the development Mac; later runs reuse compatible circuit/key artifacts. The proving process uses four Go workers and a 3 GiB Go heap GC target, which is not a hard process-memory cap. Local generation was validated on an 8 GB Mac.

The setup is a single-machine **development ceremony**. Production use requires an appropriate trusted setup and review. Generated keys, proofs, and Solidity exports are ignored by Git.

### Commands

Run these from the repository root:

| Command | Purpose |
| --- | --- |
| `npm run test:bls:batch` | Full two-entry aggregate-BLS proof and local-EVM workflow |
| `npm run bench:bls:batch` | Compare individual BLS, aggregate BLS, and ZK with identical batch/state accounting |
| `npm run bls:batch:inspect` | Compile the batch circuit and report its size |
| `npm run bls:batch:setup` | Regenerate batch development keys and the generated verifier |
| `npm run bls:batch:prove -- batch.json` | Prove an aggregate signed for a deployment/batch context |
| `npm run test:bls:proof` | Separate one-signature proof reference workflow |
| `npm run bls:proof:inspect` | Compile the BLS circuit and report its size |
| `npm run bls:proof:setup` | Explicitly regenerate the BLS circuit's development keys and verifier |
| `npm run bls:proof:prove -- statement.json` | Prove a supported BLS statement using existing/current setup artifacts |
| `npm run test:bls` | Rust/JavaScript/direct-Solidity reference verification, without a ZK proof |
| `npm test` | Mock bookkeeping and direct Solidity BLS tests |
| `cargo test --locked` | Native BLS, parser, artifact-loading, and CLI tests |
| `cargo clippy --all-targets --locked -- -D warnings` | Rust warning checks |

The batch circuit supports exactly two active entries with 25-byte payloads under `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`. Its complete signed messages are 119-byte frames covering payload and submission context. See the [batch guide](docs/BLS_BATCH.md) for aggregation, framing, commitment encoding, and limitations. The separate [one-signature circuit](docs/BLS_PROOF.md) accepts 25 raw message bytes.

### Local batch deployment and demonstration

Generate batch keys and start a persistent local node:

```sh
npm run bls:batch:setup
npm run node
```

In another terminal at the repository root:

```sh
npm run bls:batch:deploy
npm run bls:batch:demo
```

This deploys the generated batch verifier and [BLSBatchVerifier](contracts/BLSBatchVerifier.sol). The local demo authorizes public test keys, signs the current chain/contract/batch context, generates one aggregate-BLS proof, and submits both entries. Repeating the demo signs and submits the next batch. Deployment addresses are saved to `deployments/<network>-bls-batch.json`.

Real applications collect context-bound signatures from their signers and authorize the corresponding keys through the deploying owner. The [batch guide](docs/BLS_BATCH.md) describes the prover's JSON input and `submitBatch` arguments. Generated proofs and local transaction measurements are saved under `proofs/gnark/build/batch/`. Regenerating keys requires new proofs and a new verifier deployment.

The batch contract records verified commitments and enforces replay/authorization checks. It does not execute payloads or prove account-state transitions. The earlier [BLSProofVerifier](contracts/BLSProofVerifier.sol) remains a separate stateless one-signature consumer.

### Comparison benchmark

Run `npm run bench:bls:batch` with Python 3.8 or newer installed on macOS/Linux. It generates genuine proofs for the first and subsequent batch states and compares direct individual, direct aggregate, and ZK verification with identical signed data, authorization, and storage effects. It records transaction gas/calldata, proving and full-command time, peak child-process memory, deployments, environment metadata, and raw samples. The [reference two-entry pilot](benchmarks/reference/batch2-prague.md) measured ZK gas about 6.3–6.6% below the implemented direct aggregate baseline. See the [benchmark guide](docs/BENCHMARKS.md) for raw results, repetitions, optional fresh-setup measurements, and interpretation limits. This result does not establish a crossover batch size or throughput.

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
| [proofs/gnark/batch/](proofs/gnark/batch/) | Aggregate-BLS batch circuit, prover, and adversarial witness tests |
| [contracts/BLSBatchVerifier.sol](contracts/BLSBatchVerifier.sol) | Batch commitment, signer authorization, and replay protection |
| [integration/BLSBatch.test.js](integration/BLSBatch.test.js) | Genuine aggregate proof acceptance and adversarial contract tests |
| [proofs/gnark/](proofs/gnark/) | One-signature BLS circuit/reference and pinned Go dependencies |
| [contracts/BLSProofVerifier.sol](contracts/BLSProofVerifier.sol) | Real BLS proof consumer with public-statement/key binding |
| [integration/BLSProof.test.js](integration/BLSProof.test.js) | Genuine BLS proof acceptance, transaction, and tampering tests |
| [src/bls.rs](src/bls.rs) | Native BLS12-381 reference verification |
| [src/bin/bls-reference.rs](src/bin/bls-reference.rs) | Native reference CLI |
| [contracts/BLS12381Verifier.sol](contracts/BLS12381Verifier.sol) | Direct on-chain BLS baseline |
| [circuits/bls_verify.circom](circuits/bls_verify.circom) | Legacy Poseidon demo |
| [src/lib.rs](src/lib.rs), [src/main.rs](src/main.rs) | Legacy snarkjs orchestration/CLI and reference module exports |
| [contracts/ZKRollupBLS.sol](contracts/ZKRollupBLS.sol) | Legacy batch bookkeeping and state-root storage |
| [scripts/](scripts/) | Setup, proving, and deployment workflows |
| [test/](test/), [integration/](integration/) | Reference, mock bookkeeping, and proof tests |

Generated artifacts live under `proofs/gnark/build/`, `circuits/build/`, and `contracts/generated/`. Manifests and dependency lockfiles are tracked.

## Help and documentation

Use the repository's **Issues** tab for questions and reproducible bug reports. Include tool versions, commands, and output. Start with the [batch guide](docs/BLS_BATCH.md), [benchmark guide](docs/BENCHMARKS.md), [one-signature proof guide](docs/BLS_PROOF.md), [BLS scheme reference](docs/BLS_REFERENCE.md), [backend rationale](docs/BLS_PROVING.md), and [roadmap](docs/ROADMAP.md).

Upstream references: [gnark](https://github.com/Consensys-Incorporated/gnark), [blst](https://github.com/supranational/blst), [Circom](https://github.com/iden3/circom), [snarkjs](https://github.com/iden3/snarkjs), and [Hardhat 2](https://v2.hardhat.org/hardhat-runner/docs/getting-started).

## Maintainers and contributions

[Cargo.toml](Cargo.toml) lists **ZK-Rollup** as the author. Coordinate maintenance through repository issues and pull requests; no dedicated maintenance contact or separate contribution guide is supplied.

Create a focused branch and open a pull request describing the behavior change and checks performed. Run relevant Rust, reference, circuit, and proof tests listed above. Circuit changes require fresh keys/proofs and rejection tests. For native Go checks, use `go -C proofs/gnark test ./...` and `go -C proofs/gnark vet ./...`. Keep `.env`, private user data, generated proofs, and keys out of commits.

## License

The manifests declare **MIT**, and Solidity sources carry MIT SPDX labels. A standalone `LICENSE` file has not yet been supplied.
