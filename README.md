# blsZK

An experimental project studying BLS batch validity proofs and the trade-offs between off-chain proving and Ethereum verification.

**Current status:** a working Circom → snarkjs → Rust CLI → Solidity pipeline for a **Poseidon demo relation**, plus real **BLS12-381 reference verification** in Rust and Solidity. BLS verification inside a ZK proof, signature aggregation, and proven rollup state transitions remain to be implemented. The Groth16 demo does not establish BLS security or the presentation's performance claims.

## Why use this project?

- Generate and verify actual Groth16 proofs on BN254, including on a local EVM.
- Verify actual BLS12-381 signatures natively and through Ethereum precompiles, with independent interoperability and rejection tests.
- Build circuit artifacts with a pinned local Circom compiler and compile contracts with a pinned Solidity compiler.
- Use a Rust CLI for artifact loading, proving, verification, Solidity calldata export, and demo timing.
- Test sequencer access control and submission bookkeeping separately from cryptographic verification.
- Extend a reproducible baseline toward real BLS batch proofs. See the [implementation roadmap](docs/ROADMAP.md).

## Getting started

### Prerequisites

- Node.js 22 or newer and npm 9 or newer. Node.js 22 is recorded in [.nvmrc](.nvmrc).
- Rust and Cargo supporting the Rust 2021 edition; no minimum Rust version is pinned.
- A C compiler such as Clang or GCC for the `blst` Rust dependency.
- A Bash-compatible shell. No global Circom or snarkjs installation is required.

```sh
git clone https://github.com/msalauchuk/blsZK.git
cd blsZK
npm ci
npm run test:proof
```

`test:proof` compiles the circuit, creates development proving keys, generates a satisfying sample input and proof, builds the Rust CLI, compiles the Solidity verifier, and runs the real-proof integration tests on Hardhat's local EVM. Contributions use fresh randomness; proofs and key files vary between runs.

The local `circom2` package bundles Circom 2.2.3 as WASM. To use an installed native compiler, set `CIRCOM_BIN=circom` when running `npm run circuit:compile`. Solidity 0.8.20 is loaded from the locked `solc` npm package, so compilation needs no additional compiler download.

The development setup runs a single-machine ceremony. It is not a production trusted setup. A reusable Powers of Tau file is cached locally; circuit-specific keys and the verifier are regenerated on each circuit compilation. Regenerate proofs and redeploy any verifier after recompiling.

### Common commands

Run these from the repository root:

| Command | Purpose |
| --- | --- |
| `npm run circuit:compile` | Compile the demo, create development keys, and export the Solidity verifier |
| `npm run circuit:prove` | Generate a satisfying demo fixture and a snarkjs proof |
| `npm run circuit:prove -- /path/to/input.json` | Prove a supplied input file without replacing it |
| `npm run prover:build` | Build the Rust CLI in release mode |
| `npm run full:setup` | Generate circuit artifacts and build the release CLI and Solidity contracts |
| `npm test` | Run mock bookkeeping tests and direct Solidity BLS tests |
| `npm run test:proof` | Build prerequisites and test real proofs across Rust, snarkjs, and Solidity |
| `npm run test:bls` | Build the native reference and test real BLS verification across Rust, JavaScript, and Solidity; no ZK proof |
| `cargo test --locked` | Run native BLS, parser, artifact-loading, and CLI validation tests |
| `cargo clippy --all-targets --locked -- -D warnings` | Check Rust code for warnings |
| `npm run prover:bench` | Time repeated proofs of the same satisfying demo fixture; run `circuit:prove` first |
| `REPORT_GAS=true npm test` | Gas reporting for the standard tests; no ZK/BLS savings comparison |

### Real BLS reference verification

The selected scheme is BLS12-381 Basic/min-pk: 48-byte compressed G1 public keys, 96-byte compressed G2 signatures, and the fixed `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` ciphersuite. Message bytes are hashed to G2 with SHA-256 XMD and the RFC 9380 mapping. Infinity and invalid/non-subgroup points are rejected.

```sh
npm run test:bls
cargo run --locked --bin bls-reference -- verify \
  --input test/fixtures/bls12_381_basic.json
```

Use `bls-reference fixture` to generate deterministic statements signed with a publicly known test key. Its `--message` argument is UTF-8 text; the verification JSON accepts arbitrary hex-encoded message bytes. These fixtures are not wallet keys.

[BLS12381Verifier](contracts/BLS12381Verifier.sol) verifies signatures directly using Prague's EIP-2537 precompiles. It computes hash-to-curve from the raw message inside the contract. Its EIP-2537 point encoding differs from compressed Rust/JSON input. See the [reference specification](docs/BLS_REFERENCE.md) for formats and examples.

This verifier is a reference/baseline, and is not connected to the rollup's Groth16 verifier interface. A proof of this BLS computation remains the next milestone; see the [backend assessment](docs/BLS_PROVING.md).

### What the demo proves

The circuit enforces this field relation:

```text
Poseidon(messageHash, signatureX, signatureY, publicKeyX)
    == publicKeyX + publicKeyY
```

`isValid` is constrained to `1`. The sample generator computes `publicKeyY` to satisfy this equation; the named inputs are **not BLS key/signature points**. This relation has no BLS pairing or hash-to-curve operation.

The public-signal order is `[isValid, messageHash, publicKeyX, publicKeyY]`. The [demo adapter](contracts/DemoVerifierAdapter.sol) supplies `isValid = 1` and maps exactly one tuple into the generated verifier's fixed-size ABI. It rejects multi-tuple inputs. This lets the existing rollup interface exercise a real proof without claiming batch verification.

### Rust CLI

Build with `cargo build --locked`, then inspect `./target/debug/bls-prover --help`. Its default circuit directory is `./circuits`.

Load existing artifacts and optionally export the verification key:

```sh
cargo run --locked -- setup --output circuits/build/exported_verification_key.json
```

`setup` loads files created by `circuit:compile`; it does not perform a ceremony. To prove the generated sample using the Rust wrapper:

```sh
DEMO_PUBLIC_KEY_Y="$(node -p 'require("./circuits/test_input.json").publicKeyY')"
cargo run --locked -- prove \
  --message-hash 12345678901234567890 \
  --public-key-x 98765432109876543210 \
  --public-key-y "$DEMO_PUBLIC_KEY_Y" \
  --signature-x 22222222222222222222 \
  --signature-y 33333333333333333333 \
  --output circuits/build/rust_proof.json

cargo run --locked -- verify --proof-file circuits/build/rust_proof.json
```

The output includes `proof` (hex-encoded snarkjs proof JSON), `publicInputs`, `solidityCalldata`, and `stats`. The JSON proof bytes are different from ABI-encoded Solidity proof coordinates. `proof_size_bytes` measures JSON size; `num_constraints` is `null` because the wrapper does not read R1CS metadata. Proving time includes witness generation and process startup; verification time includes its snarkjs process startup. Each operation uses a separate temporary directory.

Raw snarkjs proof files are also supported:

```sh
cargo run --locked -- verify \
  --proof-file circuits/build/proof.json \
  --inputs-file circuits/build/public.json
```

Invalid proofs return a nonzero exit status. Proving and verification delegate to the project's local snarkjs installation, with a global `snarkjs` executable as a fallback. Rust does not implement a separate Arkworks prover. The library's `BatchProver` produces independent proofs sequentially; its concatenated bytes are not one aggregated proof.

### Local deployment

After `npm run full:setup`, start a local node:

```sh
npm run node
```

In another terminal at the repository root:

```sh
npm run deploy
```

The deployment script deploys the generated Groth16 verifier, the single-tuple demo adapter, and `ZKRollupBLS`. The deployer becomes sequencer. Addresses are saved to `deployments/<network>.json`. Deployment fails if the generated verifier is missing; there is no automatic mock fallback.

The rollup still accepts a sequencer-supplied state root that is not proven by the circuit. Proof replay protection and transitions between account states are not implemented. Use the current workflow for local experiments.

## Project layout

| Path | Purpose |
| --- | --- |
| [circuits/bls_verify.circom](circuits/bls_verify.circom) | Current Poseidon demo circuit |
| [src/lib.rs](src/lib.rs) | snarkjs orchestration and calldata parsing |
| [src/main.rs](src/main.rs) | `bls-prover` CLI |
| [src/bls.rs](src/bls.rs) | Native BLS12-381 validation using blst |
| [src/bin/bls-reference.rs](src/bin/bls-reference.rs) | Real BLS reference CLI |
| [contracts/BLS12381Verifier.sol](contracts/BLS12381Verifier.sol) | Direct on-chain BLS verification with hash-to-curve |
| [contracts/ZKRollupBLS.sol](contracts/ZKRollupBLS.sol) | Experimental submission bookkeeping and state tracking |
| [contracts/DemoVerifierAdapter.sol](contracts/DemoVerifierAdapter.sol) | Single-tuple adapter for the demo's four public signals |
| [contracts/test/MockBLSVerifier.sol](contracts/test/MockBLSVerifier.sol) | Configurable test double with no cryptography |
| [scripts/](scripts/) | Development setup, fixture/proof generation, and deployment |
| [test/](test/) | Mock bookkeeping and direct BLS verification tests |
| [integration/ProofPipeline.test.js](integration/ProofPipeline.test.js) | Real-proof interoperability and rejection tests |
| [hardhat.config.js](hardhat.config.js) | Solidity compiler, local networks, and gas reporting |

Generated files live in `circuits/build/` and `contracts/generated/` and are ignored by Git. Manifests and lockfiles are tracked normally.

## Help and documentation

Use the repository's **Issues** tab for questions and reproducible bug reports. Include tool versions, the command run, and its output. Read the [roadmap](docs/ROADMAP.md), [BLS reference](docs/BLS_REFERENCE.md), [CLI source](src/main.rs), and [integration tests](integration/ProofPipeline.test.js) for scope and examples.

Upstream references: [Circom](https://github.com/iden3/circom), [circom2 WASM compiler](https://github.com/antimatter15/circom), [snarkjs](https://github.com/iden3/snarkjs), and [Hardhat 2](https://v2.hardhat.org/hardhat-runner/docs/getting-started).

## Maintainers and contributions

[Cargo.toml](Cargo.toml) lists **ZK-Rollup** as the author. No dedicated maintenance contact is documented; coordinate through repository issues and pull requests.

Fork the repository, create a focused branch, and open a pull request describing the behavior change and checks performed. Run the relevant Rust, contract, and real-proof tests listed above. For circuit changes, regenerate keys/proofs and include rejection tests. Mock gas measurements must not be presented as real BLS verification savings.

Keep private keys, `.env`, generated proofs, and build outputs out of commits. There is no separate contribution guide or CI workflow yet.

## License

The package manifests declare **MIT**, and Solidity sources carry MIT SPDX labels. A standalone `LICENSE` file has not yet been supplied.
