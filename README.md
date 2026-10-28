# blsZK

An educational prototype for exploring off-chain Groth16 proofs and Ethereum batch submission. The project combines a Circom circuit, a Rust prover wrapper around snarkjs, and Solidity contracts that record submissions and update an L2 state root.

**Status: experimental and incomplete.** The circuit demonstrates a Poseidon-based relation; it does not implement BLS signature verification or elliptic-curve pairings. The current checkout also has build and integration blockers described below. Use it for learning and development experiments.

## Why use this project?

- Explore the circuit → witness → Groth16 proof → verifier workflow on BN254.
- Experiment with public message/key inputs and private signature-coordinate witnesses.
- Study sequencer-controlled batch submission, submission events, and state tracking in Solidity.
- Extend a Rust CLI with setup, proving, verification, and timing commands.
- Inspect Hardhat tests for access control, batch validation, and gas measurements.

## Project layout

| Path | Purpose |
| --- | --- |
| [circuits/bls_verify.circom](circuits/bls_verify.circom) | Simplified verification relation and signature-coordinate range checks |
| [src/lib.rs](src/lib.rs) | snarkjs process wrapper, verification-key loading, and sequential batch proving |
| [src/main.rs](src/main.rs) | `bls-prover` CLI |
| [contracts/ZKRollupBLS.sol](contracts/ZKRollupBLS.sol) | Batch submission, submission records, and L2 state tracking |
| [contracts/IBLSVerifier.sol](contracts/IBLSVerifier.sol) | Separate bytes-based verifier interface |
| [scripts/](scripts/) | Circuit setup, sample proof generation, and deployment helpers |
| [test/ZKRollupBLS.test.js](test/ZKRollupBLS.test.js) | Hardhat tests intended to use a mock verifier |
| [benches/proving_benchmark.rs](benches/proving_benchmark.rs) | Benchmark placeholder |
| [hardhat.config.js](hardhat.config.js) | Solidity 0.8.20, optimizer, networks, and gas reporter settings |

## Getting started

### Prerequisites

- Git, Node.js, and npm. [package.json](package.json) declares Node.js `>=18` and npm `>=9`; use a Node.js version supported by the installed Hardhat 2 release.
- A Circom **2.x** compiler on `PATH` for circuit work. See the [Circom compiler repository](https://github.com/iden3/circom) for installation instructions.
- Rust and Cargo with Rust 2021 edition support for the prover. No minimum Rust version is pinned.
- A Bash-compatible shell for the examples and helper scripts.

```sh
git clone https://github.com/msalauchuk/blsZK.git
cd blsZK
npm install
export PATH="$PWD/node_modules/.bin:$PATH"
```

The supplied `package-lock.json` differs from `package.json`; use `npm install` to reconcile it before adopting `npm ci`. The `PATH` addition exposes the local `snarkjs` executable to scripts and the Rust wrapper; repeat it in each new shell.

### Current setup blockers

These limitations apply to the supplied source, before any local fixes:

| Area | What needs attention |
| --- | --- |
| npm shortcuts | `circuit:*` scripts look for helpers under `circuits/scripts/`, but helpers live in `scripts/`. `prover:*` scripts expect a nonexistent `prover/` directory. `full:setup` inherits these problems. |
| Circuit helpers | Both shell helpers resolve the circuit directory to the repository root, so their input and output paths differ from `circuits/build/`, which the prover expects. Use the direct circuit commands below. |
| Rust build | `src/lib.rs` imports undeclared `ark_ec`; Arkworks 0.4 dependencies are mixed with `ark-circom` 0.5. `BLSProofInputs` lacks `Clone` for batch proving, and the CLI passes proof bytes where `verify_proof` expects JSON text. Dependency/API alignment is required. |
| Solidity build and tests | `ZKRollupBLS.sol` starts with `/ SPDX...` instead of a valid comment. Tests and the deployment fallback require `MockBLSVerifier`, whose source is absent. |
| On-chain integration | The rollup calls a verifier with a dynamic `uint256[]`; snarkjs generates a fixed-size public-signal parameter. The circuit exposes four public signals, while the rollup prepares three per submission. An adapter or coordinated circuit/contract changes are required. |

### Compile the circuit and create development keys

Run from the repository root after installing dependencies and Circom. These direct commands bypass the helper path problems:

```sh
mkdir -p circuits/build
circom circuits/bls_verify.circom --r1cs --wasm --sym \
  -l node_modules -o circuits/build
snarkjs r1cs info circuits/build/bls_verify.r1cs

cd circuits/build
snarkjs powersoftau new bn128 12 pot12_0000.ptau
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau \
  --name="Local development"
snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau
snarkjs groth16 setup bls_verify.r1cs pot12_final.ptau bls_verify_0000.zkey
snarkjs zkey contribute bls_verify_0000.zkey bls_verify_final.zkey \
  --name="Local development"
snarkjs zkey verify bls_verify.r1cs pot12_final.ptau bls_verify_final.zkey
snarkjs zkey export verificationkey bls_verify_final.zkey verification_key.json
snarkjs zkey export solidityverifier bls_verify_final.zkey Verifier.sol
cd ../..
```

The contribution commands prompt for entropy. This is a local development setup; it does not establish a production ceremony. Power `12` accommodates up to 4,096 constraints; increase it if circuit changes exceed that capacity. See the [snarkjs setup guide](https://github.com/iden3/snarkjs#guide) for ceremony details.

The generated files under `circuits/build/` include the R1CS, witness-generator JavaScript/WASM, proving key, verification key, and Solidity verifier. Regenerate the keys and verifier whenever the circuit changes.

### Generate and verify an example proof

Create an input file at the repository root. Values are decimal strings representing field elements:

```sh
cat > circuits/test_input.json <<'JSON'
{
  "messageHash": "12345678901234567890",
  "publicKeyX": "98765432109876543210",
  "publicKeyY": "11111111111111111111",
  "signatureX": "22222222222222222222",
  "signatureY": "33333333333333333333"
}
JSON

snarkjs groth16 fullprove circuits/test_input.json \
  circuits/build/bls_verify_js/bls_verify.wasm \
  circuits/build/bls_verify_final.zkey \
  circuits/build/proof.json circuits/build/public.json

snarkjs groth16 verify circuits/build/verification_key.json \
  circuits/build/public.json circuits/build/proof.json

snarkjs zkey export soliditycalldata \
  circuits/build/public.json circuits/build/proof.json
```

`proof.json` contains the Groth16 proof; `public.json` contains `[isValid, messageHash, publicKeyX, publicKeyY]`. Solidity calldata is printed to the terminal.

**Proof verification does not establish signature validity here.** The circuit computes whether `Poseidon(messageHash, signatureX, signatureY, publicKeyX)` equals `publicKeyX + publicKeyY`, but never constrains `isValid` to `1`. An output of `0` can therefore have a valid proof. The sample inputs demonstrate the proof workflow without asserting that this relation holds.

### Rust prover CLI

After resolving the Rust build blockers above, build from the repository root:

```sh
cargo build --release
./target/release/bls-prover --help
./target/release/bls-prover setup --circuit-path ./circuits \
  --output circuits/build/exported_verification_key.json
./target/release/bls-prover prove --circuit-path ./circuits \
  --message-hash 12345678901234567890 \
  --public-key-x 98765432109876543210 \
  --public-key-y 11111111111111111111 \
  --signature-x 22222222222222222222 \
  --signature-y 33333333333333333333 \
  --output circuits/build/rust_proof.json
```

Always pass `--circuit-path ./circuits` when running from the root; the CLI defaults to `../circuits`. Its `setup` command loads existing snarkjs artifacts and optionally exports the verification-key JSON. It does not perform a trusted setup.

The CLI output file contains `proof` (hex-encoded proof JSON), `publicInputs`, and timing/size statistics. This differs from snarkjs's `proof.json` and from the contract's 256-byte coordinate encoding. The library's Solidity-calldata parser currently returns placeholders; use the direct snarkjs calldata export for experiments. The CLI `verify` path needs the type fix noted above and currently requires an unused `--inputs-file` argument.

`BatchProver` generates individual proofs sequentially and concatenates their JSON bytes. It does not aggregate proofs into one Groth16 proof.

### Contracts and local deployment

After repairing the Solidity build, supplying the mock verifier for tests, and resolving the verifier integration:

```sh
npm run compile
npm test
REPORT_GAS=true npm test
npm run coverage
```

The tests exercise batch submission through struct and bytes interfaces, sequencer permissions, submission records, state reads, verifier updates, and gas usage. They use a mock verifier, so their results do not validate the circuit or establish real-proof gas savings.

To make the generated verifier available before Hardhat compiles:

```sh
cp circuits/build/Verifier.sol contracts/Verifier.sol
npm run compile
npm run node
```

Keep the node running, then open another terminal at the repository root:

```sh
npm run deploy
```

[scripts/deploy.js](scripts/deploy.js) uses the deployer as sequencer and writes addresses and verifier type to `deployments/<network>.json`. It attempts a generated verifier and falls back to `MockBLSVerifier` if unavailable; that fallback requires the missing mock contract. Copying the generated source before compilation avoids the script's first-run artifact ordering issue, but the verifier ABI and public-signal mismatches still require implementation changes.

The rollup records a sequencer-supplied state root. That root is not bound to the circuit's public signals, and the circuit handles a single input tuple rather than proving a batch state transition.

## Development and contributions

Contributions can focus on the setup blockers, enforcing the intended circuit relation, aligning the verifier ABI/public signals, and adding integration tests with real proofs.

1. Fork the repository and create a focused branch.
2. Make the change and add tests for the affected behavior.
3. Run the relevant checks from the root: `cargo check`, `cargo test`, `npm run compile`, and `npm test`. For circuit changes, regenerate artifacts and verify a sample proof.
4. Open a pull request describing the behavior change, validation performed, and any remaining blockers.

The Rust tests and benchmark are currently placeholders. There is no CI configuration or separate contribution guide in this checkout; report which checks actually ran and passed.

Keep `.env`, private keys, generated proofs, and build outputs out of commits. Review [.gitignore](.gitignore) when contributing: its broad `*.json` rule also ignores package manifests and lockfiles unless already tracked or explicitly included.

## Help and documentation

- Use the repository's **Issues** tab for questions and reproducible bug reports, and **Pull requests** for proposed changes. Include tool versions, the command run, and the error output.
- Read the [circuit](circuits/bls_verify.circom), [CLI](src/main.rs), [prover library](src/lib.rs), and [contract tests](test/ZKRollupBLS.test.js) for implementation examples.
- Consult the upstream [Circom repository](https://github.com/iden3/circom), [snarkjs documentation](https://github.com/iden3/snarkjs), and [Hardhat 2 documentation](https://v2.hardhat.org/hardhat-runner/docs/getting-started).

## Maintainers

[Cargo.toml](Cargo.toml) lists **ZK-Rollup** as the author. No individual maintainer or dedicated support contact is documented in the checkout. Coordinate maintenance and contributions through repository issues and pull requests.

## License

The package manifests declare **MIT**, and the Solidity sources contain MIT SPDX labels. A standalone `LICENSE` file is not included in this checkout; maintainers should add it to document the licensing terms.
