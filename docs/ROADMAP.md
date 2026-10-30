# Roadmap

blsZK applies off-chain computation and on-chain proof verification to BLS signature batches. It compares this approach with direct Ethereum verification across L1 gas, calldata, proving time, memory use, and batch capacity.

The current implementation verifies batches of two signatures, binds each proof to its submitted data and context, and includes reproducible benchmarks. Account-state execution is a possible extension beyond signature verification.

## Measurement assumptions

Use 30M gas per block and 12-second slots as an explicitly labeled historical capacity model. Record the actual EVM fork, software versions, hardware, and date for each experiment. New runs using historical parameters remain dated reproductions of that model.

Historical traditional baselines, batch-size ranges, gas savings, proving times, and crossover claims are reference points to investigate. Identify the original operation and accounting before making comparisons; a plain ETH transfer performs a different task from contract-level signature verification. Keep measured transaction gas, modeled L1 capacity, and observed prover throughput distinct.

## Milestone 1: Reproducible proof pipeline

- Working npm/Cargo manifests, local compiler dependencies, and setup scripts.
- A satisfying demo witness with the relation constrained to be true.
- Rust proof generation and verification using snarkjs artifacts.
- Solidity calldata parsed from the actual snarkjs output.
- A single-tuple adapter between the rollup and generated verifier ABIs.
- Real-proof tests covering acceptance, altered public data/proof rejection, and invalid-witness failure.
- Separate mock bookkeeping tests without assumed BLS gas-savings assertions.

This milestone proves a Poseidon relation. It does not verify BLS signatures, aggregate signatures, or establish state-transition correctness.

## Milestone 2: One real BLS signature

**Implemented for the first 25-byte-message circuit.** The selected Basic/min-pk BLS12-381 suite has native and direct Solidity references, a full gnark circuit, a genuine BN254 Groth16 proof, native proof verification, and local Ethereum VM acceptance/rejection tests. The signature is private; the public key and all message bytes are bound on-chain.

See the [proof workflow](BLS_PROOF.md), [reference specification](BLS_REFERENCE.md), and [backend rationale](BLS_PROVING.md). The original Circom/Poseidon adapter remains a separately labeled legacy demo, while the real proof uses its own generated verifier and consumer.

This one-signature, fixed-message-length circuit remains a reference alongside the batch implementation below.

## Milestone 3: One proof for a signed batch

**Implemented for fixed batches of two active entries with 25-byte payloads.** The [batch backend](BLS_BATCH.md) aggregates the G2 signatures and proves one Basic/min-pk multi-pairing relation over both framed messages. Position bytes guarantee that complete signed messages are distinct. No padding or caller-selected active count is supported.

- The circuit computes the canonical SHA-256 batch commitment, including keys, payloads, size, chain ID, consumer address, and batch ID.
- The same submission context is covered by each actual BLS signature.
- The contract reconstructs the commitment, checks every key against current signer authorization, accepts one proof, and advances a sequential batch counter.
- Accepted state consists of verified batch commitments; it does not claim account-state transition correctness.
- Adversarial circuit and genuine-proof EVM tests cover changed entries/context, missing signatures, unauthorized/revoked keys, malformed proofs, and replay.

The earlier Rust library's `BatchProver` remains part of the separately labeled Poseidon demo. It is not the aggregate-BLS backend. Larger or variable capacities require an explicitly constrained circuit family/design and matching verifiers; arbitrary batch sizes are not implemented.

## Milestone 4: Reproducible measurements

The [comparison runner](BENCHMARKS.md) implements the first fixed-two-entry experiment: individual/direct aggregate/ZK paths share exact signed workloads, authorization, and state effects. It separates first/subsequent batch storage, genuine proving commands, peak child-process RSS, calldata, deployment/registration receipts, and optional fresh setup measurements. The default is a pilot with one independent proof per state and five EVM transaction repetitions per path. A [saved reference run](../benchmarks/reference/batch2-prague.json) records two genuine proofs and 30 measured transactions with all three paths accepted.

Larger batch sizes and more independent samples are needed to characterize latency and throughput beyond the current two-entry workload.

Compare individual on-chain BLS verification, direct aggregate BLS verification, and ZK verification for the same curve, message set, and signature scheme. Include the relevant precompile implementation for the selected chain fork.

Measure witness generation, proof generation, verification, peak memory, proof/calldata sizes, and complete transaction gas. Record hardware, software versions, chain fork, batch sizes, repetitions, and raw results. Separate cold/steady-state storage behavior and deployment cost. Measure fixed proof overhead separately from per-entry calldata/storage costs.

Treat any calculated TPS as a model estimate with stated assumptions. Support gas savings, crossover sizes, and proving times with reproducible measurements. Distinguish proof acceptance from Ethereum consensus finality.

## Possible extensions

1. Increase supported batch capacity from two, starting with four entries, and validate one genuine aggregate-BLS proof for each implemented capacity. Extend further as the available hardware permits and record resource limits.
2. Repeat matched direct-individual, direct-aggregate, and ZK experiments with more independent proofs. Measure complete and per-entry L1 gas, calldata, proving/full-command time, and memory to characterize amortization and any observed crossover.
3. Evaluate gas-limited capacity under the stated historical assumptions, alongside measured prover limits. Describe modeled capacity as a model rather than measured end-to-end transaction throughput.
4. Keep the project documentation and demonstrations aligned with the implementation and data: the gnark/BLS12-381 backend, the separate legacy Poseidon demo, supported batch sizes, benchmark conditions, results, and limitations.

These extensions build on the current signature-verification workload. The optimistic-ECDSA implementation remains a separate repository; comparisons with it require aligned workloads and accounting.

## Account-state transitions

Adding transaction execution would require account state, nonces, execution rules, old/new state roots, data availability, and withdrawal semantics. The circuit would check state transitions and the contract would enforce continuity between batches. Including a new root as a public input alone does not prove a valid state transition. This remains a separate extension to the current signature-verification pipeline.
