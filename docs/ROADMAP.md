# Implementation roadmap

The research goal is to measure the trade-offs between off-chain BLS verification/proving and Ethereum verification: gas, data costs, proving time, latency, and throughput.

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

**In progress.** The signature suite and native reference are implemented. A direct Solidity verifier also computes hash-to-curve and checks the BLS pairing equation using EIP-2537. Rust, Solidity, and an independent JavaScript library agree on valid/invalid cases. See the [BLS reference specification](BLS_REFERENCE.md).

**Remaining:** execute the BLS predicate inside a proven computation and verify that proof on Ethereum. The existing Groth16 circuit still proves the Poseidon demo relation. The [proving-backend assessment](BLS_PROVING.md) documents the next implementation decision.

1. Pin the signature curve, G1/G2 orientation, message encoding, hash-to-curve suite, domain separation, and serialization. The BLS signature curve and outer Groth16 curve are separate choices.
2. Establish a native reference implementation and valid/invalid test vectors.
3. Evaluate a complete verification gadget or alternative proving backend before committing to in-circuit pairing implementation. Calling a native verifier outside the proven computation is insufficient.
4. Prove signature verification, including point/subgroup validation and the hash-to-curve computation (or explicitly defined, securely bound preprocessing).
5. Test on Ethereum: correct signature succeeds; changed message, key, signature, or proof fails.

Success means one actual signature is covered by the proof verified on-chain. The demo adapter and circuit should then be replaced rather than relabeled as BLS.

## Milestone 3: One proof for a signed batch

- Define whether messages are distinct or shared and select the aggregation scheme and rogue-key defence accordingly.
- Verify a real aggregate signature over all active batch entries inside one proven computation.
- Bind the proof to a canonical batch commitment, its size, authorized signer information, and chain/contract/batch context.
- Define fixed batch capacity or a supported family of circuits and constrain padding/active entries.
- Reject changes to any batch entry, unauthorized signers, invalid aggregates, and replayed submissions.

Concatenating independent proofs or verifying BLS off-chain without constraining its result does not meet this milestone.

## Milestone 4: Reproducible measurements

Compare individual on-chain BLS verification, direct aggregate BLS verification, and ZK verification for the same curve, message set, and signature scheme. Include the relevant precompile implementation for the selected chain fork.

Measure witness generation, proof generation, verification, peak memory, proof/calldata sizes, and complete transaction gas. Record hardware, software versions, chain fork, batch sizes, repetitions, and raw results. Separate cold/steady-state storage behavior and deployment cost. Measure fixed proof overhead separately from per-entry calldata/storage costs.

Treat any calculated TPS as a model estimate with stated assumptions. Do not reuse the presentation's gas savings, crossover size, or proving times until reproduced. Distinguish proof acceptance from Ethereum consensus finality.

## Later: Rollup state transitions

Define account state, nonces, transaction execution, old/new state roots, data availability, and withdrawal semantics. The circuit must check transitions and the contract must enforce continuity; merely including an arbitrary new root as a public input does not prove a valid state transition.
