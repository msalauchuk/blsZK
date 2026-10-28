# BLS proving backend assessment

## Current boundary

The repository now verifies actual BLS12-381 signatures in native Rust and directly in Solidity. Its Circom/Groth16 path still proves the Poseidon demo. Calling the native verifier before proving that demo would not turn it into a BLS proof.

The next acceptance criterion is one proof covering the full fixed BLS predicate defined in [BLS_REFERENCE.md](BLS_REFERENCE.md): raw message hashing, canonical point decoding, nonidentity and subgroup checks, and the pairing equation. The proof must also bind its public statement to the data checked by the Ethereum contract.

## Options reviewed

| Approach | Evidence | Work before it can replace the demo |
| --- | --- | --- |
| Circom pairing gadgets | The upstream [circom-pairing benchmarks](https://github.com/yi-sun/circom-pairing#benchmarks) report a 19.2-million-constraint signature-verification circuit and a 12 GB proving key, using a 256 GB RAM machine. These are their historical measurements. | Review the exact input/hash boundary and subgroup constraints; adapt the selected ciphersuite and message binding; obtain suitable compilation/proving resources and setup parameters. |
| Rust zkVM with curve acceleration | [SP1 lists a patched bls12_381 crate](https://docs.succinct.xyz/docs/sp1/optimizing-programs/precompiles) and supports [Solidity proof verification](https://docs.succinct.xyz/docs/sp1/verification/solidity-sdk). | Implement the predicate in a guest-compatible Rust library, cross-check against blst/noble, pin the guest/toolchain and verifier, generate a genuine EVM-compatible proof, and test public-value binding. |

SP1's published [hardware requirements](https://docs.succinct.xyz/docs/sp1/getting-started/hardware-requirements) distinguish execution/mock testing from real proving; its Groth16 wrapping step requires roughly 14 GB memory and additional toolchain/artifact storage. These are upstream requirements, not a measurement of this project's workload.

## Recommended next implementation experiment

Evaluate a Rust zkVM guest with the patched BLS12-381 arithmetic before committing to the large Circom circuit. This is a candidate, not an integrated backend or a completed migration. The C/assembly `blst` reference is the independent oracle; it should not be assumed to run unchanged inside the selected zkVM.

1. Compile and execute a guest that implements the fixed Basic/min-pk suite and all validation checks. Invalid signatures must cause rejection, rather than a successful proof of an output value of `false`.
2. Run the existing positive/negative fixtures and boundary cases through it, matching the reference behavior.
3. Commit a canonical digest of the public message and key, with explicit framing/versioning, as public values. The signature can remain a private witness. The Ethereum consumer must recompute and enforce the same digest from the submitted public statement. If the application publishes signatures too, that choice and its calldata cost must be explicit.
4. Generate and verify a real proof locally with a pinned verifier/program key. A mock proof or successful guest execution is insufficient.
5. Add on-chain acceptance/rejection tests and record actual memory/time requirements.

Do not change the existing rollup to trust a backend's result until those checks pass. Batch aggregation, replay context, authorization, and state semantics remain subsequent requirements in the [roadmap](ROADMAP.md).
