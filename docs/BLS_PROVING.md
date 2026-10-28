# BLS proving backend

## Selected implementation

The working backend uses **gnark v0.16.4** and **gnark-crypto v0.22.0**, pinned by the [Go module](../proofs/gnark/go.mod) and checksums. It compiles the full BLS12-381 verification predicate directly to a BN254 Groth16 circuit. The generated proof was verified natively and in a local Ethereum VM transaction. See [BLS_PROOF.md](BLS_PROOF.md) for the supported statement and reproduction steps.

The one-signature reference circuit supports a 25-byte message and one signature. The public message and G1 key coordinates are bound to 37 public inputs. The G2 signature is private. Hash-to-curve and pairing checks are constrained inside the proof computation; the host does not supply a trusted verification result or message point.

The one-signature implementation uses gnark's [BLS verification component](https://github.com/Consensys-Incorporated/gnark/blob/v0.16.4/std/signature/bls/bls_g1.go) and [hash-to-G2 component](https://github.com/Consensys-Incorporated/gnark/blob/v0.16.4/std/algebra/emulated/sw_bls12381/map_to_g2.go). The convenience BLS `Verify` method selects the PoP DST, so this backend explicitly computes hash-to-G2 with the selected **Basic/NUL** suite and calls `VerifyG2`. It also asserts canonical coordinates, byte ranges, nonidentity signatures, and subgroup membership, and forbids caller-supplied precomputed signature lines.

The Solidity consumer reconstructs the public inputs from the actual submitted message/key and pins its generated verifier/key identifier. Proofs carry gnark's commitment and proof-of-knowledge data; those bytes must not be discarded.

## Why this backend

The development Mac has 8 GB RAM. SP1's published [requirements](https://docs.succinct.xyz/docs/sp1/getting-started/hardware-requirements) put its final Groth16 wrapping step at roughly 14 GB memory. Direct circuit compilation avoids that wrapping step. This repository's full BLS circuit compiled to **2,090,737 constraints**, with approximately **1.2 GiB Go heap allocated at the end of compilation** in the observed run. This is not peak total-process memory.

The previous [circom-pairing benchmark](https://github.com/yi-sun/circom-pairing#benchmarks) describes a larger historical circuit and substantially larger setup resources. We retain the project's small Circom relation as a separate legacy demo; it is not relabeled as BLS verification.

## Acceptance evidence

- The circuit accepts the committed Rust/blst signature fixture.
- Adversarial witness tests bypass host validation and reject changed messages, keys and signatures, identities, subgroup violations, non-byte messages, and noncanonical key aliases.
- A real Groth16 proof is verified with the generated native verifying key.
- The exact exported verifier and statement consumer accept a local EVM transaction.
- The EVM tests reject every changed message byte, another key, noncanonical padding, malformed proofs, and a mismatched verifier key.
- The generated verifier satisfies Ethereum's standard deployed-code size limit.

A single observed run produced a 384-byte proof in about 12.7 seconds and consumed 713,281 gas for the local verification transaction. See the generated measurement file and the [proof guide](BLS_PROOF.md) for scope and timing boundaries. No BLS gas-savings or throughput comparison has yet been established.

## Remaining work

The [batch backend](BLS_BATCH.md) adds one aggregate-BLS proof for two active entries, a canonical batch commitment, context-bound signatures, contract signer authorization, and replay checks. It uses the same pinned gnark dependencies with a separate circuit, keys, and verifier. Larger batch capacities, account-state transitions, and comparable benchmark workloads remain in the [roadmap](ROADMAP.md). Supporting other message lengths requires a defined circuit family or a correctly constrained variable-length design and matching consumers/keys. The current development setup also needs an appropriate ceremony and review before production use.
