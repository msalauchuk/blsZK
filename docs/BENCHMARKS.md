# Comparing direct BLS and ZK verification

The benchmark compares the L1 gas costs and off-chain resource use of direct BLS verification and verification through a Groth16 proof. Each run records its date, hardware, software, and EVM fork. Historical gas-budget models are documented separately in the [measurement assumptions](ROADMAP.md#measurement-assumptions).

The comparison runner measures **the same fixed batch of two entries** through three implemented verification paths:

1. Two individual BLS12-381 signature checks.
2. One Basic aggregate BLS check, with two message hashes and one three-pair pairing.
3. One genuine Groth16 proof of aggregate BLS verification.

Direct checks use the [Prague EIP-2537 precompiles](https://eips.ethereum.org/EIPS/eip-2537). The [benchmark contract](../contracts/benchmarks/BLSBatchBenchmark.sol) inherits the actual ZK submission path and adds direct alternatives. It uses shared preparation and acceptance helpers from [BLSBatchVerifier](../contracts/BLSBatchVerifier.sol).

## Run

Use the [project prerequisites](../README.md#prerequisites), plus **Python 3.8 or newer on macOS or Linux** for process resource measurements:

```sh
npm ci
npm run bench:bls:batch
```

The default generates **one independent proof for each of two storage states** and repeats every verification path **five times per proof**, from restored local-EVM state snapshots. This is an initial comparison with two proving samples, not a statistically mature latency study. The runner first executes the aggregate-verifier and shared-policy rejection tests.

For more independent proof samples:

```sh
BLSZK_BENCH_PROOF_RUNS=3 BLSZK_BENCH_GAS_RUNS=5 npm run bench:bls:batch
```

Proof generation is sequential. Each proof command loads the large proving artifacts in a fresh Go process; budget several minutes per command on the development 8 GB Mac. Repeating a fixed proof's EVM transaction measures controlled gas accounting, not independent proof-generation performance.

Compatible development keys are reused by default. To measure fresh circuit compilation, key generation, and artifact writing as a separate setup command:

```sh
BLSZK_BENCH_FRESH_SETUP=1 npm run bench:bls:batch
```

This regenerates development keys and the exported Solidity verifier. Other deployments/proofs using the previous key must be regenerated/redeployed. Dependency installation, Go binary compilation, and Solidity compilation are outside the measured setup/prover commands.

## Reference pilot result

The saved [raw reference run](../benchmarks/reference/batch2-prague.json) and [generated summary](../benchmarks/reference/batch2-prague.md) contain two genuine proofs and 30 successful measured transactions on the development Apple M1/8 GB Mac, using the Prague local Ethereum VM:

| State | Individual BLS gas | Aggregate BLS gas | ZK gas |
| --- | ---: | ---: | ---: |
| First batch, counter 0 | 552,570 | 476,959 | 446,691 |
| Subsequent batch, counter 1 | 535,470 | 459,895 | 429,579 |

Within this implementation and workload, ZK used **6.35%** and **6.59%** less transaction gas than the direct aggregate baseline. Complete calldata was **1,348 bytes** for individual signatures, **996 bytes** for the aggregate, and **1,124 bytes** for ZK. The ZK path's gas reduction therefore does not imply smaller calldata than the aggregate path.

The two proofs took **31.07 / 32.56 seconds** in `groth16.Prove`, **142.44 / 144.08 seconds** for the full prover command, and **1.39 / 1.92 GiB** measured peak child-process RSS. These are individual observations for the two storage scenarios. Cached setup was reused; this pilot did not measure fresh setup. Deployment and registration costs are available separately in the JSON.

The baseline is the implemented Solidity hash-to-curve/pairing verifier, not a claimed optimal implementation. The default's repeated gas samples reuse one proof per state; more independent proving samples and larger implemented batches are needed before broader performance claims.

## What makes the workloads comparable

All three paths run in **the same consumer contract**, on the same chain and fork. Within each scenario they use identical public keys, payloads, complete signed messages, batch ID, caller, and signer authorization. The aggregate is the sum of the same two individual signatures, and the ZK witness uses that exact aggregate.

Each payload is 25 bytes. The signed 119-byte frames include the chain, consumer address, batch number, size, and fixed position, as specified in the [batch guide](BLS_BATCH.md). The consumer computes these frames itself for direct verification; no trusted prehash is accepted. Position bytes ensure the distinct complete messages required by the [Basic BLS scheme](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature#section-3.1).

Every path performs the same commitment reconstruction, current signer-authorization checks, batch-number validation, commitment storage, counter advancement, and event emission. Successful transactions must leave the same accepted commitment and next batch number. The ZK proof has two public inputs holding the complete SHA-256 commitment, without scalar-field truncation.

The two scenarios are:

| Scenario | State before the measured transaction |
| --- | --- |
| First batch | Counter is zero; commitment slot for batch 0 is empty |
| Subsequent batch | A genuine batch-0 proof has already been accepted; counter is 1 and the batch-1 slot is empty |

State snapshots restore the same starting point before every transaction. “First” and “subsequent” describe contract storage, not operating-system file-cache conditions. No filesystem-cache flush or CPU affinity is imposed.

## Measurements and files

Each run writes an ignored directory under `proofs/gnark/build/batch/benchmark/<UTC timestamp>/` containing raw `results.json`, a readable `summary.md`, prover inputs/proofs, and per-command resource measurements. `benchmark/latest.json` and `benchmark/latest.md` point to the latest **completed** result. Failed runs retain a failure checkpoint without replacing completed results.

The JSON records:

- Actual receipt gas for every successful transaction, with complete calldata byte counts, zero/nonzero bytes, calldata hashes, and transaction hashes.
- Independent proof-command wall time, CPU time, peak RSS, and page faults, alongside the backend's narrower `groth16.Prove` time.
- Proof/evidence sizes: two 256-byte individual signatures, one 256-byte aggregate, or the full generated ZK proof. Public keys/payloads and ABI overhead are counted in complete transaction calldata.
- Actual deployment and signer-registration receipts separately from per-batch gas. The benchmark consumer contains both alternatives, so its deployment is not a minimal standalone deployment estimate for either design.
- Setup mode. Reusing cached keys is explicitly **not** a measurement of fresh setup cost; forced/fresh setup receives its own process measurements.
- Hardware, OS, Node/Go/Python/Hardhat/solc versions, compiler settings, chain fork, circuit/key identifiers, dependency checksums, source hashes, repetition counts, and individual samples.

Process memory uses a fresh Python runner for each Go command and [`getrusage(RUSAGE_CHILDREN)`](https://docs.python.org/3/library/resource.html#resource.getrusage). It records the Go child's maximum RSS, not a Go heap sample or the total machine/process-tree memory. RSS is normalized from bytes on [macOS](https://github.com/apple/darwin-xnu/blob/main/bsd/man/man2/getrusage.2) and KiB on [Linux](https://man7.org/linux/man-pages/man2/getrusage.2.html). The Go heap's 3 GiB GC target is not a hard RSS limit.

## Interpretation limits

The default's five gas repetitions reuse one proof per state. They verify repeatable accounting and do not provide five independent proving-time observations. Increasing proof repetitions generates fresh randomized proofs with the same statement and records their calldata/gas variation.

The complete transaction includes real verification, calldata, authorization, commitment computation, counter/commitment storage, and the event. Deployment, signer registration, key setup, off-chain signing, networking, and Ethereum consensus finality are separate costs. Test-vector creation/preflight timing is not real signer-collection latency.

This benchmark covers **one fixed two-entry circuit** and one payload/frame format. Larger batch sizes, another signature scheme, compressed on-chain input/decompression, different forks or storage designs, and a prover service retaining keys in memory are different workloads. Do not infer a crossover size or TPS from this two-entry result. The benchmark establishes no account-state transition or complete rollup throughput guarantee.
