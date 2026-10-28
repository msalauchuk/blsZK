# One proof for an aggregate BLS batch

The batch backend targets exactly **two active entries**, each carrying a G1 public key and a **25-byte application payload**. It sums the signers' G2 signatures and verifies the aggregate with one BLS multi-pairing inside one BN254 Groth16 circuit. It does not concatenate individual ZK proofs. The single-signature [reference proof](BLS_PROOF.md) remains a separate workflow with its original keys.

## Run the complete local workflow

Use the [README prerequisites](../README.md#prerequisites), then run:

```sh
npm ci
npm run test:bls:batch
```

This builds the pinned Go backend, runs adversarial circuit tests, generates development keys when necessary, exports the actual verifier, and deploys it locally. It then signs the deployment's exact context with deterministic test keys, generates and natively verifies one genuine aggregate-BLS proof, and submits it to the local Ethereum VM. Contract tests cover statement binding, authorization, malformed inputs, and replay rejection.

The circuit has **3,805,660 constraints** and two public inputs. Initial key generation took about **13 minutes** on the development 8 GB Mac and uses substantial memory; later runs reuse the source/dependency-compatible setup. Four Go workers and a 3 GiB Go heap GC target limit resource use, but the GC target is not a hard process-memory cap. This is a single-machine development setup, not a production ceremony.

Other commands:

| Command | Purpose |
| --- | --- |
| `npm run bls:batch:inspect` | Compile and report the circuit size |
| `npm run bls:batch:setup` | Explicitly regenerate development keys and Solidity verifier |
| `npm run bls:batch:prove -- batch.json` | Prove a batch signed for a specific deployment/context |
| `npm run bls:batch:deploy` | Deploy the generated verifier and batch consumer on localhost |
| `npm run bls:batch:demo` | Sign, prove, and submit the next batch on localhost with public test keys |

For a persistent demonstration, run `npm run bls:batch:setup` and `npm run node`. In another terminal run `npm run bls:batch:deploy`, then `npm run bls:batch:demo`. Repeating the demo signs the next batch number. The demo is restricted to a local development network and uses publicly known test keys. Deployment starts with no authorized signers; the demo authorizes its two test keys through the owner account.

## Scheme and signed context

The ciphersuite remains `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`: Basic/min-pk BLS12-381 with SHA-256 XMD hash-to-G2. The [Basic scheme requires distinct signed messages to resist rogue-key attacks](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature#section-3.1).

Each signer signs a **119-byte framed message**, not just the payload:

```text
SHA256(UTF8("blsZK.batch.message.v1"))   32 bytes
chainId                                 32 bytes, big-endian uint256
verifyingContract                       20 bytes
batchId                                  8 bytes, big-endian uint64
batchSize = 2                            1 byte
position = 0 or 1                        1 byte
payload                                 25 bytes
```

Positions are fixed circuit constants. They make the complete messages distinct even when both payloads or keys are identical. Chain, contract, batch number, size, and position are covered by the actual BLS signatures. An old aggregate cannot be reused simply by generating a new proof with a different batch context. This is a batch-specific application framing under the Basic suite; signatures from the unframed single-signature fixture are not interchangeable.

`BLSBatchVerifier.signingMessage(batchId, position, payload)` returns the exact bytes to sign. The [JavaScript test helper](../test/helpers/bls-batch.js) and [committed aggregate fixture](../test/fixtures/bls12_381_batch2.json) provide independent examples. The committed fixture targets address `0x0000000000000000000000000000000000000001` for circuit tests; collect fresh signatures for an actual deployment.

## Canonical commitment and public inputs

The circuit and contract compute SHA-256 over the same **399-byte** preimage:

```text
SHA256(UTF8("blsZK.batch.commitment.v1")) 32 bytes
chainId || verifyingContract || batchId || batchSize  61 bytes
entry 0: publicKey || payload            128 + 25 bytes
entry 1: publicKey || payload            128 + 25 bytes
```

The G1 public key uses EIP-2537 encoding: `x || y`, each a 64-byte big-endian coordinate with 16 leading zero bytes. The circuit constrains canonical field elements, nonidentity points and subgroup membership; the contract also rejects ignored/nonzero high padding. Every slot is active, so there is no unconstrained padding or caller-selected active-entry count.

The digest is exposed as two BN254 field inputs: its high 128 bits, then its low 128 bits. There is no reduction of the full digest modulo the scalar field. All context, keys, and payloads are private witnesses to the circuit but are supplied publicly in transaction calldata, which the consumer hashes again. The aggregate signature remains private to the prover.

## Input, proof, and submission

The prover reads a strict JSON object:

```json
{
  "ciphersuite": "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
  "chainId": "31337",
  "verifyingContract": "0x0000000000000000000000000000000000000001",
  "batchId": "0",
  "entries": [
    { "publicKey": "0x<48 compressed G1 bytes>", "payload": "0x<25 bytes>" },
    { "publicKey": "0x<48 compressed G1 bytes>", "payload": "0x<25 bytes>" }
  ],
  "aggregateSignature": "0x<96 compressed G2 bytes>"
}
```

The angle-bracket values above describe encoding lengths. Use the committed fixture for a complete valid JSON example. Decimal IDs are strings to preserve their full range. The backend decodes compressed points, independently constrains their validity and the BLS relation, and emits canonical uncompressed public keys for the contract.

Generated keys, manifests, proofs, measurements, and the binary live under ignored `proofs/gnark/build/batch/`. The manifest checks a fingerprint of the embedded backend/circuit source and linked Go dependency versions/checksums. Changing setup keys requires new proofs and a new generated-verifier deployment. A fingerprint/key identifier is a consistency check, not independent attestation of trusted deployment code.

The proof artifact contains `entries`, `batchId`, `commitment`, the complete Solidity `proof` bytes, public inputs, and context metadata. Do not truncate gnark's commitment/proof-of-knowledge encoding. Submit it to the deployed consumer:

```js
await consumer.submitBatch(
  artifact.batchId,
  artifact.entries.map((entry) => entry.publicKey),
  artifact.entries.map((entry) => entry.payload),
  artifact.proof
);
```

## Authorization, replay, and state

The deploying account is the immutable owner. It manages `setSignerAuthorization(publicKey, authorized)` for canonical uncompressed keys. Every key must be authorized **at submission time**, so revocation invalidates acceptance even if a proof was prepared earlier. Authorization is enforced by the contract over the keys bound to the proof's commitment.

Anyone can submit a valid authorized batch. The batch ID must equal `nextBatchId`; after successful verification the contract records `batchCommitments[batchId]`, emits `BatchVerified`, and advances the counter. Reverting proof or authorization checks leave both records and the counter unchanged. Replaying a consumed batch, retargeting a proof to another batch number or contract, and replacing submitted entries are rejected.

These are verified batch commitments, not account state roots. The consumer does not execute payloads, maintain balances, prove withdrawals, or implement a complete rollup. Larger/variable batch capacities, transaction semantics, production setup/review, and comparable baseline measurements remain separate work.

## Observed validation and costs

The first genuine two-entry proof passed native verification and a transaction on Hardhat's Prague Ethereum VM. The eight contract/integration tests passed, together with the existing 45 tests. Circuit tests independently reject modified entries/context with recomputed commitments, a signature from only the first signer, identity/non-subgroup keys, noncanonical coordinate aliases, and non-byte values.

One development run recorded:

| Measurement | Observation |
| --- | --- |
| Constraints | 3,805,660 |
| Entries / ZK proofs | 2 / 1 |
| Proof bytes | 384 |
| Complete transaction calldata | 1,124 bytes |
| `groth16.Prove` time, including witness solving | About 62.5 seconds |
| Full prover command, including key loading | About four minutes |
| First accepted-batch transaction | 446,622 gas |

The transaction includes commitment reconstruction, authorization checks, proof verification, counter/commitment storage, and the event. It excludes deployment and prior signer-registration transactions. The first batch starts with a zero batch counter; later batches have different storage costs. Proving time excludes artifact loading, compilation, setup, and Solidity compilation. Raw local measurements are written to `proofs/gnark/build/batch/evm-verification.json`; subsequent runs also record full prover-command time separately.

These are single-run prototype observations. They do not establish BLS gas savings, a crossover batch size, or throughput; comparisons require identical signed messages, workloads, chain rules, and accounting.
