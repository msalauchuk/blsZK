const { expect } = require("chai");
const { ethers, artifacts } = require("hardhat");
const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const { bls, g1 } = require("../test/helpers/bls");
const { createTestBatch, wireEntries, batchCommitment, signingMessage } = require("../test/helpers/bls-batch");

const root = path.join(__dirname, "..");
const build = path.join(root, "proofs/gnark/build/batch");

describe("One genuine Groth16 proof for an aggregate BLS batch", function () {
  this.timeout(720000);
  let owner, submitter, generated, consumer, metadata, input, proof, keys, payloads, snapshot, proverCommandTimeMs;

  before(async function () {
    if (!fs.existsSync(path.join(build, "circuit.json"))) throw new Error("Run npm run test:bls:batch first.");
    metadata = JSON.parse(fs.readFileSync(path.join(build, "circuit.json")));
    expect(metadata.schema).to.equal("blszk.gnark-bls12-381.batch2.v1");
    expect(metadata.batchSize).to.equal(2);
    expect(metadata.publicInputCount).to.equal(2);
    const artifact = await artifacts.readArtifact("BLSBatchGroth16Verifier");
    expect(ethers.getBytes(artifact.deployedBytecode).length).to.be.at.most(24576);
    [owner, submitter] = await ethers.getSigners();
    const Generated = await ethers.getContractFactory("BLSBatchGroth16Verifier");
    generated = await Generated.deploy();
    await generated.waitForDeployment();
    expect(await generated.circuitId()).to.equal(metadata.verifyingKeyHash);
    const Consumer = await ethers.getContractFactory("BLSBatchVerifier");
    consumer = await Consumer.deploy(await generated.getAddress(), metadata.verifyingKeyHash);
    await consumer.waitForDeployment();
    input = createTestBatch({ chainId: (await ethers.provider.getNetwork()).chainId.toString(), verifyingContract: await consumer.getAddress(), batchId: "0" });
    const entries = wireEntries(input);
    keys = entries.map((e) => e.publicKey);
    payloads = entries.map((e) => e.payload);
    for (const key of keys) await (await consumer.setSignerAuthorization(key, true)).wait();
    fs.writeFileSync(path.join(build, "input.json"), JSON.stringify(input, null, 2) + "\n");
    // This executes the genuine prover, not a mock or a stored proof from
    // another contract. The chain/address/batch context is signed above.
    const proofStart = Date.now();
    execFileSync(path.join(build, "bls-batch"), [
      "prove", "--artifacts", build, "--input", path.join(build, "input.json"), "--output", path.join(build, "proof.json"),
    ], { cwd: root, timeout: 600000, stdio: "inherit" });
    proverCommandTimeMs = Date.now() - proofStart;
    proof = JSON.parse(fs.readFileSync(path.join(build, "proof.json")));
    expect(proof.publicInputs).to.have.length(2);
    expect(proof).to.not.have.property("aggregateSignature");
    expect(proof.entries).to.deep.equal(entries);
    snapshot = await ethers.provider.send("evm_snapshot", []);
  });

  beforeEach(async function () {
    await ethers.provider.send("evm_revert", [snapshot]);
    snapshot = await ethers.provider.send("evm_snapshot", []);
  });

  it("matches the exact signed framing and canonical commitment across JS, Go, and Solidity", async function () {
    expect(await consumer.BATCH_SIZE()).to.equal(2);
    for (let i = 0; i < 2; i++) {
      expect(await consumer.signingMessage(0, i, payloads[i])).to.equal(signingMessage(input, i, payloads[i]));
    }
    expect(signingMessage(input, 0, payloads[0])).to.not.equal(signingMessage(input, 1, payloads[0]));
    expect(await consumer.batchCommitment(0, keys, payloads)).to.equal(batchCommitment(input));
    expect(proof.commitment).to.equal(batchCommitment(input));
    const digest = BigInt(proof.commitment);
    expect(proof.publicInputs).to.deep.equal([(digest >> 128n).toString(), (digest & ((1n << 128n) - 1n)).toString()]);
    await expect(generated.verifyProof(proof.proof, proof.publicInputs)).to.not.be.reverted;
  });

  it("accepts one proof for both entries, records its commitment, and measures a real transaction", async function () {
    const tx = await consumer.connect(submitter).submitBatch(0, keys, payloads, proof.proof);
    const receipt = await tx.wait();
    expect(receipt.status).to.equal(1);
    await expect(tx).to.emit(consumer, "BatchVerified").withArgs(0, proof.commitment, 2);
    expect(await consumer.batchCommitments(0)).to.equal(proof.commitment);
    expect(await consumer.nextBatchId()).to.equal(1);
    const measurement = {
      network: "hardhat-prague", chainId: input.chainId, batchSize: 2, proofs: 1,
      constraints: metadata.constraints, proofBytes: ethers.getBytes(proof.proof).length,
      transactionCalldataBytes: ethers.getBytes(tx.data).length, verificationTransactionGas: receipt.gasUsed.toString(),
      provingTimeMs: proof.provingTimeMs, proverCommandTimeMs, verifyingKeyHash: metadata.verifyingKeyHash,
    };
    fs.writeFileSync(path.join(build, "evm-verification.json"), JSON.stringify(measurement, null, 2) + "\n");
    console.log(`    Aggregate batch: 2 entries; 1 proof; ${measurement.proofBytes} proof bytes; ${measurement.verificationTransactionGas} transaction gas`);
  });

  it("rejects a change to every payload byte in either entry", async function () {
    for (let entry = 0; entry < 2; entry++) {
      for (let byte = 0; byte < 25; byte++) {
        const changed = payloads.slice();
        const bytes = ethers.getBytes(changed[entry]);
        bytes[byte] ^= 1;
        changed[entry] = ethers.hexlify(bytes);
        await expect(consumer.submitBatch(0, keys, changed, proof.proof)).to.be.reverted;
      }
    }
    expect(await consumer.nextBatchId()).to.equal(0);
    expect(await consumer.batchCommitments(0)).to.equal(ethers.ZeroHash);
  });

  it("rejects replacing an authorized key or reordering entries", async function () {
    const alternate = g1(bls.G1.ProjectivePoint.BASE);
    await consumer.setSignerAuthorization(alternate, true);
    for (let i = 0; i < 2; i++) {
      const changed = keys.slice(); changed[i] = alternate;
      await expect(consumer.submitBatch(0, changed, payloads, proof.proof)).to.be.reverted;
    }
    await expect(consumer.submitBatch(0, keys.slice().reverse(), payloads.slice().reverse(), proof.proof)).to.be.reverted;
  });

  it("enforces live signer authorization and owner-only changes", async function () {
    await expect(consumer.connect(submitter).setSignerAuthorization(keys[0], false)).to.be.revertedWithCustomError(consumer, "NotOwner");
    await consumer.setSignerAuthorization(keys[1], false);
    await expect(consumer.submitBatch(0, keys, payloads, proof.proof)).to.be.revertedWithCustomError(consumer, "UnauthorizedSigner");
    expect(await consumer.nextBatchId()).to.equal(0);
    await consumer.setSignerAuthorization(keys[1], true);
    await expect(consumer.submitBatch(0, keys, payloads, proof.proof)).to.not.be.reverted;
  });

  it("rejects replay and retargeting the same proof to the next batch", async function () {
    await consumer.submitBatch(0, keys, payloads, proof.proof);
    await expect(consumer.submitBatch(0, keys, payloads, proof.proof)).to.be.revertedWithCustomError(consumer, "InvalidBatchId");
    await expect(consumer.submitBatch(1, keys, payloads, proof.proof)).to.be.reverted;
    expect(await consumer.nextBatchId()).to.equal(1);
    expect(await consumer.batchCommitments(1)).to.equal(ethers.ZeroHash);
  });

  it("rejects the same proof in another consumer contract and a changed chain commitment", async function () {
    const Consumer = await ethers.getContractFactory("BLSBatchVerifier");
    const other = await Consumer.deploy(await generated.getAddress(), metadata.verifyingKeyHash);
    for (const key of keys) await other.setSignerAuthorization(key, true);
    await expect(other.submitBatch(0, keys, payloads, proof.proof)).to.be.reverted;
    const changed = batchCommitment({ ...input, chainId: "1" });
    const digest = BigInt(changed);
    await expect(generated.verifyProof(proof.proof, [digest >> 128n, digest & ((1n << 128n) - 1n)])).to.be.reverted;
  });

  it("rejects malformed entries/proofs and pins the actual generated key", async function () {
    const padding = ethers.getBytes(keys[0]); padding[0] = 1;
    await expect(consumer.submitBatch(0, [padding, keys[1]], payloads, proof.proof)).to.be.revertedWithCustomError(consumer, "InvalidEntry");
    await expect(consumer.submitBatch(0, keys, ["0x00", payloads[1]], proof.proof)).to.be.revertedWithCustomError(consumer, "InvalidEntry");
    await expect(consumer.signingMessage(0, 2, payloads[0])).to.be.revertedWithCustomError(consumer, "InvalidEntry");
    const corrupt = ethers.getBytes(proof.proof); corrupt[corrupt.length - 1] ^= 1;
    for (const malformed of [corrupt, proof.proof.slice(0, -2), proof.proof + "00"]) {
      await expect(consumer.submitBatch(0, keys, payloads, malformed)).to.be.reverted;
    }
    const Consumer = await ethers.getContractFactory("BLSBatchVerifier");
    await expect(Consumer.deploy(await generated.getAddress(), ethers.ZeroHash)).to.be.revertedWithCustomError(consumer, "InvalidVerifier");
    await expect(Consumer.deploy(owner.address, metadata.verifyingKeyHash)).to.be.revertedWithCustomError(consumer, "InvalidVerifier");
    expect(await consumer.nextBatchId()).to.equal(0);
  });
});
