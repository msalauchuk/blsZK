const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");
const { bls, fromHex, g2 } = require("../test/helpers/bls");
const { createTestBatchVectors, wireEntries, batchCommitment } = require("../test/helpers/bls-batch");

describe("Batch benchmark baselines with shared application semantics", function () {
  let consumer, vectors, keys, payloads, submitter, context, snapshot;
  before(async function () {
    const file = path.join(__dirname, "../proofs/gnark/build/batch/circuit.json");
    if (!fs.existsSync(file)) throw new Error("Run npm run bls:batch:setup first.");
    const metadata = JSON.parse(fs.readFileSync(file));
    const Generated = await ethers.getContractFactory("BLSBatchGroth16Verifier");
    const generated = await Generated.deploy();
    const Direct = await ethers.getContractFactory("BLS12381Verifier");
    const direct = await Direct.deploy();
    const Consumer = await ethers.getContractFactory("BLSBatchBenchmark");
    consumer = await Consumer.deploy(await generated.getAddress(), metadata.verifyingKeyHash, await direct.getAddress());
    await consumer.waitForDeployment();
    [, submitter] = await ethers.getSigners();
    context = { chainId: (await ethers.provider.getNetwork()).chainId.toString(), verifyingContract: await consumer.getAddress() };
    vectors = createTestBatchVectors({ ...context, batchId: "0" });
    const entries = wireEntries(vectors.statement);
    keys = entries.map((e) => e.publicKey); payloads = entries.map((e) => e.payload);
    for (const key of keys) await consumer.setSignerAuthorization(key, true);
    snapshot = await ethers.provider.send("evm_snapshot", []);
  });
  beforeEach(async function () {
    await ethers.provider.send("evm_revert", [snapshot]);
    snapshot = await ethers.provider.send("evm_snapshot", []);
  });

  it("accepts two real individual signatures and records the canonical commitment", async function () {
    await expect(consumer.connect(submitter).submitIndividual(0, keys, payloads, vectors.signatures))
      .to.emit(consumer, "BatchVerified").withArgs(0, batchCommitment(vectors.statement), 2);
    expect(await consumer.batchCommitments(0)).to.equal(batchCommitment(vectors.statement));
    expect(await consumer.nextBatchId()).to.equal(1);
  });

  it("accepts the real aggregate over exactly the same entries and context", async function () {
    await expect(consumer.connect(submitter).submitAggregate(0, keys, payloads, vectors.aggregateSignature))
      .to.emit(consumer, "BatchVerified").withArgs(0, batchCommitment(vectors.statement), 2);
    expect(await consumer.batchCommitments(0)).to.equal(batchCommitment(vectors.statement));
    expect(await consumer.nextBatchId()).to.equal(1);
  });

  it("enforces live authorization equally for both direct paths", async function () {
    await consumer.setSignerAuthorization(keys[1], false);
    await expect(consumer.submitAggregate(0, keys, payloads, vectors.aggregateSignature)).to.be.revertedWithCustomError(consumer, "UnauthorizedSigner");
    await expect(consumer.submitIndividual(0, keys, payloads, vectors.signatures)).to.be.revertedWithCustomError(consumer, "UnauthorizedSigner");
    expect(await consumer.nextBatchId()).to.equal(0);
    expect(await consumer.batchCommitments(0)).to.equal(ethers.ZeroHash);
  });

  it("rejects partial signatures, changed data, and reordered entries without changing state", async function () {
    await expect(consumer.submitAggregate(0, keys, payloads, vectors.signatures[0])).to.be.revertedWithCustomError(consumer, "InvalidBLSSignature");
    const bad = g2(bls.G2.ProjectivePoint.fromHex(fromHex(vectors.statement.aggregateSignature)).negate());
    await expect(consumer.submitIndividual(0, keys, payloads, [vectors.signatures[0], bad])).to.be.revertedWithCustomError(consumer, "InvalidBLSSignature");
    const changed = [ethers.hexlify(Buffer.alloc(25, 255)), payloads[1]];
    await expect(consumer.submitAggregate(0, keys, changed, vectors.aggregateSignature)).to.be.revertedWithCustomError(consumer, "InvalidBLSSignature");
    await expect(consumer.submitIndividual(0, keys, changed, vectors.signatures)).to.be.revertedWithCustomError(consumer, "InvalidBLSSignature");
    await expect(consumer.submitAggregate(0, keys.slice().reverse(), payloads.slice().reverse(), vectors.aggregateSignature)).to.be.revertedWithCustomError(consumer, "InvalidBLSSignature");
    expect(await consumer.nextBatchId()).to.equal(0);
    expect(await consumer.batchCommitments(0)).to.equal(ethers.ZeroHash);
  });

  it("rejects replay and accepts the next batch only with freshly context-bound signatures", async function () {
    await consumer.submitAggregate(0, keys, payloads, vectors.aggregateSignature);
    await expect(consumer.submitIndividual(0, keys, payloads, vectors.signatures)).to.be.revertedWithCustomError(consumer, "InvalidBatchId");
    await expect(consumer.submitAggregate(1, keys, payloads, vectors.aggregateSignature)).to.be.revertedWithCustomError(consumer, "InvalidBLSSignature");
    const fresh = createTestBatchVectors({ ...context, batchId: "1" });
    await consumer.submitIndividual(1, keys, payloads, fresh.signatures);
    expect(await consumer.nextBatchId()).to.equal(2);
    expect(await consumer.batchCommitments(1)).to.equal(batchCommitment(fresh.statement));
  });
});
