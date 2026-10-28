const { expect } = require("chai");
const { ethers } = require("hardhat");
const { bls, CIPHERSUITE, fromHex, fp, g1, g2, nonSubgroupG2 } = require("./helpers/bls");
const { createTestBatchVectors, signingMessage, wireEntries } = require("./helpers/bls-batch");

describe("Direct Basic aggregate BLS verification", function () {
  let verifier, vectors, messages, keys;
  before(async function () {
    const Verifier = await ethers.getContractFactory("BLS12381Verifier");
    verifier = await Verifier.deploy();
    await verifier.waitForDeployment();
    vectors = createTestBatchVectors({ chainId: "31337", verifyingContract: "0x0000000000000000000000000000000000000001", batchId: "0" });
    const entries = wireEntries(vectors.statement);
    keys = entries.map((e) => e.publicKey);
    messages = entries.map((e, i) => signingMessage(vectors.statement, i, e.payload));
  });

  it("accepts one real aggregate and both individual signatures over the identical frames", async function () {
    expect(await verifier.verifyAggregate(messages, keys, vectors.aggregateSignature)).to.equal(true);
    for (let i = 0; i < 2; i++) expect(await verifier.verify(messages[i], keys[i], vectors.signatures[i])).to.equal(true);
  });

  it("rejects duplicate complete messages even with a mathematically valid same-message aggregate", async function () {
    const message = "0xdeadbeef";
    const point = bls.G2.hashToCurve(fromHex(message), { DST: CIPHERSUITE });
    const signature = g2(point.multiply(42n + 43n));
    expect(await verifier.verifyAggregate([message, message], keys, signature)).to.equal(false);
  });

  it("accepts identical payloads when the signed position frames are distinct", async function () {
    const v = createTestBatchVectors(vectors.statement, [Buffer.alloc(25, 1), Buffer.alloc(25, 1)]);
    const entries = wireEntries(v.statement);
    const framed = entries.map((e, i) => signingMessage(v.statement, i, e.payload));
    expect(framed[0]).to.not.equal(framed[1]);
    expect(await verifier.verifyAggregate(framed, entries.map((e) => e.publicKey), v.aggregateSignature)).to.equal(true);
  });

  it("requires both signers and rejects altered messages, keys, order, and aggregate", async function () {
    expect(await verifier.verifyAggregate(messages, keys, vectors.signatures[0])).to.equal(false);
    for (let i = 0; i < 2; i++) {
      const changed = messages.slice(); changed[i] = changed[i].slice(0, -2) + "ff";
      expect(await verifier.verifyAggregate(changed, keys, vectors.aggregateSignature)).to.equal(false);
      const different = keys.slice(); different[i] = g1(bls.G1.ProjectivePoint.BASE);
      expect(await verifier.verifyAggregate(messages, different, vectors.aggregateSignature)).to.equal(false);
    }
    expect(await verifier.verifyAggregate(messages.slice().reverse(), keys, vectors.aggregateSignature)).to.equal(false);
    const negative = bls.G2.ProjectivePoint.fromHex(fromHex(vectors.statement.aggregateSignature)).negate();
    expect(await verifier.verifyAggregate(messages, keys, g2(negative))).to.equal(false);
  });

  it("rejects identities, noncanonical encodings, and points outside prime-order subgroups", async function () {
    const badKeys = ["0x" + "00".repeat(128), "0x" + fp(0n) + fp(2n), "0x" + fp(bls.fields.Fp.ORDER) + fp(2n), keys[0].slice(0, -2)];
    for (const bad of badKeys) expect(await verifier.verifyAggregate(messages, [bad, keys[1]], vectors.aggregateSignature)).to.equal(false);
    for (const signature of ["0x" + "00".repeat(256), g2(nonSubgroupG2()), vectors.aggregateSignature + "00", vectors.statement.aggregateSignature]) {
      expect(await verifier.verifyAggregate(messages, keys, signature)).to.equal(false);
    }
  });

  it("rejects an aggregate produced with the PoP domain", async function () {
    let aggregate = bls.G2.ProjectivePoint.ZERO;
    for (let i = 0; i < 2; i++) {
      aggregate = aggregate.add(bls.G2.hashToCurve(fromHex(messages[i]), { DST: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_" }).multiply(42n + BigInt(i)));
    }
    expect(await verifier.verifyAggregate(messages, keys, g2(aggregate))).to.equal(false);
  });
});
