const { expect } = require("chai");
const { ethers } = require("hardhat");
const fixture = require("./fixtures/bls12_381_basic.json");
const {
  bls, CIPHERSUITE, fromHex, fp, g1, g2, decodeStatement, signWithNoble, nonSubgroupG2,
} = require("./helpers/bls");

describe("BLS12-381 direct verification (not a ZK proof)", function () {
  let verifier, vector;

  before(async function () {
    const Verifier = await ethers.getContractFactory("BLS12381Verifier");
    verifier = await Verifier.deploy();
    await verifier.waitForDeployment();
    vector = decodeStatement(fixture);
  });

  it("uses the fixed Basic/min-pk ciphersuite", async function () {
    expect(await verifier.CIPHERSUITE()).to.equal(CIPHERSUITE);
  });

  it("accepts the Rust/blst fixture and agrees with noble", async function () {
    const messagePoint = bls.G2.hashToCurve(fromHex(fixture.message), { DST: CIPHERSUITE });
    expect(bls.verify(fromHex(fixture.signature), messagePoint, fromHex(fixture.publicKey))).to.equal(true);
    expect(await verifier.verify(vector.message, vector.publicKey, vector.signature)).to.equal(true);
  });

  it("matches independent hash-to-curve results across message boundaries", async function () {
    for (const size of [0, 1, 31, 32, 63, 64, 65, 128, 255, 256, 1024]) {
      const message = Uint8Array.from({ length: size }, (_, index) => index % 256);
      const expected = g2(bls.G2.hashToCurve(message, { DST: CIPHERSUITE }));
      expect(await verifier.hashToG2(message), `message length ${size}`).to.equal(expected);
    }
  });

  it("accepts independently signed empty and binary messages", async function () {
    for (const message of [new Uint8Array(), Uint8Array.from([0, 255, 0, 128])]) {
      const statement = decodeStatement(signWithNoble(message));
      expect(await verifier.verify(statement.message, statement.publicKey, statement.signature)).to.equal(true);
    }
  });

  it("rejects changed messages, keys, and valid but incorrect signatures", async function () {
    expect(await verifier.verify("0x00", vector.publicKey, vector.signature)).to.equal(false);
    expect(await verifier.verify(vector.message, g1(bls.G1.ProjectivePoint.BASE), vector.signature)).to.equal(false);
    const signature = bls.G2.ProjectivePoint.fromHex(fromHex(fixture.signature)).negate();
    expect(await verifier.verify(vector.message, vector.publicKey, g2(signature))).to.equal(false);
  });

  it("rejects a signature generated under a different domain", async function () {
    const wrong = signWithNoble(fromHex(fixture.message), 1n,
      "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_");
    const signature = g2(bls.G2.ProjectivePoint.fromHex(fromHex(wrong.signature)));
    expect(await verifier.verify(vector.message, g1(bls.G1.ProjectivePoint.BASE), signature)).to.equal(false);
  });

  it("rejects compressed, truncated, and overlong EIP-2537 encodings", async function () {
    expect(await verifier.verify(vector.message, fixture.publicKey, fixture.signature)).to.equal(false);
    expect(await verifier.verify(vector.message, vector.publicKey.slice(0, -2), vector.signature)).to.equal(false);
    expect(await verifier.verify(vector.message, vector.publicKey, vector.signature + "00")).to.equal(false);
  });

  it("rejects infinity even though the pairing precompile permits it", async function () {
    const zeroKey = "0x" + "00".repeat(128);
    const zeroSignature = "0x" + "00".repeat(256);
    expect(await verifier.verify(vector.message, zeroKey, vector.signature)).to.equal(false);
    expect(await verifier.verify(vector.message, vector.publicKey, zeroSignature)).to.equal(false);
    expect(await verifier.verify(vector.message, zeroKey, zeroSignature)).to.equal(false);
  });

  it("rejects the on-curve order-three public key outside G1", async function () {
    const torsionKey = "0x" + fp(0n) + fp(2n);
    expect(await verifier.verify(vector.message, torsionKey, vector.signature)).to.equal(false);
  });

  it("rejects an on-curve signature outside G2's prime-order subgroup", async function () {
    const point = nonSubgroupG2();
    expect(await verifier.verify(vector.message, vector.publicKey, g2(point))).to.equal(false);
  });

  it("rejects noncanonical field elements and malformed curve points", async function () {
    const p = bls.fields.Fp.ORDER;
    const badKey = "0x" + fp(p) + fp(2n);
    expect(await verifier.verify(vector.message, badKey, vector.signature)).to.equal(false);
    const badSignature = "0x01" + vector.signature.slice(4);
    expect(await verifier.verify(vector.message, vector.publicKey, badSignature)).to.equal(false);
  });
});
