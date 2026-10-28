const { expect } = require("chai");
const { ethers, artifacts } = require("hardhat");
const fs = require("fs");
const path = require("path");
const { bls, g1 } = require("../test/helpers/bls");

const build = path.join(__dirname, "../proofs/gnark/build");

describe("Groth16 proof of real BLS12-381 verification", function () {
  this.timeout(120000);
  let proof, generated, consumer;

  before(async function () {
    const proofFile = path.join(build, "proof.json");
    if (!fs.existsSync(proofFile)) throw new Error("Run npm run test:bls:proof to generate the BLS proof first.");
    proof = JSON.parse(fs.readFileSync(proofFile));
    expect(proof.circuit.schema).to.equal("blszk.gnark-bls12-381.basic.v1");
    expect(proof.circuit.messageBytes).to.equal(25);
    expect(proof.publicInputs).to.have.length(37);
    const generatedArtifact = await artifacts.readArtifact("BLSGroth16Verifier");
    // Check the actual Ethereum deployed-code limit despite the dev network's
    // allowUnlimitedContractSize setting.
    expect(ethers.getBytes(generatedArtifact.deployedBytecode).length).to.be.at.most(24576);
    const Generated = await ethers.getContractFactory("BLSGroth16Verifier");
    generated = await Generated.deploy();
    await generated.waitForDeployment();
    expect(await generated.circuitId()).to.equal(proof.circuit.verifyingKeyHash);
    const Consumer = await ethers.getContractFactory("BLSProofVerifier");
    consumer = await Consumer.deploy(await generated.getAddress(), proof.circuit.verifyingKeyHash);
    await consumer.waitForDeployment();
  });

  it("verifies the genuine BLS proof and binds the exact public statement", async function () {
    const inputs = await consumer.statementInputs(proof.message, proof.publicKey);
    expect(inputs.map(String)).to.deep.equal(proof.publicInputs);
    await expect(generated.verifyProof(proof.proof, proof.publicInputs)).to.not.be.reverted;
    await expect(consumer.verifyProof(proof.message, proof.publicKey, proof.proof)).to.not.be.reverted;
    expect(proof).to.not.have.property("signature");
  });

  it("accepts a real local-EVM transaction and records its gas", async function () {
    const tx = await consumer.verifyProof.send(proof.message, proof.publicKey, proof.proof, { gasLimit: 3000000 });
    const receipt = await tx.wait();
    expect(receipt.status).to.equal(1);
    const measurement = {
      network: "hardhat-prague",
      chainId: Number((await ethers.provider.getNetwork()).chainId),
      constraints: proof.circuit.constraints,
      messageBytes: ethers.getBytes(proof.message).length,
      proofBytes: ethers.getBytes(proof.proof).length,
      transactionCalldataBytes: ethers.getBytes(tx.data).length,
      verificationTransactionGas: receipt.gasUsed.toString(),
      provingTimeMs: proof.provingTimeMs,
      verifyingKeyHash: proof.circuit.verifyingKeyHash,
    };
    fs.writeFileSync(path.join(build, "evm-verification.json"), JSON.stringify(measurement, null, 2) + "\n");
    console.log(`    Real BLS proof: ${measurement.proofBytes} bytes; transaction gas: ${measurement.verificationTransactionGas}`);
  });

  it("rejects changing any message byte", async function () {
    for (let i = 0; i < 25; i++) {
      const message = ethers.getBytes(proof.message);
      message[i] ^= 1;
      await expect(consumer.verifyProof(message, proof.publicKey, proof.proof)).to.be.reverted;
    }
  });

  it("rejects a different valid public key and noncanonical padding", async function () {
    await expect(consumer.verifyProof(proof.message, g1(bls.G1.ProjectivePoint.BASE), proof.proof)).to.be.reverted;
    const key = ethers.getBytes(proof.publicKey);
    key[0] = 1;
    await expect(consumer.verifyProof(proof.message, key, proof.proof)).to.be.revertedWithCustomError(consumer, "NonCanonicalPublicKey");
    await expect(consumer.verifyProof("0x00", proof.publicKey, proof.proof)).to.be.revertedWithCustomError(consumer, "InvalidStatementLength");
  });

  it("rejects altered, truncated, and extended proof encodings", async function () {
    const changed = ethers.getBytes(proof.proof);
    changed[changed.length - 1] ^= 1;
    await expect(consumer.verifyProof(proof.message, proof.publicKey, changed)).to.be.reverted;
    await expect(consumer.verifyProof(proof.message, proof.publicKey, proof.proof.slice(0, -2))).to.be.reverted;
    await expect(consumer.verifyProof(proof.message, proof.publicKey, proof.proof + "00")).to.be.reverted;
  });

  it("pins the verifying key and rejects non-contract verifiers", async function () {
    const Consumer = await ethers.getContractFactory("BLSProofVerifier");
    await expect(Consumer.deploy(await generated.getAddress(), ethers.ZeroHash)).to.be.revertedWithCustomError(Consumer, "InvalidVerifier");
    const [account] = await ethers.getSigners();
    await expect(Consumer.deploy(account.address, proof.circuit.verifyingKeyHash)).to.be.revertedWithCustomError(Consumer, "InvalidVerifier");
  });
});
