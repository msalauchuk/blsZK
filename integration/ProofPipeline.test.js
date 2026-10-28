const { expect } = require("chai");
const { ethers } = require("hardhat");
const snarkjs = require("snarkjs");
const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const root = path.join(__dirname, "..");
const build = path.join(root, "circuits/build");
const binary = path.join(root, "target/debug/bls-prover");

function runCLI(args) {
  const result = spawnSync(binary, args, { cwd: root, encoding: "utf8" });
  if (result.error) throw result.error;
  return result;
}

function expectSuccess(result) {
  expect(result.status, result.stderr + result.stdout).to.equal(0);
}

describe("Real Groth16 pipeline (Poseidon demo, NOT BLS)", function () {
  this.timeout(120000);
  let work, input, calldata, rustArtifact, rustFile;
  let verifier, adapter, rollup;

  function provingArgs(values, output) {
    return [
      "prove",
      "--message-hash", values.messageHash,
      "--public-key-x", values.publicKeyX,
      "--public-key-y", values.publicKeyY,
      "--signature-x", values.signatureX,
      "--signature-y", values.signatureY,
      "--output", output,
    ];
  }

  before(async function () {
    if (!fs.existsSync(path.join(build, "proof.json")) || !fs.existsSync(binary)) {
      throw new Error("Run npm run test:proof to build all integration prerequisites.");
    }
    work = fs.mkdtempSync(path.join(os.tmpdir(), "blszk-integration-"));
    input = JSON.parse(fs.readFileSync(path.join(root, "circuits/test_input.json")));
    const proof = JSON.parse(fs.readFileSync(path.join(build, "proof.json")));
    const signals = JSON.parse(fs.readFileSync(path.join(build, "public.json")));
    expect(signals).to.deep.equal(["1", input.messageHash, input.publicKeyX, input.publicKeyY]);
    calldata = JSON.parse(`[${await snarkjs.groth16.exportSolidityCallData(proof, signals)}]`);

    const Generated = await ethers.getContractFactory("Groth16Verifier");
    verifier = await Generated.deploy();
    await verifier.waitForDeployment();
    const Adapter = await ethers.getContractFactory("DemoVerifierAdapter");
    adapter = await Adapter.deploy(await verifier.getAddress());
    await adapter.waitForDeployment();
    const [sequencer] = await ethers.getSigners();
    const Rollup = await ethers.getContractFactory("ZKRollupBLS");
    rollup = await Rollup.deploy(sequencer.address, await adapter.getAddress());
    await rollup.waitForDeployment();

    rustFile = path.join(work, "rust-proof.json");
    expectSuccess(runCLI(provingArgs(input, rustFile)));
    rustArtifact = JSON.parse(fs.readFileSync(rustFile));
  });

  after(function () {
    if (work) fs.rmSync(work, { recursive: true, force: true });
  });

  it("accepts snarkjs and Rust-generated proofs on the EVM", async function () {
    expect(await verifier.verifyProof(...calldata)).to.equal(true);
    const { a, b, c, inputs } = rustArtifact.solidityCalldata;
    expect(await verifier.verifyProof(a, b, c, inputs)).to.equal(true);
    expect(rustArtifact.publicInputs).to.deep.equal([
      "1", input.messageHash, input.publicKeyX, input.publicKeyY,
    ]);
    const proof = JSON.parse(Buffer.from(rustArtifact.proof, "hex").toString("utf8"));
    const expected = JSON.parse(`[${await snarkjs.groth16.exportSolidityCallData(proof, rustArtifact.publicInputs)}]`);
    expect([a, b, c, inputs]).to.deep.equal(expected);
  });

  it("verifies both CLI artifacts and raw snarkjs files", function () {
    expectSuccess(runCLI(["verify", "--proof-file", rustFile]));
    expectSuccess(runCLI([
      "verify", "--proof-file", path.join(build, "proof.json"),
      "--inputs-file", path.join(build, "public.json"),
    ]));
  });

  it("rejects changed public signals, proofs, and malformed CLI artifacts", async function () {
    const [a, b, c, signals] = calldata;
    const changed = [...signals];
    changed[1] = (BigInt(changed[1]) + 1n).toString();
    expect(await verifier.verifyProof(a, b, c, changed)).to.equal(false);
    const changedKey = [...signals];
    changedKey[2] = (BigInt(changedKey[2]) + 1n).toString();
    expect(await verifier.verifyProof(a, b, c, changedKey)).to.equal(false);
    expect(await verifier.verifyProof(a, b, c, [0, ...signals.slice(1)])).to.equal(false);
    expect(await verifier.verifyProof([0, 0], b, c, signals)).to.equal(false);

    const artifact = structuredClone(rustArtifact);
    artifact.publicInputs[1] = changed[1];
    const badFile = path.join(work, "changed-public.json");
    fs.writeFileSync(badFile, JSON.stringify(artifact));
    expect(runCLI(["verify", "--proof-file", badFile]).status).to.equal(1);

    const proof = JSON.parse(Buffer.from(artifact.proof, "hex").toString("utf8"));
    proof.pi_a = ["0", "0", "1"];
    artifact.proof = Buffer.from(JSON.stringify(proof)).toString("hex");
    artifact.publicInputs = rustArtifact.publicInputs;
    fs.writeFileSync(badFile, JSON.stringify(artifact));
    expect(runCLI(["verify", "--proof-file", badFile]).status).to.equal(1);

    artifact.publicInputs = rustArtifact.publicInputs.slice(1);
    fs.writeFileSync(badFile, JSON.stringify(artifact));
    expect(runCLI(["verify", "--proof-file", badFile]).status).to.equal(1);

    fs.writeFileSync(badFile, JSON.stringify({ proof: "00", publicInputs: [42] }));
    expect(runCLI(["verify", "--proof-file", badFile]).status).to.equal(1);
  });

  it("cannot generate a proof when the demo relation is false", function () {
    const badInput = { ...input, signatureX: (BigInt(input.signatureX) + 1n).toString() };
    const output = path.join(work, "invalid-witness.json");
    const result = runCLI(provingArgs(badInput, output));
    expect(result.status).to.equal(1);
    expect(result.stderr).to.include("Assert Failed");
    expect(fs.existsSync(output)).to.equal(false);
  });

  it("submits a real single-tuple proof through struct and bytes interfaces", async function () {
    const [a, b, c] = calldata;
    const message = ethers.zeroPadValue(ethers.toBeHex(BigInt(input.messageHash)), 32);
    const args = [ethers.ZeroHash, [message], [input.publicKeyX], [input.publicKeyY]];
    await (await rollup.submitBatchWithProof(...args, { a, b, c })).wait();
    const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256[2]", "uint256[2][2]", "uint256[2]"], [a, b, c]
    );
    await (await rollup.submitBatchWithProofBytes(...args, encoded)).wait();
    expect(await rollup.batchCount()).to.equal(2);
    expect(await rollup.isSignatureVerified(0)).to.equal(true);
  });

  it("rejects unproved tuples and data that differ from the proof", async function () {
    const [a, b, c] = calldata;
    expect(await adapter.verifyProof(a, b, c, [])).to.equal(false);
    expect(await adapter.verifyProof(a, b, c, [1, 2, 3, 4, 5, 6])).to.equal(false);
    const changedMessage = ethers.zeroPadValue(ethers.toBeHex(BigInt(input.messageHash) + 1n), 32);
    const countBefore = await rollup.batchCount();
    await expect(rollup.submitBatchWithProof(
      ethers.ZeroHash, [changedMessage], [input.publicKeyX], [input.publicKeyY], { a, b, c }
    )).to.be.revertedWithCustomError(rollup, "InvalidZKProof");
    expect(await rollup.batchCount()).to.equal(countBefore);
  });
});
