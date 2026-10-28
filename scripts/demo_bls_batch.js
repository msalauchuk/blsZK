const { ethers, network } = require("hardhat");
const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const { createTestBatch, wireEntries } = require("../test/helpers/bls-batch");

async function main() {
  const chainId = (await ethers.provider.getNetwork()).chainId;
  if (!["localhost", "hardhat"].includes(network.name) || chainId !== 31337n) {
    throw new Error("This demo uses publicly known TEST keys and runs only on a local development network (31337).");
  }
  const root = path.join(__dirname, "..");
  const build = path.join(root, "proofs/gnark/build/batch");
  const file = path.join(root, `deployments/${network.name}-bls-batch.json`);
  if (!fs.existsSync(file)) throw new Error("Run npm run bls:batch:deploy first.");
  const deployment = JSON.parse(fs.readFileSync(file));
  const consumer = await ethers.getContractAt("BLSBatchVerifier", deployment.contracts.blsBatchVerifier);
  const metadata = JSON.parse(fs.readFileSync(path.join(build, "circuit.json")));
  if (await consumer.verifyingKeyHash() !== metadata.verifyingKeyHash) throw new Error("Redeploy after changing setup keys.");
  const [account] = await ethers.getSigners();
  if (await consumer.owner() !== account.address) throw new Error("The local deployer must authorize the demo keys.");
  const binary = path.join(build, "bls-batch");
  execFileSync(binary, ["status", "--artifacts", build], { cwd: root, stdio: "inherit" });
  const input = createTestBatch({
    chainId: chainId.toString(), verifyingContract: await consumer.getAddress(), batchId: (await consumer.nextBatchId()).toString(),
  });
  const entries = wireEntries(input);
  const keys = entries.map((entry) => entry.publicKey);
  const payloads = entries.map((entry) => entry.payload);
  console.log("Signing the current batch context with publicly known TEST keys.");
  for (const key of keys) await (await consumer.setSignerAuthorization(key, true)).wait();
  const inputFile = path.join(build, "demo-input.json");
  const proofFile = path.join(build, "demo-proof.json");
  fs.writeFileSync(inputFile, JSON.stringify(input, null, 2) + "\n");
  execFileSync(binary, ["prove", "--artifacts", build, "--input", inputFile, "--output", proofFile], {
    cwd: root, stdio: "inherit", timeout: 600000,
  });
  const proof = JSON.parse(fs.readFileSync(proofFile));
  const tx = await consumer.submitBatch(input.batchId, keys, payloads, proof.proof);
  const receipt = await tx.wait();
  const result = { batchId: input.batchId, commitment: proof.commitment, transactionHash: tx.hash, gasUsed: receipt.gasUsed.toString() };
  fs.writeFileSync(path.join(build, "demo-transaction.json"), JSON.stringify(result, null, 2) + "\n");
  console.log(JSON.stringify(result, null, 2));
  return result;
}

if (require.main === module) main().catch((error) => { console.error(error); process.exitCode = 1; });
module.exports = { demoBatch: main };
