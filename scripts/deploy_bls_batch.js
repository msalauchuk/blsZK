const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const file = path.join(__dirname, "../proofs/gnark/build/batch/circuit.json");
  if (!fs.existsSync(file)) throw new Error("Run npm run bls:batch:setup first.");
  const metadata = JSON.parse(fs.readFileSync(file));
  const Generated = await ethers.getContractFactory("BLSBatchGroth16Verifier");
  const generated = await Generated.deploy();
  await generated.waitForDeployment();
  if (await generated.circuitId() !== metadata.verifyingKeyHash) throw new Error("Compiled batch verifier does not match setup metadata.");
  const Consumer = await ethers.getContractFactory("BLSBatchVerifier");
  const consumer = await Consumer.deploy(await generated.getAddress(), metadata.verifyingKeyHash);
  await consumer.waitForDeployment();
  const network = await ethers.provider.getNetwork();
  const deployment = {
    network: network.name,
    chainId: network.chainId.toString(),
    verifierType: metadata.schema,
    batchSize: metadata.batchSize,
    payloadBytes: metadata.payloadBytes,
    verifyingKeyHash: metadata.verifyingKeyHash,
    owner: await consumer.owner(),
    contracts: { generatedVerifier: await generated.getAddress(), blsBatchVerifier: await consumer.getAddress() },
  };
  const directory = path.join(__dirname, "../deployments");
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, `${network.name}-bls-batch.json`), JSON.stringify(deployment, null, 2) + "\n");
  console.log(JSON.stringify(deployment, null, 2));
  console.log("Authorize signer keys before submission; collect signatures for this exact contract/chain/batch context.");
  return deployment;
}

if (require.main === module) main().catch((error) => { console.error(error); process.exitCode = 1; });
module.exports = { deployBatch: main };
