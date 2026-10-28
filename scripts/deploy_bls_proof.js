const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const file = path.join(__dirname, "../proofs/gnark/build/circuit.json");
  if (!fs.existsSync(file)) throw new Error("Run npm run bls:proof:setup first.");
  const metadata = JSON.parse(fs.readFileSync(file));
  const Generated = await ethers.getContractFactory("BLSGroth16Verifier");
  const generated = await Generated.deploy();
  await generated.waitForDeployment();
  if (await generated.circuitId() !== metadata.verifyingKeyHash) {
    throw new Error("Compiled verifier differs from setup metadata; rerun BLS proof setup and compile.");
  }
  const Consumer = await ethers.getContractFactory("BLSProofVerifier");
  const consumer = await Consumer.deploy(await generated.getAddress(), metadata.verifyingKeyHash);
  await consumer.waitForDeployment();
  const network = await ethers.provider.getNetwork();
  const deployment = {
    network: network.name,
    chainId: Number(network.chainId),
    verifierType: "gnark-groth16-bls12-381-basic-v1",
    messageBytes: metadata.messageBytes,
    verifyingKeyHash: metadata.verifyingKeyHash,
    contracts: {
      generatedVerifier: await generated.getAddress(),
      blsProofVerifier: await consumer.getAddress(),
    },
  };
  const directory = path.join(__dirname, "../deployments");
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, `${network.name}-bls-proof.json`), JSON.stringify(deployment, null, 2) + "\n");
  console.log(JSON.stringify(deployment, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
