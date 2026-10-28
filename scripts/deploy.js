const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  const generated = path.join(__dirname, "../contracts/generated/Verifier.sol");
  if (!fs.existsSync(generated)) {
    throw new Error("Run npm run full:setup first to generate and compile the demo verifier.");
  }
  console.log("Deploying the single-tuple Poseidon demo. BLS verification is not implemented.");
  const Verifier = await ethers.getContractFactory("Groth16Verifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const Adapter = await ethers.getContractFactory("DemoVerifierAdapter");
  const adapter = await Adapter.deploy(await verifier.getAddress());
  await adapter.waitForDeployment();
  const Rollup = await ethers.getContractFactory("ZKRollupBLS");
  const rollup = await Rollup.deploy(deployer.address, await adapter.getAddress());
  await rollup.waitForDeployment();

  const deployment = {
    network: network.name,
    chainId: Number(network.chainId),
    deployer: deployer.address,
    verifierType: "groth16-poseidon-demo",
    contracts: {
      generatedVerifier: await verifier.getAddress(),
      verifier: await adapter.getAddress(),
      zkRollupBLS: await rollup.getAddress(),
    },
  };
  const directory = path.join(__dirname, "../deployments");
  fs.mkdirSync(directory, { recursive: true });
  const file = path.join(directory, `${network.name}.json`);
  fs.writeFileSync(file, JSON.stringify(deployment, null, 2) + "\n");
  console.log(JSON.stringify(deployment, null, 2));
  console.log(`Deployment saved to ${file}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
