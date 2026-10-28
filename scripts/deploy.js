const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

/**
 * Deploy Script per ZK-Rollup BLS
 *
 * Questo script:
 * 1. Cerca Verifier.sol generato da snarkjs
 * 2. Se non esiste, usa MockBLSVerifier per testing
 * 3. Deploya ZKRollupBLS con il verifier appropriato
 */

async function main() {
  console.log("\n╔══════════════════════════════════════════╗");
  console.log("║        ZK-ROLLUP BLS DEPLOYMENT          ║");
  console.log("╚══════════════════════════════════════════╝\n");

  // Get deployer account
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();

  console.log(" Deployment Information:");
  console.log(`   Network:  ${network.name || `Chain ID ${network.chainId}`}`);
  console.log(`   Deployer: ${deployer.address}`);

  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`   Balance:  ${ethers.formatEther(balance)} ETH\n`);

  // Check if snarkjs-generated Verifier.sol exists
  const verifierPath = path.join(__dirname, "../circuits/build/Verifier.sol");
  let verifierAddress;
  let isRealVerifier = false;

  if (fs.existsSync(verifierPath)) {
    console.log("✓ Found snarkjs-generated Verifier.sol\n");

    // Copy to contracts directory
    const verifierContent = fs.readFileSync(verifierPath, "utf8");
    const targetPath = path.join(__dirname, "../contracts/Verifier.sol");
    fs.writeFileSync(targetPath, verifierContent);
    console.log(`  Copied to: ${targetPath}\n`);

    // Deploy generated Verifier
    console.log("[1/2] Deploying Groth16 Verifier...");

    try {
      const Verifier = await ethers.getContractFactory("Groth16Verifier");
      const verifier = await Verifier.deploy();
      await verifier.waitForDeployment();
      verifierAddress = await verifier.getAddress();
      isRealVerifier = true;
      console.log(`  ✓ Verifier deployed at: ${verifierAddress}`);
    } catch (e) {
      // Try alternative name (snarkjs sometimes uses "Verifier")
      try {
        const Verifier = await ethers.getContractFactory("Verifier");
        const verifier = await Verifier.deploy();
        await verifier.waitForDeployment();
        verifierAddress = await verifier.getAddress();
        isRealVerifier = true;
        console.log(`  ✓ Verifier deployed at: ${verifierAddress}`);
      } catch (e2) {
        console.log(`  ✗ Failed to deploy generated verifier: ${e2.message}`);
        console.log("  → Falling back to MockBLSVerifier\n");
      }
    }
  }

  // Fall back to mock verifier if needed
  if (!verifierAddress) {
    console.log("  Using MockBLSVerifier (for testing only!)\n");
    console.log("[1/2] Deploying Mock Verifier...");

    const MockVerifier = await ethers.getContractFactory("MockBLSVerifier");
    const mockVerifier = await MockVerifier.deploy();
    await mockVerifier.waitForDeployment();
    verifierAddress = await mockVerifier.getAddress();
    console.log(`  ✓ Mock Verifier deployed at: ${verifierAddress}`);
  }

  // Deploy ZKRollupBLS
  console.log("\n[2/2] Deploying ZKRollupBLS...");
  const ZKRollupBLS = await ethers.getContractFactory("ZKRollupBLS");
  const zkRollup = await ZKRollupBLS.deploy(
      deployer.address,  // sequencer
      verifierAddress    // verifier
  );
  await zkRollup.waitForDeployment();
  const zkRollupAddress = await zkRollup.getAddress();
  console.log(`  ZKRollupBLS deployed at: ${zkRollupAddress}`);

  // Verify initial state
  console.log("\n Initial State Verification:");
  const sequencer = await zkRollup.sequencer();
  const verifierContract = await zkRollup.verifier();
  const batchCount = await zkRollup.batchCount();
  const currentStateRoot = await zkRollup.currentStateRoot();

  console.log(`   Sequencer:   ${sequencer}`);
  console.log(`   Verifier:    ${verifierContract}`);
  console.log(`   Batch Count: ${batchCount.toString()}`);
  console.log(`   State Root:  ${currentStateRoot}`);

  // Save deployment addresses
  const deploymentInfo = {
    network: network.name || `chain-${network.chainId}`,
    chainId: Number(network.chainId),
    contracts: {
      verifier: verifierAddress,
      zkRollupBLS: zkRollupAddress
    },
    verifierType: isRealVerifier ? "snarkjs-groth16" : "mock",
    deployer: deployer.address,
    timestamp: new Date().toISOString(),
    blockNumber: await ethers.provider.getBlockNumber()
  };

  const deploymentsDir = path.join(__dirname, "../deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const deploymentFile = path.join(
      deploymentsDir,
      `${deploymentInfo.network}.json`
  );

  fs.writeFileSync(
      deploymentFile,
      JSON.stringify(deploymentInfo, null, 2)
  );

  console.log(`\n Deployment saved to: ${deploymentFile}`);

  // Gas estimation
  console.log("\n Gas Estimation:");
  try {
    // Create sample Groth16 proof struct
    const sampleProof = {
      a: [BigInt(1), BigInt(2)],
      b: [[BigInt(3), BigInt(4)], [BigInt(5), BigInt(6)]],
      c: [BigInt(7), BigInt(8)]
    };

    const sampleMessageHashes = [
      ethers.keccak256(ethers.toUtf8Bytes("test1")),
      ethers.keccak256(ethers.toUtf8Bytes("test2"))
    ];
    const samplePublicKeysX = [BigInt(123), BigInt(456)];
    const samplePublicKeysY = [BigInt(789), BigInt(101112)];

    const estimatedGas = await zkRollup.submitBatchWithProof.estimateGas(
        ethers.keccak256(ethers.toUtf8Bytes("newState")),
        sampleMessageHashes,
        samplePublicKeysX,
        samplePublicKeysY,
        sampleProof
    );

    const gasPerTx = Number(estimatedGas) / 2;
    console.log(`   2-signature batch: ${estimatedGas.toString()} gas`);
    console.log(`   Per signature:     ${gasPerTx.toFixed(0)} gas`);

    // Compare with traditional BLS
    const traditionalBLSGas = 2 * 300000; // ~300k per BLS pairing
    const savings = traditionalBLSGas - Number(estimatedGas);
    const savingsPercent = (savings / traditionalBLSGas * 100).toFixed(1);

    console.log("\n Comparison with Traditional BLS:");
    console.log(`   Traditional:  ${traditionalBLSGas.toLocaleString()} gas`);
    console.log(`   ZK Rollup:    ${estimatedGas.toString()} gas`);
    console.log(`   Savings:      ${savings.toLocaleString()} gas (${savingsPercent}%)`);
  } catch (error) {
    console.log(`   Could not estimate gas: ${error.message}`);
  }

  // Final summary
  console.log("\n╔══════════════════════════════════════════╗");
  console.log("║      DEPLOYMENT COMPLETED SUCCESSFULLY   ║");
  console.log("╚══════════════════════════════════════════╝\n");

  if (!isRealVerifier) {
    console.log("️  WARNING: Using Mock Verifier!");
    console.log("   For production, run:");
    console.log("   1. cd circuits && ./scripts/compile_bls_circuit.sh");
    console.log("   2. npx hardhat run scripts/deploy.js\n");
  }

  return {
    verifier: verifierAddress,
    zkRollupBLS: zkRollupAddress,
    isRealVerifier
  };
}

// Execute deployment
main()
    .then((addresses) => {
      console.log("Deployed addresses:", addresses);
      process.exit(0);
    })
    .catch((error) => {
      console.error("\n Deployment failed:", error);
      process.exit(1);
    });