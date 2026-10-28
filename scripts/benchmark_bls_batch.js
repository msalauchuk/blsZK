const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { ethers, network, config } = require("hardhat");
const { createTestBatchVectors, wireEntries, batchCommitment, signingMessage } = require("../test/helpers/bls-batch");

const root = path.join(__dirname, "..");
const build = path.join(root, "proofs/gnark/build/batch");
const binary = path.join(build, "bls-batch");
const methods = ["individual", "aggregate", "zk"];

function repetitions(name, fallback, maximum) {
  const value = process.env[name] ?? String(fallback);
  if (!/^[1-9][0-9]*$/.test(value) || Number(value) > maximum) throw new Error(`${name} must be an integer from 1 to ${maximum}.`);
  return Number(value);
}

function summarize(values) {
  assert(values.length > 0);
  const sorted = values.slice().sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return { samples: values.length, min: sorted[0], max: sorted.at(-1), mean: sorted.reduce((a, b) => a + b, 0) / sorted.length,
    median: sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2 };
}

function fileHash(file) { return crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex"); }
function readJSON(file) { return JSON.parse(fs.readFileSync(file)); }
function writeJSON(file, value) { fs.writeFileSync(file, JSON.stringify(value, null, 2) + "\n"); }
function relativeCommands(metrics) { return { ...metrics, command: metrics.command.map((arg) => arg.replace(root, "<repo>")) }; }
function calldata(data) {
  const bytes = ethers.getBytes(data);
  const zeroBytes = bytes.filter((b) => b === 0).length;
  return { bytes: bytes.length, zeroBytes, nonzeroBytes: bytes.length - zeroBytes };
}

function summaryMarkdown(report) {
  const rows = ["# BLS batch comparison", "", `Fixed batch: two entries, 25-byte payloads, 119-byte signed frames. Fork: ${report.environment.hardfork}.`, "",
    "| State before transaction | Verification path | Gas (mean) | Min–max | Calldata bytes | Samples |",
    "| --- | --- | ---: | ---: | ---: | ---: |"];
  for (const scenario of report.scenarios) {
    for (const method of methods) {
      const values = scenario.summary[method];
      rows.push(`| ${scenario.name} | ${method} | ${values.gas.mean.toFixed(0)} | ${values.gas.min}–${values.gas.max} | ${values.calldataBytes.min}–${values.calldataBytes.max} | ${values.gas.samples} |`);
    }
  }
  rows.push("", "Gas samples repeat identical transactions from restored state snapshots; they are not independent proving samples.", "",
    "| State | Independent proof commands | Prove time, mean (s) | Full command, mean (s) | Peak child RSS, max (GiB) |",
    "| --- | ---: | ---: | ---: | ---: |");
  for (const scenario of report.scenarios) {
    const p = scenario.provingSummary;
    rows.push(`| ${scenario.name} | ${p.provingTimeMs.samples} | ${(p.provingTimeMs.mean / 1000).toFixed(2)} | ${(p.commandWallTimeMs.mean / 1000).toFixed(2)} | ${(p.peakRssBytes.max / 2**30).toFixed(2)} |`);
  }
  rows.push("", `Setup for this run: **${report.setup.mode}**. Cached setup is not a measurement of fresh setup cost.`, "",
    "Complete transaction gas includes calldata, commitment reconstruction, authorization, verification, counter/commitment writes, and the event. Deployment and signer-registration receipts are separate in the JSON.", "",
    "These results cover one fixed two-entry circuit. They establish no crossover size, general gas-savings claim, throughput, or consensus-finality estimate.", "");
  return rows.join("\n");
}

async function main() {
  if (network.name !== "hardhat" || config.networks.hardhat.hardfork !== "prague") throw new Error("Run on the in-process Hardhat Prague network; benchmark state snapshots must not target a public network.");
  const proofRuns = repetitions("BLSZK_BENCH_PROOF_RUNS", 1, 10);
  const gasRuns = repetitions("BLSZK_BENCH_GAS_RUNS", 5, 100);
  execFileSync(binary, ["status", "--artifacts", build], { cwd: root, stdio: "inherit" });
  const metadata = readJSON(path.join(build, "circuit.json"));
  assert.equal(metadata.schema, "blszk.gnark-bls12-381.batch2.v1");
  const runId = new Date().toISOString().replace(/[:.]/g, "-");
  const directory = path.join(build, "benchmark", runId);
  fs.mkdirSync(directory, { recursive: true });
  const lockPath = path.join(build, "benchmark.lock");
  const lock = fs.openSync(lockPath, "wx");
  const report = { schema: "blszk.batch2-comparison.v1", startedAt: new Date().toISOString(), status: "running",
    plan: { proofRunsPerState: proofRuns, gasRunsPerProofAndMethod: gasRuns, batchSize: 2, payloadBytes: 25, signedMessageBytes: 119 },
    environment: { platform: os.platform(), architecture: os.arch(), osRelease: os.release(), cpuModel: os.cpus()[0].model, logicalCpuCount: os.cpus().length,
      systemMemoryBytes: os.totalmem(), node: process.version, python: execFileSync("python3", ["--version"], { encoding: "utf8" }).trim(),
      go: execFileSync("go", ["version"], { encoding: "utf8" }).trim(), hardhat: require("hardhat/package.json").version,
      solc: require("solc").version(), hardfork: config.networks.hardhat.hardfork, chainId: (await ethers.provider.getNetwork()).chainId.toString(),
      compilerSettings: config.solidity.compilers[0].settings, goWorkers: 4, goHeapGcTargetBytes: 3 * 2**30,
      cachePolicy: "Fresh Go process per proof; circuit/keys reused; normal OS filesystem cache, no forced cache drop",
      peakMemoryScope: "Go child process only, measured with getrusage; excludes Node/Python and other applications" },
    source: { gitCommit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
      worktreeDirty: execFileSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" }).trim().length > 0,
      files: Object.fromEntries(["contracts/BLS12381Verifier.sol", "contracts/BLSBatchVerifier.sol", "contracts/benchmarks/BLSBatchBenchmark.sol", "scripts/benchmark_bls_batch.js", "scripts/bls_batch.sh", "scripts/measure_process.py", "test/helpers/bls-batch.js", "hardhat.config.js", "package-lock.json", "proofs/gnark/go.mod", "proofs/gnark/go.sum"].map((file) => [file, fileHash(file)])) },
    circuit: metadata, setup: { mode: "external/reused", measured: null }, deployments: [], signerRegistration: [], scenarios: [] };
  const setupFile = path.join(build, "benchmark/setup.json");
  if (fs.existsSync(setupFile)) {
    const setup = readJSON(setupFile);
    report.setup = { mode: setup.mode, measured: setup.metrics ? relativeCommands(readJSON(setup.metrics)) : null };
  }
  const checkpoint = () => writeJSON(path.join(directory, "results.json"), report);
  try {
    async function deploy(name, args = []) {
      const factory = await ethers.getContractFactory(name);
      const instance = await factory.deploy(...args);
      await instance.waitForDeployment();
      const receipt = await instance.deploymentTransaction().wait();
      const codeBytes = ethers.getBytes(await ethers.provider.getCode(await instance.getAddress())).length;
      assert(codeBytes <= 24576, `${name} exceeds standard Ethereum deployed-code limit`);
      report.deployments.push({ contract: name, address: await instance.getAddress(), gasUsed: receipt.gasUsed.toString(), codeBytes });
      return instance;
    }
    const generated = await deploy("BLSBatchGroth16Verifier");
    assert.equal(await generated.circuitId(), metadata.verifyingKeyHash);
    const direct = await deploy("BLS12381Verifier");
    const consumer = await deploy("BLSBatchBenchmark", [await generated.getAddress(), metadata.verifyingKeyHash, await direct.getAddress()]);
    const [, submitter] = await ethers.getSigners();
    report.consumer = await consumer.getAddress();
    const context = { chainId: report.environment.chainId, verifyingContract: report.consumer };
    const firstVectors = createTestBatchVectors({ ...context, batchId: "0" });
    const firstKeys = wireEntries(firstVectors.statement).map((e) => e.publicKey);
    for (const key of firstKeys) {
      const tx = await consumer.setSignerAuthorization(key, true);
      report.signerRegistration.push({ keyHash: ethers.sha256(key), gasUsed: (await tx.wait()).gasUsed.toString() });
    }
    let baseline = await ethers.provider.send("evm_snapshot", []);
    async function reset() {
      assert.equal(await ethers.provider.send("evm_revert", [baseline]), true);
      baseline = await ethers.provider.send("evm_snapshot", []);
    }
    let bootstrap;
    for (const [batchId, name] of [["0", "first batch (counter 0)"], ["1", "subsequent batch (counter 1)"]]) {
      if (batchId === "1") {
        await reset();
        const tx = await consumer.connect(submitter).submitBatch(0, bootstrap.keys, bootstrap.payloads, bootstrap.proof.proof);
        const receipt = await tx.wait();
        assert.equal(receipt.status, 1);
        assert.equal(await consumer.nextBatchId(), 1n);
        report.steadyStateBootstrap = { batchId: "0", commitment: bootstrap.proof.commitment, gasUsed: receipt.gasUsed.toString(), transactionHash: tx.hash };
        baseline = await ethers.provider.send("evm_snapshot", []);
      }
      const start = performance.now();
      const vectors = createTestBatchVectors({ ...context, batchId });
      const entries = wireEntries(vectors.statement);
      const keys = entries.map((e) => e.publicKey), payloads = entries.map((e) => e.payload);
      const messages = entries.map((e, i) => signingMessage(vectors.statement, i, e.payload));
      for (let i = 0; i < 2; i++) {
        assert.equal(await consumer.signingMessage(batchId, i, payloads[i]), messages[i]);
        assert.equal(await direct.verify(messages[i], keys[i], vectors.signatures[i]), true);
      }
      assert.equal(await direct.verifyAggregate(messages, keys, vectors.aggregateSignature), true);
      const commitment = batchCommitment(vectors.statement);
      assert.equal(await consumer.batchCommitment(batchId, keys, payloads), commitment);
      const scenario = { name, batchId, ciphersuite: vectors.statement.ciphersuite, commitment, payloads, publicKeys: keys, signedMessages: messages,
        aggregateSignature: vectors.aggregateSignature, individualSignatures: vectors.signatures, fixturePreparationAndPreflightMs: performance.now() - start,
        evidenceBytes: { individual: 512, aggregate: 256, zk: null }, proverRuns: [], transactions: [] };
      report.scenarios.push(scenario);
      const inputFile = path.join(directory, `batch-${batchId}.input.json`);
      writeJSON(inputFile, vectors.statement);
      for (let trial = 0; trial < proofRuns; trial++) {
        console.log(`Benchmark ${name}: genuine proof ${trial + 1}/${proofRuns}`);
        const proofFile = path.join(directory, `batch-${batchId}.proof-${trial}.json`);
        const metricsFile = path.join(directory, `batch-${batchId}.process-${trial}.json`);
        execFileSync("python3", [path.join(root, "scripts/measure_process.py"), "--metrics", metricsFile, "--timeout", "1200", "--", binary,
          "prove", "--artifacts", build, "--input", inputFile, "--output", proofFile], { cwd: root, stdio: "inherit", timeout: 1230000 });
        const measured = relativeCommands(readJSON(metricsFile));
        assert.equal(measured.exitCode, 0);
        assert(measured.peakRssBytes > 0);
        const proof = readJSON(proofFile);
        assert.equal(proof.circuit.verifyingKeyHash, metadata.verifyingKeyHash);
        assert.equal(proof.commitment, commitment);
        assert.equal(proof.batchId, batchId);
        assert.equal(ethers.getAddress(proof.verifyingContract), ethers.getAddress(report.consumer));
        assert.deepEqual(proof.entries, entries);
        const digest = BigInt(commitment);
        assert.deepEqual(proof.publicInputs, [(digest >> 128n).toString(), (digest & ((1n << 128n) - 1n)).toString()]);
        await generated.verifyProof(proof.proof, proof.publicInputs);
        scenario.evidenceBytes.zk = ethers.getBytes(proof.proof).length;
        scenario.proverRuns.push({ trial, provingTimeMs: proof.provingTimeMs, proofBytes: scenario.evidenceBytes.zk, proofHash: ethers.sha256(proof.proof), ...measured });
        if (batchId === "0" && trial === 0) bootstrap = { keys, payloads, proof };
        for (const method of methods) {
          for (let repeat = 0; repeat < gasRuns; repeat++) {
            await reset();
            assert.equal(await consumer.nextBatchId(), BigInt(batchId));
            const args = [batchId, keys, payloads];
            const connected = consumer.connect(submitter);
            const tx = method === "individual" ? await connected.submitIndividual(...args, vectors.signatures)
              : method === "aggregate" ? await connected.submitAggregate(...args, vectors.aggregateSignature)
                : await connected.submitBatch(...args, proof.proof);
            const receipt = await tx.wait();
            assert.equal(receipt.status, 1);
            assert.equal(await consumer.batchCommitments(batchId), commitment);
            assert.equal(await consumer.nextBatchId(), BigInt(batchId) + 1n);
            scenario.transactions.push({ method, proofTrial: trial, repeat, gasUsed: receipt.gasUsed.toString(), calldata: calldata(tx.data), calldataHash: ethers.sha256(tx.data),
              transactionHash: tx.hash, status: receipt.status });
          }
        }
        checkpoint();
      }
      scenario.summary = Object.fromEntries(methods.map((method) => {
        const samples = scenario.transactions.filter((sample) => sample.method === method);
        return [method, { gas: summarize(samples.map((s) => Number(s.gasUsed))), calldataBytes: summarize(samples.map((s) => s.calldata.bytes)) }];
      }));
      scenario.provingSummary = { provingTimeMs: summarize(scenario.proverRuns.map((r) => r.provingTimeMs)),
        commandWallTimeMs: summarize(scenario.proverRuns.map((r) => r.wallTimeMs)), peakRssBytes: summarize(scenario.proverRuns.map((r) => r.peakRssBytes)) };
      checkpoint();
      console.log(`${name}:`, Object.fromEntries(methods.map((m) => [m, scenario.summary[m].gas.mean])));
    }
    report.status = "complete";
    report.completedAt = new Date().toISOString();
    checkpoint();
    const markdown = summaryMarkdown(report);
    fs.writeFileSync(path.join(directory, "summary.md"), markdown);
    writeJSON(path.join(build, "benchmark/latest.json"), report);
    fs.writeFileSync(path.join(build, "benchmark/latest.md"), markdown);
    console.log(markdown);
    console.log(`Raw measurements: ${path.relative(root, path.join(directory, "results.json"))}`);
    return report;
  } catch (error) {
    report.status = "failed";
    report.error = error.message;
    checkpoint();
    throw error;
  } finally {
    fs.closeSync(lock);
    fs.unlinkSync(lockPath);
  }
}

if (require.main === module) main().catch((error) => { console.error(error); process.exitCode = 1; });
module.exports = { runBenchmark: main, summarize };
