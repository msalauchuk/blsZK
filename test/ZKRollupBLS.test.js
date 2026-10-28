const { expect } = require("chai");
const { ethers } = require("hardhat");

/**
 * Test Suite per ZKRollupBLS
 *
 * Questi test verificano:
 * - Deployment corretto
 * - Submission di batch con prove ZK
 * - Gestione dello stato L2
 * - Analisi gas
 */
describe("ZKRollupBLS", function () {
    let zkContract;
    let mockVerifier;
    let deployer, sequencer, user1, user2;

    // Helper per creare una prova Groth16 mock
    function createMockProof() {
        return {
            a: [BigInt(1), BigInt(2)],
            b: [[BigInt(3), BigInt(4)], [BigInt(5), BigInt(6)]],
            c: [BigInt(7), BigInt(8)]
        };
    }

    beforeEach(async function () {
        [deployer, sequencer, user1, user2] = await ethers.getSigners();

        // Deploy MockBLSVerifier
        const MockVerifier = await ethers.getContractFactory("MockBLSVerifier");
        mockVerifier = await MockVerifier.deploy();
        await mockVerifier.waitForDeployment();
        const verifierAddress = await mockVerifier.getAddress();

        // Deploy ZKRollupBLS
        const ZKRollupBLS = await ethers.getContractFactory("ZKRollupBLS");
        zkContract = await ZKRollupBLS.deploy(sequencer.address, verifierAddress);
        await zkContract.waitForDeployment();

        console.log("    Verifier:", verifierAddress);
        console.log("    ZKRollupBLS:", await zkContract.getAddress());
    });

    describe("Deployment", function () {
        it("Dovrebbe deployare con sequencer corretto", async function () {
            expect(await zkContract.sequencer()).to.equal(sequencer.address);
            expect(await zkContract.batchCount()).to.equal(0);
            expect(await zkContract.submissionCount()).to.equal(0);
        });

        it("Dovrebbe inizializzare stato L2 a zero", async function () {
            expect(await zkContract.l2BlockNumber()).to.equal(0);
            expect(await zkContract.currentStateRoot()).to.equal(ethers.ZeroHash);
        });

        it("Dovrebbe avere verifier configurato", async function () {
            expect(await zkContract.verifier()).to.equal(await mockVerifier.getAddress());
        });
    });

    describe("Batch Submission con Groth16 Proof", function () {
        it("Dovrebbe accettare batch con prova valida (struct)", async function () {
            const messageHashes = [
                ethers.keccak256(ethers.toUtf8Bytes("message1")),
                ethers.keccak256(ethers.toUtf8Bytes("message2")),
            ];

            const publicKeysX = [
                BigInt("98765432109876543210"),
                BigInt("98765432109876543211"),
            ];

            const publicKeysY = [
                BigInt("11111111111111111111"),
                BigInt("11111111111111111112"),
            ];

            const stateRoot = ethers.keccak256(ethers.toUtf8Bytes("new_state"));
            const proof = createMockProof();

            const tx = await zkContract.connect(sequencer).submitBatchWithProof(
                stateRoot,
                messageHashes,
                publicKeysX,
                publicKeysY,
                proof
            );

            const receipt = await tx.wait();
            console.log("    Gas utilizzato:", receipt.gasUsed.toString());

            // Verifica batch creato
            const batch = await zkContract.batches(0);
            expect(batch.stateRoot).to.equal(stateRoot);
            expect(batch.numSignatures).to.equal(2);
            expect(batch.verified).to.be.true;

            // Verifica stato aggiornato
            expect(await zkContract.currentStateRoot()).to.equal(stateRoot);
            expect(await zkContract.l2BlockNumber()).to.equal(1);
        });

        it("Dovrebbe rifiutare batch quando verifier ritorna false", async function () {
            // Imposta mock per rifiutare
            await mockVerifier.setShouldVerify(false);

            const messageHash = ethers.keccak256(ethers.toUtf8Bytes("msg"));
            const proof = createMockProof();

            await expect(
                zkContract.connect(sequencer).submitBatchWithProof(
                    ethers.ZeroHash,
                    [messageHash],
                    [BigInt(123)],
                    [BigInt(456)],
                    proof
                )
            ).to.be.revertedWithCustomError(zkContract, "InvalidZKProof");
        });

        it("NON dovrebbe accettare batch da non-sequencer", async function () {
            const messageHash = ethers.keccak256(ethers.toUtf8Bytes("msg"));
            const proof = createMockProof();

            await expect(
                zkContract.connect(user1).submitBatchWithProof(
                    ethers.ZeroHash,
                    [messageHash],
                    [BigInt(123)],
                    [BigInt(456)],
                    proof
                )
            ).to.be.revertedWithCustomError(zkContract, "OnlySequencer");
        });

        it("NON dovrebbe accettare batch vuoti", async function () {
            const proof = createMockProof();

            await expect(
                zkContract.connect(sequencer).submitBatchWithProof(
                    ethers.ZeroHash,
                    [],
                    [],
                    [],
                    proof
                )
            ).to.be.revertedWithCustomError(zkContract, "EmptyBatch");
        });

        it("NON dovrebbe accettare array con length mismatch", async function () {
            const messageHash = ethers.keccak256(ethers.toUtf8Bytes("msg"));
            const proof = createMockProof();

            await expect(
                zkContract.connect(sequencer).submitBatchWithProof(
                    ethers.ZeroHash,
                    [messageHash],
                    [BigInt(123)],
                    [BigInt(456), BigInt(789)],  // Mismatch!
                    proof
                )
            ).to.be.revertedWithCustomError(zkContract, "LengthMismatch");
        });
    });

    describe("Batch Submission con Bytes", function () {
        it("Dovrebbe accettare batch con prova in bytes", async function () {
            const messageHashes = [
                ethers.keccak256(ethers.toUtf8Bytes("message1")),
            ];

            const publicKeysX = [BigInt("12345678901234567890")];
            const publicKeysY = [BigInt("98765432109876543210")];
            const stateRoot = ethers.keccak256(ethers.toUtf8Bytes("state"));

            // Crea proof bytes (8 * 32 = 256 bytes)
            const proofBytes = ethers.hexlify(new Uint8Array(256).fill(1));

            const tx = await zkContract.connect(sequencer).submitBatchWithProofBytes(
                stateRoot,
                messageHashes,
                publicKeysX,
                publicKeysY,
                proofBytes
            );

            await tx.wait();

            const batch = await zkContract.batches(0);
            expect(batch.verified).to.be.true;
        });
    });

    describe("Signature Submission", function () {
        it("Dovrebbe permettere a chiunque di sottomettere firme", async function () {
            const messageHash = ethers.keccak256(ethers.toUtf8Bytes("my message"));
            const publicKeyX = BigInt(12345);
            const publicKeyY = BigInt(67890);

            await expect(
                zkContract.connect(user1).submitSignature(
                    messageHash,
                    publicKeyX,
                    publicKeyY
                )
            ).to.emit(zkContract, "SignatureSubmitted");

            const submission = await zkContract.submissions(0);
            expect(submission.messageHash).to.equal(messageHash);
            expect(submission.included).to.be.false;
        });
    });

    describe("View Functions", function () {
        beforeEach(async function () {
            const messageHashes = [
                ethers.keccak256(ethers.toUtf8Bytes("msg1")),
                ethers.keccak256(ethers.toUtf8Bytes("msg2")),
                ethers.keccak256(ethers.toUtf8Bytes("msg3")),
            ];

            const publicKeysX = [BigInt(100), BigInt(200), BigInt(300)];
            const publicKeysY = [BigInt(400), BigInt(500), BigInt(600)];
            const stateRoot = ethers.keccak256(ethers.toUtf8Bytes("state"));
            const proof = createMockProof();

            await zkContract.connect(sequencer).submitBatchWithProof(
                stateRoot,
                messageHashes,
                publicKeysX,
                publicKeysY,
                proof
            );
        });

        it("Dovrebbe restituire dettagli batch", async function () {
            const [stateRoot, numSigs, timestamp, proposer, verified, l2Block] =
                await zkContract.getBatch(0);

            expect(numSigs).to.equal(3);
            expect(proposer).to.equal(sequencer.address);
            expect(verified).to.be.true;
            expect(l2Block).to.equal(1);
        });

        it("Dovrebbe restituire submission IDs per batch", async function () {
            const submissionIds = await zkContract.getBatchSubmissions(0);
            expect(submissionIds.length).to.equal(3);
        });

        it("Dovrebbe restituire stato L2", async function () {
            const [stateRoot, blockNumber, totalBatches] =
                await zkContract.getL2State();

            expect(blockNumber).to.equal(1);
            expect(totalBatches).to.equal(1);
        });

        it("Dovrebbe verificare se signature è inclusa", async function () {
            expect(await zkContract.isSignatureVerified(0)).to.be.true;
            expect(await zkContract.isSignatureVerified(1)).to.be.true;
            expect(await zkContract.isSignatureVerified(2)).to.be.true;
        });
    });

    describe("Admin Functions", function () {
        it("Dovrebbe permettere al sequencer di aggiornare verifier", async function () {
            const newVerifierAddress = user1.address;

            await expect(
                zkContract.connect(sequencer).updateVerifier(newVerifierAddress)
            ).to.emit(zkContract, "VerifierUpdated");

            expect(await zkContract.verifier()).to.equal(newVerifierAddress);
        });

        it("NON dovrebbe permettere a non-sequencer di aggiornare verifier", async function () {
            await expect(
                zkContract.connect(user1).updateVerifier(user2.address)
            ).to.be.revertedWithCustomError(zkContract, "OnlySequencer");
        });

        it("NON dovrebbe accettare indirizzo zero come verifier", async function () {
            await expect(
                zkContract.connect(sequencer).updateVerifier(ethers.ZeroAddress)
            ).to.be.revertedWithCustomError(zkContract, "InvalidVerifier");
        });
    });

    describe("Gas Analysis", function () {
        it("Dovrebbe misurare gas per batch di diverse dimensioni", async function () {
            const sizes = [1, 5, 10, 20];
            const results = [];

            console.log("\n    === Gas Analysis ===");

            for (const size of sizes) {
                const messageHashes = Array.from({ length: size }, (_, i) =>
                    ethers.keccak256(ethers.toUtf8Bytes(`msg${i}`))
                );

                const publicKeysX = Array.from({ length: size }, (_, i) =>
                    BigInt(1000 + i)
                );

                const publicKeysY = Array.from({ length: size }, (_, i) =>
                    BigInt(2000 + i)
                );

                const stateRoot = ethers.keccak256(
                    ethers.toUtf8Bytes(`state${size}`)
                );
                const proof = createMockProof();

                const tx = await zkContract
                    .connect(sequencer)
                    .submitBatchWithProof(
                        stateRoot,
                        messageHashes,
                        publicKeysX,
                        publicKeysY,
                        proof
                    );

                const receipt = await tx.wait();
                const gasUsed = Number(receipt.gasUsed);
                const gasPerTx = gasUsed / size;

                results.push({ size, gasUsed, gasPerTx });

                console.log(
                    `    Batch ${size}: ${gasUsed.toLocaleString()} gas (${gasPerTx.toFixed(0)}/tx)`
                );
            }

            // Verifica che gas per tx diminuisce con batch size
            expect(results[3].gasPerTx).to.be.lessThan(results[0].gasPerTx);
        });

        it("Dovrebbe confrontare con approccio tradizionale", async function () {
            const numTx = 10;
            const proof = createMockProof();

            const messageHashes = Array.from({ length: numTx }, (_, i) =>
                ethers.keccak256(ethers.toUtf8Bytes(`msg${i}`))
            );
            const publicKeysX = Array.from({ length: numTx }, (_, i) =>
                BigInt(1000 + i)
            );
            const publicKeysY = Array.from({ length: numTx }, (_, i) =>
                BigInt(2000 + i)
            );
            const stateRoot = ethers.keccak256(ethers.toUtf8Bytes("state"));

            const tx = await zkContract
                .connect(sequencer)
                .submitBatchWithProof(
                    stateRoot,
                    messageHashes,
                    publicKeysX,
                    publicKeysY,
                    proof
                );
            const receipt = await tx.wait();
            const zkGas = Number(receipt.gasUsed);

            // Traditional: ogni BLS pairing costa ~120k gas
            const traditionalGas = numTx * 120000;

            const savings = traditionalGas - zkGas;
            const savingsPercent = (savings / traditionalGas) * 100;

            console.log("\n    === ZK vs Traditional ===");
            console.log(`    Transazioni: ${numTx}`);
            console.log(`    ZK Rollup: ${zkGas.toLocaleString()} gas`);
            console.log(`    Traditional: ${traditionalGas.toLocaleString()} gas`);
            console.log(`    Risparmio: ${savings.toLocaleString()} gas (${savingsPercent.toFixed(1)}%)`);

            expect(zkGas).to.be.lessThan(traditionalGas);
        });
    });

    describe("Multi-Batch Scenario", function () {
        it("Dovrebbe gestire batch multipli correttamente", async function () {
            const proof = createMockProof();

            // Batch 1
            await zkContract.connect(sequencer).submitBatchWithProof(
                ethers.keccak256(ethers.toUtf8Bytes("state1")),
                [ethers.keccak256(ethers.toUtf8Bytes("msg1"))],
                [BigInt(100)],
                [BigInt(200)],
                proof
            );

            // Batch 2
            await zkContract.connect(sequencer).submitBatchWithProof(
                ethers.keccak256(ethers.toUtf8Bytes("state2")),
                [
                    ethers.keccak256(ethers.toUtf8Bytes("msg2")),
                    ethers.keccak256(ethers.toUtf8Bytes("msg3"))
                ],
                [BigInt(300), BigInt(400)],
                [BigInt(500), BigInt(600)],
                proof
            );

            // Verifica stato
            expect(await zkContract.batchCount()).to.equal(2);
            expect(await zkContract.l2BlockNumber()).to.equal(2);
            expect(await zkContract.submissionCount()).to.equal(3);

            // Verifica batch
            const [stateRoot1] = await zkContract.getBatch(0);
            const [stateRoot2] = await zkContract.getBatch(1);

            expect(stateRoot1).to.equal(ethers.keccak256(ethers.toUtf8Bytes("state1")));
            expect(stateRoot2).to.equal(ethers.keccak256(ethers.toUtf8Bytes("state2")));
        });
    });
});