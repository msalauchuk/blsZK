const { ethers } = require("ethers");
const { bls, CIPHERSUITE, fromHex, g1 } = require("./bls");

const BATCH_SIZE = 2;
const PAYLOAD_BYTES = 25;
const COMMITMENT_DOMAIN = ethers.sha256(ethers.toUtf8Bytes("blsZK.batch.commitment.v1"));
const SIGNING_DOMAIN = ethers.sha256(ethers.toUtf8Bytes("blsZK.batch.message.v1"));

function contextBytes({ chainId, verifyingContract, batchId }) {
  return ethers.concat([
    ethers.toBeHex(BigInt(chainId), 32), ethers.getAddress(verifyingContract),
    ethers.toBeHex(BigInt(batchId), 8), ethers.toBeHex(BATCH_SIZE, 1),
  ]);
}

function signingMessage(context, position, payload) {
  if (!Number.isInteger(position) || position < 0 || position >= BATCH_SIZE || ethers.getBytes(payload).length !== PAYLOAD_BYTES) {
    throw new Error("Expected a supported position and 25 payload bytes");
  }
  return ethers.concat([SIGNING_DOMAIN, contextBytes(context), ethers.toBeHex(position, 1), payload]);
}

function wireEntries(statement) {
  return statement.entries.map((entry) => ({
    publicKey: g1(bls.G1.ProjectivePoint.fromHex(fromHex(entry.publicKey))),
    payload: entry.payload,
  }));
}

function batchCommitment(statement) {
  if (statement.entries.length !== BATCH_SIZE) throw new Error("Expected exactly two entries");
  const encoded = [COMMITMENT_DOMAIN, contextBytes(statement)];
  for (const entry of wireEntries(statement)) encoded.push(entry.publicKey, entry.payload);
  return ethers.sha256(ethers.concat(encoded));
}

// Public, deterministic TEST keys only. Applications must collect signatures
// from their signers; the prover's input contains no secret keys.
function createTestBatch(context, payloads = [Buffer.alloc(PAYLOAD_BYTES, 1), Buffer.alloc(PAYLOAD_BYTES, 2)]) {
  const statement = { ciphersuite: CIPHERSUITE, ...context, entries: [] };
  let aggregate = bls.G2.ProjectivePoint.ZERO;
  const points = [], keys = [];
  for (let i = 0; i < BATCH_SIZE; i++) {
    const secret = 42n + BigInt(i);
    const payload = ethers.hexlify(payloads[i]);
    const point = bls.G2.hashToCurve(ethers.getBytes(signingMessage(statement, i, payload)), { DST: CIPHERSUITE });
    points.push(point);
    const key = bls.getPublicKey(secret);
    keys.push(key);
    aggregate = aggregate.add(bls.sign(point, secret));
    statement.entries.push({ publicKey: ethers.hexlify(key), payload });
  }
  if (!bls.verifyBatch(aggregate, points, keys)) throw new Error("Independent aggregate BLS verification failed");
  statement.aggregateSignature = "0x" + bls.Signature.toHex(aggregate);
  return statement;
}

module.exports = { BATCH_SIZE, PAYLOAD_BYTES, COMMITMENT_DOMAIN, SIGNING_DOMAIN, contextBytes, signingMessage, wireEntries, batchCommitment, createTestBatch };
