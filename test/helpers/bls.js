const { bls12_381: bls } = require("@noble/curves/bls12-381");

const CIPHERSUITE = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const fromHex = (value) => Buffer.from(value.replace(/^0x/, ""), "hex");
const fp = (value) => value.toString(16).padStart(128, "0");

function g1(point) {
  const { x, y } = point.toAffine();
  return "0x" + fp(x) + fp(y);
}

function g2(point) {
  const { x, y } = point.toAffine();
  return "0x" + fp(x.c0) + fp(x.c1) + fp(y.c0) + fp(y.c1);
}

function decodeStatement(statement) {
  if (statement.ciphersuite !== CIPHERSUITE) throw new Error("Unexpected test suite");
  return {
    message: statement.message,
    publicKey: g1(bls.G1.ProjectivePoint.fromHex(fromHex(statement.publicKey))),
    signature: g2(bls.G2.ProjectivePoint.fromHex(fromHex(statement.signature))),
  };
}

function signWithNoble(message, secret = 42n, dst = CIPHERSUITE) {
  const point = bls.G2.hashToCurve(message, { DST: dst });
  return {
    ciphersuite: dst,
    message: "0x" + Buffer.from(message).toString("hex"),
    publicKey: "0x" + Buffer.from(bls.getPublicKey(secret)).toString("hex"),
    signature: "0x" + bls.Signature.toHex(bls.sign(point, secret)),
  };
}

function nonSubgroupG2() {
  const Fp2 = bls.fields.Fp2;
  for (let i = 0n; i < 100n; i++) {
    const x = { c0: i, c1: 0n };
    let y;
    try {
      y = Fp2.sqrt(Fp2.add(Fp2.mul(Fp2.sqr(x), x), { c0: 4n, c1: 4n }));
    } catch (_) {
      continue;
    }
    const point = bls.G2.ProjectivePoint.fromAffine({ x, y });
    if (!point.isTorsionFree()) return point;
  }
  throw new Error("Could not construct a non-subgroup G2 test point");
}

module.exports = { bls, CIPHERSUITE, fromHex, fp, g1, g2, decodeStatement, signWithNoble, nonSubgroupG2 };
