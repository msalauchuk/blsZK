const { expect } = require("chai");
const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  bls, CIPHERSUITE, fromHex, signWithNoble, nonSubgroupG2,
} = require("../test/helpers/bls");
const fixture = require("../test/fixtures/bls12_381_basic.json");

const root = path.join(__dirname, "..");
const binary = path.join(root, "target/debug/bls-reference");
function cli(args) {
  const result = spawnSync(binary, args, { cwd: root, encoding: "utf8" });
  if (result.error) throw result.error;
  return result;
}

describe("Rust BLS reference interoperability (no ZK proof)", function () {
  let work, input;
  before(function () {
    work = fs.mkdtempSync(path.join(os.tmpdir(), "blszk-bls-"));
    input = path.join(work, "statement.json");
  });
  after(function () {
    if (work) fs.rmSync(work, { recursive: true, force: true });
  });

  it("reproduces the committed fixture and verifies it", function () {
    const generated = cli(["fixture", "--output", input]);
    expect(generated.status, generated.stderr).to.equal(0);
    expect(JSON.parse(fs.readFileSync(input))).to.deep.equal(fixture);
    const verified = cli(["verify", "--input", input]);
    expect(verified.status, verified.stderr).to.equal(0);
    const message = bls.G2.hashToCurve(fromHex(fixture.message), { DST: CIPHERSUITE });
    expect(bls.verify(fromHex(fixture.signature), message, fromHex(fixture.publicKey))).to.equal(true);
  });

  it("verifies independent noble signatures over empty and binary messages", function () {
    for (const message of [new Uint8Array(), Uint8Array.from([0, 255, 1, 128])]) {
      fs.writeFileSync(input, JSON.stringify(signWithNoble(message)));
      const result = cli(["verify", "--input", input]);
      expect(result.status, result.stderr).to.equal(0);
    }
  });

  it("returns failure for altered statements and malformed JSON data", function () {
    // IETF G2 compression stores x.c1 before x.c0; either y sign remains outside G2.
    const { x } = nonSubgroupG2().toAffine();
    const torsionSignature = Buffer.from(
      x.c1.toString(16).padStart(96, "0") + x.c0.toString(16).padStart(96, "0"), "hex"
    );
    torsionSignature[0] |= 0x80;
    const wrongDomain = signWithNoble(fromHex(fixture.message), 42n,
      "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_");
    const cases = [
      { ...fixture, message: "0x00" },
      { ...fixture, publicKey: "0x" + "00".repeat(48) },
      { ...fixture, signature: "0x" + "00".repeat(96) },
      { ...fixture, ciphersuite: "unrecognized" },
      { ...fixture, signature: "0xxyz" },
      { ...fixture, signature: "0x" + torsionSignature.toString("hex") },
      { ...wrongDomain, ciphersuite: CIPHERSUITE },
      { ...fixture, isValid: true },
    ];
    for (const statement of cases) {
      fs.writeFileSync(input, JSON.stringify(statement));
      const result = cli(["verify", "--input", input]);
      expect(result.status).to.equal(1);
      expect(result.stderr).to.not.include("panicked");
    }
  });
});
