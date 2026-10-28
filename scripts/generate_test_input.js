const { buildPoseidon } = require("circomlibjs");
const fs = require("fs");
const path = require("path");

async function main() {
  const poseidon = await buildPoseidon();
  const input = {
    messageHash: "12345678901234567890",
    publicKeyX: "98765432109876543210",
    signatureX: "22222222222222222222",
    signatureY: "33333333333333333333",
  };
  // Construct a witness of the toy relation. These are NOT BLS key/signature points.
  const hash = poseidon([
    input.messageHash, input.signatureX, input.signatureY, input.publicKeyX,
  ]);
  input.publicKeyY = poseidon.F.toObject(
    poseidon.F.sub(hash, poseidon.F.e(input.publicKeyX))
  ).toString();
  const output = process.argv[2] || path.join(__dirname, "../circuits/test_input.json");
  fs.writeFileSync(output, JSON.stringify(input, null, 2) + "\n");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
