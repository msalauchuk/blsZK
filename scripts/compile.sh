#!/usr/bin/env bash
# Local-development setup for the Poseidon demo. This does NOT implement BLS.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CIRCUIT_DIR="$PROJECT_DIR/circuits"
BUILD_DIR="$CIRCUIT_DIR/build"
export PATH="$PROJECT_DIR/node_modules/.bin:$PATH"
CIRCOM_BIN="${CIRCOM_BIN:-$PROJECT_DIR/node_modules/.bin/circom2}"

if ! command -v "$CIRCOM_BIN" >/dev/null || ! command -v snarkjs >/dev/null; then
    echo "Missing circuit tools. Run npm ci first." >&2
    exit 1
fi
mkdir -p "$BUILD_DIR" "$PROJECT_DIR/contracts/generated"
cd "$PROJECT_DIR"
echo "Compiling the demo relation (not BLS verification)..."
"$CIRCOM_BIN" "$CIRCUIT_DIR/bls_verify.circom" --r1cs --wasm --sym \
    -l "$PROJECT_DIR/node_modules" -o "$BUILD_DIR"
snarkjs r1cs info "$BUILD_DIR/bls_verify.r1cs"

# Powers of Tau are reusable; circuit-specific keys below are always regenerated.
# This single-machine ceremony is only for development.
if [ ! -f "$BUILD_DIR/pot12_final.ptau" ]; then
    snarkjs powersoftau new bn128 12 "$BUILD_DIR/pot12_0000.ptau"
    ENTROPY="$(node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("hex"))')"
    snarkjs powersoftau contribute "$BUILD_DIR/pot12_0000.ptau" \
        "$BUILD_DIR/pot12_0001.ptau" --name="Local development" -e="$ENTROPY"
    snarkjs powersoftau prepare phase2 "$BUILD_DIR/pot12_0001.ptau" "$BUILD_DIR/pot12_final.ptau"
fi
snarkjs powersoftau verify "$BUILD_DIR/pot12_final.ptau"
snarkjs groth16 setup "$BUILD_DIR/bls_verify.r1cs" \
    "$BUILD_DIR/pot12_final.ptau" "$BUILD_DIR/bls_verify_0000.zkey"
ENTROPY="$(node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("hex"))')"
snarkjs zkey contribute "$BUILD_DIR/bls_verify_0000.zkey" \
    "$BUILD_DIR/bls_verify_final.zkey" --name="Local development" -e="$ENTROPY"
unset ENTROPY
snarkjs zkey verify "$BUILD_DIR/bls_verify.r1cs" \
    "$BUILD_DIR/pot12_final.ptau" "$BUILD_DIR/bls_verify_final.zkey"
snarkjs zkey export verificationkey "$BUILD_DIR/bls_verify_final.zkey" "$BUILD_DIR/verification_key.json"
snarkjs zkey export solidityverifier "$BUILD_DIR/bls_verify_final.zkey" "$BUILD_DIR/Verifier.sol"
cp "$BUILD_DIR/Verifier.sol" "$PROJECT_DIR/contracts/generated/Verifier.sol"
echo "Development artifacts generated. Run npm run circuit:prove next."
