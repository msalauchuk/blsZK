#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/circuits/build"
export PATH="$PROJECT_DIR/node_modules/.bin:$PATH"

if [ ! -f "$BUILD_DIR/bls_verify_final.zkey" ]; then
    echo "Missing circuit artifacts. Run npm run circuit:compile first." >&2
    exit 1
fi
if [ "$#" -gt 0 ]; then
    INPUT_FILE="$1"
else
    INPUT_FILE="$PROJECT_DIR/circuits/test_input.json"
    node "$PROJECT_DIR/scripts/generate_test_input.js" "$INPUT_FILE"
fi
snarkjs groth16 fullprove "$INPUT_FILE" \
    "$BUILD_DIR/bls_verify_js/bls_verify.wasm" "$BUILD_DIR/bls_verify_final.zkey" \
    "$BUILD_DIR/proof.json" "$BUILD_DIR/public.json"
snarkjs groth16 verify "$BUILD_DIR/verification_key.json" \
    "$BUILD_DIR/public.json" "$BUILD_DIR/proof.json"
snarkjs zkey export soliditycalldata "$BUILD_DIR/public.json" "$BUILD_DIR/proof.json"
echo "Demo proof verified. This proves the Poseidon relation, not a BLS signature."
