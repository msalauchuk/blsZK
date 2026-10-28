#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MODULE_DIR="$PROJECT_DIR/proofs/gnark"
BUILD_DIR="$MODULE_DIR/build"
BINARY="$BUILD_DIR/bls-gnark"
ACTION="${1:-test}"
INPUT_FILE="${2:-$PROJECT_DIR/test/fixtures/bls12_381_basic.json}"
case "$INPUT_FILE" in /*) ;; *) INPUT_FILE="$PROJECT_DIR/$INPUT_FILE" ;; esac

# Keep the build cache writable inside the project; do not alter Go settings.
mkdir -p "$BUILD_DIR"
export GOCACHE="${BLSZK_GO_CACHE:-$BUILD_DIR/go-cache}"
go -C "$MODULE_DIR" build -mod=readonly -p 4 -o "$BINARY" .

copy_verifier() {
    mkdir -p "$PROJECT_DIR/contracts/generated"
    cp "$BUILD_DIR/BLSGroth16Verifier.sol" "$PROJECT_DIR/contracts/generated/BLSGroth16Verifier.sol"
}

ensure_setup() {
    if ! "$BINARY" status --artifacts "$BUILD_DIR"; then
        echo "Generating development Groth16 keys for the full BLS circuit..."
        "$BINARY" setup --artifacts "$BUILD_DIR"
    fi
    copy_verifier
}

case "$ACTION" in
    build) ;;
    inspect) "$BINARY" inspect ;;
    setup)
        "$BINARY" setup --artifacts "$BUILD_DIR"
        copy_verifier
        ;;
    prove)
        ensure_setup
        "$BINARY" prove --artifacts "$BUILD_DIR" --input "$INPUT_FILE" --output "$BUILD_DIR/proof.json"
        ;;
    test)
        go -C "$MODULE_DIR" test -mod=readonly -p 4 ./...
        ensure_setup
        "$BINARY" prove --artifacts "$BUILD_DIR" --input "$INPUT_FILE" --output "$BUILD_DIR/proof.json"
        cd "$PROJECT_DIR"
        ./node_modules/.bin/hardhat test integration/BLSProof.test.js
        ;;
    *) echo "Usage: bash scripts/bls_proof.sh build|inspect|setup|prove|test [statement.json]" >&2; exit 1 ;;
esac
