#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MODULE_DIR="$PROJECT_DIR/proofs/gnark"
BUILD_DIR="$MODULE_DIR/build/batch"
BINARY="$BUILD_DIR/bls-batch"
ACTION="${1:-test}"

mkdir -p "$BUILD_DIR"
export GOCACHE="${BLSZK_GO_CACHE:-$MODULE_DIR/build/go-cache}"
go -C "$MODULE_DIR" build -mod=readonly -p 4 -o "$BINARY" ./batch

copy_verifier() {
    mkdir -p "$PROJECT_DIR/contracts/generated"
    cp "$BUILD_DIR/BLSBatchGroth16Verifier.sol" "$PROJECT_DIR/contracts/generated/BLSBatchGroth16Verifier.sol"
}

ensure_setup() {
    if ! "$BINARY" status --artifacts "$BUILD_DIR"; then
        echo "Generating development keys for the aggregate BLS batch circuit..."
        "$BINARY" setup --artifacts "$BUILD_DIR"
    fi
    copy_verifier
}

case "$ACTION" in
    build) ;;
    inspect) "$BINARY" inspect ;;
    setup) "$BINARY" setup --artifacts "$BUILD_DIR"; copy_verifier ;;
    prove)
        if [[ -z "${2:-}" ]]; then
            echo "Usage: npm run bls:batch:prove -- batch.json (signed for the target deployment/context)" >&2
            exit 1
        fi
        INPUT_FILE="$2"
        case "$INPUT_FILE" in /*) ;; *) INPUT_FILE="$PROJECT_DIR/$INPUT_FILE" ;; esac
        ensure_setup
        "$BINARY" prove --artifacts "$BUILD_DIR" --input "$INPUT_FILE" --output "$BUILD_DIR/proof.json"
        ;;
    test)
        go -C "$MODULE_DIR" test -mod=readonly -p 4 ./batch
        ensure_setup
        cd "$PROJECT_DIR"
        # The test deploys first, then collects fixture signatures for that
        # exact contract/chain/batch context and generates one real proof.
        ./node_modules/.bin/hardhat test integration/BLSBatch.test.js
        ;;
    *) echo "Usage: bash scripts/bls_batch.sh build|inspect|setup|prove|test [batch.json]" >&2; exit 1 ;;
esac
