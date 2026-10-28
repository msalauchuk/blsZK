#!/bin/bash

# Script per generare una prova di test
# Usa snarkjs per creare witness e prova

set -e

echo "======================================"
echo "Generazione Prova di Test"
echo "======================================"
echo ""

CIRCUIT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$CIRCUIT_DIR/build"
INPUT_FILE="$CIRCUIT_DIR/test_input.json"

# Crea input di test se non esiste
if [ ! -f "$INPUT_FILE" ]; then
    echo "[1/4] Creazione input di test..."
    cat > "$INPUT_FILE" << EOF
{
  "messageHash": "12345678901234567890",
  "publicKeyX": "98765432109876543210",
  "publicKeyY": "11111111111111111111",
  "signatureX": "22222222222222222222",
  "signatureY": "33333333333333333333"
}
EOF
    echo "      Input creato: $INPUT_FILE"
else
    echo "[1/4] Usando input esistente: $INPUT_FILE"
fi
echo ""

# Genera witness
echo "[2/4] Generazione witness..."
node "$BUILD_DIR/bls_verify_js/generate_witness.js" \
    "$BUILD_DIR/bls_verify_js/bls_verify.wasm" \
    "$INPUT_FILE" \
    "$BUILD_DIR/witness.wtns"

echo "      Witness generato"
echo ""

# Genera prova
echo "[3/4] Generazione prova Groth16..."
snarkjs groth16 prove \
    "$BUILD_DIR/bls_verify_final.zkey" \
    "$BUILD_DIR/witness.wtns" \
    "$BUILD_DIR/proof.json" \
    "$BUILD_DIR/public.json"

echo "      Prova generata"
echo ""

# Verifica prova
echo "[4/4] Verifica prova..."
snarkjs groth16 verify \
    "$BUILD_DIR/verification_key.json" \
    "$BUILD_DIR/public.json" \
    "$BUILD_DIR/proof.json"

echo ""
echo "======================================"
echo "Prova generata e verificata!"
echo "======================================"
echo ""
echo "File generati:"
echo "  - $BUILD_DIR/witness.wtns"
echo "  - $BUILD_DIR/proof.json"
echo "  - $BUILD_DIR/public.json"
echo ""
echo "Per usare la prova in Solidity:"
echo "  snarkjs zkey export soliditycalldata $BUILD_DIR/public.json $BUILD_DIR/proof.json"
