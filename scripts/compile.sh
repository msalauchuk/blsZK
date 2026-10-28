#!/bin/bash

# Script per compilare il circuito Circom BLS
# Questo script usa circom e snarkjs per generare i file necessari

set -e

echo "======================================"
echo "Compilazione Circuito BLS"
echo "======================================"
echo ""

CIRCUIT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CIRCUIT_FILE="$CIRCUIT_DIR/bls_verify.circom"
BUILD_DIR="$CIRCUIT_DIR/build"

echo "Circuit dir: $CIRCUIT_DIR"
echo "Build dir: $BUILD_DIR"
echo ""

# Crea directory build se non esiste
mkdir -p "$BUILD_DIR"

# Step 1: Compila circuito con circom
echo "[1/6] Compilazione circuito con circom..."
circom "$CIRCUIT_FILE" \
    --r1cs \
    --wasm \
    --sym \
    --c \
    -o "$BUILD_DIR"

echo "      R1CS generato"
echo "      WASM generato"
echo ""

# Step 2: Info sul circuito
echo "[2/6] Informazioni circuito:"
snarkjs r1cs info "$BUILD_DIR/bls_verify.r1cs"
echo ""

# Step 3: Trusted setup fase 1 (Powers of Tau)
echo "[3/6] Trusted setup - Powers of Tau..."
PTAU_FILE="$BUILD_DIR/powersOfTau28_hez_final_10.ptau"

if [ ! -f "$PTAU_FILE" ]; then
    echo "      Download ptau file..."
    wget -O "$PTAU_FILE" \
        https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_10.ptau
else
    echo "      Ptau file già esistente"
fi
echo ""

# Step 4: Trusted setup fase 2 (Circuit-specific)
echo "[4/6] Trusted setup - Circuit-specific..."
snarkjs groth16 setup \
    "$BUILD_DIR/bls_verify.r1cs" \
    "$PTAU_FILE" \
    "$BUILD_DIR/bls_verify_0000.zkey"

echo "      Zkey generata"
echo ""

# Step 5: Contribuzione (per produzione si farebbe cerimonia multi-party)
echo "[5/6] Contribuzione random beacon..."
echo "random" | snarkjs zkey contribute \
    "$BUILD_DIR/bls_verify_0000.zkey" \
    "$BUILD_DIR/bls_verify_final.zkey" \
    --name="Test contribution"

echo "      Contribuzione applicata"
echo ""

# Step 6: Esporta verifying key
echo "[6/6] Export verifying key..."
snarkjs zkey export verificationkey \
    "$BUILD_DIR/bls_verify_final.zkey" \
    "$BUILD_DIR/verification_key.json"

echo "      Verification key esportata"
echo ""

# Step 7: Genera Solidity verifier (opzionale)
echo "[7/6] Generazione Solidity verifier..."
snarkjs zkey export solidityverifier \
    "$BUILD_DIR/bls_verify_final.zkey" \
    "$BUILD_DIR/Verifier.sol"

echo "      Solidity verifier generato"
echo ""

echo "======================================"
echo "Compilazione completata con successo!"
echo "======================================"
echo ""
echo "File generati:"
echo "  - $BUILD_DIR/bls_verify.r1cs"
echo "  - $BUILD_DIR/bls_verify_js/bls_verify.wasm"
echo "  - $BUILD_DIR/bls_verify_final.zkey"
echo "  - $BUILD_DIR/verification_key.json"
echo "  - $BUILD_DIR/Verifier.sol"
echo ""
echo "Per generare una prova di test:"
echo "  cd circuits"
echo "  ./scripts/generate_test_proof.sh"
