pragma circom 2.0.0;

/*
 * BLS Signature Verification Circuit (Simplified)
 *
 * Questo circuito dimostra il pattern di verifica di una firma BLS
 * in un contesto zero-knowledge. Per semplicità didattica, utilizziamo
 * una versione semplificata che opera su BN254 (la curva supportata
 * dalle precompilate Ethereum) invece di BLS12-381.
 *
 * In produzione, si userebbe BLS12-381 con implementazione completa
 * delle operazioni di pairing. Qui dimostriamo il concetto.
 */

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

// Template principale per verifica firma BLS semplificata
template BLSVerifySimplified() {
    // Input pubblici
    signal input messageHash;      // Hash del messaggio (pubblico)
    signal input publicKeyX;       // Coordinata X della chiave pubblica
    signal input publicKeyY;       // Coordinata Y della chiave pubblica

    // Input privati (witness)
    signal input signatureX;       // Coordinata X della firma
    signal input signatureY;       // Coordinata Y della firma

    // Output
    signal output isValid;

    // Componenti
    component poseidon = Poseidon(4);
    component isEqual = IsEqual();

    // Calcola hash di verifica usando Poseidon
    // In una implementazione reale, qui ci sarebbero le operazioni
    // di pairing e1(S, g2) == e2(H(m), PK)
    poseidon.inputs[0] <== messageHash;
    poseidon.inputs[1] <== signatureX;
    poseidon.inputs[2] <== signatureY;
    poseidon.inputs[3] <== publicKeyX;

    // Per semplicità, verifichiamo che il risultato del hash
    // corrisponda ad un valore atteso derivato dalla chiave pubblica
    // In produzione: verifica pairing completa
    signal expectedValue;
    expectedValue <== publicKeyX + publicKeyY;

    // Verifica che i valori corrispondano
    isEqual.in[0] <== poseidon.out;
    isEqual.in[1] <== expectedValue;

    isValid <== isEqual.out;
}

// Template helper per calcolo commitment della firma
template SignatureCommitment() {
    signal input signatureX;
    signal input signatureY;
    signal output commitment;

    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== signatureX;
    poseidon.inputs[1] <== signatureY;

    commitment <== poseidon.out;
}

// Template helper per range check (verifica che i valori siano nel campo)
template RangeCheck(n) {
    signal input in;
    signal bits[n];

    var sum = 0;
    for (var i = 0; i < n; i++) {
        bits[i] <-- (in >> i) & 1;
        bits[i] * (bits[i] - 1) === 0;  // Deve essere 0 o 1
        sum += bits[i] * (2 ** i);
    }

    sum === in;
}

// Template completo con range checks
template BLSVerifyComplete() {
    signal input messageHash;
    signal input publicKeyX;
    signal input publicKeyY;
    signal input signatureX;
    signal input signatureY;
    signal output isValid;

    // Range checks per assicurare che i valori siano nel campo
    component rangeCheckSigX = RangeCheck(254);
    component rangeCheckSigY = RangeCheck(254);

    rangeCheckSigX.in <== signatureX;
    rangeCheckSigY.in <== signatureY;

    // Verifica principale
    component verify = BLSVerifySimplified();
    verify.messageHash <== messageHash;
    verify.publicKeyX <== publicKeyX;
    verify.publicKeyY <== publicKeyY;
    verify.signatureX <== signatureX;
    verify.signatureY <== signatureY;

    isValid <== verify.isValid;
}

// Entry point del circuito
component main {public [messageHash, publicKeyX, publicKeyY]} = BLSVerifyComplete();