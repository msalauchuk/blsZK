// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IBLSVerifier
 * @notice Interfaccia per la verifica di prove ZK BLS
 */
interface IBLSVerifier {
    /**
     * @notice Verifica una prova Groth16
     * @param proof La prova ZK (serializzata)
     * @param publicInputs Input pubblici per la verifica
     * @return isValid True se la prova è valida
     */
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool isValid);
}