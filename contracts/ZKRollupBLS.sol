/ SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ZKRollupBLS
 * @notice ZK Rollup per verifica batch di firme BLS usando Groth16
 * @dev Compatibile con prove generate da snarkjs
 *
 * ARCHITETTURA:
 * - Le prove ZK vengono generate off-chain usando snarkjs
 * - Il Verifier.sol è generato da snarkjs e verifica le prove
 * - Questo contratto gestisce il rollup e chiama il verifier
 */
contract ZKRollupBLS {
// ============ STRUCTS ============

struct Batch {
bytes32 stateRoot;
uint32 numSignatures;
uint64 timestamp;
address proposer;
bool verified;
uint64 l2BlockNumber;
}

struct SignatureSubmission {
bytes32 messageHash;
uint256 publicKeyX;
uint256 publicKeyY;
bool included;
}

/// @notice Formato prova Groth16 compatibile con snarkjs
struct Groth16Proof {
uint256[2] a;
uint256[2][2] b;
uint256[2] c;
}

// ============ STATE VARIABLES ============

address public immutable sequencer;
address public verifier;

uint256 public batchCount;
uint256 public submissionCount;
uint256 public l2BlockNumber;
bytes32 public currentStateRoot;

mapping(uint256 => Batch) public batches;
mapping(uint256 => SignatureSubmission) public submissions;
mapping(uint256 => uint256[]) public batchSubmissions;

// ============ EVENTS ============

event BatchSubmitted(
uint256 indexed batchId,
bytes32 stateRoot,
uint32 numSignatures,
address proposer,
uint64 l2BlockNumber
);

event SignatureSubmitted(
uint256 indexed submissionId,
bytes32 messageHash,
uint256 publicKeyX,
uint256 publicKeyY
);

event StateUpdated(
bytes32 newStateRoot,
uint64 newL2BlockNumber
);

event VerifierUpdated(
address oldVerifier,
address newVerifier
);

// ============ ERRORS ============

error OnlySequencer();
error InvalidVerifier();
error EmptyBatch();
error LengthMismatch();
error InvalidZKProof();
error VerificationFailed();

// ============ MODIFIERS ============

modifier onlySequencer() {
if (msg.sender != sequencer) revert OnlySequencer();
_;
}

// ============ CONSTRUCTOR ============

constructor(address _sequencer, address _verifier) {
if (_sequencer == address(0)) revert InvalidVerifier();
if (_verifier == address(0)) revert InvalidVerifier();

sequencer = _sequencer;
verifier = _verifier;
currentStateRoot = bytes32(0);
l2BlockNumber = 0;
}

// ============ EXTERNAL FUNCTIONS ============

/**
 * @notice Sottomette un batch con prova ZK in formato snarkjs
     * @param _stateRoot Nuovo state root L2
     * @param _messageHashes Array di hash dei messaggi
     * @param _publicKeysX Array di coordinate X delle chiavi pubbliche
     * @param _publicKeysY Array di coordinate Y delle chiavi pubbliche
     * @param _proof Prova Groth16 (a, b, c)
     */
function submitBatchWithProof(
bytes32 _stateRoot,
bytes32[] calldata _messageHashes,
uint256[] calldata _publicKeysX,
uint256[] calldata _publicKeysY,
Groth16Proof calldata _proof
) external onlySequencer {
if (_messageHashes.length == 0) revert EmptyBatch();
if (_messageHashes.length != _publicKeysX.length ||
_publicKeysX.length != _publicKeysY.length) {
revert LengthMismatch();
}

uint256 batchId = batchCount;

// Prepara gli input pubblici per la verifica
uint256[] memory publicInputs = _preparePublicInputs(
_messageHashes,
_publicKeysX,
_publicKeysY
);

// Verifica la prova chiamando il Verifier snarkjs
bool isValid = _verifyGroth16Proof(_proof, publicInputs);
if (!isValid) revert InvalidZKProof();

// Crea e memorizza il batch
batches[batchId] = Batch({
stateRoot: _stateRoot,
numSignatures: uint32(_messageHashes.length),
timestamp: uint64(block.timestamp),
proposer: msg.sender,
verified: true,
l2BlockNumber: uint64(l2BlockNumber + 1)
});

// Memorizza le submission individuali
for (uint256 i = 0; i < _messageHashes.length; i++) {
uint256 submissionId = submissionCount++;

submissions[submissionId] = SignatureSubmission({
messageHash: _messageHashes[i],
publicKeyX: _publicKeysX[i],
publicKeyY: _publicKeysY[i],
included: true
});

batchSubmissions[batchId].push(submissionId);

emit SignatureSubmitted(
submissionId,
_messageHashes[i],
_publicKeysX[i],
_publicKeysY[i]
);
}

// Aggiorna stato L2
currentStateRoot = _stateRoot;
l2BlockNumber++;
batchCount++;

emit BatchSubmitted(
batchId,
_stateRoot,
uint32(_messageHashes.length),
msg.sender,
uint64(l2BlockNumber)
);

emit StateUpdated(_stateRoot, uint64(l2BlockNumber));
}

/**
 * @notice Versione con bytes per retrocompatibilità
     * @dev Decodifica la prova da bytes e chiama la versione struct
     */
function submitBatchWithProofBytes(
bytes32 _stateRoot,
bytes32[] calldata _messageHashes,
uint256[] calldata _publicKeysX,
uint256[] calldata _publicKeysY,
bytes calldata _proofBytes
) external onlySequencer {
if (_messageHashes.length == 0) revert EmptyBatch();
if (_messageHashes.length != _publicKeysX.length ||
_publicKeysX.length != _publicKeysY.length) {
revert LengthMismatch();
}

// Decodifica prova da bytes (formato: a[0], a[1], b[0][0], b[0][1], b[1][0], b[1][1], c[0], c[1])
Groth16Proof memory proof = _decodeProof(_proofBytes);

uint256 batchId = batchCount;

uint256[] memory publicInputs = _preparePublicInputs(
_messageHashes,
_publicKeysX,
_publicKeysY
);

bool isValid = _verifyGroth16Proof(proof, publicInputs);
if (!isValid) revert InvalidZKProof();

// Stesso codice di submitBatchWithProof...
batches[batchId] = Batch({
stateRoot: _stateRoot,
numSignatures: uint32(_messageHashes.length),
timestamp: uint64(block.timestamp),
proposer: msg.sender,
verified: true,
l2BlockNumber: uint64(l2BlockNumber + 1)
});

for (uint256 i = 0; i < _messageHashes.length; i++) {
uint256 submissionId = submissionCount++;

submissions[submissionId] = SignatureSubmission({
messageHash: _messageHashes[i],
publicKeyX: _publicKeysX[i],
publicKeyY: _publicKeysY[i],
included: true
});

batchSubmissions[batchId].push(submissionId);

emit SignatureSubmitted(
submissionId,
_messageHashes[i],
_publicKeysX[i],
_publicKeysY[i]
);
}

currentStateRoot = _stateRoot;
l2BlockNumber++;
batchCount++;

emit BatchSubmitted(
batchId,
_stateRoot,
uint32(_messageHashes.length),
msg.sender,
uint64(l2BlockNumber)
);

emit StateUpdated(_stateRoot, uint64(l2BlockNumber));
}

/**
 * @notice Sottomette una singola firma per inclusione futura
     */
function submitSignature(
bytes32 _messageHash,
uint256 _publicKeyX,
uint256 _publicKeyY
) external {
uint256 submissionId = submissionCount++;

submissions[submissionId] = SignatureSubmission({
messageHash: _messageHash,
publicKeyX: _publicKeyX,
publicKeyY: _publicKeyY,
included: false
});

emit SignatureSubmitted(
submissionId,
_messageHash,
_publicKeyX,
_publicKeyY
);
}

// ============ VIEW FUNCTIONS ============

function getBatch(uint256 _batchId) external view returns (
bytes32 stateRoot,
uint32 numSignatures,
uint64 timestamp,
address proposer,
bool verified,
uint64 batchL2BlockNumber
) {
Batch memory batch = batches[_batchId];
return (
batch.stateRoot,
batch.numSignatures,
batch.timestamp,
batch.proposer,
batch.verified,
batch.l2BlockNumber
);
}

function getBatchSubmissions(uint256 _batchId) external view returns (uint256[] memory) {
return batchSubmissions[_batchId];
}

function getL2State() external view returns (
bytes32 stateRoot,
uint256 blockNumber,
uint256 totalBatches
) {
return (currentStateRoot, l2BlockNumber, batchCount);
}

function isSignatureVerified(uint256 _submissionId) external view returns (bool) {
return submissions[_submissionId].included;
}

// ============ INTERNAL FUNCTIONS ============

/**
 * @notice Verifica prova Groth16 chiamando il Verifier snarkjs
     */
function _verifyGroth16Proof(
Groth16Proof memory _proof,
uint256[] memory _publicInputs
) internal view returns (bool) {
// Costruisci la chiamata al verifier snarkjs
// Il verifier generato da snarkjs ha la signature:
// verifyProof(uint[2] a, uint[2][2] b, uint[2] c, uint[n] input)

bytes memory callData = abi.encodeWithSignature(
"verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[])",
_proof.a,
_proof.b,
_proof.c,
_publicInputs
);

(bool success, bytes memory result) = verifier.staticcall(callData);

if (!success || result.length == 0) {
return false;
}

return abi.decode(result, (bool));
}

/**
 * @notice Prepara gli input pubblici per il verifier
     */
function _preparePublicInputs(
bytes32[] calldata _messageHashes,
uint256[] calldata _publicKeysX,
uint256[] calldata _publicKeysY
) internal pure returns (uint256[] memory) {
// Per un batch di N firme, abbiamo 3N input pubblici
uint256[] memory publicInputs = new uint256[](_messageHashes.length * 3);

for (uint256 i = 0; i < _messageHashes.length; i++) {
publicInputs[i * 3] = uint256(_messageHashes[i]);
publicInputs[i * 3 + 1] = _publicKeysX[i];
publicInputs[i * 3 + 2] = _publicKeysY[i];
}

return publicInputs;
}

/**
 * @notice Decodifica prova da bytes
     */
function _decodeProof(bytes calldata _proofBytes) internal pure returns (Groth16Proof memory) {
require(_proofBytes.length >= 256, "Proof too short");

Groth16Proof memory proof;

// Decodifica 8 uint256 (32 bytes ciascuno)
proof.a[0] = _bytesToUint256(_proofBytes, 0);
proof.a[1] = _bytesToUint256(_proofBytes, 32);
proof.b[0][0] = _bytesToUint256(_proofBytes, 64);
proof.b[0][1] = _bytesToUint256(_proofBytes, 96);
proof.b[1][0] = _bytesToUint256(_proofBytes, 128);
proof.b[1][1] = _bytesToUint256(_proofBytes, 160);
proof.c[0] = _bytesToUint256(_proofBytes, 192);
proof.c[1] = _bytesToUint256(_proofBytes, 224);

return proof;
}

function _bytesToUint256(bytes calldata _bytes, uint256 _start) internal pure returns (uint256) {
require(_start + 32 <= _bytes.length, "Out of bounds");
uint256 result;
assembly {
result := calldataload(add(_bytes.offset, _start))
}
return result;
}

// ============ ADMIN FUNCTIONS ============

/**
 * @notice Aggiorna il verifier (solo sequencer, per upgrade)
     */
function updateVerifier(address _newVerifier) external onlySequencer {
if (_newVerifier == address(0)) revert InvalidVerifier();

address oldVerifier = verifier;
verifier = _newVerifier;

emit VerifierUpdated(oldVerifier, _newVerifier);
}
}