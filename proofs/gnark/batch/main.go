package main

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/uints"
)

type entry struct {
	PublicKey string `json:"publicKey"`
	Payload   string `json:"payload"`
}

type statement struct {
	Ciphersuite        string  `json:"ciphersuite"`
	ChainID            string  `json:"chainId"`
	Consumer           string  `json:"verifyingContract"`
	BatchID            string  `json:"batchId"`
	Entries            []entry `json:"entries"`
	AggregateSignature string  `json:"aggregateSignature"`
}

type metadata struct {
	Schema           string `json:"schema"`
	PayloadBytes     int    `json:"payloadBytes"`
	BatchSize        int    `json:"batchSize"`
	PublicInputs     int    `json:"publicInputCount"`
	Constraints      int    `json:"constraints"`
	VerifyingKeyHash string `json:"verifyingKeyHash"`
	SourceHash       string `json:"sourceHash"`
}

//go:embed circuit.go main.go
var circuitSources embed.FS

func sourceHash() (string, error) {
	h := sha256.New()
	for _, name := range []string{"circuit.go", "main.go"} {
		data, err := circuitSources.ReadFile(name)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s:%d:", name, len(data))
		h.Write(data)
	}
	// Fingerprint the actual linked dependency versions/checksums as well as
	// source. Unlike a working-directory path this also works in a moved binary.
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", errors.New("missing Go build information")
	}
	fmt.Fprintln(h, info.GoVersion)
	for _, dep := range info.Deps {
		fmt.Fprintf(h, "%s:%s:%s\n", dep.Path, dep.Version, dep.Sum)
		if dep.Replace != nil {
			return "", errors.New("replaced dependencies are unsupported for proof setup")
		}
	}
	return "0x" + hex.EncodeToString(h.Sum(nil)), nil
}

func loadMetadata(directory string) (metadata, error) {
	var meta metadata
	data, err := os.ReadFile(filepath.Join(directory, "circuit.json"))
	if err != nil {
		return meta, err
	}
	if err = json.Unmarshal(data, &meta); err != nil {
		return meta, err
	}
	hash, err := sourceHash()
	if err != nil {
		return meta, err
	}
	if meta.Schema != "blszk.gnark-bls12-381.batch2.v1" || meta.PayloadBytes != payloadBytes || meta.BatchSize != batchSize || meta.PublicInputs != publicInputCount || meta.SourceHash != hash {
		return meta, errors.New("circuit source/dependencies changed; rerun the BLS proof setup")
	}
	key, err := os.ReadFile(filepath.Join(directory, "verifying.key"))
	if err != nil {
		return meta, err
	}
	keyHash := sha256.Sum256(key)
	if meta.VerifyingKeyHash != "0x"+hex.EncodeToString(keyHash[:]) {
		return meta, errors.New("verifying key differs from setup metadata")
	}
	for _, file := range []string{"circuit.r1cs", "proving.key", "BLSBatchGroth16Verifier.sol"} {
		if _, err = os.Stat(filepath.Join(directory, file)); err != nil {
			return meta, err
		}
	}
	return meta, nil
}

type proofArtifact struct {
	Metadata      metadata `json:"circuit"`
	ChainID       string   `json:"chainId"`
	Consumer      string   `json:"verifyingContract"`
	BatchID       string   `json:"batchId"`
	Entries       []entry  `json:"entries"`
	Commitment    string   `json:"commitment"`
	Proof         string   `json:"proof"`
	PublicInputs  []string `json:"publicInputs"`
	ProvingTimeMS int64    `json:"provingTimeMs"`
}

func decodeHex(value string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(value, "0x"))
}

func contextBytes(s statement) ([]byte, error) {
	chain, ok := new(big.Int).SetString(s.ChainID, 10)
	if !ok || chain.Sign() <= 0 || chain.BitLen() > 256 || chain.String() != s.ChainID {
		return nil, errors.New("chainId must be a canonical positive uint256 decimal string")
	}
	id, err := strconv.ParseUint(s.BatchID, 10, 64)
	if err != nil || strconv.FormatUint(id, 10) != s.BatchID {
		return nil, errors.New("batchId must be a canonical uint64 decimal string")
	}
	consumer, err := decodeHex(s.Consumer)
	if err != nil || len(consumer) != 20 {
		return nil, errors.New("verifyingContract must be a 20-byte address")
	}
	result := make([]byte, 61)
	chain.FillBytes(result[:32])
	copy(result[32:52], consumer)
	binary.BigEndian.PutUint64(result[52:60], id)
	result[60] = batchSize
	return result, nil
}

func signingMessage(context []byte, position int, payload []byte) []byte {
	result := append([]byte{}, signingDomain[:]...)
	result = append(result, context...)
	result = append(result, byte(position))
	return append(result, payload...)
}

func wireKey(pk *bls12381.G1Affine) []byte {
	result := make([]byte, 128)
	x, y := pk.X.Bytes(), pk.Y.Bytes()
	copy(result[16:64], x[:])
	copy(result[80:128], y[:])
	return result
}

// No native BLS predicate is trusted here: all verification is constrained.
func assignmentFromStatement(s statement) (*circuit, []entry, [32]byte, error) {
	var empty [32]byte
	if s.Ciphersuite != ciphersuite || len(s.Entries) != batchSize {
		return nil, nil, empty, errors.New("expected Basic/NUL suite and exactly two entries")
	}
	context, err := contextBytes(s)
	if err != nil {
		return nil, nil, empty, err
	}
	assignment := &circuit{}
	copy(assignment.ChainID[:], uints.NewU8Array(context[:32]))
	copy(assignment.Consumer[:], uints.NewU8Array(context[32:52]))
	copy(assignment.BatchID[:], uints.NewU8Array(context[52:60]))
	encoded := append([]byte{}, commitmentDomain[:]...)
	encoded = append(encoded, context...)
	entries := make([]entry, batchSize)
	for i, e := range s.Entries {
		payload, err := decodeHex(e.Payload)
		if err != nil || len(payload) != payloadBytes {
			return nil, nil, empty, fmt.Errorf("entry %d needs exactly %d payload bytes", i, payloadBytes)
		}
		key, err := decodeHex(e.PublicKey)
		if err != nil || len(key) != 48 {
			return nil, nil, empty, fmt.Errorf("entry %d needs a 48-byte compressed G1 key", i)
		}
		var pk bls12381.G1Affine
		if _, err = pk.SetBytes(key); err != nil || pk.IsInfinity() {
			return nil, nil, empty, fmt.Errorf("entry %d has invalid/identity public key", i)
		}
		assignment.PublicKeys[i] = sw_bls12381.NewG1Affine(pk)
		copy(assignment.Payloads[i][:], uints.NewU8Array(payload))
		wire := wireKey(&pk)
		encoded = append(encoded, wire...)
		encoded = append(encoded, payload...)
		entries[i] = entry{PublicKey: "0x" + hex.EncodeToString(wire), Payload: "0x" + hex.EncodeToString(payload)}
	}
	sigBytes, err := decodeHex(s.AggregateSignature)
	if err != nil || len(sigBytes) != 96 {
		return nil, nil, empty, errors.New("expected a 96-byte compressed aggregate signature")
	}
	var sig bls12381.G2Affine
	if _, err = sig.SetBytes(sigBytes); err != nil || sig.IsInfinity() {
		return nil, nil, empty, errors.New("invalid/identity aggregate signature")
	}
	assignment.AggregateSignature = sw_bls12381.NewG2Affine(sig)
	digest := sha256.Sum256(encoded)
	assignment.Commitment[0] = new(big.Int).SetBytes(digest[:16])
	assignment.Commitment[1] = new(big.Int).SetBytes(digest[16:])
	return assignment, entries, digest, nil
}

func readStatement(path string) (statement, error) {
	var result statement
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil {
		return result, err
	}
	if len(data) > 64*1024 {
		return result, errors.New("statement JSON exceeds 64 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&result); err != nil {
		return result, err
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return result, errors.New("expected exactly one JSON statement")
	}
	return result, nil
}

func compileCircuit() (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit{})
}

func saveBinary(path string, value io.WriterTo) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".blszk-artifact-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := value.WriteTo(file)
	closeErr := file.Close()
	if err = errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func readBinary(path string, value io.ReaderFrom) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = value.ReadFrom(file)
	return err
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return saveBinary(path, bytes.NewReader(append(data, '\n')))
}

func inspect() error {
	start := time.Now()
	ccs, err := compileCircuit()
	if err != nil {
		return err
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	fmt.Printf("constraints=%d publicInputs=%d compileTime=%s heapMiB=%d\n", ccs.GetNbConstraints(), ccs.GetNbPublicVariables()-1, time.Since(start), mem.HeapAlloc>>20)
	return nil
}

func setup(directory string) error {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	start := time.Now()
	ccs, err := compileCircuit()
	if err != nil {
		return err
	}
	if ccs.GetNbPublicVariables()-1 != publicInputCount {
		return errors.New("unexpected public witness schema")
	}
	fmt.Printf("Compiled %d constraints; generating development Groth16 keys...\n", ccs.GetNbConstraints())
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return err
	}
	if vk.NbPublicWitness()-len(vk.(*groth16bn254.VerifyingKey).CommitmentKeys) != publicInputCount {
		return errors.New("unexpected verifying-key public input count")
	}
	var vkBuffer bytes.Buffer
	if _, err = vk.WriteTo(&vkBuffer); err != nil {
		return err
	}
	hash := sha256.Sum256(vkBuffer.Bytes())
	source, err := sourceHash()
	if err != nil {
		return err
	}
	meta := metadata{
		Schema:       "blszk.gnark-bls12-381.batch2.v1",
		PayloadBytes: payloadBytes, BatchSize: batchSize, PublicInputs: publicInputCount,
		Constraints: ccs.GetNbConstraints(), VerifyingKeyHash: "0x" + hex.EncodeToString(hash[:]),
		SourceHash: source,
	}
	if err = saveBinary(filepath.Join(directory, "circuit.r1cs"), ccs); err != nil {
		return err
	}
	if err = saveBinary(filepath.Join(directory, "proving.key"), pk); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(directory, "verifying.key"), vkBuffer.Bytes(), 0600); err != nil {
		return err
	}
	var soliditySource bytes.Buffer
	functions := fmt.Sprintf("function circuitId() external pure returns(bytes32) { return %s; }", meta.VerifyingKeyHash)
	if err = vk.ExportSolidity(&soliditySource,
		solidity.WithPragmaVersion("^0.8.20"), solidity.WithHashToFieldFunction(sha256.New()),
		solidity.WithFunctions(strings.NewReader(functions)),
	); err != nil {
		return err
	}
	contract := strings.Replace(soliditySource.String(), "contract Verifier", "contract BLSBatchGroth16Verifier", 1)
	if !strings.Contains(contract, "contract BLSBatchGroth16Verifier") {
		return errors.New("unexpected Solidity export")
	}
	if err = os.WriteFile(filepath.Join(directory, "BLSBatchGroth16Verifier.sol"), []byte(contract), 0600); err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(directory, "circuit.json"), meta); err != nil {
		return err
	}
	fmt.Printf("Development setup completed in %s; key hash %s\n", time.Since(start), meta.VerifyingKeyHash)
	return nil
}

func prove(directory, input, output string) error {
	s, err := readStatement(input)
	if err != nil {
		return err
	}
	assignment, entries, digest, err := assignmentFromStatement(s)
	if err != nil {
		return err
	}
	meta, err := loadMetadata(directory)
	if err != nil {
		return err
	}
	ccs := groth16.NewCS(ecc.BN254)
	if err = readBinary(filepath.Join(directory, "circuit.r1cs"), ccs); err != nil {
		return err
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if err = readBinary(filepath.Join(directory, "proving.key"), pk); err != nil {
		return err
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err = readBinary(filepath.Join(directory, "verifying.key"), vk); err != nil {
		return err
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	start := time.Now()
	proof, err := groth16.Prove(ccs, pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		return fmt.Errorf("prove BLS constraints: %w", err)
	}
	elapsed := time.Since(start)
	public, err := witness.Public()
	if err != nil {
		return err
	}
	if err = groth16.Verify(proof, vk, public, backend.WithVerifierHashToFieldFunction(sha256.New())); err != nil {
		return err
	}
	inputs := make([]string, 0, publicInputCount)
	for _, value := range public.Vector().(fr.Vector) {
		inputs = append(inputs, value.String())
	}
	solidityProof := proof.(*groth16bn254.Proof).MarshalSolidity()
	artifact := proofArtifact{
		Metadata: meta, ChainID: s.ChainID, Consumer: "0x" + strings.ToLower(strings.TrimPrefix(s.Consumer, "0x")), BatchID: s.BatchID,
		Entries: entries, Commitment: "0x" + hex.EncodeToString(digest[:]),
		Proof: "0x" + hex.EncodeToString(solidityProof), PublicInputs: inputs, ProvingTimeMS: elapsed.Milliseconds(),
	}
	if err = writeJSON(output, artifact); err != nil {
		return err
	}
	fmt.Printf("Aggregate BLS batch Groth16 proof verified natively; %d proof bytes, proving %s\n", len(solidityProof), elapsed)
	return nil
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: bls-gnark inspect|status|setup|prove [options]")
	}
	flags := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	directory := flags.String("artifacts", "build/batch", "circuit/key artifact directory")
	input := flags.String("input", "", "batch statement JSON (required for prove)")
	output := flags.String("output", "build/batch/proof.json", "proof artifact JSON")
	if err := flags.Parse(os.Args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	switch os.Args[1] {
	case "inspect":
		return inspect()
	case "setup":
		return setup(*directory)
	case "status":
		_, err := loadMetadata(*directory)
		return err
	case "prove":
		if *input == "" {
			return errors.New("prove requires --input batch.json")
		}
		return prove(*directory, *input, *output)
	default:
		return errors.New("unknown command")
	}
}

func main() {
	// Keep a local proof run from occupying every core or growing an unbounded
	// Go heap. GOMEMLIMIT is a GC target, not a hard total-process memory limit.
	runtime.GOMAXPROCS(4)
	debug.SetMemoryLimit(3 << 30)
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
