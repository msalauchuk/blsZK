package main

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
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

type statement struct {
	Ciphersuite string `json:"ciphersuite"`
	Message     string `json:"message"`
	PublicKey   string `json:"publicKey"`
	Signature   string `json:"signature"`
}

type metadata struct {
	Schema           string `json:"schema"`
	MessageBytes     int    `json:"messageBytes"`
	PublicInputs     int    `json:"publicInputCount"`
	Constraints      int    `json:"constraints"`
	VerifyingKeyHash string `json:"verifyingKeyHash"`
	SourceHash       string `json:"sourceHash"`
}

//go:embed circuit.go main.go go.mod go.sum
var circuitSources embed.FS

func sourceHash() (string, error) {
	h := sha256.New()
	for _, name := range []string{"circuit.go", "main.go", "go.mod", "go.sum"} {
		data, err := circuitSources.ReadFile(name)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s:%d:", name, len(data))
		h.Write(data)
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
	if meta.Schema != "blszk.gnark-bls12-381.basic.v1" || meta.MessageBytes != messageBytes || meta.PublicInputs != publicInputCount || meta.SourceHash != hash {
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
	for _, file := range []string{"circuit.r1cs", "proving.key", "BLSGroth16Verifier.sol"} {
		if _, err = os.Stat(filepath.Join(directory, file)); err != nil {
			return meta, err
		}
	}
	return meta, nil
}

type proofArtifact struct {
	Metadata      metadata `json:"circuit"`
	Message       string   `json:"message"`
	PublicKey     string   `json:"publicKey"`
	Proof         string   `json:"proof"`
	PublicInputs  []string `json:"publicInputs"`
	ProvingTimeMS int64    `json:"provingTimeMs"`
}

func decodeHex(value string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(value, "0x"))
}

func assignmentFromStatement(s statement) (*circuit, []byte, error) {
	if s.Ciphersuite != ciphersuite {
		return nil, nil, errors.New("unsupported BLS ciphersuite")
	}
	message, err := decodeHex(s.Message)
	if err != nil || len(message) != messageBytes {
		return nil, nil, fmt.Errorf("message must contain exactly %d bytes", messageBytes)
	}
	pkBytes, err := decodeHex(s.PublicKey)
	if err != nil || len(pkBytes) != 48 {
		return nil, nil, errors.New("expected a 48-byte compressed G1 public key")
	}
	sigBytes, err := decodeHex(s.Signature)
	if err != nil || len(sigBytes) != 96 {
		return nil, nil, errors.New("expected a 96-byte compressed G2 signature")
	}
	var pk bls12381.G1Affine
	if _, err = pk.SetBytes(pkBytes); err != nil {
		return nil, nil, fmt.Errorf("decode public key: %w", err)
	}
	var sig bls12381.G2Affine
	if _, err = sig.SetBytes(sigBytes); err != nil {
		return nil, nil, fmt.Errorf("decode signature: %w", err)
	}
	if pk.IsInfinity() || sig.IsInfinity() {
		return nil, nil, errors.New("identity points are forbidden")
	}
	assignment := &circuit{
		PublicKey: sw_bls12381.NewG1Affine(pk),
		Signature: sw_bls12381.NewG2Affine(sig),
	}
	copy(assignment.Message[:], uints.NewU8Array(message))
	// EIP-2537 public encoding: x and y as 64-byte big-endian coordinates.
	publicKey := make([]byte, 128)
	x, y := pk.X.Bytes(), pk.Y.Bytes()
	copy(publicKey[16:64], x[:])
	copy(publicKey[80:128], y[:])
	return assignment, publicKey, nil
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
		Schema:       "blszk.gnark-bls12-381.basic.v1",
		MessageBytes: messageBytes, PublicInputs: publicInputCount,
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
	contract := strings.Replace(soliditySource.String(), "contract Verifier", "contract BLSGroth16Verifier", 1)
	if !strings.Contains(contract, "contract BLSGroth16Verifier") {
		return errors.New("unexpected Solidity export")
	}
	if err = os.WriteFile(filepath.Join(directory, "BLSGroth16Verifier.sol"), []byte(contract), 0600); err != nil {
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
	assignment, publicKey, err := assignmentFromStatement(s)
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
		Metadata: meta, Message: s.Message, PublicKey: "0x" + hex.EncodeToString(publicKey),
		Proof: "0x" + hex.EncodeToString(solidityProof), PublicInputs: inputs, ProvingTimeMS: elapsed.Milliseconds(),
	}
	if err = writeJSON(output, artifact); err != nil {
		return err
	}
	fmt.Printf("BLS Groth16 proof verified natively; %d proof bytes, proving %s\n", len(solidityProof), elapsed)
	return nil
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: bls-gnark inspect|status|setup|prove [options]")
	}
	flags := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	directory := flags.String("artifacts", "build", "circuit/key artifact directory")
	input := flags.String("input", "../../test/fixtures/bls12_381_basic.json", "BLS statement JSON")
	output := flags.String("output", "build/proof.json", "proof artifact JSON")
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
