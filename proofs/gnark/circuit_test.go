package main

import (
	"encoding/json"
	"math/big"
	"os"
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

func TestMain(m *testing.M) {
	runtime.GOMAXPROCS(4)
	debug.SetMemoryLimit(2 << 30)
	os.Exit(m.Run())
}

func fixture(t *testing.T) statement {
	t.Helper()
	s, err := readStatement("../../test/fixtures/bls12_381_basic.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBLSCircuitConstraints(t *testing.T) {
	cases := []struct {
		name   string
		modify func(*circuit)
		valid  bool
	}{
		{"valid_blst_signature", func(c *circuit) {}, true},
		{"changed_message", func(c *circuit) { c.Message[0].Val = 0 }, false},
		{"changed_public_key", func(c *circuit) {
			_, _, g1, _ := bls12381.Generators()
			c.PublicKey = sw_bls12381.NewG1Affine(g1)
		}, false},
		{"changed_signature", func(c *circuit) {
			s := fixture(t)
			b, _ := decodeHex(s.Signature)
			var sig bls12381.G2Affine
			if _, err := sig.SetBytes(b); err != nil {
				t.Fatal(err)
			}
			sig.Neg(&sig)
			c.Signature = sw_bls12381.NewG2Affine(sig)
		}, false},
		{"identity_signature", func(c *circuit) { c.Signature = sw_bls12381.NewG2Affine(bls12381.G2Affine{}) }, false},
		{"identity_key", func(c *circuit) { c.PublicKey = sw_bls12381.NewG1Affine(bls12381.G1Affine{}) }, false},
		{"non_subgroup_key", func(c *circuit) {
			var point bls12381.G1Affine
			point.Y.SetUint64(2)
			c.PublicKey = sw_bls12381.NewG1Affine(point)
		}, false},
		{"non_byte_message_value", func(c *circuit) { c.Message[0].Val = 256 }, false},
		{"noncanonical_key_alias", func(c *circuit) {
			s := fixture(t)
			b, _ := decodeHex(s.PublicKey)
			var point bls12381.G1Affine
			if _, err := point.SetBytes(b); err != nil {
				t.Fatal(err)
			}
			value := point.X.BigInt(new(big.Int))
			modulus := sw_bls12381.BaseField{}.Modulus()
			value.Add(value, modulus)
			mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
			// ValueOf stores a deferred native witness, not populated limbs.
			// Supply fresh raw limbs to bypass that canonicalization path.
			limbs := make([]frontend.Variable, 6)
			for i := range limbs {
				limbs[i] = new(big.Int).And(new(big.Int).Set(value), mask)
				value.Rsh(value, 64)
			}
			c.PublicKey.X = emulated.Element[sw_bls12381.BaseField]{Limbs: limbs}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assignment, _, err := assignmentFromStatement(fixture(t))
			if err != nil {
				t.Fatal(err)
			}
			tc.modify(assignment)
			// These checks deliberately bypass JSON/native validation and exercise
			// the circuit's assertions with adversarial witness values directly.
			err = test.IsSolved(&circuit{}, assignment, ecc.BN254.ScalarField())
			if tc.valid && err != nil {
				t.Fatal(err)
			}
			if !tc.valid && err == nil {
				t.Fatal("invalid witness satisfied the BLS circuit")
			}
		})
	}
}

func TestStatementInputValidation(t *testing.T) {
	for _, modify := range []func(*statement){
		func(s *statement) { s.Ciphersuite = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_" },
		func(s *statement) { s.Message = "0x00" },
		func(s *statement) { s.Signature = "0x123" },
		func(s *statement) { s.PublicKey = "0x00" },
	} {
		s := fixture(t)
		modify(&s)
		if _, _, err := assignmentFromStatement(s); err == nil {
			t.Fatal("malformed statement accepted")
		}
	}
	path := t.TempDir() + "/statement.json"
	data, err := json.Marshal(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, append(data, []byte(" {}")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readStatement(path); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}
