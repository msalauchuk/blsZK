package main

import (
	"encoding/hex"
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
	s, err := readStatement("../../../test/fixtures/bls12_381_batch2.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func assignment(t *testing.T, s statement) *circuit {
	t.Helper()
	c, _, _, err := assignmentFromStatement(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAggregateBatchCircuit(t *testing.T) {
	tests := []struct {
		name      string
		statement func(*statement)
		witness   func(*circuit)
		valid     bool
	}{
		{name: "independent_noble_aggregate", valid: true},
		{name: "changed_commitment", witness: func(c *circuit) { c.Commitment[0] = 1 }},
		{name: "changed_payload_with_recomputed_commitment", statement: func(s *statement) { s.Entries[1].Payload = "0x" + "00000000000000000000000000000000000000000000000000" }},
		{name: "changed_chain_with_recomputed_commitment", statement: func(s *statement) { s.ChainID = "1" }},
		{name: "changed_contract_with_recomputed_commitment", statement: func(s *statement) { s.Consumer = "0x0000000000000000000000000000000000000002" }},
		{name: "changed_batch_id_with_recomputed_commitment", statement: func(s *statement) { s.BatchID = "1" }},
		{name: "reordered_entries_with_recomputed_commitment", statement: func(s *statement) { s.Entries[0], s.Entries[1] = s.Entries[1], s.Entries[0] }},
		{name: "changed_key_with_recomputed_commitment", statement: func(s *statement) {
			_, _, g, _ := bls12381.Generators()
			b := g.Bytes()
			s.Entries[1].PublicKey = "0x" + hex.EncodeToString(b[:])
		}},
		{name: "negated_aggregate", witness: func(c *circuit) {
			b, _ := decodeHex(fixture(t).AggregateSignature)
			var sig bls12381.G2Affine
			if _, err := sig.SetBytes(b); err != nil {
				t.Fatal(err)
			}
			sig.Neg(&sig)
			c.AggregateSignature = sw_bls12381.NewG2Affine(sig)
		}},
		{name: "only_first_entry_signed", witness: func(c *circuit) {
			s := fixture(t)
			context, err := contextBytes(s)
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := decodeHex(s.Entries[0].Payload)
			h, err := bls12381.HashToG2(signingMessage(context, 0, payload), []byte(ciphersuite))
			if err != nil {
				t.Fatal(err)
			}
			var sig bls12381.G2Affine
			sig.ScalarMultiplication(&h, big.NewInt(42))
			c.AggregateSignature = sw_bls12381.NewG2Affine(sig)
		}},
		{name: "identity_aggregate", witness: func(c *circuit) { c.AggregateSignature = sw_bls12381.NewG2Affine(bls12381.G2Affine{}) }},
		{name: "identity_key", witness: func(c *circuit) { c.PublicKeys[1] = sw_bls12381.NewG1Affine(bls12381.G1Affine{}) }},
		{name: "non_subgroup_key", witness: func(c *circuit) {
			var p bls12381.G1Affine
			p.Y.SetUint64(2)
			c.PublicKeys[1] = sw_bls12381.NewG1Affine(p)
		}},
		{name: "non_byte_context", witness: func(c *circuit) { c.ChainID[0].Val = 256 }},
		{name: "non_byte_payload", witness: func(c *circuit) { c.Payloads[1][0].Val = 256 }},
		{name: "noncanonical_key_alias", witness: func(c *circuit) {
			s := fixture(t)
			b, _ := decodeHex(s.Entries[1].PublicKey)
			var p bls12381.G1Affine
			if _, err := p.SetBytes(b); err != nil {
				t.Fatal(err)
			}
			v := p.X.BigInt(new(big.Int))
			v.Add(v, sw_bls12381.BaseField{}.Modulus())
			mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
			limbs := make([]frontend.Variable, 6)
			for i := range limbs {
				limbs[i] = new(big.Int).And(new(big.Int).Set(v), mask)
				v.Rsh(v, 64)
			}
			c.PublicKeys[1].X = emulated.Element[sw_bls12381.BaseField]{Limbs: limbs}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture(t)
			if tc.statement != nil {
				tc.statement(&s)
			}
			c := assignment(t, s)
			if tc.witness != nil {
				tc.witness(c)
			}
			err := test.IsSolved(&circuit{}, c, ecc.BN254.ScalarField())
			if tc.valid && err != nil {
				t.Fatal(err)
			}
			if !tc.valid && err == nil {
				t.Fatal("invalid aggregate batch satisfied circuit")
			}
		})
	}
}

func TestBatchInputValidation(t *testing.T) {
	for _, change := range []func(*statement){
		func(s *statement) { s.Entries = s.Entries[:1] },
		func(s *statement) { s.Entries = append(s.Entries, s.Entries[0]) },
		func(s *statement) { s.ChainID = "-1" },
		func(s *statement) { s.ChainID = "01" },
		func(s *statement) { s.BatchID = "18446744073709551616" },
		func(s *statement) { s.Consumer = "0x1234" },
		func(s *statement) { s.Ciphersuite = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_" },
		func(s *statement) { s.Entries[0].Payload = "0x00" },
		func(s *statement) { s.AggregateSignature = "0x00" },
	} {
		s := fixture(t)
		change(&s)
		if _, _, _, err := assignmentFromStatement(s); err == nil {
			t.Fatal("invalid statement accepted")
		}
	}
}
