package main

import (
	"crypto/sha256"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

const ciphersuite = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
const batchSize = 2
const payloadBytes = 25
const publicInputCount = 2

var commitmentDomain = sha256.Sum256([]byte("blsZK.batch.commitment.v1"))
var signingDomain = sha256.Sum256([]byte("blsZK.batch.message.v1"))

// Every slot is active. The two complete signed messages are distinct because
// their fixed position byte differs, even if the application payloads match.
// The only public inputs are the high and low 128-bit halves of SHA-256.
type circuit struct {
	Commitment         [publicInputCount]frontend.Variable `gnark:",public"`
	ChainID            [32]uints.U8
	Consumer           [20]uints.U8
	BatchID            [8]uints.U8
	PublicKeys         [batchSize]sw_bls12381.G1Affine
	Payloads           [batchSize][payloadBytes]uints.U8
	AggregateSignature sw_bls12381.G2Affine
}

func (c *circuit) Define(api frontend.API) error {
	fp, err := emulated.NewField[sw_bls12381.BaseField](api)
	if err != nil {
		return err
	}
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return err
	}
	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		return err
	}
	if c.AggregateSignature.Lines != nil {
		return fmt.Errorf("precomputed aggregate-signature lines are forbidden")
	}
	for _, v := range []*emulated.Element[sw_bls12381.BaseField]{
		&c.AggregateSignature.P.X.A0, &c.AggregateSignature.P.X.A1,
		&c.AggregateSignature.P.Y.A0, &c.AggregateSignature.P.Y.A1,
	} {
		fp.AssertIsInRange(v)
	}
	zeroSig := api.And(
		api.And(fp.IsZero(&c.AggregateSignature.P.X.A0), fp.IsZero(&c.AggregateSignature.P.X.A1)),
		api.And(fp.IsZero(&c.AggregateSignature.P.Y.A0), fp.IsZero(&c.AggregateSignature.P.Y.A1)),
	)
	api.AssertIsEqual(zeroSig, 0)
	g2.AssertIsOnG2(&c.AggregateSignature)

	context := make([]uints.U8, 0, 61)
	context = append(context, c.ChainID[:]...)
	context = append(context, c.Consumer[:]...)
	context = append(context, c.BatchID[:]...)
	context = append(context, uints.NewU8(batchSize))
	for _, b := range context {
		api.ToBinary(b.Val, 8)
	}
	encoded := append(uints.NewU8Array(commitmentDomain[:]), context...)

	_, _, generator, _ := bls12381.Generators()
	var negative bls12381.G1Affine
	negative.Neg(&generator)
	negGenerator := sw_bls12381.NewG1Affine(negative)
	keys := []*sw_bls12381.G1Affine{&negGenerator}
	points := []*sw_bls12381.G2Affine{&c.AggregateSignature}
	for i := 0; i < batchSize; i++ {
		pk := &c.PublicKeys[i]
		fp.AssertIsInRange(&pk.X)
		fp.AssertIsInRange(&pk.Y)
		api.AssertIsEqual(api.And(fp.IsZero(&pk.X), fp.IsZero(&pk.Y)), 0)
		pairing.AssertIsOnG1(pk)
		// Canonical EIP-2537 encoding: x || y, each 16 zero bytes + 48 Fp bytes.
		for _, coordinate := range []*emulated.Element[sw_bls12381.BaseField]{&pk.X, &pk.Y} {
			for j := 0; j < 16; j++ {
				encoded = append(encoded, uints.NewU8(0))
			}
			bits := fp.ToBits(coordinate)
			for j := 47; j >= 0; j-- {
				encoded = append(encoded, uints.U8{Val: api.FromBinary(bits[j*8 : (j+1)*8]...)})
			}
		}
		for _, b := range c.Payloads[i] {
			api.ToBinary(b.Val, 8)
		}
		encoded = append(encoded, c.Payloads[i][:]...)
		message := append(uints.NewU8Array(signingDomain[:]), context...)
		message = append(message, uints.NewU8(uint8(i)))
		message = append(message, c.Payloads[i][:]...)
		hashed, err := g2.HashToG2(message, []byte(ciphersuite))
		if err != nil {
			return fmt.Errorf("hash entry %d: %w", i, err)
		}
		keys = append(keys, pk)
		points = append(points, hashed)
	}
	h, err := sha2.New(api)
	if err != nil {
		return err
	}
	h.Write(encoded)
	digest := h.Sum()
	for half := 0; half < 2; half++ {
		var value frontend.Variable = 0
		for _, b := range digest[half*16 : (half+1)*16] {
			value = api.Add(api.Mul(value, 256), b.Val)
		}
		api.AssertIsEqual(c.Commitment[half], value)
	}
	// One multi-pairing and one proof cover the aggregate over every slot.
	return pairing.PairingCheck(keys, points)
}
