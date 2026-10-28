package main

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/bls"
)

const ciphersuite = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
const messageBytes = 25
const publicInputCount = 12 + messageBytes

// One-signature circuit. Message length is fixed by the compiled circuit/key.
// The public statement consists of canonical G1 coordinates and all message
// bytes. The G2 signature is private and is validated inside the circuit.
type circuit struct {
	PublicKey sw_bls12381.G1Affine   `gnark:",public"`
	Message   [messageBytes]uints.U8 `gnark:",public"`
	Signature sw_bls12381.G2Affine
}

func (c *circuit) Define(api frontend.API) error {
	fp, err := emulated.NewField[sw_bls12381.BaseField](api)
	if err != nil {
		return err
	}
	// Bind the public limbs to canonical Fp values, not residue-class aliases.
	fp.AssertIsInRange(&c.PublicKey.X)
	fp.AssertIsInRange(&c.PublicKey.Y)
	fp.AssertIsInRange(&c.Signature.P.X.A0)
	fp.AssertIsInRange(&c.Signature.P.X.A1)
	fp.AssertIsInRange(&c.Signature.P.Y.A0)
	fp.AssertIsInRange(&c.Signature.P.Y.A1)
	for _, b := range c.Message {
		api.ToBinary(b.Val, 8)
	}
	if c.Signature.Lines != nil {
		return fmt.Errorf("precomputed signature lines are forbidden")
	}

	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		return err
	}
	// Hash the actual public message under Basic/NUL, rather than using the
	// std/signature/bls convenience method's different PoP DST.
	hashed, err := g2.HashToG2(c.Message[:], []byte(ciphersuite))
	if err != nil {
		return fmt.Errorf("hash to G2: %w", err)
	}

	// Reject the signature identity explicitly. PairingCheck also checks its
	// curve and subgroup membership when deriving the Miller-loop lines.
	zeroSig := api.And(
		api.And(fp.IsZero(&c.Signature.P.X.A0), fp.IsZero(&c.Signature.P.X.A1)),
		api.And(fp.IsZero(&c.Signature.P.Y.A0), fp.IsZero(&c.Signature.P.Y.A1)),
	)
	api.AssertIsEqual(zeroSig, 0)
	g2.AssertIsOnG2(&c.Signature)
	pk := bls.PublicKeyG1(c.PublicKey)
	sig := bls.SignatureG2(c.Signature)
	return pk.VerifyG2(api, &sig, hashed)
}
