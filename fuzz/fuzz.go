package fuzz

import (
	"bytes"
	"fmt"
	"github.com/drand/drand/core"
	"github.com/drand/kyber/encrypt/ecies"
	"github.com/drand/drand/key"
)

var FixedMessage = []byte("Hello threshold Boneh-Lynn-Shacham")

// Fuzzes encrypt/decrypt using fuzzed keys, given a fixed message.
func FuzzECIESKey(data []byte) int {
	// get key from fuzz input (just a scalar number, modulo the curveorder)
	// then generate pubkey from it
	priv := key.KeyGroup.Scalar().SetBytes(data)
	// Could also use UnmarshalBinary(data), but that will error if not exactly the right byte length
	// This could result in some input with that is equivalent (e.g. nq + k = k mod q), but not much problem

	pub := key.KeyGroup.Point().Mul(priv, nil)

	ciphertext, err := ecies.Encrypt(key.KeyGroup, pub, FixedMessage, core.EciesHash)
	if err != nil {
		// not sure if this would/could error if the key is correct?
		// if this should never fail (given a valid key) we want to panic here
		panic(fmt.Sprintf("Possibly unexpected error: %v", err))
		// TODO if this causes a "false positive" crash, replace with below:
		// return 0
	}
	plain, err := ecies.Decrypt(key.KeyGroup, priv, ciphertext, core.EciesHash)
	res := bytes.Compare(FixedMessage, plain)
	if err != nil {
		panic(fmt.Sprintf("Should be able to decrypt anything we encrypt. Error decrypting: %v", err))
	} else if res != 0 {
		panic(fmt.Sprintf("Decrypted data is not the same as the original message.\n Expected:\n 0x%x\n\nActual:\n0x%x", data, plain))
	}
	return 1
}
