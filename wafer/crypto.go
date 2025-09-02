package wafer

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// GenerateSigningKeyPair creates a new Ed25519 key pair for signing Wafers.
// It returns the public key and the private key, or an error if one occurred.
func GenerateSigningKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate ed25519 key pair: %w", err)
	}
	return pub, priv, nil
}
