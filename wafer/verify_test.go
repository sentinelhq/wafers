package wafer

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// fullWaferTestRig sets up a complete scenario for testing:
// - Issuer with keys and a root secret.
// - A multi-layer, delegated wafer.
// - Keys for all holders.
type fullWaferTestRig struct {
	issuerSK    ed25519.PrivateKey
	rootSecret  []byte
	wafer       Wafer
	holder1Priv ed25519.PrivateKey
	holder2Priv ed25519.PrivateKey
}

func newFullWaferTestRig(t *testing.T) *fullWaferTestRig {
	t.Helper()
	rig := &fullWaferTestRig{}

	// Issuer
	issuerPub, issuerSK, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}
	rig.issuerSK = issuerSK
	rig.rootSecret = make([]byte, 32)
	if _, err := rand.Read(rig.rootSecret); err != nil {
		t.Fatalf("could not generate rootSecret: %v", err)
	}

	// Wafer
	w := NewWafer(NewWaferID(), time.Now().Add(1*time.Hour), "issuer.com", issuerPub)

	// First attenuation
	k0, err := w.DeriveK0(rig.rootSecret)
	if err != nil {
		t.Fatalf("DeriveK0 failed: %v", err)
	}
	holder1Pub, holder1Priv, _ := GenerateSigningKeyPair()
	rig.holder1Priv = holder1Priv
	w1, err := w.Attenuate(k0, AttenuationOptions{
		Caveats:             []Caveat{[]byte("caveat1")},
		NextHolderPublicKey: holder1Pub,
	})
	if err != nil {
		t.Fatalf("Attenuate failed: %v", err)
	}

	// Second attenuation
	holder2Pub, holder2Priv, _ := GenerateSigningKeyPair()
	rig.holder2Priv = holder2Priv
	w2, err := w1.AttenuateWithPrivKey(holder1Priv, AttenuationOptions{
		Caveats:             []Caveat{[]byte("caveat2")},
		NextHolderPublicKey: holder2Pub,
	})
	if err != nil {
		t.Fatalf("AttenuateWithPrivKey failed: %v", err)
	}
	rig.wafer = w2
	return rig
}

func TestVerifyChainSuccess(t *testing.T) {
	rig := newFullWaferTestRig(t)
	rootSecretLookup := func(id WaferID) ([]byte, error) {
		if id == rig.wafer.ID {
			return rig.rootSecret, nil
		}
		return nil, errors.New("not found")
	}

	_, err := rig.wafer.Verify(rootSecretLookup, rig.issuerSK)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

func TestVerifyTamperedLayerSeal(t *testing.T) {
	rig := newFullWaferTestRig(t)
	rootSecretLookup := func(id WaferID) ([]byte, error) { return rig.rootSecret, nil }

	// Tamper with the seal of the first layer
	rig.wafer.Layers[0].Seal[0] ^= 0x01

	_, err := rig.wafer.Verify(rootSecretLookup, rig.issuerSK)
	if err == nil {
		t.Fatalf("expected verification to fail for tampered layer seal, but it succeeded")
	}
}

func TestVerifyTamperedHolderSeal(t *testing.T) {
	rig := newFullWaferTestRig(t)
	rootSecretLookup := func(id WaferID) ([]byte, error) { return rig.rootSecret, nil }

	// Tamper with the seal of the first holder
	rig.wafer.Holders[0].Seal[0] ^= 0x01

	_, err := rig.wafer.Verify(rootSecretLookup, rig.issuerSK)
	if err == nil {
		t.Fatalf("expected verification to fail for tampered holder seal, but it succeeded")
	}
}

func TestVerifyLayerAfterTerminal(t *testing.T) {
	rig := newFullWaferTestRig(t)
	rootSecretLookup := func(id WaferID) ([]byte, error) { return rig.rootSecret, nil }

	// Manually create a terminal wafer by not adding a holder for the last layer.
	w := rig.wafer
	wTerminal, err := w.AttenuateWithPrivKey(rig.holder2Priv, AttenuationOptions{
		Caveats: []Caveat{[]byte("terminal")},
		// No NextHolderPublicKey
	})
	if err != nil {
		t.Fatalf("AttenuateWithPrivKey failed: %v", err)
	}

	// Manually (and incorrectly) add another layer. This simulates a structural tampering.
	wTerminal.Layers = append(wTerminal.Layers, Layer{Caveats: []Caveat{[]byte("extra")}, Seal: []byte("badseal")})

	_, err = wTerminal.Verify(rootSecretLookup, rig.issuerSK)
	if err == nil {
		t.Fatalf("expected verification to fail for layer after terminal, but it succeeded")
	}
}

func TestVerifyRejectsLowOrderHolderPublicKey(t *testing.T) {
	issuerPub, issuerSK, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}
	rootSecret := make([]byte, 32)
	if _, err := rand.Read(rootSecret); err != nil {
		t.Fatalf("could not generate rootSecret: %v", err)
	}

	w := NewWafer(NewWaferID(), time.Now().Add(1*time.Hour), "issuer.com", issuerPub)
	k0, err := w.DeriveK0(rootSecret)
	if err != nil {
		t.Fatalf("DeriveK0 failed: %v", err)
	}

	// Low-order Ed25519 public key: identity point encodes to 0x01 || 31*0x00
	lowOrderPub := make([]byte, ed25519.PublicKeySize)
	lowOrderPub[0] = 0x01

	w1, err := w.Attenuate(k0, AttenuationOptions{
		Caveats:             []Caveat{[]byte("c1")},
		NextHolderPublicKey: ed25519.PublicKey(lowOrderPub),
	})
	if err != nil {
		t.Fatalf("Attenuate failed: %v", err)
	}

	rootSecretLookup := func(id WaferID) ([]byte, error) { return rootSecret, nil }
	_, err = w1.Verify(rootSecretLookup, issuerSK)
	if err == nil {
		t.Fatalf("expected verification to fail for low-order holder public key, but it succeeded")
	}
}

func TestVerifyRejectsMoreHoldersThanLayers(t *testing.T) {
	issuerPub, issuerSK, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)

	w := NewWafer(NewWaferID(), time.Now().Add(1*time.Hour), "issuer.com", issuerPub)
	// Manually append a holder without any layers
	w.Holders = append(w.Holders, Holder{PublicKey: issuerPub, Identifier: "h"})

	rootSecretLookup := func(id WaferID) ([]byte, error) { return rootSecret, nil }
	_, err = w.Verify(rootSecretLookup, issuerSK)
	if err == nil {
		t.Fatalf("expected verification to fail for more holders than layers, but it succeeded")
	}
}

func TestVerifyRejectsInvalidIssuerPublicKeyLength(t *testing.T) {
	badPub := ed25519.PublicKey(make([]byte, 31))
	_, issuerSK, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)

	w := NewWafer(NewWaferID(), time.Now().Add(1*time.Hour), "issuer.com", badPub)
	rootSecretLookup := func(id WaferID) ([]byte, error) { return rootSecret, nil }
	_, err = w.Verify(rootSecretLookup, issuerSK)
	if err == nil {
		t.Fatalf("expected verification to fail for invalid issuer public key length, but it succeeded")
	}
}

func TestVerifyChainWithFourHolders(t *testing.T) {
	issuerPub, issuerSK, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}
	rootSecret := make([]byte, 32)
	if _, err := rand.Read(rootSecret); err != nil {
		t.Fatalf("could not generate rootSecret: %v", err)
	}

	w := NewWafer(NewWaferID(), time.Now().Add(1*time.Hour), "issuer.com", issuerPub)
	k0, err := w.DeriveK0(rootSecret)
	if err != nil {
		t.Fatalf("DeriveK0 failed: %v", err)
	}

	// Holder 1
	h1Pub, h1Priv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}
	w1, err := w.Attenuate(k0, AttenuationOptions{
		Caveats:             []Caveat{[]byte("c1")},
		NextHolderPublicKey: h1Pub,
	})
	if err != nil {
		t.Fatalf("Attenuate failed: %v", err)
	}

	// Holder 2
	h2Pub, h2Priv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}
	w2, err := w1.AttenuateWithPrivKey(h1Priv, AttenuationOptions{
		Caveats:             []Caveat{[]byte("c2")},
		NextHolderPublicKey: h2Pub,
	})
	if err != nil {
		t.Fatalf("AttenuateWithPrivKey failed: %v", err)
	}

	// Holder 3
	h3Pub, h3Priv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}
	w3, err := w2.AttenuateWithPrivKey(h2Priv, AttenuationOptions{
		Caveats:             []Caveat{[]byte("c3")},
		NextHolderPublicKey: h3Pub,
	})
	if err != nil {
		t.Fatalf("AttenuateWithPrivKey failed: %v", err)
	}

	// Holder 4
	h4Pub, _, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}
	w4, err := w3.AttenuateWithPrivKey(h3Priv, AttenuationOptions{
		Caveats:             []Caveat{[]byte("c4")},
		NextHolderPublicKey: h4Pub,
	})
	if err != nil {
		t.Fatalf("AttenuateWithPrivKey failed: %v", err)
	}

	if len(w4.Layers) != 4 {
		t.Fatalf("expected 4 layers, got %d", len(w4.Layers))
	}
	if len(w4.Holders) != 4 {
		t.Fatalf("expected 4 holders, got %d", len(w4.Holders))
	}

	rootSecretLookup := func(id WaferID) ([]byte, error) { return rootSecret, nil }
	caveats, err := w4.Verify(rootSecretLookup, issuerSK)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if len(caveats) != 4 {
		t.Fatalf("expected 4 caveats, got %d", len(caveats))
	}
}
