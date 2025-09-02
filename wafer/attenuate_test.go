package wafer

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestAttenuationSuccess(t *testing.T) {
	// 1. Issuer setup
	issuerPub, _, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}
	rootSecret := make([]byte, 32)
	if _, err := rand.Read(rootSecret); err != nil {
		t.Fatalf("could not generate rootSecret: %v", err)
	}

	// 2. Create a new Wafer
	w := NewWafer(NewWaferID(), time.Now().Add(1*time.Hour), "issuer.com", issuerPub)

	// 3. First attenuation with K0
	k0, err := w.DeriveK0(rootSecret)
	if err != nil {
		t.Fatalf("DeriveK0 failed: %v", err)
	}

	holder1Pub, holder1Priv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}

	opts1 := AttenuationOptions{
		Caveats:             []Caveat{[]byte("caveat1")},
		NextHolderPublicKey: holder1Pub,
		NextHolderID:        "holder1",
	}

	w1, err := w.Attenuate(k0, opts1)
	if err != nil {
		t.Fatalf("Attenuate failed: %v", err)
	}

	if len(w1.Layers) != 1 {
		t.Fatalf("expected 1 layer, got %d", len(w1.Layers))
	}
	if len(w1.Holders) != 1 {
		t.Fatalf("expected 1 holder, got %d", len(w1.Holders))
	}
	if w1.IsTerminal() {
		t.Fatalf("wafer should not be terminal")
	}

	// 4. Second attenuation (delegation)
	holder2Pub, _, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}
	opts2 := AttenuationOptions{
		Caveats:             []Caveat{[]byte("caveat2")},
		NextHolderPublicKey: holder2Pub,
		NextHolderID:        "holder2",
	}
	w2, err := w1.AttenuateWithPrivKey(holder1Priv, opts2)
	if err != nil {
		t.Fatalf("AttenuateWithPrivKey failed: %v", err)
	}

	if len(w2.Layers) != 2 {
		t.Fatalf("expected 2 layers, got %d", len(w2.Layers))
	}
	if len(w2.Holders) != 2 {
		t.Fatalf("expected 2 holders, got %d", len(w2.Holders))
	}
}

func TestAttenuateTerminalWafer(t *testing.T) {
	issuerPub, _, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)
	w := NewWafer(NewWaferID(), time.Now().Add(1*time.Hour), "issuer.com", issuerPub)
	k0, _ := w.DeriveK0(rootSecret)
	_, holder1Priv, _ := GenerateSigningKeyPair()

	// Create a terminal wafer (no next holder)
	terminalOpts := AttenuationOptions{Caveats: []Caveat{[]byte("c1")}}
	terminalWafer, err := w.Attenuate(k0, terminalOpts)
	if err != nil {
		t.Fatalf("Attenuate failed: %v", err)
	}
	if !terminalWafer.IsTerminal() {
		t.Fatalf("wafer should be terminal")
	}

	// Try to attenuate it again
	_, err = terminalWafer.AttenuateWithPrivKey(holder1Priv, AttenuationOptions{})
	if err == nil {
		t.Fatalf("expected error when attenuating terminal wafer, got nil")
	}
}

func TestAttenuateKeyMismatch(t *testing.T) {
	issuerPub, _, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)
	w := NewWafer(NewWaferID(), time.Now().Add(1*time.Hour), "issuer.com", issuerPub)
	k0, _ := w.DeriveK0(rootSecret)
	holder1Pub, _, _ := GenerateSigningKeyPair()
	_, otherPriv, _ := GenerateSigningKeyPair() // Mismatched key

	opts := AttenuationOptions{
		Caveats:             []Caveat{[]byte("c1")},
		NextHolderPublicKey: holder1Pub,
	}
	w1, err := w.Attenuate(k0, opts)
	if err != nil {
		t.Fatalf("Attenuate failed: %v", err)
	}

	_, err = w1.AttenuateWithPrivKey(otherPriv, AttenuationOptions{})
	if err == nil {
		t.Fatalf("expected error when attenuating with mismatched key, got nil")
	}
}

func TestAttenuateDeepCopiesInputs(t *testing.T) {
	issuerPub, _, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}
	rootSecret := make([]byte, 32)
	rand.Read(rootSecret)
	w := NewWafer(NewWaferID(), time.Now().Add(1*time.Hour), "issuer.com", issuerPub)
	k0, _ := w.DeriveK0(rootSecret)

	caveat := []byte("c1")
	holderPub, _, _ := GenerateSigningKeyPair()
	opts := AttenuationOptions{Caveats: []Caveat{caveat}, NextHolderPublicKey: holderPub}
	w1, err := w.Attenuate(k0, opts)
	if err != nil {
		t.Fatalf("Attenuate failed: %v", err)
	}

	// Mutate original inputs; wafer must remain unchanged
	caveat[0] ^= 0xFF
	holderPub[0] ^= 0xFF

	if string(w1.Layers[0].Caveats[0]) == string(caveat) {
		t.Fatalf("wafer should have deep-copied caveats")
	}
	if w1.Holders[0].PublicKey[0] == holderPub[0] {
		t.Fatalf("wafer should have deep-copied next holder public key")
	}
}
