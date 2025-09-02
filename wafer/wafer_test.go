package wafer

import (
	"bytes"
	"testing"
	"time"
)

func TestNewWafer(t *testing.T) {
	id := NewWaferID()
	expiresAt := time.Now().Add(1 * time.Hour)
	issuer := "test.example.com"
	pub, _, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}

	wafer := NewWafer(id, expiresAt, issuer, pub)

	if wafer == nil {
		t.Fatal("NewWafer returned nil")
	}

	if wafer.Version != Version {
		t.Errorf("Expected version %s, got %s", Version, wafer.Version)
	}

	if wafer.ID != id {
		t.Errorf("Expected ID %v, got %v", id, wafer.ID)
	}

	if !wafer.ExpiresAt.Equal(expiresAt) {
		t.Errorf("Expected ExpiresAt %v, got %v", expiresAt, wafer.ExpiresAt)
	}

	if wafer.Issuer != issuer {
		t.Errorf("Expected Issuer %s, got %s", issuer, wafer.Issuer)
	}

	if !bytes.Equal(wafer.PublicKey, pub) {
		t.Errorf("Expected PublicKey %s, got %s", pub, wafer.PublicKey)
	}

	if wafer.Signature != nil {
		t.Errorf("Expected Signature to be nil, but it was not")
	}
}

func TestSignAndVerifySuccess(t *testing.T) {
	pub, priv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}

	id := NewWaferID()
	expiresAt := time.Now().Add(1 * time.Hour)
	issuer := "example.com"

	w := NewWafer(id, expiresAt, issuer, pub)

	if err := w.Sign(priv); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(w.Signature) == 0 {
		t.Fatalf("empty signature")
	}

	if !w.VerifySignature() {
		t.Fatalf("signature did not verify")
	}
}

func TestSignMismatchedKey(t *testing.T) {
	_, priv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}
	otherPub, _, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}
	w := NewWafer(NewWaferID(), time.Now().Add(time.Hour), "", otherPub)
	if err := w.Sign(priv); err == nil {
		t.Fatalf("expected mismatch error, got nil")
	}
}

func TestVerifyTamperedWafer(t *testing.T) {
	pub, priv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair error: %v", err)
	}

	w := NewWafer(NewWaferID(), time.Now().Add(1*time.Hour), "example.com", pub)
	if err := w.Sign(priv); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Tamper with ExpiresAt
	w.ExpiresAt = w.ExpiresAt.Add(1 * time.Minute)
	if w.VerifySignature() {
		t.Errorf("signature verified with tampered ExpiresAt")
	}
	// Reset
	w.ExpiresAt = w.ExpiresAt.Add(-1 * time.Minute)
	if !w.VerifySignature() {
		t.Errorf("signature failed to verify after resetting ExpiresAt")
	}

	// Tamper with Issuer
	w.Issuer = "evil.com"
	if w.VerifySignature() {
		t.Errorf("signature verified with tampered Issuer")
	}
	// Reset
	w.Issuer = "example.com"
	if !w.VerifySignature() {
		t.Errorf("signature failed to verify after resetting Issuer")
	}

	// Tamper with ID
	w.ID = NewWaferID()
	if w.VerifySignature() {
		t.Errorf("signature verified with tampered ID")
	}
}
