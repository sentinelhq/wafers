package wafer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"filippo.io/edwards25519"
	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	Version               = "0"
	headerSignatureDomain = "wafer/v0/header-signature"
	layerSealDomain       = "wafer/v0/layer"
	holderSealDomain      = "wafer/v0/holder"
	k0Domain              = "wafer/v0/K0"
	kiDomain              = "wafer/v0/Ki"
)

// WaferID is a 16-byte unique identifier for a Wafer.
type WaferID [16]byte

// Wafer represents a capability token as described in the spec.
type Wafer struct {
	// Version of the Wafer format.
	Version string

	// ID is a unique identifier for this Wafer.
	ID WaferID

	// ExpiresAt is the expiration time of the Wafer. A token is invalid after this time.
	ExpiresAt time.Time

	// Issuer is a string identifying the service that issued the Wafer.
	Issuer string

	// PublicKey is the issuer's public key.
	PublicKey ed25519.PublicKey

	// Signature is a signature of the header fields.
	//
	// NOTE: This is an optional field that can be used by third parties to verify
	// the Wafer's header fields authenticity without needing access to the root secret.
	Signature []byte

	// Layers is a list of layers that have been applied to the Wafer.
	Layers []Layer

	// Holders is a list of holders that have been applied to the Wafer.
	Holders []Holder
}

// Caveat is a single restriction. Its format is intentionally flexible.
type Caveat []byte

// Layer represents a set of caveats added by a holder.
type Layer struct {
	Caveats []Caveat
	Seal    []byte // HMAC seal of the serialized caveats
}

// Holder links a Wafer to the next holder in the delegation chain.
type Holder struct {
	PublicKey  ed25519.PublicKey
	Identifier string
	Seal       []byte // HMAC seal of the holder information
}

// AttenuationOptions specifies what to add in a new attenuation step.
type AttenuationOptions struct {
	Caveats             []Caveat
	NextHolderPublicKey ed25519.PublicKey // if nil -> terminal
	NextHolderID        string
}

// NewWafer creates a new Wafer with the given parameters.
func NewWafer(id WaferID, expiresAt time.Time, issuer string, publicKey ed25519.PublicKey) *Wafer {
	return &Wafer{
		Version:   Version,
		ID:        id,
		ExpiresAt: expiresAt,
		Issuer:    issuer,
		PublicKey: publicKey,
	}
}

// NewWaferID creates a new Wafer ID.
func NewWaferID() WaferID {
	return WaferID(uuid.New())
}

// Sign creates an ed25519 signature over a canonical encoding of (ID, ExpiresAt, Issuer)
// and stores it in Signature. It validates header preconditions and does not panic.
func (w *Wafer) Sign(privateKey ed25519.PrivateKey) error {
	if w.ExpiresAt.IsZero() {
		return errors.New("wafer: expiresAt is zero")
	}
	if len(w.Issuer) > 0xFFFF {
		return errors.New("wafer: issuer too long")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("wafer: invalid ed25519 private key size")
	}
	pubAny := privateKey.Public()
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		return errors.New("wafer: could not derive public key from private key")
	}
	if !bytes.Equal(pub, w.PublicKey) {
		return errors.New("wafer: public key does not match private key")
	}

	msg := buildHeaderSignatureMessage(w.ID[:], w.ExpiresAt, w.Issuer)
	sig := ed25519.Sign(privateKey, msg)
	w.Signature = make([]byte, len(sig))
	copy(w.Signature, sig)
	return nil
}

// buildHeaderSignatureMessage constructs the canonical message to be signed for the header.
// Format:
//
//	domain = "wafer/v0/header-signature"
//	domain || id(16 bytes) || uint64(expiry_unix_seconds_be) || uint16(len(issuer)) || issuer
func buildHeaderSignatureMessage(id []byte, expiresAt time.Time, issuer string) []byte {
	var buf bytes.Buffer
	buf.WriteString(headerSignatureDomain)
	buf.Write(id)
	var tmp8 [8]byte
	unix := uint64(expiresAt.Unix())
	binary.BigEndian.PutUint64(tmp8[:], unix)
	buf.Write(tmp8[:])
	var tmp2 [2]byte
	binary.BigEndian.PutUint16(tmp2[:], uint16(len(issuer)))
	buf.Write(tmp2[:])
	buf.WriteString(issuer)
	return buf.Bytes()
}

// VerifySignature verifies the Wafer's signature against its public key.
// It returns true if the signature is valid, and false otherwise.
func (w *Wafer) VerifySignature() bool {
	if len(w.PublicKey) != ed25519.PublicKeySize {
		return false
	}

	if len(w.Signature) == 0 {
		return false
	}

	msg := buildHeaderSignatureMessage(w.ID[:], w.ExpiresAt, w.Issuer)
	return ed25519.Verify(w.PublicKey, msg, w.Signature)
}

// Attenuate adds the first layer of caveats to a Wafer using the root-derived key K0.
// It can only be called on a fresh Wafer with no layers. The returned Wafer is a new
// immutable copy.
func (w Wafer) Attenuate(k0 []byte, opts AttenuationOptions) (Wafer, error) {
	if len(w.Layers) != 0 {
		return w, errors.New("wafer: Attenuate can only be called on a new Wafer")
	}
	if len(k0) == 0 {
		return w, errors.New("wafer: k0 cannot be empty")
	}

	// Create a new copy to maintain immutability.
	newWafer := w
	newWafer.Layers = make([]Layer, 1)
	newWafer.Holders = make([]Holder, 0) // May not have a holder

	// Create and seal the layer.
	layer := Layer{Caveats: cloneCaveats(opts.Caveats)}
	layerBytes, err := layer.serialize()
	if err != nil {
		return w, err
	}
	layer.Seal = seal(k0, layerSealDomain, layerBytes)
	newWafer.Layers[0] = layer

	// If a next holder is specified, create and seal it.
	if opts.NextHolderPublicKey != nil {
		holder := Holder{
			PublicKey:  cloneEd25519PublicKey(opts.NextHolderPublicKey),
			Identifier: opts.NextHolderID,
		}
		holderBytes, err := holder.serialize()
		if err != nil {
			return w, err
		}
		holder.Seal = seal(k0, holderSealDomain, holderBytes)
		newWafer.Holders = append(newWafer.Holders, holder)
	}

	return newWafer, nil
}

// AttenuateWithPrivKey adds a new layer of caveats to a Wafer. It derives the sealing
// key Ki using the provided holder's private key. The Wafer must not be terminal and
// the private key must correspond to the last nominated holder. The returned Wafer is
// a new immutable copy.
func (w Wafer) AttenuateWithPrivKey(holderSK ed25519.PrivateKey, opts AttenuationOptions) (Wafer, error) {
	ki, err := w.DeriveKi(holderSK)
	if err != nil {
		return w, err
	}

	// Create a new copy to maintain immutability.
	newWafer := w
	newWafer.Layers = make([]Layer, len(w.Layers)+1)
	copy(newWafer.Layers, w.Layers)
	newWafer.Holders = make([]Holder, len(w.Holders))
	copy(newWafer.Holders, w.Holders)

	// Create and seal the layer.
	layer := Layer{Caveats: cloneCaveats(opts.Caveats)}
	layerBytes, err := layer.serialize()
	if err != nil {
		return w, err
	}
	layer.Seal = seal(ki, layerSealDomain, layerBytes)
	newWafer.Layers[len(newWafer.Layers)-1] = layer

	// If a next holder is specified, create and seal it.
	if opts.NextHolderPublicKey != nil {
		holder := Holder{
			PublicKey:  cloneEd25519PublicKey(opts.NextHolderPublicKey),
			Identifier: opts.NextHolderID,
		}
		holderBytes, err := holder.serialize()
		if err != nil {
			return w, err
		}
		holder.Seal = seal(ki, holderSealDomain, holderBytes)
		newWafer.Holders = append(newWafer.Holders, holder)
	}

	return newWafer, nil
}

// DeriveK0 derives the initial sealing key (K0) from the root secret.
func (w Wafer) DeriveK0(rootSecret []byte) ([]byte, error) {
	if len(rootSecret) == 0 {
		return nil, errors.New("wafer: rootSecret cannot be empty")
	}
	mac := hmac.New(sha256.New, rootSecret)
	mac.Write([]byte(k0Domain))
	mac.Write(w.ID[:])
	return mac.Sum(nil), nil
}

// DeriveKi derives a sealing key (Ki) for a new layer from the holder's private key.
func (w Wafer) DeriveKi(holderSK ed25519.PrivateKey) ([]byte, error) {
	if w.IsTerminal() {
		return nil, errors.New("wafer: cannot derive key for terminal wafer")
	}
	if len(w.Layers) == 0 {
		return nil, errors.New("wafer: cannot derive Ki for a wafer with no layers")
	}
	if len(holderSK) != ed25519.PrivateKeySize {
		return nil, errors.New("wafer: invalid ed25519 private key size")
	}

	// The holderSK must correspond to the last holder in the chain.
	lastHolder := w.Holders[len(w.Holders)-1]
	if !bytes.Equal(holderSK.Public().(ed25519.PublicKey), lastHolder.PublicKey) {
		return nil, errors.New("wafer: private key does not match last holder")
	}

	// Convert keys for X25519
	issuerPubBytes, err := ed25519PublicKeyToCurve25519(w.PublicKey)
	if err != nil {
		return nil, err
	}
	holderSKBytes, err := ed25519PrivateKeyToCurve25519(holderSK)
	if err != nil {
		return nil, err
	}

	// ECDH shared secret
	ss, err := curve25519.X25519(holderSKBytes, issuerPubBytes)
	if err != nil {
		return nil, fmt.Errorf("wafer: X25519 failed: %w", err)
	}
	// Reject low-order points that produce an all-zero shared secret.
	var zeroSS [32]byte
	if hmac.Equal(ss, zeroSS[:]) {
		return nil, errors.New("wafer: invalid ECDH shared secret (low order)")
	}

	// Derive the key using HKDF-SHA256
	// Ki := HKDF(ikm=ss, salt=prevMac, info=kiDomain||Version||w.ID||lastHolderPubEd25519)
	salt := w.HeadMAC()
	info := bytes.NewBuffer(make([]byte, 0))
	info.WriteString(kiDomain)
	info.WriteString(Version)
	info.Write(w.ID[:])
	info.Write(lastHolder.PublicKey)

	hkdf := hkdf.New(sha256.New, ss, salt, info.Bytes())
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, fmt.Errorf("wafer: could not read from hkdf: %w", err)
	}

	return key, nil
}

// HeadMAC returns the seal of the most recent Layer. This is required for deriving the next sealing key.
func (w Wafer) HeadMAC() []byte {
	if len(w.Layers) == 0 {
		return nil
	}
	return w.Layers[len(w.Layers)-1].Seal
}

// IsTerminal returns true if the Wafer cannot be attenuated further.
// This happens when a Layer is added without nominating a next Holder.
func (w Wafer) IsTerminal() bool {
	return len(w.Layers) > len(w.Holders)
}

// Verify checks the full cryptographic validity of the Wafer. If valid, it returns
// a slice of all caveats for policy engine evaluation. It requires a function
// to look up the root secret for the Wafer's ID and the issuer's private key.
func (w Wafer) Verify(
	rootSecretLookup func(WaferID) ([]byte, error),
	issuerSK ed25519.PrivateKey,
) ([]Caveat, error) {
	// 1. Header Checks
	if time.Now().After(w.ExpiresAt) {
		return nil, errors.New("wafer: expired")
	}
	if len(w.Signature) > 0 && !w.VerifySignature() {
		return nil, errors.New("wafer: invalid header signature")
	}
	if len(w.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("wafer: invalid ed25519 public key size")
	}

	// 2. Chain Check
	if err := w.verifyChain(rootSecretLookup, issuerSK); err != nil {
		return nil, err
	}

	// 3. Success: return all caveats
	var allCaveats []Caveat
	for _, layer := range w.Layers {
		allCaveats = append(allCaveats, layer.Caveats...)
	}
	return allCaveats, nil
}

// verifyChain performs the cryptographic integrity check of the layers and holders.
func (w Wafer) verifyChain(
	rootSecretLookup func(WaferID) ([]byte, error),
	issuerSK ed25519.PrivateKey,
) error {
	rootSecret, err := rootSecretLookup(w.ID)
	if err != nil {
		return fmt.Errorf("wafer: root secret lookup failed: %w", err)
	}
	if len(rootSecret) == 0 {
		return errors.New("wafer: root secret not found or empty")
	}
	if len(w.Holders) > len(w.Layers) {
		return errors.New("wafer: more holders than layers")
	}

	if len(w.Layers) == 0 {
		return nil // No layers means nothing to verify.
	}

	// Derive K0 to start the chain.
	currentKey, err := w.DeriveK0(rootSecret)
	if err != nil {
		return fmt.Errorf("wafer: could not derive K0 for verification: %w", err)
	}

	issuerSKBytes, err := ed25519PrivateKeyToCurve25519(issuerSK)
	if err != nil {
		return err
	}

	for i, layer := range w.Layers {
		// Verify the layer seal.
		layerBytes, err := layer.serialize()
		if err != nil {
			return fmt.Errorf("wafer: could not serialize layer %d: %w", i, err)
		}
		expectedSeal := seal(currentKey, layerSealDomain, layerBytes)
		if !hmac.Equal(layer.Seal, expectedSeal) {
			return fmt.Errorf("wafer: invalid seal for layer %d", i)
		}

		// Check for a holder corresponding to this layer.
		if i < len(w.Holders) {
			// This is a non-terminal step, verify the holder and derive the next key.
			holder := w.Holders[i]
			holderBytes, err := holder.serialize()
			if err != nil {
				return fmt.Errorf("wafer: could not serialize holder %d: %w", i, err)
			}
			expectedHolderSeal := seal(currentKey, holderSealDomain, holderBytes)
			if !hmac.Equal(holder.Seal, expectedHolderSeal) {
				return fmt.Errorf("wafer: invalid seal for holder %d", i)
			}

			// Derive the next key, K_{i+1}.
			holderPubBytes, err := ed25519PublicKeyToCurve25519(holder.PublicKey)
			if err != nil {
				return err
			}

			ss, err := curve25519.X25519(issuerSKBytes, holderPubBytes)
			if err != nil {
				return fmt.Errorf("wafer: X25519 failed for holder %d: %w", i, err)
			}
			// Reject low-order points that produce an all-zero shared secret.
			var zeroSS [32]byte
			if hmac.Equal(ss, zeroSS[:]) {
				return fmt.Errorf("wafer: invalid ECDH shared secret for holder %d (low order)", i)
			}

			salt := layer.Seal
			info := bytes.NewBuffer(make([]byte, 0))
			info.WriteString(kiDomain)
			info.WriteString(Version)
			info.Write(w.ID[:])
			info.Write(holder.PublicKey)

			hkdf := hkdf.New(sha256.New, ss, salt, info.Bytes())
			nextKey := make([]byte, 32)
			if _, err := io.ReadFull(hkdf, nextKey); err != nil {
				return fmt.Errorf("wafer: could not read from hkdf for key %d: %w", i+1, err)
			}
			currentKey = nextKey

		} else {
			// This layer is terminal. Ensure it's the last one.
			if i != len(w.Layers)-1 {
				return fmt.Errorf("wafer: layer %d is terminal but not the last layer", i)
			}
		}
	}

	return nil
}

// ed25519PublicKeyToCurve25519 converts an Ed25519 public key to a Curve25519 public key.
// This is based on RFC 8032, Section 5.1.5.
func ed25519PublicKeyToCurve25519(pk ed25519.PublicKey) ([]byte, error) {
	p, err := (&edwards25519.Point{}).SetBytes(pk)
	if err != nil {
		return nil, err
	}
	return p.BytesMontgomery(), nil
}

// ed25519PrivateKeyToCurve25519 converts an Ed25519 private key to a Curve25519 private key.
// This is based on RFC 8032, Section 5.1.5.
func ed25519PrivateKeyToCurve25519(sk ed25519.PrivateKey) ([]byte, error) {
	if len(sk) != ed25519.PrivateKeySize {
		return nil, errors.New("wafer: invalid ed25519 private key size")
	}
	seed := sk.Seed()
	sum := sha512.Sum512(seed)
	var k [32]byte
	copy(k[:], sum[:32])
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	out := make([]byte, 32)
	copy(out, k[:])
	return out, nil
}

func seal(key []byte, domain string, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(domain))
	mac.Write(data)
	return mac.Sum(nil)
}

// cloneCaveats deep-copies a slice of caveats to avoid aliasing caller memory.
func cloneCaveats(in []Caveat) []Caveat {
	if len(in) == 0 {
		return nil
	}
	out := make([]Caveat, len(in))
	for i, c := range in {
		if c == nil {
			continue
		}
		b := make([]byte, len(c))
		copy(b, c)
		out[i] = Caveat(b)
	}
	return out
}

// cloneEd25519PublicKey deep-copies an Ed25519 public key slice to prevent aliasing.
func cloneEd25519PublicKey(pk ed25519.PublicKey) ed25519.PublicKey {
	if pk == nil {
		return nil
	}
	out := make(ed25519.PublicKey, len(pk))
	copy(out, pk)
	return out
}

// serialize concatenates the caveats in a layer into a single byte slice.
// Format: uint16(len(caveat1)) || caveat1 || uint16(len(caveat2)) || caveat2 ...
func (l *Layer) serialize() ([]byte, error) {
	var buf bytes.Buffer
	for _, c := range l.Caveats {
		if len(c) > 0xFFFF {
			return nil, errors.New("wafer: caveat too long")
		}
		var tmp [2]byte
		binary.BigEndian.PutUint16(tmp[:], uint16(len(c)))
		buf.Write(tmp[:])
		buf.Write(c)
	}
	return buf.Bytes(), nil
}

// serialize concatenates the holder fields into a single byte slice.
// Format: pub_key(32 bytes) || uint16(len(identifier)) || identifier
func (h *Holder) serialize() ([]byte, error) {
	var buf bytes.Buffer
	if len(h.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("wafer: invalid ed25519 public key size")
	}
	buf.Write(h.PublicKey)
	if len(h.Identifier) > 0xFFFF {
		return nil, errors.New("wafer: identifier too long")
	}
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], uint16(len(h.Identifier)))
	buf.Write(tmp[:])
	buf.WriteString(h.Identifier)
	return buf.Bytes(), nil
}
