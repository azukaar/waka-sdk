package waka

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// Sealed blob layout, version 1:
//
//	0x01 | ephemeral P-256 public key (65 bytes, uncompressed) | nonce (12) | AES-256-GCM ciphertext
//
// The AES key is HKDF-SHA256 over the ECDH shared secret, salted with both
// public keys. P-256 is used because every WebCrypto implementation has it.
const (
	sealVersion = 1
	sealPubLen  = 65
	sealNonce   = 12
)

var sealInfo = "waka-seal-v1"

func sealKey(shared, ephPub, recipientPub []byte) (cipher.AEAD, error) {
	salt := append(append([]byte{}, ephPub...), recipientPub...)
	key, err := hkdf.Key(sha256.New, shared, salt, sealInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plaintext so only the holder of the device key can read it.
func Seal(recipientPub, plaintext []byte) ([]byte, error) {
	pub, err := ecdh.P256().NewPublicKey(recipientPub)
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	ephPub := eph.PublicKey().Bytes()
	aead, err := sealKey(shared, ephPub, recipientPub)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, sealNonce)
	rand.Read(nonce)
	out := append([]byte{sealVersion}, ephPub...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, nil), nil
}

// OpenSealed is the device side of Seal. Clients do this in the SDK; it is
// here for Go clients and tests.
func OpenSealed(priv *ecdh.PrivateKey, blob []byte) ([]byte, error) {
	if len(blob) < 1+sealPubLen+sealNonce || blob[0] != sealVersion {
		return nil, errors.New("waka: not a sealed blob")
	}
	ephPub := blob[1 : 1+sealPubLen]
	nonce := blob[1+sealPubLen : 1+sealPubLen+sealNonce]
	pub, err := ecdh.P256().NewPublicKey(ephPub)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	aead, err := sealKey(shared, ephPub, priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, blob[1+sealPubLen+sealNonce:], nil)
}
