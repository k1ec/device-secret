package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
)

var ErrInvalidPEM = errors.New("crypto: invalid PEM data")

func GenerateKeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

func MarshalPrivateKey(key ed25519.PrivateKey) ([]byte, error) {
	block := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: key,
	}
	return pem.EncodeToMemory(block), nil
}

func MarshalPublicKey(key ed25519.PublicKey) ([]byte, error) {
	block := &pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: key,
	}
	return pem.EncodeToMemory(block), nil
}

func ParsePrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "ED25519 PRIVATE KEY" {
		return nil, fmt.Errorf("%w: not a valid ED25519 private key", ErrInvalidPEM)
	}
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: invalid private key size", ErrInvalidPEM)
	}
	return ed25519.PrivateKey(block.Bytes), nil
}

func ParsePublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "ED25519 PUBLIC KEY" {
		return nil, fmt.Errorf("%w: not a valid ED25519 public key", ErrInvalidPEM)
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid public key size", ErrInvalidPEM)
	}
	return ed25519.PublicKey(block.Bytes), nil
}

func Sign(key ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(key, message)
}

func Verify(key ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(key, message, sig)
}
