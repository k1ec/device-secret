package crypto

import (
	"crypto/ed25519"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key size = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("public key size = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
}

func TestPEMRoundTripPrivateKey(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	pemBytes, err := MarshalPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPrivateKey() error = %v", err)
	}
	parsed, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey() error = %v", err)
	}
	if !ed25519.PrivateKey(parsed).Equal(priv) {
		t.Error("round-tripped private key not equal to original")
	}
}

func TestPEMRoundTripPublicKey(t *testing.T) {
	_, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	pemBytes, err := MarshalPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPublicKey() error = %v", err)
	}
	parsed, err := ParsePublicKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePublicKey() error = %v", err)
	}
	if !ed25519.PublicKey(parsed).Equal(pub) {
		t.Error("round-tripped public key not equal to original")
	}
}

func TestParsePrivateKey_WrongType(t *testing.T) {
	pemData := "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhDHEQ==\n-----END RSA PRIVATE KEY-----"
	_, err := ParsePrivateKey([]byte(pemData))
	if err == nil {
		t.Error("expected error for wrong PEM type, got nil")
	}
}

func TestParsePublicKey_WrongType(t *testing.T) {
	pemData := "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAMkaPw==\n-----END RSA PUBLIC KEY-----"
	_, err := ParsePublicKey([]byte(pemData))
	if err == nil {
		t.Error("expected error for wrong PEM type, got nil")
	}
}

func TestSignAndVerify(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	message := []byte("hello world")
	sig := Sign(priv, message)
	if !Verify(pub, message, sig) {
		t.Error("Verify() returned false for valid signature")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	_, wrongPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	message := []byte("hello world")
	sig := Sign(priv, message)
	if Verify(wrongPub, message, sig) {
		t.Error("Verify() returned true for signature made with different key")
	}
}

func TestVerify_TamperedMessage(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	message := []byte("hello world")
	sig := Sign(priv, message)
	if Verify(pub, []byte("goodbye world"), sig) {
		t.Error("Verify() returned true for tampered message")
	}
}
