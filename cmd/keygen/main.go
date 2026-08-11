package main

import (
	"flag"
	"fmt"
	"os"

	"device-secret/internal/crypto"
)

func main() {
	outPriv := flag.String("out", "private.pem", "private key output path")
	outPub := flag.String("pub", "public.pem", "public key output path")
	flag.Parse()

	priv, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		os.Exit(1)
	}

	privPEM, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		os.Exit(1)
	}
	pubPEM, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outPriv, privPEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outPub, pubPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Private key: %s\nPublic key:  %s\n", *outPriv, *outPub)
}
