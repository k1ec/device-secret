.PHONY: build test lint build-keygen

build: build-fingerprint build-license-gen build-keygen

build-fingerprint:
	CGO_ENABLED=0 go build -o bin/fingerprint ./cmd/fingerprint

build-license-gen:
	CGO_ENABLED=0 go build -o bin/license-gen ./cmd/license-gen

build-keygen:
	CGO_ENABLED=0 go build -o bin/keygen ./cmd/keygen

test:
	go test ./...

lint:
	golangci-lint run ./...
