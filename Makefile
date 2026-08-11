.PHONY: build test lint

build: build-fingerprint build-license-gen

build-fingerprint:
	CGO_ENABLED=0 go build -o bin/fingerprint ./cmd/fingerprint

build-license-gen:
	CGO_ENABLED=0 go build -o bin/license-gen ./cmd/license-gen

test:
	go test ./...

lint:
	golangci-lint run ./...
