.PHONY: build test lint build-keygen
.PHONY: build-linux-arm64 build-linux-amd64
.PHONY: build-all clean

# —— Native build (host platform) ——
build: build-fingerprint build-license-gen build-keygen

build-fingerprint:
	CGO_ENABLED=0 go build -o bin/fingerprint ./cmd/fingerprint

build-license-gen:
	CGO_ENABLED=0 go build -o bin/license-gen ./cmd/license-gen

build-keygen:
	CGO_ENABLED=0 go build -o bin/keygen ./cmd/keygen

# —— Cross-compiled Linux binaries ——
# ARM64 (e.g. RK3568, AWS Graviton)
build-linux-arm64: build-fingerprint-linux-arm64 build-license-gen-linux-arm64 build-keygen-linux-arm64

build-fingerprint-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/linux-arm64/fingerprint ./cmd/fingerprint

build-license-gen-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/linux-arm64/license-gen ./cmd/license-gen

build-keygen-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/linux-arm64/keygen ./cmd/keygen

# AMD64 (x86_64 — typical server/desktop Linux)
build-linux-amd64: build-fingerprint-linux-amd64 build-license-gen-linux-amd64 build-keygen-linux-amd64

build-fingerprint-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/linux-amd64/fingerprint ./cmd/fingerprint

build-license-gen-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/linux-amd64/license-gen ./cmd/license-gen

build-keygen-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/linux-amd64/keygen ./cmd/keygen

# —— Convenience ——
build-all: build build-linux-arm64 build-linux-amd64

clean:
	rm -rf bin/

# —— Test & lint ——
test:
	go test ./...

lint:
	golangci-lint run ./...
