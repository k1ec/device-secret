# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Summary

A software license system that binds applications to specific devices via hardware fingerprinting and Ed25519 signatures, preventing unauthorized copying to unlicensed machines. Three artifacts: a `fingerprint` CLI (host-side hardware collection), a `license-gen` CLI (signing machine), and an embeddable `pkg/sdk` library for in-app verification.

**Target:** Linux x86_64 and ARM (RK3568), offline operation, Docker deployment with bind mounts for `/proc` and `/sys`.

## Constraints
- **Zero third-party dependencies** — standard library only (`crypto/ed25519`, `crypto/sha256`, `encoding/json`, `encoding/base64`, `encoding/pem`)
- **Go 1.25+** required for `crypto/ed25519`
- **`CGO_ENABLED=0`** for all builds (static binaries)
- **SDK must never panic** — all public functions return errors instead
- **Integration tests** are gated by `//go:build integration` tag and require real Linux hardware
- `internal/` packages are importable within this module but blocked for external consumers
llow the plan's 10 tasks in order: project scaffolding → `internal/crypto` → `internal/fingerprint` → `internal/license` → `internal/grace` → `pkg/sdk` → `cmd/fingerprint` → `cmd/license-gen` → integration tests → 

### Security invariants

- Private key never leaves the signing machine; SDK and fingerprint CLI only embed the public key
- SDK re-collects the fingerprint on every `Verify()` call and compares against the license's `device_hash`
- Copying a license to a different machine fails because the hash won't match
- All Base64 uses URL-safe encoding without padding (`base64.URLEncoding.WithPadding(base64.NoPadding)`)
- `kid` field in license payloads enables key rotation without invalidating active licenses
