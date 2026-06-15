# HMAC Signing Method Option Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add configurable HMAC signing methods with `HS256` as the default while preserving strict algorithm validation and documenting the security trade-offs of `HS256`/`HS384`/`HS512`.

**Architecture:** Extend shared config with a HMAC-only signing method option, validate it during `JwtHmac` construction, and keep `JwtEd25519` unaffected. Use TDD to lock default behavior, configurable behavior, and invalid-option rejection before updating README.

**Tech Stack:** Go 1.26, `github.com/golang-jwt/jwt/v5`, testify

---

### Task 1: HMAC Signing Method Tests

**Files:**
- Modify: `jwt_test.go`

- [ ] Write failing tests for default `HS256`, configurable `HS384`/`HS512`, rejection of non-HMAC methods, and algorithm-specific secret validation.
- [ ] Run the targeted `go test ./... -run '...'` command and verify the new tests fail for the expected reasons.

### Task 2: HMAC Config Implementation

**Files:**
- Modify: `options.go`
- Modify: `jwthmac.go`

- [ ] Add an HMAC signing method option and validation helpers.
- [ ] Update `JwtHmac` sign/parse paths to use the configured method and validate only that method.
- [ ] Keep `HS256` as the default when no option is supplied.
- [ ] Run the targeted tests and verify they pass.

### Task 3: Documentation Sync

**Files:**
- Modify: `README.md`

- [ ] Update the HMAC description to explain default `HS256`, optional `HS384`/`HS512`, and practical differences between the three.
- [ ] Run `go test ./...`, `go test -race ./...`, and `go vet ./...` to verify the full package still passes.
