# Blacklist Expiration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add exp-aware automatic expiration to the in-memory blacklist without breaking the existing `Blacklister` interface.

**Architecture:** Keep `Blacklister` unchanged, upgrade `Blacklist` storage from a set to an expiration map, add exp-aware helper methods on the concrete `Blacklist` type, and lazily evict expired entries during lookup. Preserve `Add(tokenID)` as a permanent blacklist entry for backward compatibility.

**Tech Stack:** Go 1.26, `github.com/golang-jwt/jwt/v5`, testify

---

### Task 1: Write Failing Tests

**Files:**
- Modify: `jwt_test.go`
- Create: `blacklist_internal_test.go`

- [ ] Add external-behavior tests for `AddToken`, `AddWithExpiration`, and permanent `Add`.
- [ ] Add an internal test that proves `In` lazily removes expired entries from the map.
- [ ] Run targeted `go test ./... -run 'TestBlacklist'` and verify the new tests fail for the expected reasons.

### Task 2: Implement Exp-Aware Blacklist

**Files:**
- Modify: `blacklist.go`

- [ ] Change blacklist storage to keep expiration timestamps.
- [ ] Keep `Add(tokenID)` backward compatible as a permanent blacklist entry.
- [ ] Add `AddToken(*claims.Claims) error` and `AddWithExpiration(tokenID string, expiresAt time.Time)`.
- [ ] Make `In` lazily evict expired entries.
- [ ] Run targeted blacklist tests and verify they pass.

### Task 3: Sync Documentation And Examples

**Files:**
- Modify: `README.md`

- [ ] Update blacklist docs to prefer exp-aware usage with `AddToken`.
- [ ] Clarify that `Add(tokenID)` is the backward-compatible permanent-entry path.
- [ ] Run `go test ./...`, `go test -race ./...`, and `go vet ./...`.
