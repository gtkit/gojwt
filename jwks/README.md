# Public JSON Web Key Sets

`github.com/gtkit/gojwt/jwks` is an optional public-key distribution package. It
supports RSA (RS/PS algorithms), NIST P-256/P-384/P-521 (ES256/384/512), and
Ed25519 (EdDSA). It uses the standard library and the parent gojwt package.
Private keys and HMAC secrets are never exported or accepted in a set.

## Local verification and publication

```go
key, err := jwks.NewKey("auth-2026", publicKey, "RS256")
if err != nil { return err }
set, err := jwks.NewSet(key)
if err != nil { return err }
verifier, err := gojwt.NewVerifier(set, []string{"RS256"},
    gojwt.WithParserOptions(jwtv5.WithIssuer("https://auth.example"), jwtv5.WithAudience("api")))
if err != nil { return err }
tokenClaims, err := verifier.ParseTokenContext(ctx, token)
```

`NewKey` takes a Go public key. The algorithm may be empty to permit all supported
signature algorithms compatible with that key, while the verifier still needs
an explicit trusted algorithm whitelist. Exported descriptors use `use: "sig"`
and `key_ops: ["verify"]`. `NewSet` validates and copies descriptors;
`Parse` accepts a complete `{"keys":[...]}` JSON document. `Set.Keys`, key
resolution and JSON encoding cannot expose mutable internal key storage.

`NewPublisher(set)` returns an `http.Handler`. Bind it to an application-owned
route, for example `mux.Handle("/.well-known/jwks.json", publisher)`. It serves
GET/HEAD with `application/jwk-set+json`. `publisher.Replace(nextSet)` atomically
publishes a complete snapshot; errors preserve the preceding response. The
application chooses HTTPS, routing and response cache policy. This handler does
not generate keys, keep private material or start background work.

## Remote verification

```go
remote, err := jwks.NewRemote("https://auth.example/.well-known/jwks.json")
if err != nil { return err }
if err := remote.Refresh(ctx); err != nil { return err } // optional eager sync
verifier, err := gojwt.NewVerifier(remote, []string{"RS256"},
    gojwt.WithParserOptions(jwtv5.WithIssuer("https://auth.example"), jwtv5.WithAudience("api")))
if err != nil { return err }
tokenClaims, err := verifier.ParseTokenContext(ctx, token)
```

The URL must come from trusted application configuration and use HTTPS. Userinfo,
fragments and redirects are rejected. Token `jku`/`x5u` fields never change it.
The copied HTTP client has cookies disabled and requests add no authorization.
A custom transport remains a trusted dependency and must honor request contexts.

`NewRemote` makes no request. `ResolveKey` fetches on first use, on snapshot expiry,
or after an unknown kid when the refresh interval permits it. This is automatic
**on-demand** updating: there is no implicit background goroutine or timer.
`Refresh(ctx)` permits explicit synchronization and bypasses automatic throttling.
Concurrent fetches are coalesced; waiting callers may cancel independently. The
caller starting the fetch supplies the I/O context: its cancellation fails that
shared attempt, and the waiters receive that failure without an updated snapshot.

| Option | Purpose, default and constraints |
|---|---|
| `WithClient(client)` | Inject a shared HTTP transport or test client; default is a new client using the standard HTTPS transport. A nil client is invalid. The client is copied, its cookie jar is cleared, redirects are disabled and `WithTimeout` sets its timeout. |
| `WithClock(now)` | Clock for freshness and throttling; defaults to `time.Now`. The function must be non-nil and safe for concurrent calls. Request deadlines still use real contexts. |
| `WithTTL(duration)` | Lifetime of each successfully fetched snapshot; defaults to 5 minutes and must be positive. Failure preserves the old expiry. |
| `WithTimeout(duration)` | HTTP request deadline; defaults to 5 seconds and must be positive. A shorter caller deadline also applies. |
| `WithMinRefreshInterval(duration)` | Minimum interval for automatic unknown-kid and failed fetch attempts; defaults to 30 seconds and must be positive. Explicit Refresh bypasses it. Successful TTL expiry is refreshed immediately even when TTL is shorter than this interval. |

Only fully parsed successful responses replace the snapshot. A failed update
does not partially install keys or prolong the old expiry. A fresh previous set
remains usable for its known keys. After its original expiry, a failed or
throttled refresh rejects verification instead of using stale public keys.
Every ResolveKey makes at most one fetch attempt. Unknown kids are exact misses;
they never fall back to another key. Empty kid is only accepted if explicitly
present as the identifier of one key. Successful rotation/removal applies to
subsequent resolutions, including the parent's dynamic verifier cache entrypoints.

## Accepted input and limits

Sets contain at most 128 keys and 1 MiB of valid UTF-8 JSON, with nesting limited to 32 levels.
The same size limit applies to exports and downloaded bodies, including chunked
or decompressed responses. RSA moduli must be positive odd integers of 2048–16384
bits, with an odd exponent between 3 and 2³¹−1. EC coordinates use their curve's
exact width and must form a valid point. Ed25519 requires exactly 32 public bytes.
Parameters use canonical unpadded base64url; RSA integers are minimally encoded.

Reserved parameter names are case-sensitive. Null scalar parameters, duplicate
JSON members, duplicate kid values, private fields (even null or case variants),
symmetric keys, mixed key-type parameters, conflicting alg/use/key_ops and
unsupported curves/algorithms are rejected. Omitted use/key_ops is permitted;
when present they must permit signature verification (`sig`, `verify`). Other
public metadata is ignored and is not retained when exporting the parsed set.

Errors support `errors.Is`: `jwks.ErrInvalidSet`, `jwks.ErrInvalidConfig`,
`jwks.ErrAlgorithmMismatch`, `jwks.ErrFetch`, and `gojwt.ErrUnknownKeyID`.
Context cancellation/deadline and underlying fetch errors remain discoverable.
