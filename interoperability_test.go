package gojwt_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
)

func interoperableKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func externalToken(t *testing.T, key []byte, payload jwtv5.MapClaims, header map[string]any) string {
	t.Helper()
	token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, payload)
	maps.Copy(token.Header, header)
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestMandatoryJOSEValidation(t *testing.T) {
	t.Parallel()
	key := interoperableKey(t)
	j, err := gojwt.NewJwtHmac(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		header map[string]any
		exp    any
		opts   []jwtv5.ParserOption
		want   error
	}{
		{name: "valid", exp: time.Now().Add(time.Hour).Unix()},
		{name: "unknown critical", exp: time.Now().Add(time.Hour).Unix(), header: map[string]any{"crit": []string{"deny-access"}, "deny-access": true}, want: gojwt.ErrTokenUnverifiable},
		{name: "empty critical", exp: time.Now().Add(time.Hour).Unix(), header: map[string]any{"crit": []string{}}, want: gojwt.ErrTokenUnverifiable},
		{name: "null critical", exp: time.Now().Add(time.Hour).Unix(), header: map[string]any{"crit": nil}, want: gojwt.ErrTokenUnverifiable},
		{name: "unencoded extension", exp: time.Now().Add(time.Hour).Unix(), header: map[string]any{"b64": false}, want: gojwt.ErrTokenUnverifiable},
		{name: "missing exp bypass", opts: []jwtv5.ParserOption{jwtv5.WithoutClaimsValidation()}, want: gojwt.ErrTokenRequiredClaimMissing},
		{name: "expired bypass", exp: time.Now().Add(-time.Hour).Unix(), opts: []jwtv5.ParserOption{jwtv5.WithoutClaimsValidation()}, want: gojwt.ErrTokenExpired},
		{name: "caller algorithm cannot replace fixed algorithm", exp: time.Now().Add(time.Hour).Unix(), opts: []jwtv5.ParserOption{jwtv5.WithValidMethods([]string{"none"})}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			payload := jwtv5.MapClaims{"sub": "42"}
			if tt.exp != nil {
				payload["exp"] = tt.exp
			}
			raw := externalToken(t, key, payload, tt.header)
			_, err := j.ParseToken(raw, tt.opts...)
			if !errors.Is(err, tt.want) {
				t.Fatalf("want %v, got %v", tt.want, err)
			}
		})
	}
	for _, parse := range []func(string) (*claims.Claims, error){func(raw string) (*claims.Claims, error) { return j.ParseToken(raw) }, func(raw string) (*claims.Claims, error) { return j.CachedParseToken(raw) }} {
		if _, err := parse(strings.Repeat("x", gojwt.MaxTokenBytes+1)); !errors.Is(err, gojwt.ErrTokenMalformed) {
			t.Fatal(err)
		}
	}
}

func TestCachedCustomClockRevalidation(t *testing.T) {
	t.Parallel()
	key := interoperableKey(t)
	base := time.Now().Add(time.Hour).Truncate(time.Second)
	var clock atomic.Int64
	clock.Store(base.Unix())
	j, err := gojwt.NewJwtHmac(key, gojwt.WithParseLeeway(0), gojwt.WithParserOptions(jwtv5.WithTimeFunc(func() time.Time { return time.Unix(clock.Load(), 0) })))
	if err != nil {
		t.Fatal(err)
	}
	raw := externalToken(t, key, jwtv5.MapClaims{"exp": base.Add(time.Minute).Unix(), "iat": base.Unix(), "nbf": base.Unix()}, nil)
	if _, err := j.CachedParseToken(raw); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name  string
		clock int64
		want  error
	}{
		{name: "future issued", clock: base.Add(-time.Minute).Unix(), want: gojwt.ErrTokenUsedBeforeIssued},
		{name: "expired", clock: base.Add(2 * time.Minute).Unix(), want: gojwt.ErrTokenExpired},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clock.Store(tt.clock)
			_, err := j.CachedParseToken(raw)
			if !errors.Is(err, tt.want) {
				t.Fatalf("want %v got %v", tt.want, err)
			}
		})
	}
}

func TestExternalClaimInteroperability(t *testing.T) {
	t.Parallel()
	key := interoperableKey(t)
	for _, tt := range []struct {
		name        string
		subject     any
		compat      bool
		wantSubject string
		want        error
	}{
		{name: "string", subject: "42", wantSubject: "42"},
		{name: "numeric rejected", subject: 42, want: gojwt.ErrTokenMalformed},
		{name: "numeric opt in", subject: 42, compat: true, wantSubject: "42"},
		{name: "large integer", subject: json.Number("9007199254740993"), compat: true, wantSubject: "9007199254740993"},
		{name: "fraction rejected", subject: 42.5, compat: true, want: gojwt.ErrTokenMalformed},
		{name: "null rejected", subject: nil, compat: true, want: gojwt.ErrTokenMalformed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			j, err := gojwt.NewJwtHmac(key, gojwt.WithNumericSubject(tt.compat))
			if err != nil {
				t.Fatal(err)
			}
			raw := externalToken(t, key, jwtv5.MapClaims{"sub": tt.subject, "jti": "laravel-id", "exp": time.Now().Add(time.Hour).Unix(), "tenant_id": json.Number("9007199254740993")}, nil)
			c, err := j.ParseToken(raw)
			if !errors.Is(err, tt.want) {
				t.Fatalf("want %v got %v", tt.want, err)
			}
			if err != nil {
				return
			}
			if c.Subject != tt.wantSubject || c.UserID != 0 || c.ID != "laravel-id" || c.TokenID != "laravel-id" {
				t.Fatalf("unexpected identity: %+v", c)
			}
			if c.Custom["tenant_id"] != json.Number("9007199254740993") {
				t.Fatal(c.Custom)
			}
		})
	}
	for _, tt := range []struct {
		name    string
		jti     string
		tokenID string
		want    error
	}{
		{name: "jti blacklist", jti: "revoked", want: gojwt.ErrTokenBlacklisted},
		{name: "conflicting ids", jti: "a", tokenID: "b", want: gojwt.ErrTokenInvalidID},
		{name: "matching ids", jti: "a", tokenID: "a"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			j, err := gojwt.NewJwtHmac(key, gojwt.WithBlacklistFunc(func(id string) bool { return id == "revoked" }))
			if err != nil {
				t.Fatal(err)
			}
			raw := externalToken(t, key, jwtv5.MapClaims{"jti": tt.jti, "token_id": tt.tokenID, "exp": time.Now().Add(time.Hour).Unix()}, nil)
			_, err = j.ParseToken(raw)
			if !errors.Is(err, tt.want) {
				t.Fatalf("want %v got %v", tt.want, err)
			}
		})
	}
}

func TestRefreshPreservesExternalFieldsAndInteger(t *testing.T) {
	t.Parallel()
	key := interoperableKey(t)
	j, err := gojwt.NewJwtHmac(key, gojwt.WithTokenDuration(time.Minute), gojwt.WithRefreshWindow(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw := externalToken(t, key, jwtv5.MapClaims{"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "sub": "42", "jti": "external-id", "tenant_id": json.Number("9007199254740993"), "ext": map[string]any{"large": json.Number("9007199254740993"), "small": 42, "nested": []any{map[string]any{"large": json.Number("9007199254740993")}}}}, nil)
	for _, tt := range []struct {
		name string
		raw  string
	}{{name: "original", raw: raw}} {
		t.Run(tt.name, func(t *testing.T) {
			c, err := j.CachedParseToken(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			if value, ok := c.ExtInt64("large"); !ok || value != 9007199254740993 {
				t.Fatalf("%v %v", value, ok)
			}
			if _, ok := c.Ext["small"].(json.Number); !ok {
				t.Fatal("small-number compatibility changed")
			}
			c.Custom["tenant_id"] = "mutated"
			c.Ext["nested"].([]any)[0].(map[string]any)["large"] = "mutated"
			fresh, err := j.CachedParseToken(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			if fresh.Custom["tenant_id"] != json.Number("9007199254740993") {
				t.Fatal(fresh.Custom)
			}
		})
	}
	refreshed, err := j.RefreshToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	c, err := j.ParseToken(refreshed)
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := c.ExtInt64("large"); !ok || value != 9007199254740993 {
		t.Fatalf("refreshed integer %v %v", value, ok)
	}
	if c.Custom["tenant_id"] != json.Number("9007199254740993") || c.TokenID == "external-id" {
		t.Fatal("external field or rotation lost")
	}
}

func TestResolverVerifierLifecycle(t *testing.T) {
	t.Parallel()
	key := interoperableKey(t)
	var removed atomic.Bool
	var calls atomic.Int64
	resolver := gojwt.KeyResolverFunc(func(ctx context.Context, kid, alg string) (any, error) {
		calls.Add(1)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if removed.Load() || kid != "current" {
			return nil, gojwt.ErrUnknownKeyID
		}
		if alg != "HS256" {
			return nil, gojwt.ErrInvalidKeyType
		}
		return key, nil
	})
	v, err := gojwt.NewVerifier(resolver, []string{"HS256"}, gojwt.WithParserOptions(jwtv5.WithIssuer("laravel"), jwtv5.WithAudience("go-api"), jwtv5.WithSubject("42")))
	if err != nil {
		t.Fatal(err)
	}
	raw := externalToken(t, key, jwtv5.MapClaims{"iss": "laravel", "aud": "go-api", "sub": "42", "exp": time.Now().Add(time.Hour).Unix()}, map[string]any{"kid": "current"})
	for _, tt := range []struct {
		name    string
		removed bool
		want    error
	}{{name: "valid", want: nil}, {name: "removed", removed: true, want: gojwt.ErrUnknownKeyID}} {
		t.Run(tt.name, func(t *testing.T) {
			removed.Store(tt.removed)
			_, err := v.CachedParseToken(raw)
			if !errors.Is(err, tt.want) {
				t.Fatalf("want %v got %v", tt.want, err)
			}
		})
	}
	if calls.Load() != 2 {
		t.Fatalf("resolver calls %d", calls.Load())
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := v.ParseTokenContext(ctx, raw); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("canceled request reached resolver")
	}
	results, errs := v.ParallelVerify([]string{raw, raw})
	if len(results) != 2 || len(errs) != 2 {
		t.Fatal("result order length")
	}
	var nilResolver gojwt.KeyResolverFunc
	var nilHMAC *gojwt.JwtHmac
	for _, tt := range []struct {
		name     string
		resolver gojwt.KeyResolver
		algs     []string
		opts     []gojwt.Option
	}{
		{name: "nil", algs: []string{"HS256"}},
		{name: "typed nil", resolver: nilResolver, algs: []string{"HS256"}},
		{name: "missing algorithms", resolver: resolver},
		{name: "unknown algorithm", resolver: resolver, algs: []string{"none"}},
		{name: "signing option", resolver: resolver, algs: []string{"HS256"}, opts: []gojwt.Option{gojwt.WithECDSASigningMethod(jwtv5.SigningMethodES256)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := gojwt.NewVerifier(tt.resolver, tt.algs, tt.opts...); !errors.Is(err, gojwt.ErrInvalidConfig) {
				t.Fatal(err)
			}
		})
	}
	if err := gojwt.NewKeyRing().Register("nil", nilHMAC); !errors.Is(err, gojwt.ErrInvalidConfig) {
		t.Fatal(err)
	}
}

func TestStrictBearerRequest(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		values  []string
		want    string
		wantErr error
	}{
		{name: "missing", wantErr: gojwt.ErrAuthorizationMissing},
		{name: "valid", values: []string{"Bearer abc.def_ghi"}, want: "abc.def_ghi"},
		{name: "duplicate", values: []string{"Bearer abc", "Bearer xyz"}, wantErr: gojwt.ErrAuthorizationInvalid},
		{name: "comma", values: []string{"Bearer abc,def"}, wantErr: gojwt.ErrAuthorizationInvalid},
		{name: "colon", values: []string{"Bearer abc:def"}, wantErr: gojwt.ErrAuthorizationInvalid},
		{name: "tab", values: []string{"Bearer \tabc"}, wantErr: gojwt.ErrAuthorizationInvalid},
		{name: "nonterminal padding", values: []string{"Bearer ab=c"}, wantErr: gojwt.ErrAuthorizationInvalid},
		{name: "oauth opaque", values: []string{"bearer  abc~/+=="}, want: "abc~/+=="},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request := &http.Request{Header: make(http.Header)}
			for _, value := range tt.values {
				request.Header.Add("Authorization", value)
			}
			got, err := gojwt.ParseBearerRequest(request)
			if got != tt.want || !errors.Is(err, tt.wantErr) {
				t.Fatalf("got %q %v", got, err)
			}
		})
	}
}
