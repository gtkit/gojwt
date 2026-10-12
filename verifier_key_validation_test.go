package gojwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

func verifierKeyValidationToken(t *testing.T, method jwtv5.SigningMethod, key any) string {
	t.Helper()
	token := jwtv5.NewWithClaims(method, jwtv5.MapClaims{
		"sub": "42", "jti": "resolver-test", "exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "current"
	raw, err := token.SignedString(key)
	require.NoError(t, err)
	return raw
}

func TestVerifierKeyValidationAlgorithmsAndDomains(t *testing.T) {
	t.Parallel()
	secret := interoperableKey(t)
	rsaKey := capabilityRSAKey(t)
	p256 := capabilityECDSAKey(t, elliptic.P256())
	p384 := capabilityECDSAKey(t, elliptic.P384())
	p521 := capabilityECDSAKey(t, elliptic.P521())
	edPublic, edPrivate := capabilityEd25519Keys(t)
	tokens := map[string]string{
		"HS256": verifierKeyValidationToken(t, jwtv5.SigningMethodHS256, secret),
		"HS384": verifierKeyValidationToken(t, jwtv5.SigningMethodHS384, secret),
		"HS512": verifierKeyValidationToken(t, jwtv5.SigningMethodHS512, secret),
		"RS256": verifierKeyValidationToken(t, jwtv5.SigningMethodRS256, rsaKey),
		"PS256": verifierKeyValidationToken(t, jwtv5.SigningMethodPS256, rsaKey),
		"ES256": verifierKeyValidationToken(t, jwtv5.SigningMethodES256, p256),
		"ES384": verifierKeyValidationToken(t, jwtv5.SigningMethodES384, p384),
		"ES512": verifierKeyValidationToken(t, jwtv5.SigningMethodES512, p521),
		"EdDSA": verifierKeyValidationToken(t, jwtv5.SigningMethodEdDSA, edPrivate),
	}
	tests := []struct {
		name      string
		algorithm string
		key       any
		wantErr   error
	}{
		{name: "HS256 matching", algorithm: "HS256", key: secret},
		{name: "HS384 matching", algorithm: "HS384", key: secret},
		{name: "HS512 matching", algorithm: "HS512", key: secret},
		{name: "RS256 matching", algorithm: "RS256", key: &rsaKey.PublicKey},
		{name: "PS256 matching", algorithm: "PS256", key: &rsaKey.PublicKey},
		{name: "ES256 matching", algorithm: "ES256", key: &p256.PublicKey},
		{name: "ES384 matching", algorithm: "ES384", key: &p384.PublicKey},
		{name: "ES512 matching", algorithm: "ES512", key: &p521.PublicKey},
		{name: "EdDSA matching", algorithm: "EdDSA", key: edPublic},
		{name: "HMAC with RSA key", algorithm: "HS256", key: &rsaKey.PublicKey, wantErr: gojwt.ErrInvalidKeyType},
		{name: "HMAC with EC key", algorithm: "HS256", key: &p256.PublicKey, wantErr: gojwt.ErrInvalidKeyType},
		{name: "HMAC with string secret", algorithm: "HS256", key: string(secret), wantErr: gojwt.ErrInvalidKeyType},
		{name: "HS256 weak secret", algorithm: "HS256", key: secret[:31], wantErr: gojwt.ErrInvalidConfig},
		{name: "HS384 weak secret", algorithm: "HS384", key: secret[:47], wantErr: gojwt.ErrInvalidConfig},
		{name: "HS512 weak secret", algorithm: "HS512", key: secret[:63], wantErr: gojwt.ErrInvalidConfig},
		{name: "HS256 nil secret", algorithm: "HS256", key: []byte(nil), wantErr: gojwt.ErrInvalidConfig},
		{name: "RSA with HMAC bytes", algorithm: "RS256", key: secret, wantErr: gojwt.ErrInvalidKeyType},
		{name: "PSS with HMAC bytes", algorithm: "PS256", key: secret, wantErr: gojwt.ErrInvalidKeyType},
		{name: "RSA typed nil", algorithm: "RS256", key: (*rsa.PublicKey)(nil), wantErr: gojwt.ErrInvalidKey},
		{name: "RSA nil modulus", algorithm: "RS256", key: &rsa.PublicKey{E: 65537}, wantErr: gojwt.ErrInvalidKey},
		{name: "RSA weak modulus", algorithm: "RS256", key: &rsa.PublicKey{N: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 1024), big.NewInt(1)), E: 65537}, wantErr: gojwt.ErrInvalidConfig},
		{name: "EC wrong type", algorithm: "ES256", key: &rsaKey.PublicKey, wantErr: gojwt.ErrInvalidKeyType},
		{name: "EC typed nil", algorithm: "ES256", key: (*ecdsa.PublicKey)(nil), wantErr: gojwt.ErrInvalidKey},
		{name: "EC missing curve", algorithm: "ES256", key: &ecdsa.PublicKey{}, wantErr: gojwt.ErrInvalidKey},
		{name: "ES256 P384 mismatch", algorithm: "ES256", key: &p384.PublicKey, wantErr: gojwt.ErrInvalidKey},
		{name: "ES384 P521 mismatch", algorithm: "ES384", key: &p521.PublicKey, wantErr: gojwt.ErrInvalidKey},
		{name: "ES512 P256 mismatch", algorithm: "ES512", key: &p256.PublicKey, wantErr: gojwt.ErrInvalidKey},
		{name: "EdDSA wrong type", algorithm: "EdDSA", key: []byte(edPublic), wantErr: gojwt.ErrInvalidKeyType},
		{name: "EdDSA too short", algorithm: "EdDSA", key: edPublic[:31], wantErr: gojwt.ErrInvalidKey},
		{name: "EdDSA too long", algorithm: "EdDSA", key: append(ed25519.PublicKey{}, append(edPublic, 0)...), wantErr: gojwt.ErrInvalidKey},
		{name: "EdDSA typed nil", algorithm: "EdDSA", key: ed25519.PublicKey(nil), wantErr: gojwt.ErrInvalidKey},
		{name: "EdDSA nil interface", algorithm: "EdDSA", wantErr: gojwt.ErrInvalidKeyType},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resolver := gojwt.KeyResolverFunc(func(_ context.Context, kid, algorithm string) (any, error) {
				if kid != "current" || algorithm != tc.algorithm {
					return nil, gojwt.ErrUnknownKeyID
				}
				return tc.key, nil
			})
			verifier, err := gojwt.NewVerifier(resolver, []string{tc.algorithm})
			require.NoError(t, err)
			for _, parser := range []struct {
				name  string
				parse func(context.Context, string, ...jwtv5.ParserOption) (*claims.Claims, error)
			}{
				{name: "normal", parse: verifier.ParseTokenContext},
				{name: "cached", parse: verifier.CachedParseTokenContext},
			} {
				t.Run(parser.name, func(t *testing.T) {
					parsed, err := parser.parse(t.Context(), tokens[tc.algorithm])
					if tc.wantErr != nil {
						require.ErrorIs(t, err, tc.wantErr)
						require.Nil(t, parsed)
						return
					}
					require.NoError(t, err)
					require.Equal(t, "42", parsed.Subject)
					require.Equal(t, "resolver-test", parsed.TokenID)
				})
			}
		})
	}
}

func TestVerifierKeyValidationResolverErrorsAndCancellation(t *testing.T) {
	t.Parallel()
	secret := interoperableKey(t)
	token := verifierKeyValidationToken(t, jwtv5.SigningMethodHS256, secret)
	lookupFailure := errors.New("resolver unavailable")
	tests := []struct {
		name             string
		resolverErr      error
		cancelBefore     bool
		cancelInResolver bool
		wantErr          error
		wantCalls        int64
	}{
		{name: "lookup cause preserved", resolverErr: fmt.Errorf("key lookup: %w", lookupFailure), wantErr: lookupFailure, wantCalls: 1},
		{name: "resolver canceled cause", resolverErr: fmt.Errorf("remote canceled: %w", context.Canceled), wantErr: context.Canceled, wantCalls: 1},
		{name: "resolver deadline cause", resolverErr: fmt.Errorf("remote timeout: %w", context.DeadlineExceeded), wantErr: context.DeadlineExceeded, wantCalls: 1},
		{name: "unknown kid cause", resolverErr: gojwt.ErrUnknownKeyID, wantErr: gojwt.ErrUnknownKeyID, wantCalls: 1},
		{name: "cancel before lookup", cancelBefore: true, wantErr: context.Canceled},
		{name: "cancel after lookup starts", cancelInResolver: true, wantErr: context.Canceled, wantCalls: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancelBefore {
				cancel()
			}
			var calls atomic.Int64
			verifier, err := gojwt.NewVerifier(gojwt.KeyResolverFunc(func(context.Context, string, string) (any, error) {
				calls.Add(1)
				if tc.cancelInResolver {
					cancel()
				}
				return secret, tc.resolverErr
			}), []string{"HS256"})
			require.NoError(t, err)
			parsed, err := verifier.CachedParseTokenContext(ctx, token)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, parsed)
			require.Equal(t, tc.wantCalls, calls.Load())
		})
	}
}

func TestVerifierKeyValidationHeaderAndAlgorithmGate(t *testing.T) {
	t.Parallel()
	secret := interoperableKey(t)
	valid := verifierKeyValidationToken(t, jwtv5.SigningMethodHS256, secret)
	wrongAlgorithm := verifierKeyValidationToken(t, jwtv5.SigningMethodHS512, secret)
	exp := time.Now().Add(time.Hour).Unix()
	tests := []struct {
		name    string
		raw     string
		wantErr error
	}{
		{name: "valid", raw: valid},
		{name: "algorithm outside allowlist", raw: wrongAlgorithm, wantErr: gojwt.ErrTokenUnverifiable},
		{name: "empty", wantErr: gojwt.ErrTokenMalformed},
		{name: "malformed", raw: "not JWT", wantErr: gojwt.ErrTokenMalformed},
		{name: "numeric algorithm", raw: externalToken(t, secret, jwtv5.MapClaims{"exp": exp}, map[string]any{"alg": 42}), wantErr: gojwt.ErrTokenMalformed},
		{name: "numeric kid", raw: externalToken(t, secret, jwtv5.MapClaims{"exp": exp}, map[string]any{"kid": 42}), wantErr: gojwt.ErrTokenMalformed},
		{name: "unknown crit", raw: externalToken(t, secret, jwtv5.MapClaims{"exp": exp}, map[string]any{"crit": []string{"extension"}, "extension": true}), wantErr: gojwt.ErrTokenUnverifiable},
		{name: "invalid header JSON", raw: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":`)) + ".e30.invalid", wantErr: gojwt.ErrTokenMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int64
			verifier, err := gojwt.NewVerifier(gojwt.KeyResolverFunc(func(context.Context, string, string) (any, error) {
				calls.Add(1)
				return secret, nil
			}), []string{"HS256"})
			require.NoError(t, err)
			parsed, err := verifier.ParseTokenContext(t.Context(), tc.raw, jwtv5.WithValidMethods([]string{"HS512"}))
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, parsed)
				require.Zero(t, calls.Load())
				return
			}
			require.NoError(t, err)
			require.Equal(t, "42", parsed.Subject)
			require.Equal(t, int64(1), calls.Load())
		})
	}
}

func TestVerifierKeyValidationNilAndZeroReceivers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		j    *gojwt.TokenVerifier
	}{
		{name: "nil"},
		{name: "zero", j: &gojwt.TokenVerifier{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parsers := []struct {
				name  string
				parse func() (*claims.Claims, error)
			}{
				{name: "normal", parse: func() (*claims.Claims, error) { return tc.j.ParseToken("invalid") }},
				{name: "context", parse: func() (*claims.Claims, error) { return tc.j.ParseTokenContext(t.Context(), "invalid") }},
				{name: "cached", parse: func() (*claims.Claims, error) { return tc.j.CachedParseToken("invalid") }},
				{name: "cached context", parse: func() (*claims.Claims, error) { return tc.j.CachedParseTokenContext(t.Context(), "invalid") }},
			}
			for _, parser := range parsers {
				t.Run(parser.name, func(t *testing.T) {
					parsed, err := parser.parse()
					require.ErrorIs(t, err, gojwt.ErrJWTNotInit)
					require.Nil(t, parsed)
				})
			}
			for _, parallel := range []struct {
				name   string
				verify func() ([]*claims.Claims, []error)
			}{
				{name: "parallel", verify: func() ([]*claims.Claims, []error) { return tc.j.ParallelVerify([]string{"a", "b"}) }},
				{name: "parallel context", verify: func() ([]*claims.Claims, []error) { return tc.j.ParallelVerifyContext(t.Context(), []string{"a", "b"}) }},
			} {
				t.Run(parallel.name, func(t *testing.T) {
					results, errs := parallel.verify()
					require.Len(t, results, 2)
					require.Len(t, errs, 2)
					for i := range errs {
						require.ErrorIs(t, errs[i], gojwt.ErrJWTNotInit)
						require.Nil(t, results[i])
					}
				})
			}
		})
	}
}
