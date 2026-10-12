package gojwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"path/filepath"
	"sync"
	"testing"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

func capabilityRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func TestVerifierCapabilitiesRSAAlgorithms(t *testing.T) {
	t.Parallel()
	privateKey := capabilityRSAKey(t)
	tests := []struct {
		name   string
		method jwtv5.SigningMethod
	}{
		{name: "RS256", method: jwtv5.SigningMethodRS256},
		{name: "RS384", method: jwtv5.SigningMethodRS384},
		{name: "RS512", method: jwtv5.SigningMethodRS512},
		{name: "PS256", method: jwtv5.SigningMethodPS256},
		{name: "PS384", method: jwtv5.SigningMethodPS384},
		{name: "PS512", method: jwtv5.SigningMethodPS512},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			issuer, err := gojwt.NewJwtRSAFromKeys(privateKey, &privateKey.PublicKey, gojwt.WithRSASigningMethod(tc.method))
			require.NoError(t, err)
			verifier, err := gojwt.NewJwtRSAVerifier(&privateKey.PublicKey, gojwt.WithRSASigningMethod(tc.method))
			require.NoError(t, err)
			token, err := issuer.GenerateToken(42)
			require.NoError(t, err)
			parsed, err := verifier.ParseTokenContext(t.Context(), token)
			require.NoError(t, err)
			require.Equal(t, int64(42), parsed.UserID)

			otherMethod := jwtv5.SigningMethodRS256
			if tc.method.Alg() == otherMethod.Alg() {
				otherMethod = jwtv5.SigningMethodRS512
			}
			wrongAlgorithm, err := gojwt.NewJwtRSAVerifier(&privateKey.PublicKey, gojwt.WithRSASigningMethod(otherMethod))
			require.NoError(t, err)
			_, err = wrongAlgorithm.ParseTokenContext(t.Context(), token)
			require.ErrorIs(t, err, gojwt.ErrTokenSignatureInvalid)
		})
	}
}

func TestVerifierCapabilitiesRSAConstruction(t *testing.T) {
	t.Parallel()
	privateKey := capabilityRSAKey(t)
	tests := []struct {
		name      string
		publicKey *rsa.PublicKey
		opts      []gojwt.Option
		wantErr   error
	}{
		{name: "valid default", publicKey: &privateKey.PublicKey},
		{name: "nil public", wantErr: gojwt.ErrInvalidKey},
		{name: "nil modulus", publicKey: &rsa.PublicKey{E: 65537}, wantErr: gojwt.ErrInvalidKey},
		{name: "too small modulus", publicKey: &rsa.PublicKey{N: big.NewInt(17), E: 65537}, wantErr: gojwt.ErrInvalidConfig},
		{name: "HMAC option", publicKey: &privateKey.PublicKey, opts: []gojwt.Option{gojwt.WithHMACSigningMethod(jwtv5.SigningMethodHS256)}, wantErr: gojwt.ErrInvalidConfig},
		{name: "non RSA algorithm", publicKey: &privateKey.PublicKey, opts: []gojwt.Option{gojwt.WithRSASigningMethod(jwtv5.SigningMethodEdDSA)}, wantErr: gojwt.ErrInvalidConfig},
		{name: "nil algorithm", publicKey: &privateKey.PublicKey, opts: []gojwt.Option{gojwt.WithRSASigningMethod(nil)}, wantErr: gojwt.ErrInvalidConfig},
		{name: "invalid options", publicKey: &privateKey.PublicKey, opts: []gojwt.Option{gojwt.WithTokenDuration(0)}, wantErr: gojwt.ErrInvalidConfig},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			verifier, err := gojwt.NewJwtRSAVerifier(tc.publicKey, tc.opts...)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, verifier)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, verifier)
		})
	}
}

func TestVerifierCapabilitiesRSAFromFile(t *testing.T) {
	t.Parallel()
	privateKey := capabilityRSAKey(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tests := []struct {
		name    string
		data    []byte
		wantErr error
	}{
		{name: "PKIX", data: capabilityPEM(t, "PUBLIC KEY", &privateKey.PublicKey)},
		{name: "PKCS1", data: pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)})},
		{name: "missing file", wantErr: fs.ErrNotExist},
		{name: "invalid PEM", data: []byte("not PEM"), wantErr: gojwt.ErrInvalidKey},
		{name: "invalid PKIX", data: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}}), wantErr: gojwt.ErrInvalidKey},
		{name: "invalid PKCS1", data: pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: []byte{1}}), wantErr: gojwt.ErrInvalidKey},
		{name: "unsupported block", data: pem.EncodeToMemory(&pem.Block{Type: "UNSUPPORTED", Bytes: []byte{1}}), wantErr: gojwt.ErrInvalidKey},
		{name: "other key type", data: capabilityPEM(t, "PUBLIC KEY", &otherKey.PublicKey), wantErr: gojwt.ErrInvalidKeyType},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "missing-public.pem")
			if tc.data != nil {
				path = capabilityKeyFile(t, "public.pem", tc.data)
			}
			verifier, err := gojwt.NewJwtRSAVerifierFromFile(path)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, verifier)
				return
			}
			require.NoError(t, err)
			issuer, err := gojwt.NewJwtRSAFromKeys(privateKey, &privateKey.PublicKey)
			require.NoError(t, err)
			token, err := issuer.GenerateToken(42)
			require.NoError(t, err)
			parsed, err := verifier.ParseTokenContext(t.Context(), token)
			require.NoError(t, err)
			require.Equal(t, int64(42), parsed.UserID)
		})
	}
}

func TestVerifierCapabilitiesRSACopiesPublicKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*rsa.PublicKey)
	}{
		{name: "modulus", mutate: func(key *rsa.PublicKey) { key.N.SetInt64(17) }},
		{name: "exponent", mutate: func(key *rsa.PublicKey) { key.E = 3 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			privateKey := capabilityRSAKey(t)
			issuer, err := gojwt.NewJwtRSAFromKeys(privateKey, &privateKey.PublicKey)
			require.NoError(t, err)
			verifier, err := gojwt.NewJwtRSAVerifier(&privateKey.PublicKey)
			require.NoError(t, err)
			tc.mutate(&privateKey.PublicKey)
			token, err := issuer.GenerateToken(42)
			require.NoError(t, err)
			parsed, err := verifier.ParseTokenContext(t.Context(), token)
			require.NoError(t, err)
			require.Equal(t, int64(42), parsed.UserID)
		})
	}
}

func TestVerifierCapabilitiesRSANoSigning(t *testing.T) {
	t.Parallel()
	privateKey := capabilityRSAKey(t)
	tests := []struct {
		name string
		call func(context.Context, *gojwt.JwtRSA) (string, error)
	}{
		{name: "generate", call: func(_ context.Context, j *gojwt.JwtRSA) (string, error) { return j.GenerateToken(42) }},
		{name: "refresh", call: func(_ context.Context, j *gojwt.JwtRSA) (string, error) { return j.RefreshToken("invalid") }},
		{name: "refresh context", call: func(ctx context.Context, j *gojwt.JwtRSA) (string, error) {
			return j.RefreshTokenContext(ctx, "invalid")
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			verifier, err := gojwt.NewJwtRSAVerifier(&privateKey.PublicKey)
			require.NoError(t, err)
			token, err := tc.call(t.Context(), verifier)
			require.ErrorIs(t, err, gojwt.ErrNoSigningKey)
			require.Empty(t, token)
		})
	}
}

func TestVerifierCapabilitiesRSAConcurrentVerification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		parse func(context.Context, *gojwt.JwtRSA, string) (*claims.Claims, error)
	}{
		{name: "normal", parse: func(ctx context.Context, j *gojwt.JwtRSA, token string) (*claims.Claims, error) {
			return j.ParseTokenContext(ctx, token)
		}},
		{name: "cached", parse: func(ctx context.Context, j *gojwt.JwtRSA, token string) (*claims.Claims, error) {
			return j.CachedParseTokenContext(ctx, token)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			privateKey := capabilityRSAKey(t)
			issuer, err := gojwt.NewJwtRSAFromKeys(privateKey, &privateKey.PublicKey)
			require.NoError(t, err)
			verifier, err := gojwt.NewJwtRSAVerifier(&privateKey.PublicKey)
			require.NoError(t, err)
			token, err := issuer.GenerateToken(42, claims.WithRoles("reader"))
			require.NoError(t, err)
			const workers = 12
			errs := make(chan error, workers)
			ctx := t.Context()
			var wg sync.WaitGroup
			for range workers {
				wg.Go(func() {
					for range 8 {
						parsed, err := tc.parse(ctx, verifier, token)
						if err != nil {
							errs <- err
							return
						}
						if parsed.UserID != 42 || len(parsed.Roles) != 1 || parsed.Roles[0] != "reader" {
							errs <- fmt.Errorf("claims changed during concurrent verification")
							return
						}
						parsed.Roles[0] = "changed"
					}
				})
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				require.NoError(t, err)
			}
		})
	}
}
