package gojwt_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

func capabilityEd25519Keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return publicKey, privateKey
}

func capabilityPEM(t *testing.T, blockType string, key any) []byte {
	t.Helper()
	var (
		der []byte
		err error
	)
	switch blockType {
	case "PRIVATE KEY":
		der, err = x509.MarshalPKCS8PrivateKey(key)
	case "PUBLIC KEY":
		der, err = x509.MarshalPKIXPublicKey(key)
	default:
		switch value := key.(type) {
		case ed25519.PrivateKey:
			der = value
		case ed25519.PublicKey:
			der = value
		case []byte:
			der = value
		default:
			t.Fatalf("unsupported test key type %T", key)
		}
	}
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func capabilityKeyFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func TestEd25519CapabilitiesFromKeys(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := capabilityEd25519Keys(t)
	otherPublicKey, _ := capabilityEd25519Keys(t)
	changedSeed := bytes.Clone(privateKey)
	changedSeed[0] ^= 1
	replacedTail := bytes.Clone(privateKey)
	copy(replacedTail[ed25519.SeedSize:], otherPublicKey)
	tests := []struct {
		name       string
		privateKey ed25519.PrivateKey
		publicKey  ed25519.PublicKey
		wantErr    error
	}{
		{name: "valid", privateKey: privateKey, publicKey: publicKey},
		{name: "nil private", publicKey: publicKey, wantErr: gojwt.ErrInvalidKey},
		{name: "empty private", privateKey: ed25519.PrivateKey{}, publicKey: publicKey, wantErr: gojwt.ErrInvalidKey},
		{name: "seed only", privateKey: privateKey[:ed25519.SeedSize], publicKey: publicKey, wantErr: gojwt.ErrInvalidKey},
		{name: "short private", privateKey: privateKey[:ed25519.PrivateKeySize-1], publicKey: publicKey, wantErr: gojwt.ErrInvalidKey},
		{name: "long private", privateKey: append(bytes.Clone(privateKey), 0), publicKey: publicKey, wantErr: gojwt.ErrInvalidKey},
		{name: "nil public", privateKey: privateKey, wantErr: gojwt.ErrInvalidKey},
		{name: "short public", privateKey: privateKey, publicKey: publicKey[:ed25519.PublicKeySize-1], wantErr: gojwt.ErrInvalidKey},
		{name: "long public", privateKey: privateKey, publicKey: append(bytes.Clone(publicKey), 0), wantErr: gojwt.ErrInvalidKey},
		{name: "changed seed", privateKey: changedSeed, publicKey: publicKey, wantErr: gojwt.ErrInvalidKey},
		{name: "replaced tail matches configured public", privateKey: replacedTail, publicKey: otherPublicKey, wantErr: gojwt.ErrInvalidKey},
		{name: "different configured public", privateKey: privateKey, publicKey: otherPublicKey, wantErr: gojwt.ErrInvalidKey},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			issuer, err := gojwt.NewJwtEd25519FromKeys(tc.privateKey, tc.publicKey)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, issuer)
				return
			}
			require.NoError(t, err)
			verifier, err := gojwt.NewJwtEd25519Verifier(tc.publicKey)
			require.NoError(t, err)
			token, err := issuer.GenerateToken(42)
			require.NoError(t, err)
			parsed, err := verifier.ParseTokenContext(t.Context(), token)
			require.NoError(t, err)
			require.Equal(t, int64(42), parsed.UserID)
		})
	}
}

func TestEd25519CapabilitiesVerifierConstruction(t *testing.T) {
	t.Parallel()
	publicKey, _ := capabilityEd25519Keys(t)
	tests := []struct {
		name      string
		publicKey ed25519.PublicKey
		opts      []gojwt.Option
		wantErr   error
	}{
		{name: "valid", publicKey: publicKey},
		{name: "nil public", wantErr: gojwt.ErrInvalidKey},
		{name: "empty public", publicKey: ed25519.PublicKey{}, wantErr: gojwt.ErrInvalidKey},
		{name: "short public", publicKey: publicKey[:ed25519.PublicKeySize-1], wantErr: gojwt.ErrInvalidKey},
		{name: "long public", publicKey: append(bytes.Clone(publicKey), 0), wantErr: gojwt.ErrInvalidKey},
		{name: "invalid option", publicKey: publicKey, opts: []gojwt.Option{gojwt.WithTokenDuration(0)}, wantErr: gojwt.ErrInvalidConfig},
		{name: "HMAC option", publicKey: publicKey, opts: []gojwt.Option{gojwt.WithHMACSigningMethod(jwtv5.SigningMethodHS256)}, wantErr: gojwt.ErrInvalidConfig},
		{name: "RSA option", publicKey: publicKey, opts: []gojwt.Option{gojwt.WithRSASigningMethod(jwtv5.SigningMethodRS256)}, wantErr: gojwt.ErrInvalidConfig},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			verifier, err := gojwt.NewJwtEd25519Verifier(tc.publicKey, tc.opts...)
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

func TestEd25519CapabilitiesPEMParsing(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := capabilityEd25519Keys(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tests := []struct {
		name    string
		private bool
		data    []byte
		want    []byte
		wantErr error
	}{
		{name: "PKCS8 private", private: true, data: capabilityPEM(t, "PRIVATE KEY", privateKey), want: privateKey},
		{name: "raw private", private: true, data: capabilityPEM(t, "ED25519 PRIVATE KEY", privateKey), want: privateKey},
		{name: "PKIX public", data: capabilityPEM(t, "PUBLIC KEY", publicKey), want: publicKey},
		{name: "raw public", data: capabilityPEM(t, "ED25519 PUBLIC KEY", publicKey), want: publicKey},
		{name: "nil private PEM", private: true, wantErr: gojwt.ErrInvalidKey},
		{name: "invalid public PEM", data: []byte("not PEM"), wantErr: gojwt.ErrInvalidKey},
		{name: "unsupported private block", private: true, data: capabilityPEM(t, "UNSUPPORTED", privateKey), wantErr: gojwt.ErrInvalidKey},
		{name: "unsupported public block", data: capabilityPEM(t, "UNSUPPORTED", publicKey), wantErr: gojwt.ErrInvalidKey},
		{name: "short raw private", private: true, data: capabilityPEM(t, "ED25519 PRIVATE KEY", privateKey[:ed25519.PrivateKeySize-1]), wantErr: gojwt.ErrInvalidKey},
		{name: "long raw private", private: true, data: capabilityPEM(t, "ED25519 PRIVATE KEY", append(bytes.Clone(privateKey), 0)), wantErr: gojwt.ErrInvalidKey},
		{name: "short raw public", data: capabilityPEM(t, "ED25519 PUBLIC KEY", publicKey[:ed25519.PublicKeySize-1]), wantErr: gojwt.ErrInvalidKey},
		{name: "long raw public", data: capabilityPEM(t, "ED25519 PUBLIC KEY", append(bytes.Clone(publicKey), 0)), wantErr: gojwt.ErrInvalidKey},
		{name: "invalid PKCS8", private: true, data: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), wantErr: gojwt.ErrInvalidKey},
		{name: "invalid PKIX", data: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2, 3}}), wantErr: gojwt.ErrInvalidKey},
		{name: "other private key type", private: true, data: capabilityPEM(t, "PRIVATE KEY", otherKey), wantErr: gojwt.ErrInvalidKeyType},
		{name: "other public key type", data: capabilityPEM(t, "PUBLIC KEY", &otherKey.PublicKey), wantErr: gojwt.ErrInvalidKeyType},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var got []byte
			var err error
			if tc.private {
				got, err = gojwt.ParseEd25519PrivateKeyPEM(tc.data)
			} else {
				got, err = gojwt.ParseEd25519PublicKeyPEM(tc.data)
			}
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestEd25519CapabilitiesFileConstruction(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := capabilityEd25519Keys(t)
	otherPublicKey, _ := capabilityEd25519Keys(t)
	replacedTail := bytes.Clone(privateKey)
	copy(replacedTail[ed25519.SeedSize:], otherPublicKey)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tests := []struct {
		name       string
		verifier   bool
		privatePEM []byte
		publicPEM  []byte
		wantErr    error
	}{
		{name: "PKCS8 PKIX pair", privatePEM: capabilityPEM(t, "PRIVATE KEY", privateKey), publicPEM: capabilityPEM(t, "PUBLIC KEY", publicKey)},
		{name: "raw pair", privatePEM: capabilityPEM(t, "ED25519 PRIVATE KEY", privateKey), publicPEM: capabilityPEM(t, "ED25519 PUBLIC KEY", publicKey)},
		{name: "PKIX verifier", verifier: true, publicPEM: capabilityPEM(t, "PUBLIC KEY", publicKey)},
		{name: "raw verifier", verifier: true, publicPEM: capabilityPEM(t, "ED25519 PUBLIC KEY", publicKey)},
		{name: "missing private file", publicPEM: capabilityPEM(t, "PUBLIC KEY", publicKey), wantErr: fs.ErrNotExist},
		{name: "missing pair public file", privatePEM: capabilityPEM(t, "PRIVATE KEY", privateKey), wantErr: fs.ErrNotExist},
		{name: "missing verifier public file", verifier: true, wantErr: fs.ErrNotExist},
		{name: "invalid private PEM", privatePEM: []byte("invalid"), publicPEM: capabilityPEM(t, "PUBLIC KEY", publicKey), wantErr: gojwt.ErrInvalidKey},
		{name: "invalid verifier PEM", verifier: true, publicPEM: []byte("invalid"), wantErr: gojwt.ErrInvalidKey},
		{name: "wrong private type", privatePEM: capabilityPEM(t, "PRIVATE KEY", otherKey), publicPEM: capabilityPEM(t, "PUBLIC KEY", publicKey), wantErr: gojwt.ErrInvalidKeyType},
		{name: "wrong pair public type", privatePEM: capabilityPEM(t, "PRIVATE KEY", privateKey), publicPEM: capabilityPEM(t, "PUBLIC KEY", &otherKey.PublicKey), wantErr: gojwt.ErrInvalidKeyType},
		{name: "wrong verifier public type", verifier: true, publicPEM: capabilityPEM(t, "PUBLIC KEY", &otherKey.PublicKey), wantErr: gojwt.ErrInvalidKeyType},
		{name: "inconsistent raw private", privatePEM: capabilityPEM(t, "ED25519 PRIVATE KEY", ed25519.PrivateKey(replacedTail)), publicPEM: capabilityPEM(t, "PUBLIC KEY", otherPublicKey), wantErr: gojwt.ErrInvalidKey},
		{name: "mismatched pair", privatePEM: capabilityPEM(t, "PRIVATE KEY", privateKey), publicPEM: capabilityPEM(t, "PUBLIC KEY", otherPublicKey), wantErr: gojwt.ErrInvalidKey},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			privatePath := filepath.Join(t.TempDir(), "missing-private.pem")
			publicPath := filepath.Join(t.TempDir(), "missing-public.pem")
			if tc.privatePEM != nil {
				privatePath = capabilityKeyFile(t, "private.pem", tc.privatePEM)
			}
			if tc.publicPEM != nil {
				publicPath = capabilityKeyFile(t, "public.pem", tc.publicPEM)
			}
			var instance *gojwt.JwtEd25519
			var err error
			if tc.verifier {
				instance, err = gojwt.NewJwtEd25519VerifierFromFile(publicPath)
			} else {
				instance, err = gojwt.NewJwtEd25519(privatePath, publicPath)
			}
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, instance)
				return
			}
			require.NoError(t, err)
			issuer, err := gojwt.NewJwtEd25519FromKeys(privateKey, publicKey)
			require.NoError(t, err)
			token, err := issuer.GenerateToken(42)
			require.NoError(t, err)
			parsed, err := instance.ParseTokenContext(t.Context(), token)
			require.NoError(t, err)
			require.Equal(t, int64(42), parsed.UserID)
		})
	}
}

func TestEd25519CapabilitiesCopyKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		verifier bool
	}{
		{name: "signing pair"},
		{name: "public only", verifier: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			publicKey, privateKey := capabilityEd25519Keys(t)
			issuer, err := gojwt.NewJwtEd25519FromKeys(privateKey, publicKey)
			require.NoError(t, err)
			verifier, err := gojwt.NewJwtEd25519Verifier(publicKey)
			require.NoError(t, err)
			clear(privateKey)
			clear(publicKey)
			token, err := issuer.GenerateToken(42)
			require.NoError(t, err)
			instance := issuer
			if tc.verifier {
				instance = verifier
			}
			parsed, err := instance.ParseTokenContext(t.Context(), token)
			require.NoError(t, err)
			require.Equal(t, int64(42), parsed.UserID)
		})
	}
}

func TestEd25519CapabilitiesVerifierNoSigning(t *testing.T) {
	t.Parallel()
	publicKey, _ := capabilityEd25519Keys(t)
	tests := []struct {
		name string
		call func(context.Context, *gojwt.JwtEd25519) (string, error)
	}{
		{name: "generate", call: func(_ context.Context, j *gojwt.JwtEd25519) (string, error) { return j.GenerateToken(42) }},
		{name: "refresh", call: func(_ context.Context, j *gojwt.JwtEd25519) (string, error) { return j.RefreshToken("invalid") }},
		{name: "refresh context", call: func(ctx context.Context, j *gojwt.JwtEd25519) (string, error) {
			return j.RefreshTokenContext(ctx, "invalid")
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			verifier, err := gojwt.NewJwtEd25519Verifier(publicKey)
			require.NoError(t, err)
			token, err := tc.call(t.Context(), verifier)
			require.ErrorIs(t, err, gojwt.ErrNoSigningKey)
			require.Empty(t, token)
		})
	}
}

func TestEd25519CapabilitiesVerifierRejectsInvalidTokens(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := capabilityEd25519Keys(t)
	otherPublicKey, otherPrivateKey := capabilityEd25519Keys(t)
	issuer, err := gojwt.NewJwtEd25519FromKeys(privateKey, publicKey)
	require.NoError(t, err)
	otherIssuer, err := gojwt.NewJwtEd25519FromKeys(otherPrivateKey, otherPublicKey)
	require.NoError(t, err)
	token, err := issuer.GenerateToken(42)
	require.NoError(t, err)
	wrongSignature, err := otherIssuer.GenerateToken(42)
	require.NoError(t, err)
	tests := []struct {
		name     string
		token    string
		canceled bool
		wantErr  error
	}{
		{name: "valid", token: token},
		{name: "different signer", token: wrongSignature, wantErr: gojwt.ErrTokenSignatureInvalid},
		{name: "malformed", token: "invalid", wantErr: gojwt.ErrTokenMalformed},
		{name: "empty", wantErr: gojwt.ErrTokenMalformed},
		{name: "canceled", token: token, canceled: true, wantErr: context.Canceled},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			verifier, err := gojwt.NewJwtEd25519Verifier(publicKey)
			require.NoError(t, err)
			ctx := t.Context()
			if tc.canceled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			parsers := []struct {
				name  string
				parse func(context.Context, string, ...jwtv5.ParserOption) (*claims.Claims, error)
			}{
				{name: "normal", parse: verifier.ParseTokenContext},
				{name: "cached", parse: verifier.CachedParseTokenContext},
			}
			for _, parser := range parsers {
				t.Run(parser.name, func(t *testing.T) {
					parsed, err := parser.parse(ctx, tc.token)
					if tc.wantErr != nil {
						require.ErrorIs(t, err, tc.wantErr)
						require.Nil(t, parsed)
						return
					}
					require.NoError(t, err)
					require.Equal(t, int64(42), parsed.UserID)
				})
			}
		})
	}
}

func TestEd25519CapabilitiesConcurrentVerification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		parse func(context.Context, *gojwt.JwtEd25519, string) (*claims.Claims, error)
	}{
		{name: "normal", parse: func(ctx context.Context, j *gojwt.JwtEd25519, token string) (*claims.Claims, error) {
			return j.ParseTokenContext(ctx, token)
		}},
		{name: "cached", parse: func(ctx context.Context, j *gojwt.JwtEd25519, token string) (*claims.Claims, error) {
			return j.CachedParseTokenContext(ctx, token)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			publicKey, privateKey := capabilityEd25519Keys(t)
			issuer, err := gojwt.NewJwtEd25519FromKeys(privateKey, publicKey)
			require.NoError(t, err)
			verifier, err := gojwt.NewJwtEd25519Verifier(publicKey)
			require.NoError(t, err)
			token, err := issuer.GenerateToken(42, claims.WithRoles("reader"))
			require.NoError(t, err)
			const workers = 24
			errs := make(chan error, workers)
			ctx := t.Context()
			var wg sync.WaitGroup
			for range workers {
				wg.Go(func() {
					for range 12 {
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
			results, failures := verifier.ParallelVerifyContext(ctx, []string{token, "invalid", token})
			require.Len(t, results, 3)
			require.Len(t, failures, 3)
			require.NoError(t, failures[0])
			require.NoError(t, failures[2])
			require.ErrorIs(t, failures[1], gojwt.ErrTokenMalformed)
			require.Nil(t, results[1])
			require.Equal(t, int64(42), results[0].UserID)
			require.Equal(t, int64(42), results[2].UserID)
		})
	}
}
