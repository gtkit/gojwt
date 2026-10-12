package gojwt_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"path/filepath"
	"sync"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

func capabilityECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return key
}

func TestECDSACapabilitiesAlgorithmsAndMethods(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		curve  elliptic.Curve
		method *jwtv5.SigningMethodECDSA
	}{
		{name: "ES256", curve: elliptic.P256(), method: jwtv5.SigningMethodES256},
		{name: "ES384", curve: elliptic.P384(), method: jwtv5.SigningMethodES384},
		{name: "ES512", curve: elliptic.P521(), method: jwtv5.SigningMethodES512},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := capabilityECDSAKey(t, tc.curve)
			issuer, err := gojwt.NewJwtECDSAFromKeys(key, &key.PublicKey,
				gojwt.WithECDSASigningMethod(tc.method), gojwt.WithKeyID("ec-key"),
				gojwt.WithTokenDuration(time.Minute), gojwt.WithRefreshDuration(time.Hour))
			require.NoError(t, err)
			verifier, err := gojwt.NewJwtECDSAVerifier(&key.PublicKey, gojwt.WithECDSASigningMethod(tc.method))
			require.NoError(t, err)
			var _ gojwt.Tokener = issuer
			var _ gojwt.ContextTokener = issuer
			var _ gojwt.Verifier = verifier
			var _ gojwt.Issuer = issuer
			token, err := issuer.GenerateToken(42, claims.WithIssuer("auth"), claims.WithAudience("api"))
			require.NoError(t, err)
			unverified, _, err := jwtv5.NewParser().ParseUnverified(token, &claims.Claims{})
			require.NoError(t, err)
			require.Equal(t, tc.name, unverified.Method.Alg())
			require.Equal(t, "ec-key", unverified.Header["kid"])
			ctx := t.Context()
			parsers := []struct {
				name  string
				parse func() (*claims.Claims, error)
			}{
				{name: "normal", parse: func() (*claims.Claims, error) { return verifier.ParseToken(token) }},
				{name: "context", parse: func() (*claims.Claims, error) { return verifier.ParseTokenContext(ctx, token) }},
				{name: "cached", parse: func() (*claims.Claims, error) { return verifier.CachedParseToken(token) }},
				{name: "cached context", parse: func() (*claims.Claims, error) { return verifier.CachedParseTokenContext(ctx, token) }},
			}
			for _, parser := range parsers {
				t.Run(parser.name, func(t *testing.T) {
					parsed, err := parser.parse()
					require.NoError(t, err)
					require.Equal(t, int64(42), parsed.UserID)
				})
			}
			for _, parallel := range []struct {
				name   string
				verify func() ([]*claims.Claims, []error)
			}{
				{name: "parallel", verify: func() ([]*claims.Claims, []error) { return verifier.ParallelVerify([]string{token, "invalid", token}) }},
				{name: "parallel context", verify: func() ([]*claims.Claims, []error) {
					return verifier.ParallelVerifyContext(ctx, []string{token, "invalid", token})
				}},
			} {
				t.Run(parallel.name, func(t *testing.T) {
					results, errs := parallel.verify()
					require.Len(t, results, 3)
					require.Len(t, errs, 3)
					require.NoError(t, errs[0])
					require.ErrorIs(t, errs[1], gojwt.ErrTokenMalformed)
					require.Nil(t, results[1])
					require.NoError(t, errs[2])
				})
			}
			for _, refresh := range []struct {
				name string
				call func() (string, error)
			}{
				{name: "refresh", call: func() (string, error) { return issuer.RefreshToken(token) }},
				{name: "refresh context", call: func() (string, error) { return issuer.RefreshTokenContext(ctx, token) }},
			} {
				t.Run(refresh.name, func(t *testing.T) {
					refreshed, err := refresh.call()
					require.NoError(t, err)
					parsed, err := verifier.ParseToken(refreshed)
					require.NoError(t, err)
					require.Equal(t, int64(42), parsed.UserID)
					require.NotEqual(t, token, refreshed)
				})
			}
		})
	}
}

func TestECDSACapabilitiesKeyDomain(t *testing.T) {
	t.Parallel()
	key := capabilityECDSAKey(t, elliptic.P256())
	other := capabilityECDSAKey(t, elliptic.P256())
	p384 := capabilityECDSAKey(t, elliptic.P384())
	p224 := capabilityECDSAKey(t, elliptic.P224())
	publicBytes, err := key.PublicKey.Bytes()
	require.NoError(t, err)
	x := new(big.Int).SetBytes(publicBytes[1:33])
	y := new(big.Int).SetBytes(publicBytes[33:])
	privateBytes, err := key.Bytes()
	require.NoError(t, err)
	d := new(big.Int).SetBytes(privateBytes)
	otherPrivateBytes, err := other.Bytes()
	require.NoError(t, err)
	tests := []struct {
		name    string
		private *ecdsa.PrivateKey
		public  *ecdsa.PublicKey
		wantErr error
	}{
		{name: "valid", private: key, public: &key.PublicKey},
		{name: "nil private", public: &key.PublicKey, wantErr: gojwt.ErrInvalidKey},
		{name: "nil public", private: key, wantErr: gojwt.ErrInvalidKey},
		{name: "nil curve", private: key, public: &ecdsa.PublicKey{X: x, Y: y}, wantErr: gojwt.ErrInvalidKey},                                                 //nolint:staticcheck // Malformed caller keys cannot be constructed with the validating standard parsers.
		{name: "nil X", private: key, public: &ecdsa.PublicKey{Curve: key.Curve, Y: y}, wantErr: gojwt.ErrInvalidKey},                                         //nolint:staticcheck // Malformed caller keys cannot be constructed with the validating standard parsers.
		{name: "nil Y", private: key, public: &ecdsa.PublicKey{Curve: key.Curve, X: x}, wantErr: gojwt.ErrInvalidKey},                                         //nolint:staticcheck // Malformed caller keys cannot be constructed with the validating standard parsers.
		{name: "negative X", private: key, public: &ecdsa.PublicKey{Curve: key.Curve, X: new(big.Int).Neg(x), Y: y}, wantErr: gojwt.ErrInvalidKey},            //nolint:staticcheck // Malformed caller keys cannot be constructed with the validating standard parsers.
		{name: "point at infinity", private: key, public: &ecdsa.PublicKey{Curve: key.Curve, X: new(big.Int), Y: new(big.Int)}, wantErr: gojwt.ErrInvalidKey}, //nolint:staticcheck // Malformed caller keys cannot be constructed with the validating standard parsers.
		{name: "out of field X", private: key, public: &ecdsa.PublicKey{Curve: key.Curve, X: key.Curve.Params().P, Y: y}, wantErr: gojwt.ErrInvalidKey},       //nolint:staticcheck // Malformed caller keys cannot be constructed with the validating standard parsers.
		{name: "unsupported curve", private: p224, public: &p224.PublicKey, wantErr: gojwt.ErrInvalidKey},
		{name: "wrong curve for algorithm", private: p384, public: &p384.PublicKey, wantErr: gojwt.ErrInvalidKey},
		{name: "mismatched public", private: key, public: &other.PublicKey, wantErr: gojwt.ErrInvalidKey},
		{name: "nil scalar", private: &ecdsa.PrivateKey{PublicKey: key.PublicKey}, public: &key.PublicKey, wantErr: gojwt.ErrInvalidKey},
		{name: "zero scalar", private: &ecdsa.PrivateKey{PublicKey: key.PublicKey, D: new(big.Int)}, public: &key.PublicKey, wantErr: gojwt.ErrInvalidKey},                                                             //nolint:staticcheck // Malformed caller keys cannot be constructed with the validating standard parsers.
		{name: "negative scalar", private: &ecdsa.PrivateKey{PublicKey: key.PublicKey, D: new(big.Int).Neg(d)}, public: &key.PublicKey, wantErr: gojwt.ErrInvalidKey},                                                  //nolint:staticcheck // Malformed caller keys cannot be constructed with the validating standard parsers.
		{name: "scalar equals order", private: &ecdsa.PrivateKey{PublicKey: key.PublicKey, D: key.Curve.Params().N}, public: &key.PublicKey, wantErr: gojwt.ErrInvalidKey},                                             //nolint:staticcheck // Malformed caller keys cannot be constructed with the validating standard parsers.
		{name: "scalar disagrees with point", private: &ecdsa.PrivateKey{PublicKey: key.PublicKey, D: new(big.Int).SetBytes(otherPrivateBytes)}, public: &key.PublicKey, wantErr: gojwt.ErrInvalidKey},                 //nolint:staticcheck // Malformed caller keys cannot be constructed with the validating standard parsers.
		{name: "private invalid public point", private: &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: key.Curve, X: new(big.Int), Y: new(big.Int)}, D: d}, public: &key.PublicKey, wantErr: gojwt.ErrInvalidKey}, //nolint:staticcheck // Malformed caller keys cannot be constructed with the validating standard parsers.
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			j, err := gojwt.NewJwtECDSAFromKeys(tc.private, tc.public)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, j)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, j)
		})
	}
}

func TestECDSACapabilitiesMethodOptions(t *testing.T) {
	t.Parallel()
	key := capabilityECDSAKey(t, elliptic.P256())
	tests := []struct {
		name    string
		opts    []gojwt.Option
		wantErr error
	}{
		{name: "default ES256"},
		{name: "nil method", opts: []gojwt.Option{gojwt.WithECDSASigningMethod(nil)}, wantErr: gojwt.ErrInvalidConfig},
		{name: "unsupported method", opts: []gojwt.Option{gojwt.WithECDSASigningMethod(&jwtv5.SigningMethodECDSA{Name: "ES224"})}, wantErr: gojwt.ErrInvalidConfig},
		{name: "wrong hash", opts: []gojwt.Option{gojwt.WithECDSASigningMethod(&jwtv5.SigningMethodECDSA{Name: "ES256", Hash: crypto.SHA512, KeySize: 32, CurveBits: 256})}, wantErr: gojwt.ErrInvalidConfig},
		{name: "wrong key width", opts: []gojwt.Option{gojwt.WithECDSASigningMethod(&jwtv5.SigningMethodECDSA{Name: "ES256", Hash: crypto.SHA256, KeySize: 31, CurveBits: 256})}, wantErr: gojwt.ErrInvalidConfig},
		{name: "wrong curve width", opts: []gojwt.Option{gojwt.WithECDSASigningMethod(&jwtv5.SigningMethodECDSA{Name: "ES256", Hash: crypto.SHA256, KeySize: 32, CurveBits: 255})}, wantErr: gojwt.ErrInvalidConfig},
		{name: "HMAC option", opts: []gojwt.Option{gojwt.WithHMACSigningMethod(jwtv5.SigningMethodHS256)}, wantErr: gojwt.ErrInvalidConfig},
		{name: "RSA option", opts: []gojwt.Option{gojwt.WithRSASigningMethod(jwtv5.SigningMethodRS256)}, wantErr: gojwt.ErrInvalidConfig},
		{name: "invalid duration", opts: []gojwt.Option{gojwt.WithTokenDuration(0)}, wantErr: gojwt.ErrInvalidConfig},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			j, err := gojwt.NewJwtECDSAVerifier(&key.PublicKey, tc.opts...)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, j)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, j)
		})
	}
}

func TestECDSACapabilitiesFilesAndPEM(t *testing.T) {
	t.Parallel()
	key := capabilityECDSAKey(t, elliptic.P256())
	_, edPrivate := capabilityEd25519Keys(t)
	sec1, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	privatePEM := capabilityPEM(t, "PRIVATE KEY", key)
	publicPEM := capabilityPEM(t, "PUBLIC KEY", &key.PublicKey)
	tests := []struct {
		name       string
		privatePEM []byte
		publicPEM  []byte
		verifier   bool
		wantErr    error
	}{
		{name: "PKCS8 pair", privatePEM: privatePEM, publicPEM: publicPEM},
		{name: "SEC1 pair", privatePEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}), publicPEM: publicPEM},
		{name: "public only", publicPEM: publicPEM, verifier: true},
		{name: "missing private", publicPEM: publicPEM, wantErr: fs.ErrNotExist},
		{name: "missing pair public", privatePEM: privatePEM, wantErr: fs.ErrNotExist},
		{name: "missing verifier public", verifier: true, wantErr: fs.ErrNotExist},
		{name: "private non PEM", privatePEM: []byte("invalid"), publicPEM: publicPEM, wantErr: gojwt.ErrInvalidKey},
		{name: "public non PEM", publicPEM: []byte("invalid"), verifier: true, wantErr: gojwt.ErrInvalidKey},
		{name: "private wrong type", privatePEM: capabilityPEM(t, "PRIVATE KEY", edPrivate), publicPEM: publicPEM, wantErr: gojwt.ErrInvalidKeyType},
		{name: "public wrong type", publicPEM: capabilityPEM(t, "PUBLIC KEY", edPrivate.Public()), verifier: true, wantErr: gojwt.ErrInvalidKeyType},
		{name: "private wrong block", privatePEM: pem.EncodeToMemory(&pem.Block{Type: "UNSUPPORTED", Bytes: sec1}), publicPEM: publicPEM, wantErr: gojwt.ErrInvalidKey},
		{name: "public wrong block", publicPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PUBLIC KEY", Bytes: sec1}), verifier: true, wantErr: gojwt.ErrInvalidKey},
		{name: "malformed SEC1", privatePEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}}), publicPEM: publicPEM, wantErr: gojwt.ErrInvalidKey},
		{name: "malformed PKCS8", privatePEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), publicPEM: publicPEM, wantErr: gojwt.ErrInvalidKey},
		{name: "malformed PKIX", publicPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}}), verifier: true, wantErr: gojwt.ErrInvalidKey},
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
			var j *gojwt.JwtECDSA
			var err error
			if tc.verifier {
				j, err = gojwt.NewJwtECDSAVerifierFromFile(publicPath)
			} else {
				j, err = gojwt.NewJwtECDSA(privatePath, publicPath)
			}
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, j)
				return
			}
			require.NoError(t, err)
			issuer, err := gojwt.NewJwtECDSAFromKeys(key, &key.PublicKey)
			require.NoError(t, err)
			token, err := issuer.GenerateToken(42)
			require.NoError(t, err)
			parsed, err := j.ParseTokenContext(t.Context(), token)
			require.NoError(t, err)
			require.Equal(t, int64(42), parsed.UserID)
			public, err := gojwt.ParseECDSAPublicKeyPEM(tc.publicPEM)
			require.NoError(t, err)
			require.True(t, public.Equal(&key.PublicKey))
			if !tc.verifier {
				private, err := gojwt.ParseECDSAPrivateKeyPEM(tc.privatePEM)
				require.NoError(t, err)
				require.True(t, private.Equal(key))
			}
		})
	}
}

func TestECDSACapabilitiesPEMCurves(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		curve  elliptic.Curve
		method *jwtv5.SigningMethodECDSA
	}{
		{name: "ES256", curve: elliptic.P256(), method: jwtv5.SigningMethodES256},
		{name: "ES384", curve: elliptic.P384(), method: jwtv5.SigningMethodES384},
		{name: "ES512", curve: elliptic.P521(), method: jwtv5.SigningMethodES512},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := capabilityECDSAKey(t, tc.curve)
			sec1, err := x509.MarshalECPrivateKey(key)
			require.NoError(t, err)
			formats := []struct {
				name string
				data []byte
			}{
				{name: "PKCS8", data: capabilityPEM(t, "PRIVATE KEY", key)},
				{name: "SEC1", data: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})},
			}
			publicPath := capabilityKeyFile(t, "public.pem", capabilityPEM(t, "PUBLIC KEY", &key.PublicKey))
			verifier, err := gojwt.NewJwtECDSAVerifierFromFile(publicPath, gojwt.WithECDSASigningMethod(tc.method))
			require.NoError(t, err)
			for _, format := range formats {
				t.Run(format.name, func(t *testing.T) {
					privatePath := capabilityKeyFile(t, "private.pem", format.data)
					issuer, err := gojwt.NewJwtECDSA(privatePath, publicPath, gojwt.WithECDSASigningMethod(tc.method))
					require.NoError(t, err)
					token, err := issuer.GenerateToken(42)
					require.NoError(t, err)
					parsed, err := verifier.ParseTokenContext(t.Context(), token)
					require.NoError(t, err)
					require.Equal(t, int64(42), parsed.UserID)
				})
			}
		})
	}
}

func TestECDSACapabilitiesCopyInputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*ecdsa.PrivateKey, *jwtv5.SigningMethodECDSA)
	}{
		{name: "public X", mutate: func(k *ecdsa.PrivateKey, _ *jwtv5.SigningMethodECDSA) { k.X.SetInt64(0) }},  //nolint:staticcheck // Deliberately mutate caller key material to disprove aliasing after construction.
		{name: "public Y", mutate: func(k *ecdsa.PrivateKey, _ *jwtv5.SigningMethodECDSA) { k.Y.SetInt64(0) }},  //nolint:staticcheck // Deliberately mutate caller key material to disprove aliasing after construction.
		{name: "private D", mutate: func(k *ecdsa.PrivateKey, _ *jwtv5.SigningMethodECDSA) { k.D.SetInt64(0) }}, //nolint:staticcheck // Deliberately mutate caller key material to disprove aliasing after construction.
		{name: "curve field", mutate: func(k *ecdsa.PrivateKey, _ *jwtv5.SigningMethodECDSA) { k.Curve = elliptic.P384() }},
		{name: "signing method", mutate: func(_ *ecdsa.PrivateKey, m *jwtv5.SigningMethodECDSA) { m.Name = "ES512"; m.Hash = crypto.SHA512 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := capabilityECDSAKey(t, elliptic.P256())
			method := *jwtv5.SigningMethodES256
			issuer, err := gojwt.NewJwtECDSAFromKeys(key, &key.PublicKey, gojwt.WithECDSASigningMethod(&method))
			require.NoError(t, err)
			verifier, err := gojwt.NewJwtECDSAVerifier(&key.PublicKey, gojwt.WithECDSASigningMethod(&method))
			require.NoError(t, err)
			tc.mutate(key, &method)
			token, err := issuer.GenerateToken(42)
			require.NoError(t, err)
			parsed, err := verifier.ParseTokenContext(t.Context(), token)
			require.NoError(t, err)
			require.Equal(t, int64(42), parsed.UserID)
		})
	}
}

func TestECDSACapabilitiesVerifierErrors(t *testing.T) {
	t.Parallel()
	key := capabilityECDSAKey(t, elliptic.P256())
	other := capabilityECDSAKey(t, elliptic.P256())
	issuer, err := gojwt.NewJwtECDSAFromKeys(key, &key.PublicKey)
	require.NoError(t, err)
	otherIssuer, err := gojwt.NewJwtECDSAFromKeys(other, &other.PublicKey)
	require.NoError(t, err)
	token, err := issuer.GenerateToken(42)
	require.NoError(t, err)
	wrongSignature, err := otherIssuer.GenerateToken(42)
	require.NoError(t, err)
	tests := []struct {
		name    string
		token   string
		cancel  bool
		wantErr error
	}{
		{name: "valid", token: token},
		{name: "wrong signer", token: wrongSignature, wantErr: gojwt.ErrTokenSignatureInvalid},
		{name: "malformed", token: "invalid", wantErr: gojwt.ErrTokenMalformed},
		{name: "empty", wantErr: gojwt.ErrTokenMalformed},
		{name: "canceled", token: token, cancel: true, wantErr: context.Canceled},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			verifier, err := gojwt.NewJwtECDSAVerifier(&key.PublicKey)
			require.NoError(t, err)
			ctx := t.Context()
			if tc.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			parsed, err := verifier.ParseTokenContext(ctx, tc.token)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, parsed)
				return
			}
			require.NoError(t, err)
			require.Equal(t, int64(42), parsed.UserID)
		})
	}
}

func TestECDSACapabilitiesNilAndNoSigning(t *testing.T) {
	t.Parallel()
	key := capabilityECDSAKey(t, elliptic.P256())
	verifier, err := gojwt.NewJwtECDSAVerifier(&key.PublicKey)
	require.NoError(t, err)
	tests := []struct {
		name string
		call func(context.Context, *gojwt.JwtECDSA) error
	}{
		{name: "generate", call: func(_ context.Context, j *gojwt.JwtECDSA) error { _, err := j.GenerateToken(42); return err }},
		{name: "refresh", call: func(_ context.Context, j *gojwt.JwtECDSA) error { _, err := j.RefreshToken("invalid"); return err }},
		{name: "refresh context", call: func(ctx context.Context, j *gojwt.JwtECDSA) error {
			_, err := j.RefreshTokenContext(ctx, "invalid")
			return err
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.ErrorIs(t, tc.call(t.Context(), verifier), gojwt.ErrNoSigningKey)
			require.ErrorIs(t, tc.call(t.Context(), nil), gojwt.ErrJWTNotInit)
		})
	}
	parsers := []struct {
		name string
		call func(context.Context, *gojwt.JwtECDSA) error
	}{
		{name: "parse", call: func(_ context.Context, j *gojwt.JwtECDSA) error { _, err := j.ParseToken("invalid"); return err }},
		{name: "parse context", call: func(ctx context.Context, j *gojwt.JwtECDSA) error {
			_, err := j.ParseTokenContext(ctx, "invalid")
			return err
		}},
		{name: "cached", call: func(_ context.Context, j *gojwt.JwtECDSA) error { _, err := j.CachedParseToken("invalid"); return err }},
		{name: "cached context", call: func(ctx context.Context, j *gojwt.JwtECDSA) error {
			_, err := j.CachedParseTokenContext(ctx, "invalid")
			return err
		}},
		{name: "parallel", call: func(_ context.Context, j *gojwt.JwtECDSA) error {
			_, errs := j.ParallelVerify([]string{"invalid"})
			return errs[0]
		}},
		{name: "parallel context", call: func(ctx context.Context, j *gojwt.JwtECDSA) error {
			_, errs := j.ParallelVerifyContext(ctx, []string{"invalid"})
			return errs[0]
		}},
	}
	for _, tc := range parsers {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.ErrorIs(t, tc.call(t.Context(), nil), gojwt.ErrJWTNotInit)
		})
	}
}

func TestECDSACapabilitiesConcurrentVerification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		call func(context.Context, *gojwt.JwtECDSA, string) (*claims.Claims, error)
	}{
		{name: "normal", call: func(ctx context.Context, j *gojwt.JwtECDSA, token string) (*claims.Claims, error) {
			return j.ParseTokenContext(ctx, token)
		}},
		{name: "cached", call: func(ctx context.Context, j *gojwt.JwtECDSA, token string) (*claims.Claims, error) {
			return j.CachedParseTokenContext(ctx, token)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := capabilityECDSAKey(t, elliptic.P256())
			issuer, err := gojwt.NewJwtECDSAFromKeys(key, &key.PublicKey)
			require.NoError(t, err)
			verifier, err := gojwt.NewJwtECDSAVerifier(&key.PublicKey)
			require.NoError(t, err)
			token, err := issuer.GenerateToken(42, claims.WithRoles("reader"))
			require.NoError(t, err)
			const workers = 16
			errs := make(chan error, workers)
			ctx := t.Context()
			var wg sync.WaitGroup
			for range workers {
				wg.Go(func() {
					for range 8 {
						parsed, err := tc.call(ctx, verifier, token)
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
