package gojwt_test

import (
	"crypto/elliptic"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/stretchr/testify/require"
)

func TestGenerateECDSAKeysAlgorithmsAndPermissions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		algorithm string
		curve     elliptic.Curve
		method    *jwtv5.SigningMethodECDSA
	}{
		{name: "default", curve: elliptic.P256(), method: jwtv5.SigningMethodES256},
		{name: "ES256", algorithm: "ES256", curve: elliptic.P256(), method: jwtv5.SigningMethodES256},
		{name: "ES384", algorithm: "ES384", curve: elliptic.P384(), method: jwtv5.SigningMethodES384},
		{name: "ES512", algorithm: "ES512", curve: elliptic.P521(), method: jwtv5.SigningMethodES512},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			privatePath := filepath.Join(dir, "private", "key.pem")
			publicPath := filepath.Join(dir, "public", "key.pem")
			require.NoError(t, gojwt.GenerateECDSAKeys(privatePath, publicPath, tc.algorithm))
			for _, file := range []struct {
				name string
				path string
				mode fs.FileMode
			}{
				{name: "private", path: privatePath, mode: 0o600},
				{name: "public", path: publicPath, mode: 0o644},
			} {
				t.Run(file.name, func(t *testing.T) {
					info, err := os.Stat(file.path)
					require.NoError(t, err)
					require.Equal(t, file.mode, info.Mode().Perm())
				})
			}
			privatePEM, err := os.ReadFile(privatePath)
			require.NoError(t, err)
			privateBlock, _ := pem.Decode(privatePEM)
			require.NotNil(t, privateBlock)
			require.Equal(t, "PRIVATE KEY", privateBlock.Type)
			privateKey, err := gojwt.ParseECDSAPrivateKeyPEM(privatePEM)
			require.NoError(t, err)
			require.Equal(t, tc.curve, privateKey.Curve)
			publicPEM, err := os.ReadFile(publicPath)
			require.NoError(t, err)
			publicBlock, _ := pem.Decode(publicPEM)
			require.NotNil(t, publicBlock)
			require.Equal(t, "PUBLIC KEY", publicBlock.Type)
			publicKey, err := gojwt.ParseECDSAPublicKeyPEM(publicPEM)
			require.NoError(t, err)
			require.True(t, privateKey.PublicKey.Equal(publicKey))
			issuer, err := gojwt.NewJwtECDSA(privatePath, publicPath, gojwt.WithECDSASigningMethod(tc.method))
			require.NoError(t, err)
			verifier, err := gojwt.NewJwtECDSAVerifierFromFile(publicPath, gojwt.WithECDSASigningMethod(tc.method))
			require.NoError(t, err)
			token, err := issuer.GenerateToken(42)
			require.NoError(t, err)
			parsed, err := verifier.ParseTokenContext(t.Context(), token)
			require.NoError(t, err)
			require.Equal(t, int64(42), parsed.UserID)
		})
	}
}

func TestGenerateECDSAKeysRejectsInvalidAlgorithm(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		algorithm string
	}{
		{name: "unsupported", algorithm: "ES224"},
		{name: "another key family", algorithm: "RS256"},
		{name: "wrong case", algorithm: "es256"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			privatePath := filepath.Join(dir, "private.pem")
			publicPath := filepath.Join(dir, "public.pem")
			require.ErrorIs(t, gojwt.GenerateECDSAKeys(privatePath, publicPath, tc.algorithm), gojwt.ErrInvalidConfig)
			for _, path := range []string{privatePath, publicPath} {
				_, err := os.Stat(path)
				require.ErrorIs(t, err, fs.ErrNotExist)
			}
		})
	}
}

func TestGenerateECDSAKeysPreservesFilesAndRollsBack(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		privateConflict bool
		publicConflict  bool
	}{
		{name: "private already exists", privateConflict: true},
		{name: "second file conflicts", publicConflict: true},
		{name: "both already exist", privateConflict: true, publicConflict: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			privatePath := filepath.Join(dir, "private.pem")
			publicPath := filepath.Join(dir, "public.pem")
			original := []byte("original test contents")
			if tc.privateConflict {
				require.NoError(t, os.WriteFile(privatePath, original, 0o600))
			}
			if tc.publicConflict {
				require.NoError(t, os.WriteFile(publicPath, original, 0o644))
			}
			require.ErrorIs(t, gojwt.GenerateECDSAKeys(privatePath, publicPath, "ES256"), fs.ErrExist)
			for _, file := range []struct {
				name     string
				path     string
				existing bool
			}{
				{name: "private", path: privatePath, existing: tc.privateConflict},
				{name: "public", path: publicPath, existing: tc.publicConflict},
			} {
				t.Run(file.name, func(t *testing.T) {
					data, err := os.ReadFile(file.path)
					if !file.existing {
						require.ErrorIs(t, err, fs.ErrNotExist)
						return
					}
					require.NoError(t, err)
					require.Equal(t, original, data)
				})
			}
		})
	}
}
