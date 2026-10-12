package gojwt_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/jwks"
	"github.com/stretchr/testify/require"
)

func benchmarkLocalEd25519Set(b *testing.B) (*jwks.Set, string) {
	b.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(b, err)
	key, err := jwks.NewKey("benchmark-key", publicKey, "EdDSA")
	require.NoError(b, err)
	set, err := jwks.NewSet(key)
	require.NoError(b, err)
	issuer, err := gojwt.NewJwtEd25519FromKeys(privateKey, publicKey, gojwt.WithKeyID("benchmark-key"))
	require.NoError(b, err)
	token, err := issuer.GenerateToken(42)
	require.NoError(b, err)
	_, err = set.ResolveKey(b.Context(), "benchmark-key", "EdDSA")
	require.NoError(b, err)
	return set, token
}

func BenchmarkResolverVerify(b *testing.B) {
	set, token := benchmarkLocalEd25519Set(b)
	verifier, err := gojwt.NewVerifier(set, []string{"EdDSA"})
	require.NoError(b, err)
	ctx := b.Context()
	_, err = verifier.ParseTokenContext(ctx, token)
	require.NoError(b, err)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := verifier.ParseTokenContext(ctx, token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJWKSResolveKey(b *testing.B) {
	set, _ := benchmarkLocalEd25519Set(b)
	ctx := b.Context()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := set.ResolveKey(ctx, "benchmark-key", "EdDSA"); err != nil {
			b.Fatal(err)
		}
	}
}
