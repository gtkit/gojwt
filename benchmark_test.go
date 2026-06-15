package gojwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/gtkit/gojwt"
	"github.com/stretchr/testify/require"
)

func BenchmarkJwtHmacGenerateToken(b *testing.B) {
	j, err := gojwt.NewJwtHmac([]byte("12345678901234567890123456789012"))
	require.NoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, err := j.GenerateToken(1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJwtHmacParseToken(b *testing.B) {
	j, err := gojwt.NewJwtHmac([]byte("12345678901234567890123456789012"))
	require.NoError(b, err)
	token, err := j.GenerateToken(1)
	require.NoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, err := j.ParseToken(token)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJwtHmacCachedParseToken(b *testing.B) {
	j, err := gojwt.NewJwtHmac([]byte("12345678901234567890123456789012"))
	require.NoError(b, err)
	token, err := j.GenerateToken(1)
	require.NoError(b, err)
	_, err = j.CachedParseToken(token)
	require.NoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, err := j.CachedParseToken(token)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJwtEd25519GenerateToken(b *testing.B) {
	dir := b.TempDir()
	priPath := dir + "/ed25519.pem"
	pubPath := dir + "/ed25519.pub.pem"
	require.NoError(b, gojwt.GenerateEd25519Keys(priPath, pubPath))
	j, err := gojwt.NewJwtEd25519(priPath, pubPath)
	require.NoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, err := j.GenerateToken(1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJwtRSAGenerateToken(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(b, err)
	j, err := gojwt.NewJwtRSAFromKeys(privateKey, &privateKey.PublicKey)
	require.NoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, err := j.GenerateToken(1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJwtHmacParallelVerify(b *testing.B) {
	j, err := gojwt.NewJwtHmac([]byte("12345678901234567890123456789012"))
	require.NoError(b, err)
	tokens := make([]string, 64)
	for i := range tokens {
		tokens[i], err = j.GenerateToken(int64(i + 1))
		require.NoError(b, err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, errs := j.ParallelVerify(tokens)
		for _, err := range errs {
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}
