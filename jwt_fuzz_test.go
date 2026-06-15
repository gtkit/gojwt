package gojwt

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzJwtHmacParseToken(f *testing.F) {
	j, err := NewJwtHmac([]byte("12345678901234567890123456789012"))
	if err != nil {
		f.Fatalf("new hmac jwt: %v", err)
	}

	seeds := []string{
		"",
		".",
		"..",
		"not-a-token",
		"Bearer token",
		"eyJhbGciOiJIUzI1NiJ9.e30.invalid",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, token string) {
		if len(token) > 8192 {
			t.Skip()
		}
		_, _ = j.ParseToken(token)
		_, _ = j.CachedParseToken(token)
	})
}

func FuzzPEMKeyParsers(f *testing.F) {
	seeds := [][]byte{
		nil,
		[]byte("not-pem"),
		[]byte("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n"),
		[]byte("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"),
		[]byte("-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----\n"),
		[]byte("-----BEGIN RSA PUBLIC KEY-----\n-----END RSA PUBLIC KEY-----\n"),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			t.Skip()
		}

		path := filepath.Join(t.TempDir(), "key.pem")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write fuzz key: %v", err)
		}

		_, _ = readPEMBlock(path)
		_, _ = readEd25519PrivateKey(path)
		_, _ = readEd25519PublicKey(path)
		_, _ = readRSAPrivateKey(path)
		_, _ = readRSAPublicKey(path)
	})
}
