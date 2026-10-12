package gojwt

import (
	"encoding/base64"
	"testing"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

func FuzzSignedTokenPayload(f *testing.F) {
	key, err := GenerateHMACKeyString(jwtv5.SigningMethodHS256)
	if err != nil {
		f.Fatal(err)
	}
	parser, err := NewJwtHmac([]byte(key), WithNumericSubject(true))
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{`{}`, `{"ext":{},"EXT":null}`, `{"exp":1,"EXP":2}`, `{"sub":9007199254740993}`, `{"ext":{"large":1e400}}`, `{} {}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, payload string) {
		if len(payload) > 8192 {
			t.Skip()
		}
		input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
		sig, err := jwtv5.SigningMethodHS256.Sign(input, []byte(key))
		if err != nil {
			t.Fatal(err)
		}
		raw := input + "." + base64.RawURLEncoding.EncodeToString(sig)
		_, _ = parser.ParseToken(raw)
		_, _ = parser.ParseToken(raw, jwtv5.WithJSONNumber())
	})
}

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

		_, _ = ParseEd25519PrivateKeyPEM(data)
		_, _ = ParseEd25519PublicKeyPEM(data)
		_, _ = ParseRSAPrivateKeyPEM(data)
		_, _ = ParseRSAPublicKeyPEM(data)
		_, _ = ParseECDSAPrivateKeyPEM(data)
		_, _ = ParseECDSAPublicKeyPEM(data)
	})
}
