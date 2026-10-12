package gojwt_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

func keyIDHeaderToken(header string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(header)) + ".e30.signature"
}

func TestParseKeyIDHeaderInputs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		token   string
		want    string
		wantErr error
	}{
		{name: "kid string", token: keyIDHeaderToken(`{"alg":"EdDSA","kid":"app-2026"}`), want: "app-2026"},
		{name: "missing kid", token: keyIDHeaderToken(`{"alg":"EdDSA"}`)},
		{name: "empty object", token: keyIDHeaderToken(`{}`)},
		{name: "empty kid", token: keyIDHeaderToken(`{"kid":""}`)},
		{name: "escaped kid", token: keyIDHeaderToken(`{"kid":"a\"b\\c"}`), want: `a"b\c`},
		{name: "unicode kid", token: keyIDHeaderToken(`{"kid":"密钥-2026"}`), want: "密钥-2026"},
		{name: "header null", token: keyIDHeaderToken(`null`), wantErr: gojwt.ErrTokenMalformed},
		{name: "whitespace header null", token: keyIDHeaderToken(" \n null \t"), wantErr: gojwt.ErrTokenMalformed},
		{name: "header array", token: keyIDHeaderToken(`[]`), wantErr: gojwt.ErrTokenMalformed},
		{name: "header string", token: keyIDHeaderToken(`"header"`), wantErr: gojwt.ErrTokenMalformed},
		{name: "header number", token: keyIDHeaderToken(`12`), wantErr: gojwt.ErrTokenMalformed},
		{name: "header boolean", token: keyIDHeaderToken(`true`), wantErr: gojwt.ErrTokenMalformed},
		{name: "invalid json", token: keyIDHeaderToken(`{"kid":`), wantErr: gojwt.ErrTokenMalformed},
		{name: "kid null", token: keyIDHeaderToken(`{"kid":null}`), wantErr: gojwt.ErrTokenMalformed},
		{name: "kid number", token: keyIDHeaderToken(`{"kid":12}`), wantErr: gojwt.ErrTokenMalformed},
		{name: "kid boolean", token: keyIDHeaderToken(`{"kid":true}`), wantErr: gojwt.ErrTokenMalformed},
		{name: "kid array", token: keyIDHeaderToken(`{"kid":[]}`), wantErr: gojwt.ErrTokenMalformed},
		{name: "kid object", token: keyIDHeaderToken(`{"kid":{}}`), wantErr: gojwt.ErrTokenMalformed},
		{name: "empty token", wantErr: gojwt.ErrTokenMalformed},
		{name: "missing separator", token: "token", wantErr: gojwt.ErrTokenMalformed},
		{name: "empty header", token: ".claims.signature", wantErr: gojwt.ErrTokenMalformed},
		{name: "invalid base64", token: "%%%.claims.signature", wantErr: gojwt.ErrTokenMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := gojwt.ParseKeyID(tc.token)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestParseKeyIDDoesNotAuthenticateToken(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options []claims.Option
		mutate  func(string) string
		wantErr error
	}{
		{name: "tampered signature", mutate: func(token string) string {
			parts := strings.Split(token, ".")
			parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
			return strings.Join(parts, ".")
		}, wantErr: gojwt.ErrTokenSignatureInvalid},
		{name: "tampered kid", mutate: func(token string) string {
			parts := strings.Split(token, ".")
			parts[0] = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"other","typ":"JWT"}`))
			return strings.Join(parts, ".")
		}, wantErr: gojwt.ErrTokenSignatureInvalid},
		{name: "expired token", options: []claims.Option{claims.WithExpiresAtTime(time.Now().Add(-time.Hour))}, wantErr: gojwt.ErrTokenExpired},
		{name: "invalid claims", mutate: func(token string) string {
			parts := strings.Split(token, ".")
			parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`not-json`))
			return strings.Join(parts, ".")
		}, wantErr: gojwt.ErrTokenMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer, verifier := keyRingEd25519(t, "key")
			token, err := issuer.GenerateToken(42, tc.options...)
			require.NoError(t, err)
			if tc.mutate != nil {
				token = tc.mutate(token)
			}
			kid, err := gojwt.ParseKeyID(token)
			require.NoError(t, err)
			if tc.name == "tampered kid" {
				require.Equal(t, "other", kid)
			} else {
				require.Equal(t, "key", kid)
			}
			ring := gojwt.NewKeyRing()
			require.NoError(t, ring.Register(kid, verifier))
			parsed, err := ring.ParseToken(token, jwtv5.WithLeeway(0))
			require.Nil(t, parsed)
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}
