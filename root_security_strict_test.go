package gojwt_test

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

func reviewKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

func reviewRawJWT(key []byte, header, payload string) string {
	input := header + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestReviewRejectsAmbiguousOrMalformedPayloads(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	future, past := time.Now().Add(time.Hour).Unix(), time.Now().Add(-time.Hour).Unix()
	for _, tc := range []struct {
		name    string
		payload string
		opts    []jwtv5.ParserOption
	}{
		{name: "canonical expired exp and EXP alias", payload: fmt.Sprintf(`{"exp":%d,"EXP":%d}`, past, future)},
		{name: "Unicode subject alias", payload: fmt.Sprintf(`{"exp":%d,"sub":"42","ſub":"admin"}`, future)},
		{name: "duplicate subject", payload: fmt.Sprintf(`{"exp":%d,"sub":"42","sub":"admin"}`, future)},
		{name: "trailing payload bytes", payload: fmt.Sprintf(`{"exp":%d}garbage`, future), opts: []jwtv5.ParserOption{jwtv5.WithJSONNumber()}},
		{name: "trailing payload object", payload: fmt.Sprintf(`{"exp":%d}{}`, future), opts: []jwtv5.ParserOption{jwtv5.WithJSONNumber()}},
		{name: "invalid UTF8 custom string", payload: fmt.Sprintf("{\"exp\":%d,\"extra\":\"\xff\"}", future)},
		{name: "present null subject", payload: fmt.Sprintf(`{"exp":%d,"sub":null}`, future)},
		{name: "quoted expiration", payload: fmt.Sprintf(`{"exp":"%d"}`, future)},
		{name: "overflow future issued-at", payload: fmt.Sprintf(`{"exp":%d,"iat":9223372036854775808}`, future)},
		{name: "near max int issued-at overflows Go epoch", payload: fmt.Sprintf(`{"exp":%d,"iat":9223372036854774784}`, future)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := reviewKey(t)
			verifier, err := gojwt.NewJwtHmac(key)
			require.NoError(t, err)
			parsed, err := verifier.ParseToken(reviewRawJWT(key, header, tc.payload), tc.opts...)
			require.Nil(t, parsed)
			require.ErrorIs(t, err, gojwt.ErrTokenMalformed)
		})
	}
}

func TestReviewRejectsWhitespaceInJWTEncoding(t *testing.T) {
	for _, tc := range []struct {
		name       string
		segment    int
		whitespace string
	}{
		{name: "header LF", segment: 0, whitespace: "\n"},
		{name: "header CR", segment: 0, whitespace: "\r"},
		{name: "payload LF", segment: 1, whitespace: "\n"},
		{name: "signature LF", segment: 2, whitespace: "\n"},
		{name: "signature CRLF", segment: 2, whitespace: "\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := reviewKey(t)
			verifier, err := gojwt.NewJwtHmac(key)
			require.NoError(t, err)
			plainHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
			payload := fmt.Sprintf(`{"exp":%d}`, time.Now().Add(time.Hour).Unix())
			parts := strings.Split(reviewRawJWT(key, plainHeader, payload), ".")
			parts[tc.segment] = parts[tc.segment][:3] + tc.whitespace + parts[tc.segment][3:]
			if tc.segment < 2 {
				mac := hmac.New(sha256.New, key)
				_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
				parts[2] = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
			}
			parsed, err := verifier.ParseToken(strings.Join(parts, "."))
			require.Nil(t, parsed)
			require.ErrorIs(t, err, gojwt.ErrTokenMalformed)
		})
	}
}

func TestReviewPreservesIntegersOutsideFloatRange(t *testing.T) {
	for _, opts := range [][]jwtv5.ParserOption{nil, {jwtv5.WithJSONNumber()}} {
		t.Run(map[bool]string{true: "explicit numbers", false: "default"}[len(opts) > 0], func(t *testing.T) {
			key := reviewKey(t)
			verifier, err := gojwt.NewJwtHmac(key)
			require.NoError(t, err)
			integer := strings.Repeat("9", 400)
			payload := fmt.Sprintf(`{"exp":%d,"ext":{"integer":%s},"external_integer":%s}`, time.Now().Add(time.Hour).Unix(), integer, integer)
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
			parsed, err := verifier.ParseToken(reviewRawJWT(key, header, payload), opts...)
			require.NoError(t, err)
			require.Equal(t, json.Number(integer), parsed.Ext["integer"])
			require.Equal(t, json.Number(integer), parsed.Custom["external_integer"])
		})
	}
}

func TestReviewRevocationCancellationCannotReturnClaims(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(map[bool]string{true: "cached", false: "parse"}[cached], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			key := reviewKey(t)
			var cancelOnCheck bool
			verifier, err := gojwt.NewJwtHmac(key, gojwt.WithRevocationCheck(func(context.Context, *claims.Claims) (bool, error) {
				if cancelOnCheck {
					cancel()
				}
				return false, nil
			}))
			require.NoError(t, err)
			token, err := verifier.GenerateToken(42)
			require.NoError(t, err)
			if cached {
				_, err = verifier.CachedParseToken(token)
				require.NoError(t, err)
			}
			cancelOnCheck = true
			var parsed *claims.Claims
			if cached {
				parsed, err = verifier.CachedParseTokenContext(ctx, token)
			} else {
				parsed, err = verifier.ParseTokenContext(ctx, token)
			}
			require.Nil(t, parsed)
			require.ErrorIs(t, err, context.Canceled)
		})
	}
}
