package gojwt_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/stretchr/testify/require"
)

func rootReviewRawHMACToken(t *testing.T, key []byte, payload string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	input := header + "." + body
	signature, err := jwtv5.SigningMethodHS256.Sign(input, key)
	require.NoError(t, err)
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestRootSecurityReviewCaseVariantExtNull(t *testing.T) {
	t.Parallel()
	key := interoperableKey(t)
	tests := []struct {
		name   string
		fields string
	}{
		{name: "object then upper null", fields: `"ext":{"large":9007199254740993},"EXT":null`},
		{name: "upper object then null", fields: `"EXT":{"large":9007199254740993},"ext":null`},
		{name: "null then object", fields: `"ext":null,"EXT":{"large":9007199254740993}`},
		{name: "ordinary object", fields: `"ext":{"large":9007199254740993}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			j, err := gojwt.NewJwtHmac(key)
			require.NoError(t, err)
			raw := rootReviewRawHMACToken(t, key, fmt.Sprintf(`{"exp":%d,%s}`, time.Now().Add(time.Hour).Unix(), tc.fields))
			require.NotPanics(t, func() {
				_, _ = j.ParseTokenContext(t.Context(), raw)
			})
		})
	}
}

func TestRootSecurityReviewVeryLargeExtInteger(t *testing.T) {
	t.Parallel()
	key := interoperableKey(t)
	tests := []struct {
		name    string
		integer string
	}{
		{name: "above binary64 precision", integer: "9007199254740993"},
		{name: "above binary64 range", integer: "1" + strings.Repeat("0", 350)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			j, err := gojwt.NewJwtHmac(key)
			require.NoError(t, err)
			raw := rootReviewRawHMACToken(t, key, fmt.Sprintf(`{"exp":%d,"ext":{"large":%s}}`, time.Now().Add(time.Hour).Unix(), tc.integer))
			parsed, err := j.ParseTokenContext(t.Context(), raw)
			require.NoError(t, err)
			require.Equal(t, json.Number(tc.integer), parsed.Ext["large"])
		})
	}
}
