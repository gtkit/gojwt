package gojwt_test

import (
	"fmt"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

func TestAPISIXApplicationKeyClaim(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		opts []gojwt.Option
		want string
	}{
		{name: "omitted"},
		{name: "orders", opts: []gojwt.Option{gojwt.WithApplicationKey("orders-api")}, want: "orders-api"},
		{name: "billing", opts: []gojwt.Option{gojwt.WithApplicationKey("billing-api")}, want: "billing-api"},
	}
	for _, algorithm := range lifecycleAlgorithms() {
		for _, tc := range testCases {
			t.Run(algorithm.name+"/"+tc.name, func(t *testing.T) {
				opts := []gojwt.Option{
					gojwt.WithKeyID("signing-key-2026"),
					gojwt.WithTokenDuration(time.Hour),
					gojwt.WithRefreshWindow(time.Hour),
				}
				issuer, err := algorithm.new(t, append(opts, tc.opts...)...)
				require.NoError(t, err)

				for _, uid := range []int64{42, 0} {
					token, err := issuer.GenerateToken(uid, claims.WithExt("key", "nested"))
					require.NoError(t, err)
					checkAPISIXApplicationKey(t, token, tc.want)

					refreshed, err := issuer.RefreshTokenContext(t.Context(), token)
					require.NoError(t, err)
					checkAPISIXApplicationKey(t, refreshed, tc.want)

					verified, err := issuer.ParseTokenContext(t.Context(), refreshed)
					require.NoError(t, err)
					require.Equal(t, uid, verified.UserID)
				}
			})
		}
	}
}

func checkAPISIXApplicationKey(t *testing.T, raw, want string) {
	t.Helper()
	payload := jwtv5.MapClaims{}
	token, _, err := jwtv5.NewParser().ParseUnverified(raw, payload)
	require.NoError(t, err)
	if want == "" {
		require.NotContains(t, payload, "key")
	} else {
		require.Equal(t, want, payload["key"])
	}
	require.Equal(t, "signing-key-2026", token.Header["kid"])
	require.NotContains(t, token.Header, "key")
	require.Equal(t, map[string]any{"key": "nested"}, payload["ext"])
}

func TestRefreshPreservesOriginalApplicationKey(t *testing.T) {
	t.Parallel()

	secret := reviewKey(t)
	issuer, err := gojwt.NewJwtHmac(secret, gojwt.WithApplicationKey("current-app"),
		gojwt.WithTokenDuration(time.Hour), gojwt.WithRefreshWindow(time.Hour))
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		key  string
	}{
		{name: "older application key", key: "previous-app"},
		{name: "legacy token without key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			payload := jwtv5.MapClaims{"iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
			if tc.key != "" {
				payload["key"] = tc.key
			}
			raw := externalToken(t, secret, payload, nil)
			refreshed, err := issuer.RefreshTokenContext(t.Context(), raw)
			require.NoError(t, err)
			parsed, err := issuer.ParseTokenContext(t.Context(), refreshed)
			require.NoError(t, err)
			if tc.key == "" {
				require.NotContains(t, parsed.Custom, "key")
			} else {
				require.Equal(t, tc.key, parsed.Custom["key"])
			}
		})
	}
}

func TestWithApplicationKeyAndCustomClaims(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		opts []gojwt.Option
		want string
	}{
		{name: "legacy caller", want: "custom-app"},
		{name: "configured signer", opts: []gojwt.Option{gojwt.WithApplicationKey("orders-api")}, want: "orders-api"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer, err := gojwt.NewJwtHmac(reviewKey(t), tc.opts...)
			require.NoError(t, err)
			custom := map[string]any{"key": "custom-app", "tenant": "tenant-a"}
			raw, err := issuer.GenerateToken(42, func(c *claims.Claims) { c.Custom = custom })
			require.NoError(t, err)
			parsed, err := issuer.ParseTokenContext(t.Context(), raw)
			require.NoError(t, err)
			require.Equal(t, map[string]any{"key": tc.want, "tenant": "tenant-a"}, parsed.Custom)
			require.Equal(t, "custom-app", custom["key"])
		})
	}
}

func TestWithApplicationKeyRejectsBlankValue(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		key  string
	}{
		{name: "empty"},
		{name: "whitespace", key: " \t\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := gojwt.NewJwtHmac(reviewKey(t), gojwt.WithApplicationKey(tc.key))
			require.ErrorIs(t, err, gojwt.ErrInvalidConfig)
		})
	}
}

func ExampleWithApplicationKey() {
	secret, err := gojwt.GenerateHMACKeyString(jwtv5.SigningMethodHS256)
	if err != nil {
		panic(err)
	}
	issuer, err := gojwt.NewJwtHmac([]byte(secret), gojwt.WithApplicationKey("orders-api"))
	if err != nil {
		panic(err)
	}
	token, err := issuer.GenerateToken(42)
	if err != nil {
		panic(err)
	}
	c, err := issuer.ParseToken(token)
	if err != nil {
		panic(err)
	}
	fmt.Println(c.Custom["key"])
	// Output: orders-api
}
