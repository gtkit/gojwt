package gojwt_test

import (
	"context"
	"errors"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
)

func TestRevocationBoundaries(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"missing id", "blank id", "cancel blacklist", "cancel revocation", "mutation"} {
		t.Run(mode, func(t *testing.T) {
			key := interoperableKey(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			blacklistCalls, revocationCalls := 0, 0
			j, err := gojwt.NewJwtHmac(key,
				gojwt.WithBlacklistCheckContextFunc(func(context.Context, string) (bool, error) {
					blacklistCalls++
					if mode == "cancel blacklist" {
						cancel()
					}
					return false, nil
				}),
				gojwt.WithRevocationCheck(func(_ context.Context, c *claims.Claims) (bool, error) {
					revocationCalls++
					if mode == "cancel revocation" {
						cancel()
					}
					c.Subject = "changed"
					return false, nil
				}))
			if err != nil {
				t.Fatal(err)
			}
			payload := jwtv5.MapClaims{"sub": "42", "exp": time.Now().Add(time.Hour).Unix(), "jti": "original"}
			if mode == "missing id" {
				delete(payload, "jti")
			}
			if mode == "blank id" {
				payload["jti"] = " "
			}
			raw := externalToken(t, key, payload, nil)
			c, err := j.CachedParseTokenContext(ctx, raw)
			switch mode {
			case "missing id", "blank id":
				if !errors.Is(err, gojwt.ErrTokenRequiredClaimMissing) || blacklistCalls != 0 || revocationCalls != 0 {
					t.Fatalf("missing identifier bypass: %v, callbacks %d/%d", err, blacklistCalls, revocationCalls)
				}
			case "cancel blacklist", "cancel revocation":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel ignored: %v", err)
				}
				if mode == "cancel blacklist" && revocationCalls != 0 {
					t.Fatal("called revocation after cancellation")
				}
			case "mutation":
				if err != nil || c.Subject != "42" {
					t.Fatalf("callback changed result: %v", err)
				}
				cached, err := j.CachedParseTokenContext(ctx, raw)
				if err != nil || cached.Subject != "42" || blacklistCalls != 2 || revocationCalls != 2 {
					t.Fatalf("cache callback isolation: %v", err)
				}
			}
		})
	}
}
