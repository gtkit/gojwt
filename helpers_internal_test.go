package gojwt

import (
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

func TestClaimsCacheSweepRemovesExpiredEntriesOnStore(t *testing.T) {
	var cache claimsCache
	expiredAt := time.Now().Add(-time.Minute)

	storeCachedClaims(&cache, "expired", &claims.Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(expiredAt),
		},
	})

	cache.lastSweep.Store(time.Now().Add(-cacheSweepInterval - time.Second).UnixNano())
	storeCachedClaims(&cache, "fresh", &claims.Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(time.Minute)),
		},
	})

	_, ok := cache.entries.Load("expired")
	require.False(t, ok)
}
