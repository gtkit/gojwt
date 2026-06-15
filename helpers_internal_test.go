package gojwt

import (
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

func (c *claimsCache) testContains(token string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, ok := c.entries[token]
	return ok
}

func (c *claimsCache) testLen() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.entries)
}

func TestClaimsCacheSweepRemovesExpiredEntriesOnStore(t *testing.T) {
	var cache claimsCache
	expiredAt := time.Now().Add(-time.Minute)

	storeCachedClaims(&cache, 10, "expired", &claims.Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(expiredAt),
		},
	})

	cache.lastSweep = time.Now().Add(-cacheSweepInterval - time.Second)
	storeCachedClaims(&cache, 10, "fresh", &claims.Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(time.Minute)),
		},
	})

	require.False(t, cache.testContains("expired"))
	require.True(t, cache.testContains("fresh"))
}

func TestClaimsCacheHonorsMaxEntries(t *testing.T) {
	var cache claimsCache

	storeCachedClaims(&cache, 1, "first", &claims.Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(time.Minute)),
		},
	})
	storeCachedClaims(&cache, 1, "second", &claims.Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(time.Minute)),
		},
	})

	require.False(t, cache.testContains("first"))
	require.True(t, cache.testContains("second"))
	require.Equal(t, 1, cache.testLen())
}

func TestClaimsCacheUsesLRUOrder(t *testing.T) {
	var cache claimsCache
	expiresAt := time.Now().Add(time.Minute)

	storeCachedClaims(&cache, 2, "first", &claims.Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(expiresAt),
		},
	})
	storeCachedClaims(&cache, 2, "second", &claims.Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(expiresAt),
		},
	})

	_, ok := loadCachedClaims(&cache, "first")
	require.True(t, ok)

	storeCachedClaims(&cache, 2, "third", &claims.Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(expiresAt),
		},
	})

	require.True(t, cache.testContains("first"))
	require.False(t, cache.testContains("second"))
	require.True(t, cache.testContains("third"))
	require.Equal(t, 2, cache.testLen())
}

func TestClaimsCacheCanBeDisabled(t *testing.T) {
	var cache claimsCache

	storeCachedClaims(&cache, 0, "token", &claims.Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(time.Minute)),
		},
	})

	require.False(t, cache.testContains("token"))
	require.Equal(t, 0, cache.testLen())
}
