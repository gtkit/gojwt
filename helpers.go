package gojwt

import (
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

const refreshWindow = 5 * time.Minute
const cacheSweepInterval = 5 * time.Minute

type cachedClaims struct {
	claims    *claims.Claims
	expiresAt time.Time
}

type claimsCache struct {
	entries   sync.Map
	lastSweep atomic.Int64
}

func normalizeParseError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, jwtv5.ErrTokenExpired):
		return ErrTokenExpired
	case errors.Is(err, jwtv5.ErrTokenMalformed):
		return ErrTokenMalformed
	case errors.Is(err, jwtv5.ErrTokenNotValidYet):
		return ErrTokenNotValidYet
	case errors.Is(err, jwtv5.ErrTokenSignatureInvalid):
		return ErrTokenSignatureInvalid
	case errors.Is(err, jwtv5.ErrTokenUnverifiable):
		return ErrTokenUnverifiable
	default:
		return err
	}
}

func loadCachedClaims(cache *claimsCache, token string) (*claims.Claims, bool) {
	cache.maybeSweepExpired(time.Now())

	value, ok := cache.entries.Load(token)
	if !ok {
		return nil, false
	}

	entry, ok := value.(cachedClaims)
	if !ok || entry.claims == nil {
		cache.entries.Delete(token)
		return nil, false
	}

	if !entry.expiresAt.IsZero() && !time.Now().Before(entry.expiresAt) {
		cache.entries.Delete(token)
		return nil, false
	}

	return cloneClaims(entry.claims), true
}

func storeCachedClaims(cache *claimsCache, token string, tokenClaims *claims.Claims) {
	if tokenClaims == nil {
		return
	}

	cache.maybeSweepExpired(time.Now())

	entry := cachedClaims{
		claims: cloneClaims(tokenClaims),
	}
	if tokenClaims.ExpiresAt != nil {
		entry.expiresAt = tokenClaims.ExpiresAt.Time
	}
	cache.entries.Store(token, entry)
}

func refreshTokenClaims(tokenClaims *claims.Claims, tokenDuration, refreshDuration time.Duration) error {
	if tokenClaims == nil || tokenClaims.ExpiresAt == nil || tokenClaims.IssuedAt == nil {
		return ErrTokenInvalid
	}

	now := time.Now()
	if now.Sub(tokenClaims.IssuedAt.Time) > refreshDuration {
		return ErrTokenExpired
	}
	if time.Until(tokenClaims.ExpiresAt.Time) >= refreshWindow {
		return ErrRefreshTooEarly
	}

	tokenClaims.ExpiresAt = jwtv5.NewNumericDate(now.Add(tokenDuration))
	return nil
}

func (c *claimsCache) maybeSweepExpired(now time.Time) {
	if c == nil {
		return
	}

	last := c.lastSweep.Load()
	if last != 0 && now.Sub(time.Unix(0, last)) < cacheSweepInterval {
		return
	}
	if !c.lastSweep.CompareAndSwap(last, now.UnixNano()) {
		return
	}

	c.entries.Range(func(key, value any) bool {
		entry, ok := value.(cachedClaims)
		if !ok || entry.claims == nil || (!entry.expiresAt.IsZero() && !now.Before(entry.expiresAt)) {
			c.entries.Delete(key)
		}
		return true
	})
}

func cloneClaims(src *claims.Claims) *claims.Claims {
	if src == nil {
		return nil
	}

	dst := *src
	dst.RegisteredClaims = cloneRegisteredClaims(src.RegisteredClaims)
	dst.Roles = slices.Clone(src.Roles)
	return &dst
}

func cloneRegisteredClaims(src jwtv5.RegisteredClaims) jwtv5.RegisteredClaims {
	dst := src
	dst.ExpiresAt = cloneNumericDate(src.ExpiresAt)
	dst.NotBefore = cloneNumericDate(src.NotBefore)
	dst.IssuedAt = cloneNumericDate(src.IssuedAt)
	dst.Audience = append(jwtv5.ClaimStrings(nil), src.Audience...)
	return dst
}

func cloneNumericDate(src *jwtv5.NumericDate) *jwtv5.NumericDate {
	if src == nil {
		return nil
	}
	return jwtv5.NewNumericDate(src.Time)
}
