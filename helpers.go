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

// refreshWindow 是允许刷新 token 的时间窗口。
// 只有当 token 距过期不足此时长时，RefreshToken 才允许执行。
const refreshWindow = 5 * time.Minute

// cacheSweepInterval 是缓存惰性清扫的最小间隔。
const cacheSweepInterval = 5 * time.Minute

// cachedClaims 是缓存中存储的条目，包含 Claims 副本和过期时间。
type cachedClaims struct {
	claims    *claims.Claims
	expiresAt time.Time
}

// claimsCache 是基于 sync.Map 的轻量缓存，带惰性过期清扫。
type claimsCache struct {
	entries   sync.Map
	lastSweep atomic.Int64
}

// normalizeParseError 将 golang-jwt 的内部错误归一化为本包的 sentinel error。
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

// loadCachedClaims 从缓存中加载 Claims。
// 命中时返回深拷贝副本，过期条目会被自动删除。
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

// storeCachedClaims 将 Claims 深拷贝后存入缓存。
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

// refreshTokenClaims 检查刷新条件并更新 Claims 的过期时间。
// 超过 refreshDuration 返回 ErrTokenExpired，
// 未进入刷新窗口返回 ErrRefreshTooEarly。
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

// maybeSweepExpired 惰性清扫过期缓存条目。
// 通过 CAS 操作保证同一时刻只有一个 goroutine 执行清扫。
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

// cloneClaims 对 Claims 进行深拷贝，防止缓存被调用方意外修改。
func cloneClaims(src *claims.Claims) *claims.Claims {
	if src == nil {
		return nil
	}

	dst := *src
	dst.RegisteredClaims = cloneRegisteredClaims(src.RegisteredClaims)
	dst.Roles = slices.Clone(src.Roles)
	return &dst
}

// cloneRegisteredClaims 对 JWT 标准字段进行深拷贝。
func cloneRegisteredClaims(src jwtv5.RegisteredClaims) jwtv5.RegisteredClaims {
	dst := src
	dst.ExpiresAt = cloneNumericDate(src.ExpiresAt)
	dst.NotBefore = cloneNumericDate(src.NotBefore)
	dst.IssuedAt = cloneNumericDate(src.IssuedAt)
	dst.Audience = append(jwtv5.ClaimStrings(nil), src.Audience...)
	return dst
}

// cloneNumericDate 拷贝 NumericDate 指针。
func cloneNumericDate(src *jwtv5.NumericDate) *jwtv5.NumericDate {
	if src == nil {
		return nil
	}
	return jwtv5.NewNumericDate(src.Time)
}
