package gojwt

import (
	"errors"
	"fmt"
	"runtime"
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
	case errors.Is(err, jwtv5.ErrTokenInvalidIssuer):
		return ErrTokenInvalidIssuer
	case errors.Is(err, jwtv5.ErrTokenInvalidAudience):
		return ErrTokenInvalidAudience
	case errors.Is(err, jwtv5.ErrTokenInvalidSubject):
		return ErrTokenInvalidSubject
	case errors.Is(err, jwtv5.ErrTokenInvalidId):
		return ErrTokenInvalidID
	case errors.Is(err, jwtv5.ErrTokenRequiredClaimMissing):
		return ErrTokenRequiredClaimMissing
	case errors.Is(err, jwtv5.ErrTokenExpired):
		return ErrTokenExpired
	case errors.Is(err, jwtv5.ErrTokenUsedBeforeIssued):
		return ErrTokenUsedBeforeIssued
	case errors.Is(err, jwtv5.ErrTokenMalformed):
		return ErrTokenMalformed
	case errors.Is(err, jwtv5.ErrTokenNotValidYet):
		return ErrTokenNotValidYet
	case errors.Is(err, jwtv5.ErrTokenSignatureInvalid):
		return ErrTokenSignatureInvalid
	case errors.Is(err, jwtv5.ErrTokenUnverifiable):
		return ErrTokenUnverifiable
	case errors.Is(err, jwtv5.ErrTokenInvalidClaims):
		return ErrTokenInvalidClaims
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

// refreshTokenClaims 检查刷新条件并轮换 TokenID、更新时间字段。
// 超过 refreshDuration 返回 ErrTokenExpired，
// 未进入刷新窗口返回 ErrRefreshTooEarly。
// 刷新成功后会生成新的 TokenID，并更新 iat、nbf、exp。
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

	newTokenID, err := generateTokenID()
	if err != nil {
		return err
	}

	tokenClaims.TokenID = newTokenID
	tokenClaims.ExpiresAt = jwtv5.NewNumericDate(now.Add(tokenDuration))
	tokenClaims.IssuedAt = jwtv5.NewNumericDate(now)
	tokenClaims.NotBefore = jwtv5.NewNumericDate(now)
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

// alignTokenIdentifiers 保证业务 TokenID 与标准 jti 始终一致。
func alignTokenIdentifiers(tokenClaims *claims.Claims, generatedTokenID string) {
	if tokenClaims == nil {
		return
	}

	if tokenClaims.ID != "" && tokenClaims.ID != generatedTokenID {
		tokenClaims.TokenID = tokenClaims.ID
	}
	if tokenClaims.TokenID == "" {
		tokenClaims.TokenID = generatedTokenID
	}
	tokenClaims.ID = tokenClaims.TokenID
}

// checkBlacklist 根据配置执行黑名单检查。
func checkBlacklist(cfg *config, tokenID string) error {
	if cfg == nil || tokenID == "" {
		return nil
	}

	if cfg.blacklistCheckFunc != nil {
		blacklisted, err := cfg.blacklistCheckFunc(tokenID)
		if err != nil {
			return fmt.Errorf("check token blacklist: %w", err)
		}
		if blacklisted {
			return ErrTokenBlacklisted
		}
		return nil
	}

	if cfg.isBlacklisted != nil && cfg.isBlacklisted(tokenID) {
		return ErrTokenBlacklisted
	}

	return nil
}

// parallelVerifyClaims 使用有界 worker pool 并发验证多个 token。
// 结果顺序与输入顺序严格对齐。
func parallelVerifyClaims(tokens []string, verify func(string) (*claims.Claims, error)) ([]*claims.Claims, []error) {
	results := make([]*claims.Claims, len(tokens))
	errs := make([]error, len(tokens))
	if len(tokens) == 0 {
		return results, errs
	}

	workerCount := min(len(tokens), runtime.GOMAXPROCS(0))
	jobs := make(chan int)

	var wg sync.WaitGroup
	for range workerCount {
		wg.Go(func() {
			for index := range jobs {
				tokenClaims, err := verify(tokens[index])
				results[index] = tokenClaims
				errs[index] = err
			}
		})
	}

	for index := range tokens {
		jobs <- index
	}
	close(jobs)

	wg.Wait()
	return results, errs
}
