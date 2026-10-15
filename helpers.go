package gojwt

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

// cacheSweepInterval 是缓存惰性清扫的最小间隔。
const cacheSweepInterval = 5 * time.Minute

// cachedClaims 是缓存中存储的条目，包含 Claims 副本和过期时间。
type cachedClaims struct {
	claims    *claims.Claims
	expiresAt time.Time
}

type claimsCacheEntry struct {
	token string
	value cachedClaims
}

// claimsCache 是实例级 LRU 缓存，带严格容量上限和惰性过期清扫。
type claimsCache struct {
	mu        sync.Mutex
	entries   map[string]*list.Element
	lru       list.List
	lastSweep time.Time
}

// normalizeParseError 将 golang-jwt 的内部错误归一化为本包的 sentinel error，
// 同时用 %w 保留底层原因，errors.Is 判定 sentinel 与排障读根因两不误。
func normalizeParseError(err error) error {
	sentinel := matchParseSentinel(err)
	if sentinel == nil {
		return err
	}
	return fmt.Errorf("%w: %w", sentinel, err)
}

func matchParseSentinel(err error) error {
	switch {
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
		return nil
	}
}

// loadCachedClaims 从缓存中加载 Claims。
// 命中时返回深拷贝副本，过期条目会被自动删除。
func loadCachedClaims(cache *claimsCache, token string) (*claims.Claims, bool) {
	if cache == nil {
		return nil, false
	}

	entry, ok := cache.load(token, time.Now())
	if !ok {
		return nil, false
	}

	return cloneClaims(entry.claims), true
}

// storeCachedClaims 将 Claims 深拷贝后存入缓存。
func storeCachedClaims(cache *claimsCache, maxEntries int, token string, tokenClaims *claims.Claims) {
	if cache == nil || tokenClaims == nil || maxEntries <= 0 {
		return
	}

	entry := cachedClaims{
		claims: cloneClaims(tokenClaims),
	}
	if tokenClaims.ExpiresAt != nil {
		entry.expiresAt = tokenClaims.ExpiresAt.Time
	}
	cache.store(maxEntries, token, entry, time.Now())
}

// refreshTokenClaims 检查刷新条件并轮换 TokenID、更新时间字段。
//
// 会话终点为 auth_time + refreshDuration，旧 token 无 auth_time 时以其 iat 为起点：
// 已到终点返回 ErrRefreshExpired；距过期仍超过 refreshWindow 返回 ErrRefreshTooEarly。
// 新 token 保留旧 token 的有效时长（exp - iat），但 exp 不越过会话终点，
// 因此刷新链上任何 token 都不会活过终点。
func refreshTokenClaims(tokenClaims *claims.Claims, cfg *config) error {
	if tokenClaims == nil || tokenClaims.ExpiresAt == nil || tokenClaims.IssuedAt == nil {
		return ErrTokenInvalid
	}

	now := time.Now()
	authTime := tokenClaims.IssuedAt.Time
	if tokenClaims.AuthTime != nil {
		authTime = tokenClaims.AuthTime.Time
	}
	sessionEnd := authTime.Add(cfg.refreshDuration)
	if !now.Before(sessionEnd) {
		return ErrRefreshExpired
	}
	if time.Until(tokenClaims.ExpiresAt.Time) > cfg.refreshWindow {
		return ErrRefreshTooEarly
	}

	lifetime := tokenClaims.ExpiresAt.Sub(tokenClaims.IssuedAt.Time)
	if lifetime <= 0 {
		lifetime = cfg.tokenDuration
	}
	expiresAt := now.Add(lifetime)
	if expiresAt.After(sessionEnd) {
		expiresAt = sessionEnd
	}

	newTokenID, err := generateTokenID()
	if err != nil {
		return err
	}

	tokenClaims.TokenID = newTokenID
	tokenClaims.ID = newTokenID
	tokenClaims.AuthTime = &jwtv5.NumericDate{Time: authTime}
	tokenClaims.ExpiresAt = &jwtv5.NumericDate{Time: expiresAt}
	tokenClaims.IssuedAt = &jwtv5.NumericDate{Time: now}
	tokenClaims.NotBefore = &jwtv5.NumericDate{Time: now}
	return nil
}

// maybeSweepExpired 惰性清扫过期缓存条目。
// 调用方必须先持有 c.mu。
func (c *claimsCache) maybeSweepExpired(now time.Time) {
	if c == nil {
		return
	}

	if !c.lastSweep.IsZero() && now.Sub(c.lastSweep) < cacheSweepInterval {
		return
	}
	c.lastSweep = now

	for element := c.lru.Back(); element != nil; {
		prev := element.Prev()
		entry, ok := element.Value.(*claimsCacheEntry)
		if !ok || entry == nil || entry.value.claims == nil || isCachedClaimsExpired(entry.value, now) {
			c.deleteElement(element)
		}
		element = prev
	}
}

func (c *claimsCache) load(token string, now time.Time) (cachedClaims, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.maybeSweepExpired(now)
	if c.entries == nil {
		return cachedClaims{}, false
	}

	element, ok := c.entries[token]
	if !ok {
		return cachedClaims{}, false
	}
	entry, ok := element.Value.(*claimsCacheEntry)
	if !ok || entry == nil || entry.value.claims == nil || isCachedClaimsExpired(entry.value, now) {
		c.deleteElement(element)
		return cachedClaims{}, false
	}

	c.lru.MoveToFront(element)
	return entry.value, true
}

func (c *claimsCache) store(maxEntries int, token string, value cachedClaims, now time.Time) {
	if maxEntries <= 0 || token == "" || value.claims == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.entries == nil {
		c.entries = make(map[string]*list.Element)
	}

	c.maybeSweepExpired(now)
	if element, ok := c.entries[token]; ok {
		element.Value = &claimsCacheEntry{token: token, value: value}
		c.lru.MoveToFront(element)
		return
	}

	for len(c.entries) >= maxEntries {
		c.deleteElement(c.lru.Back())
	}

	c.entries[token] = c.lru.PushFront(&claimsCacheEntry{token: token, value: value})
}

func (c *claimsCache) deleteElement(element *list.Element) {
	if element == nil {
		return
	}
	entry, ok := element.Value.(*claimsCacheEntry)
	if ok && entry != nil && c.entries != nil {
		delete(c.entries, entry.token)
	}
	c.lru.Remove(element)
}

func isCachedClaimsExpired(entry cachedClaims, now time.Time) bool {
	return !entry.expiresAt.IsZero() && !now.Before(entry.expiresAt)
}

// checkRevocation 依次执行 tokenID 黑名单检查与 claims 级吊销回调。
// 解析路径与缓存命中路径都经过这里，缓存不会成为吊销的绕过口。
// tokenID 为空的 token 没有可查的黑名单键，只走吊销回调。
func checkRevocation(ctx context.Context, cfg *config, tokenClaims *claims.Claims) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if cfg.blacklistCheck != nil {
		if strings.TrimSpace(tokenClaims.TokenID) == "" {
			return fmt.Errorf("%w: jti or token_id is required for blacklist checks", ErrTokenRequiredClaimMissing)
		}
		revoked, err := cfg.blacklistCheck(ctx, tokenClaims.TokenID)
		if err != nil {
			return fmt.Errorf("check token blacklist: %w", err)
		}
		if revoked {
			return ErrTokenBlacklisted
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if cfg.revocationCheck != nil {
		revoked, err := cfg.revocationCheck(ctx, cloneClaims(tokenClaims))
		if err != nil {
			return fmt.Errorf("check token revocation: %w", err)
		}
		if revoked {
			return ErrTokenBlacklisted
		}
	}
	return ctx.Err()
}

// cloneClaims 对 Claims 进行深拷贝，防止缓存被调用方意外修改。
func cloneClaims(src *claims.Claims) *claims.Claims {
	if src == nil {
		return nil
	}

	dst := *src
	dst.RegisteredClaims = cloneRegisteredClaims(src.RegisteredClaims)
	dst.Roles = slices.Clone(src.Roles)
	dst.AuthTime = cloneNumericDate(src.AuthTime)
	dst.Ext = cloneExtMap(src.Ext)
	dst.Custom = cloneExtMap(src.Custom)
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
	copyDate := *src
	return &copyDate
}

// cloneExtMap 递归拷贝扩展字段。JSON 解码只会产出 map[string]any 与 []any 两种容器，
// 其余值都是标量，按值复制即可。
func cloneExtMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for key, value := range src {
		dst[key] = cloneExtValue(value)
	}
	return dst
}

func cloneExtValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		return cloneExtMap(v)
	case []any:
		dst := make([]any, len(v))
		for i, item := range v {
			dst[i] = cloneExtValue(item)
		}
		return dst
	default:
		return value
	}
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

// notInitResults 返回 nil receiver 上并发验签的结果：与输入等长，错误全部为 ErrJWTNotInit，
// 调用方按输入下标读取不会越界。
func notInitResults(n int) ([]*claims.Claims, []error) {
	errs := make([]error, n)
	for i := range errs {
		errs[i] = ErrJWTNotInit
	}
	return make([]*claims.Claims, n), errs
}

// parallelVerifyClaimsContext 使用有界 worker pool 并发验证多个 token，并尊重 ctx 取消。
// 结果顺序与输入顺序严格对齐；取消后未开始的任务返回 ctx.Err()。
func parallelVerifyClaimsContext(ctx context.Context, tokens []string, verify func(string) (*claims.Claims, error)) ([]*claims.Claims, []error) {
	results := make([]*claims.Claims, len(tokens))
	errs := make([]error, len(tokens))
	if len(tokens) == 0 {
		return results, errs
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		for i := range errs {
			errs[i] = err
		}
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
		if err := ctx.Err(); err != nil {
			for remaining := index; remaining < len(tokens); remaining++ {
				errs[remaining] = err
			}
			close(jobs)
			wg.Wait()
			return results, errs
		}
		select {
		case <-ctx.Done():
			err := ctx.Err()
			for remaining := index; remaining < len(tokens); remaining++ {
				errs[remaining] = err
			}
			close(jobs)
			wg.Wait()
			return results, errs
		case jobs <- index:
		}
	}
	close(jobs)

	wg.Wait()
	return results, errs
}

// ----------------------- 通用 JWT 操作方法 -----------------------
// 以下函数消除了 JwtHmac / JwtEd25519 / JwtRSA 之间的重复代码。

// generateTokenImpl 是 GenerateToken 的通用实现。
// cfg 来自具体实例的 config，signFn 由具体实现提供（签名方式不同）。
func generateTokenImpl(cfg *config, uid int64, options []claims.Option, signFn func(*claims.Claims) (string, error)) (string, error) {
	tokenID, err := generateTokenID()
	if err != nil {
		return "", err
	}

	now := time.Now()
	tokenClaims := &claims.Claims{
		UserID:   uid,
		TokenID:  tokenID,
		AuthTime: &jwtv5.NumericDate{Time: now},
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: &jwtv5.NumericDate{Time: now.Add(cfg.tokenDuration)},
			NotBefore: &jwtv5.NumericDate{Time: now},
			IssuedAt:  &jwtv5.NumericDate{Time: now},
			ID:        tokenID,
		},
	}

	for _, opt := range options {
		if opt == nil {
			continue
		}
		opt(tokenClaims)
	}
	alignTokenIdentifiers(tokenClaims, tokenID)

	return signFn(tokenClaims)
}

// parseTokenImplContext 是 ParseTokenContext 的通用实现。
// 解析选项按 包内默认 → 实例级 WithParserOptions → 单次调用 的顺序应用；
// 默认要求 exp 存在并校验 iat，本包签发的 token 天然满足。
// keyFunc 由具体实现提供（获取验签密钥并验证算法）。
func parseTokenImplContext(ctx context.Context, cfg *config, tokenString string, opt []jwtv5.ParserOption, keyFunc func(*jwtv5.Token) (any, error), expectedAlg string) (*claims.Claims, error) {
	if tokenString == "" || len(tokenString) > MaxTokenBytes {
		return nil, ErrTokenMalformed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if _, err := readTokenHeader(tokenString); err != nil {
		return nil, err
	}
	parserOptions := validationOptions(cfg, opt)
	parserOptions = append(parserOptions, jwtv5.WithValidMethods([]string{expectedAlg}), jwtv5.WithStrictDecoding(), jwtv5.WithoutClaimsValidation())
	if err := validateTokenPayload(tokenString, parserOptions); err != nil {
		return nil, err
	}
	c := &claims.Claims{}
	parsed := &strictTokenClaims{Claims: c, allowNumericSubject: cfg.numericSubject}
	method, err := verificationMethod(expectedAlg)
	if err != nil {
		return nil, err
	}
	token, err := jwtv5.ParseWithClaims(tokenString, parsed, func(token *jwtv5.Token) (any, error) {
		if token.Method == nil || token.Method.Alg() != expectedAlg {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		token.Method = method
		return keyFunc(token)
	}, parserOptions...)
	if err != nil {
		return nil, normalizeParseError(err)
	}

	if !token.Valid {
		return nil, ErrTokenInvalid
	}
	if err := jwtv5.NewValidator(validationOptions(cfg, opt)...).Validate(c); err != nil {
		return nil, normalizeParseError(err)
	}
	if err := finalizeTokenIdentifiers(c); err != nil {
		return nil, err
	}

	if err := checkClaimsValidator(ctx, cfg, c); err != nil {
		return nil, err
	}
	if err := checkRevocation(ctx, cfg, c); err != nil {
		return nil, err
	}

	return c, nil
}

// refreshTokenImplContext 是 RefreshTokenContext 的通用实现。
// parseFn 和 signFn 由具体实现提供。
func refreshTokenImplContext(ctx context.Context, cfg *config, tokenString string, opt []jwtv5.ParserOption, parseFn func(context.Context, string, ...jwtv5.ParserOption) (*claims.Claims, error), signFn func(*claims.Claims) (string, error)) (string, error) {
	tokenClaims, err := parseFn(ctx, tokenString, opt...)
	if err != nil {
		return "", err
	}

	if err := refreshTokenClaims(tokenClaims, cfg); err != nil {
		return "", err
	}

	return signFn(tokenClaims)
}

// cachedParseTokenImplContext 是 CachedParseTokenContext 的通用实现。
// parseFn 由具体实现提供，通常指向具体类型的 ParseTokenContext。
func cachedParseTokenImplContext(ctx context.Context, cfg *config, cache *claimsCache, tokenString string, opt []jwtv5.ParserOption, parseFn func(context.Context, string, ...jwtv5.ParserOption) (*claims.Claims, error)) (*claims.Claims, error) {
	if tokenString == "" || len(tokenString) > MaxTokenBytes {
		return nil, ErrTokenMalformed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(opt) > 0 || cfg.cacheMaxEntries <= 0 {
		return parseFn(ctx, tokenString, opt...)
	}

	if c, ok := loadCachedClaims(cache, tokenString); ok {
		if err := jwtv5.NewValidator(validationOptions(cfg, nil)...).Validate(c); err != nil {
			return nil, normalizeParseError(err)
		}
		if err := checkClaimsValidator(ctx, cfg, c); err != nil {
			return nil, err
		}
		if err := checkRevocation(ctx, cfg, c); err != nil {
			return nil, err
		}
		return c, nil
	}

	tokenClaims, err := parseFn(ctx, tokenString, opt...)
	if err != nil {
		return nil, err
	}

	storeCachedClaims(cache, cfg.cacheMaxEntries, tokenString, tokenClaims)
	return tokenClaims, nil
}

// checkClaimsValidator 把应用校验与吊销检查分开，并隔离回调可修改的 claims。
func checkClaimsValidator(ctx context.Context, cfg *config, tokenClaims *claims.Claims) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if cfg.claimsValidator == nil {
		return nil
	}
	if err := cfg.claimsValidator(ctx, cloneClaims(tokenClaims)); err != nil {
		return fmt.Errorf("%w: claims validator: %w", ErrTokenInvalidClaims, err)
	}
	return nil
}

// parallelVerifyImplContext 是 ParallelVerifyContext 的通用实现。
func parallelVerifyImplContext(ctx context.Context, tokens []string, opt []jwtv5.ParserOption, parseFn func(context.Context, string, ...jwtv5.ParserOption) (*claims.Claims, error)) ([]*claims.Claims, []error) {
	return parallelVerifyClaimsContext(ctx, tokens, func(token string) (*claims.Claims, error) {
		return parseFn(ctx, token, opt...)
	})
}

// signToken 用指定算法签发 token，keyID 非空时写入 header 的 kid。
// 四种签名实现共用此函数，保证 kid 的写入时机与格式一致。
func signToken(method jwtv5.SigningMethod, tokenClaims jwtv5.Claims, keyID string, signKey any) (string, error) {
	token := jwtv5.NewWithClaims(method, tokenClaims)
	if keyID != "" {
		token.Header["kid"] = keyID
	}
	return token.SignedString(signKey)
}

// ParseKeyID 从 token 中取出 header 的 kid，用于在验签前定位该用哪一把密钥。
// token 未携带 kid 时返回空字符串和 nil error。
//
// 本函数不验证签名，也不校验 claims 时效，只对 header 段做 base64 与 JSON 解码。
// 返回的 kid 因此来自未经验证的数据，调用方可以用它挑选密钥，
// 但必须再用选中的密钥走一次 ParseToken 完成验签，
// 不能拿它直接做任何鉴权或授权判断。
// 多把密钥并存时优先使用 KeyRing，它把选键与验签合成一次调用。
//
// 使用示例：
//
//	kid, err := gojwt.ParseKeyID(tokenString)
//	if err != nil {
//	    return err
//	}
//	j, ok := jwtByKeyID[kid]
//	if !ok {
//	    return gojwt.ErrUnknownKeyID
//	}
//	cc, err := j.ParseToken(tokenString) // 验签在这一步完成
func ParseKeyID(tokenString string) (string, error) {
	// 只取 header 段：为读一个 kid 去解码整份 claims 既有额外开销，
	// 又会让 claims 的格式问题传导成"读不到 kid"。
	header, err := readTokenHeader(tokenString)
	if err != nil {
		return "", err
	}
	return keyIDFromHeader(header)
}

func keyIDFromHeader(header map[string]json.RawMessage) (string, error) {
	rawKID, ok := header["kid"]
	if !ok {
		return "", nil
	}
	var kid *string
	if err := json.Unmarshal(rawKID, &kid); err != nil {
		return "", fmt.Errorf("%w: invalid kid: %w", ErrTokenMalformed, err)
	}
	if kid == nil {
		return "", fmt.Errorf("%w: kid must be a string", ErrTokenMalformed)
	}
	return *kid, nil
}
