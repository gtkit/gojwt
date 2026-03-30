package gojwt

import (
	"fmt"
	"sync"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

// JwtHmac 基于 HMAC-SHA256 签名的 JWT 实例。
type JwtHmac struct {
	secretKey []byte
	config
	cache claimsCache
}

// minHMACKeySize 是 HMAC 密钥的最小字节长度。
const minHMACKeySize = 32

// NewJwtHmac 创建 HMAC-SHA256 JWT 实例。
// secretKey 长度必须 >= 32 字节，否则返回错误。
func NewJwtHmac(secretKey []byte, options ...Option) (*JwtHmac, error) {
	if len(secretKey) < minHMACKeySize {
		return nil, fmt.Errorf("secret key must be at least %d bytes, got %d", minHMACKeySize, len(secretKey))
	}

	j := &JwtHmac{
		secretKey: append([]byte(nil), secretKey...),
		config:    defaultConfig(),
	}
	for _, opt := range options {
		opt(&j.config)
	}

	return j, nil
}

// GenerateToken 根据用户 ID 生成 JWT token。
// 自动写入 exp、iat、nbf 并生成唯一 TokenID。
// 可通过 claims.Option 附加业务字段（角色、业务域、签发者等）。
func (j *JwtHmac) GenerateToken(uid int64, options ...claims.Option) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	tokenID, err := generateTokenID()
	if err != nil {
		return "", err
	}

	now := time.Now()
	tokenClaims := &claims.Claims{
		UserID:  uid,
		TokenID: tokenID,
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(now.Add(j.tokenDuration)),
			NotBefore: jwtv5.NewNumericDate(now),
			IssuedAt:  jwtv5.NewNumericDate(now),
			ID:        tokenID,
		},
	}

	for _, opt := range options {
		opt(tokenClaims)
	}

	return createHmacToken(*tokenClaims, j.secretKey)
}

// RefreshToken 在刷新窗口内刷新 JWT token。
// 仅当 token 距过期不足 refreshWindow（5 分钟）时允许刷新，
// 否则返回 ErrRefreshTooEarly；超过 refreshDuration 则返回 ErrTokenExpired。
func (j *JwtHmac) RefreshToken(tokenString string, opt ...jwtv5.ParserOption) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	tokenClaims, err := j.ParseToken(tokenString, opt...)
	if err != nil {
		return "", err
	}

	if err := refreshTokenClaims(tokenClaims, j.tokenDuration, j.refreshDuration); err != nil {
		return "", err
	}

	tokenClaims.RegisteredClaims.ID = tokenClaims.TokenID
	return createHmacToken(*tokenClaims, j.secretKey)
}

// ParseToken 解析并验证 JWT token。
// 完成签名验证、标准时间字段校验后返回 *claims.Claims。
// 如果通过 WithBlacklistFunc 配置了黑名单检查函数，
// 解析成功后会自动检查 tokenID 是否被拉黑。
func (j *JwtHmac) ParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	if tokenString == "" {
		return nil, ErrTokenMalformed
	}
	token, err := jwtv5.ParseWithClaims(tokenString, &claims.Claims{}, func(token *jwtv5.Token) (any, error) {
		if _, ok := token.Method.(*jwtv5.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	}, opt...)
	if err != nil {
		return nil, normalizeParseError(err)
	}

	c, ok := token.Claims.(*claims.Claims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}

	// 黑名单检查：如果注入了检查函数且 tokenID 在黑名单中，拒绝该 token
	if j.isBlacklisted != nil && c.TokenID != "" && j.isBlacklisted(c.TokenID) {
		return nil, ErrTokenBlacklisted
	}

	return c, nil
}

// CachedParseToken 带缓存的 ParseToken，相同 tokenString 不重复解析。
// 返回的是 Claims 的深拷贝副本，调用方修改不会影响缓存。
// 即使缓存命中，仍会检查黑名单（token 可能在缓存后被加入黑名单）。
func (j *JwtHmac) CachedParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	if tokenString == "" {
		return nil, ErrTokenMalformed
	}

	if c, ok := loadCachedClaims(&j.cache, tokenString); ok {
		// 缓存命中后仍需检查黑名单
		if j.isBlacklisted != nil && c.TokenID != "" && j.isBlacklisted(c.TokenID) {
			return nil, ErrTokenBlacklisted
		}
		return c, nil
	}

	tokenClaims, err := j.ParseToken(tokenString, opt...)
	if err != nil {
		return nil, err
	}

	storeCachedClaims(&j.cache, tokenString, tokenClaims)
	return tokenClaims, nil
}

// ParallelVerify 并发验证多个 token。
// results[i] 与 errs[i] 对应同一个输入 tokens[i]。
func (j *JwtHmac) ParallelVerify(tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error) {
	var wg sync.WaitGroup
	results := make([]*claims.Claims, len(tokens))
	errs := make([]error, len(tokens))

	for i, token := range tokens {
		wg.Go(func() {
			tokenClaims, err := j.ParseToken(token, opt...)
			results[i] = tokenClaims
			errs[i] = err
		})
	}

	wg.Wait()
	return results, errs
}

// createHmacToken 使用 HMAC-SHA256 签名并返回 token 字符串。
func createHmacToken(claims claims.Claims, signKey any) (string, error) {
	return jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims).SignedString(signKey)
}
