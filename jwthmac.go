package gojwt

import (
	"fmt"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

// JwtHmac 基于 HMAC-SHA 家族签名的 JWT 实例。
// 默认使用 HS256，可通过 Option 切换到 HS384 / HS512。
type JwtHmac struct {
	secretKey     []byte
	signingMethod *jwtv5.SigningMethodHMAC
	config
	cache claimsCache
}

// NewJwtHmac 创建 HMAC JWT 实例。
// 默认使用 HS256，可通过 WithHMACSigningMethod 切换到 HS384 / HS512。
func NewJwtHmac(secretKey []byte, options ...Option) (*JwtHmac, error) {
	j := &JwtHmac{
		secretKey: append([]byte(nil), secretKey...),
		config:    defaultConfig(),
	}
	for _, opt := range options {
		opt(&j.config)
	}
	if err := validateConfig(j.config); err != nil {
		return nil, err
	}
	signingMethod, err := resolveHMACSigningMethod(j.config.hmacSigningMethod, j.config.hmacSigningSet)
	if err != nil {
		return nil, err
	}
	if err := validateHMACSecretKey(j.secretKey, signingMethod); err != nil {
		return nil, err
	}
	j.signingMethod = signingMethod

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
	alignTokenIdentifiers(tokenClaims, tokenID)

	return createHmacToken(*tokenClaims, j.secretKey, j.hmacSigningMethod())
}

// RefreshToken 在刷新窗口内刷新 JWT token。
// 仅当 token 距过期不足 refreshWindow（5 分钟）时允许刷新，
// 否则返回 ErrRefreshTooEarly；超过 refreshDuration 则返回 ErrTokenExpired。
// 刷新成功后会生成新的 TokenID/jti，并重置 iat、nbf，旧 token 与新 token 可独立吊销。
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
	return createHmacToken(*tokenClaims, j.secretKey, j.hmacSigningMethod())
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
	signingMethod := j.hmacSigningMethod()
	parserOptions := append([]jwtv5.ParserOption{
		jwtv5.WithValidMethods([]string{signingMethod.Alg()}),
		jwtv5.WithLeeway(j.parseLeeway),
	}, opt...)
	token, err := jwtv5.ParseWithClaims(tokenString, &claims.Claims{}, func(token *jwtv5.Token) (any, error) {
		if token.Method == nil || token.Method.Alg() != signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return j.secretKey, nil
	}, parserOptions...)
	if err != nil {
		return nil, normalizeParseError(err)
	}

	c, ok := token.Claims.(*claims.Claims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}

	if err := checkBlacklist(&j.config, c.TokenID); err != nil {
		return nil, err
	}

	return c, nil
}

// CachedParseToken 带缓存的 ParseToken，相同 tokenString 不重复解析。
// 返回的是 Claims 的深拷贝副本，调用方修改不会影响缓存。
// 即使缓存命中，仍会检查黑名单（token 可能在缓存后被加入黑名单）。
// 当调用方传入 ParserOption 时，为避免缓存绕过更严格的校验条件，会直接退化为 ParseToken。
func (j *JwtHmac) CachedParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	if tokenString == "" {
		return nil, ErrTokenMalformed
	}
	if len(opt) > 0 {
		return j.ParseToken(tokenString, opt...)
	}

	if c, ok := loadCachedClaims(&j.cache, tokenString); ok {
		if err := checkBlacklist(&j.config, c.TokenID); err != nil {
			return nil, err
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
	return parallelVerifyClaims(tokens, func(token string) (*claims.Claims, error) {
		return j.ParseToken(token, opt...)
	})
}

// createHmacToken 使用指定的 HMAC-SHA 签名算法并返回 token 字符串。
func createHmacToken(claims claims.Claims, signKey any, signingMethod *jwtv5.SigningMethodHMAC) (string, error) {
	return jwtv5.NewWithClaims(signingMethod, claims).SignedString(signKey)
}

func (j *JwtHmac) hmacSigningMethod() *jwtv5.SigningMethodHMAC {
	if j != nil && j.signingMethod != nil {
		return j.signingMethod
	}
	return jwtv5.SigningMethodHS256
}

func resolveHMACSigningMethod(method *jwtv5.SigningMethodHMAC, configured bool) (*jwtv5.SigningMethodHMAC, error) {
	if !configured {
		return jwtv5.SigningMethodHS256, nil
	}
	if method == nil {
		return nil, fmt.Errorf("%w: HMAC signing method must not be nil", ErrInvalidConfig)
	}

	switch method.Alg() {
	case jwtv5.SigningMethodHS256.Alg():
		return jwtv5.SigningMethodHS256, nil
	case jwtv5.SigningMethodHS384.Alg():
		return jwtv5.SigningMethodHS384, nil
	case jwtv5.SigningMethodHS512.Alg():
		return jwtv5.SigningMethodHS512, nil
	default:
		return nil, fmt.Errorf("%w: unsupported HMAC signing method %q", ErrInvalidConfig, method.Alg())
	}
}

func validateHMACSecretKey(secretKey []byte, signingMethod *jwtv5.SigningMethodHMAC) error {
	minKeySize := minHMACKeySize(signingMethod)
	if len(secretKey) < minKeySize {
		return fmt.Errorf("%w: secret key must be at least %d bytes for %s, got %d", ErrInvalidConfig, minKeySize, signingMethod.Alg(), len(secretKey))
	}
	return nil
}

func minHMACKeySize(signingMethod *jwtv5.SigningMethodHMAC) int {
	switch signingMethod.Alg() {
	case jwtv5.SigningMethodHS384.Alg():
		return 48
	case jwtv5.SigningMethodHS512.Alg():
		return 64
	default:
		return 32
	}
}
