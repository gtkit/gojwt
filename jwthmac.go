package gojwt

import (
	"bytes"
	"context"
	"fmt"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

// JwtHmac 基于 HMAC-SHA 家族签名的 JWT 实例。
// 默认使用 HS256，可通过 Option 切换到 HS384 / HS512。
// JwtHmac 可被多个 goroutine 并发使用。
type JwtHmac struct {
	secretKey     []byte
	signingMethod *jwtv5.SigningMethodHMAC
	config
	cache claimsCache
}

// NewJwtHmac 创建 HMAC JWT 实例。
// 默认使用 HS256，可通过 WithHMACSigningMethod 切换到 HS384 / HS512。
// 密钥长度不足该算法最小要求时返回 ErrInvalidConfig；用 GenerateHMACKeyString 生成的密钥总能满足。
func NewJwtHmac(secretKey []byte, options ...Option) (*JwtHmac, error) {
	cfg, err := newConfig(options...)
	if err != nil {
		return nil, err
	}
	if cfg.rsaSigningSet || cfg.ecdsaSigningSet {
		return nil, fmt.Errorf("%w: RSA/ECDSA signing method option is not applicable to HMAC", ErrInvalidConfig)
	}

	signingMethod, err := resolveHMACSigningMethod(cfg.hmacSigningMethod, cfg.hmacSigningSet)
	if err != nil {
		return nil, err
	}
	if err := validateHMACSecretKey(secretKey, signingMethod); err != nil {
		return nil, err
	}

	return &JwtHmac{
		secretKey:     bytes.Clone(secretKey),
		signingMethod: signingMethod,
		config:        cfg,
	}, nil
}

// GenerateToken 根据用户 ID 生成 JWT token。
// 自动写入 exp、iat、nbf、auth_time 并生成唯一 TokenID。
// 可通过 claims.Option 附加业务字段（角色、业务域、签发者等）。
func (j *JwtHmac) GenerateToken(uid int64, options ...claims.Option) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	return generateTokenImpl(&j.config, uid, options, j.sign)
}

// RefreshToken 在刷新窗口内刷新 JWT token。
// 仅当 token 距过期不足刷新窗口时允许刷新，否则返回 ErrRefreshTooEarly；
// 会话已到 auth_time + refreshDuration 则返回 ErrRefreshExpired。
// 刷新成功后会生成新的 TokenID/jti，并重置 iat、nbf，旧 token 与新 token 可独立吊销。
func (j *JwtHmac) RefreshToken(tokenString string, opt ...jwtv5.ParserOption) (string, error) {
	return j.RefreshTokenContext(context.Background(), tokenString, opt...)
}

// RefreshTokenContext 在刷新窗口内刷新 JWT token，并尊重 ctx 取消和 deadline。
func (j *JwtHmac) RefreshTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	return refreshTokenImplContext(ctx, &j.config, tokenString, opt, j.ParseTokenContext, j.sign)
}

// ParseToken 解析并验证 JWT token。
// 完成签名验证、标准时间字段校验后返回 *claims.Claims。
// 配置了黑名单或吊销回调时，解析成功后会自动执行吊销检查。
func (j *JwtHmac) ParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	return j.ParseTokenContext(context.Background(), tokenString, opt...)
}

// ParseTokenContext 解析并验证 JWT token，并尊重 ctx 取消和 deadline。
func (j *JwtHmac) ParseTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	return parseTokenImplContext(ctx, &j.config, tokenString, opt, func(_ *jwtv5.Token) (any, error) {
		return j.secretKey, nil
	}, j.signingMethod.Alg())
}

// CachedParseToken 带缓存的 ParseToken，相同 tokenString 不重复解析。
// 返回的是 Claims 的深拷贝副本，调用方修改不会影响缓存。
// 即使缓存命中，仍会执行吊销检查（token 可能在缓存后被吊销）。
// 当调用方传入 ParserOption 时，为避免缓存绕过更严格的校验条件，会直接退化为 ParseToken。
func (j *JwtHmac) CachedParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	return j.CachedParseTokenContext(context.Background(), tokenString, opt...)
}

// CachedParseTokenContext 带缓存解析 JWT token，并尊重 ctx 取消和 deadline。
func (j *JwtHmac) CachedParseTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	return cachedParseTokenImplContext(ctx, &j.config, &j.cache, tokenString, opt, j.ParseTokenContext)
}

// ParallelVerify 并发验证多个 token。
// results[i] 与 errs[i] 对应同一个输入 tokens[i]。
func (j *JwtHmac) ParallelVerify(tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error) {
	return j.ParallelVerifyContext(context.Background(), tokens, opt...)
}

// ParallelVerifyContext 并发验证多个 token，并在 ctx 取消后停止分发未开始的任务。
// results[i] 与 errs[i] 对应同一个输入 tokens[i]。
func (j *JwtHmac) ParallelVerifyContext(ctx context.Context, tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error) {
	if j == nil {
		return notInitResults(len(tokens))
	}
	return parallelVerifyImplContext(ctx, tokens, opt, j.ParseTokenContext)
}

func (j *JwtHmac) sign(tokenClaims *claims.Claims) (string, error) {
	return signToken(j.signingMethod, tokenClaims, j.keyID, j.secretKey)
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

// minHMACKeySize 按 RFC 7518 §3.2 返回各算法的最小密钥长度：与哈希输出等长。
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
