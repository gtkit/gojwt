package gojwt

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

// JwtRSA 基于 RSA 签名的 JWT 实例。
// 默认使用 RS256，可通过 WithRSASigningMethod 切换到
// RS384 / RS512（PKCS1-v1_5）或 PS256 / PS384 / PS512（PSS）。
// JwtRSA 可被多个 goroutine 并发使用。
type JwtRSA struct {
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	signingMethod jwtv5.SigningMethod
	config
	cache claimsCache
}

// NewJwtRSA 从 PEM 文件加载 RSA 密钥对，创建 JWT 实例。
// priPath 为 PKCS1 或 PKCS8 格式私钥路径，pubPath 为 PKIX 格式公钥路径。
// 默认使用 RS256，可通过 WithRSASigningMethod 切换算法。
func NewJwtRSA(priPath, pubPath string, options ...Option) (*JwtRSA, error) {
	privateKey, err := readRSAPrivateKey(priPath)
	if err != nil {
		return nil, err
	}
	publicKey, err := readRSAPublicKey(pubPath)
	if err != nil {
		return nil, err
	}
	cfg, err := newConfig(options...)
	if err != nil {
		return nil, err
	}

	j := &JwtRSA{
		privateKey: privateKey,
		publicKey:  publicKey,
		config:     cfg,
	}
	if j.hmacSigningSet {
		return nil, fmt.Errorf("%w: HMAC signing method option is not applicable to RSA", ErrInvalidConfig)
	}

	signingMethod, err := resolveRSASigningMethod(j.rsaSigningMethod, j.rsaSigningSet)
	if err != nil {
		return nil, err
	}
	j.signingMethod = signingMethod

	if err := prepareRSAKeys(j, signingMethod); err != nil {
		return nil, err
	}

	return j, nil
}

// NewJwtRSAFromKeys 直接使用内存中的 RSA 密钥对创建 JWT 实例。
// 适用于密钥来自 KMS、Vault 等外部系统的场景。
func NewJwtRSAFromKeys(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, options ...Option) (*JwtRSA, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("%w: RSA private key must not be nil", ErrInvalidKey)
	}
	if publicKey == nil {
		return nil, fmt.Errorf("%w: RSA public key must not be nil", ErrInvalidKey)
	}
	cfg, err := newConfig(options...)
	if err != nil {
		return nil, err
	}

	j := &JwtRSA{
		privateKey: privateKey,
		publicKey:  publicKey,
		config:     cfg,
	}
	if j.hmacSigningSet {
		return nil, fmt.Errorf("%w: HMAC signing method option is not applicable to RSA", ErrInvalidConfig)
	}

	signingMethod, err := resolveRSASigningMethod(j.rsaSigningMethod, j.rsaSigningSet)
	if err != nil {
		return nil, err
	}
	j.signingMethod = signingMethod

	if err := prepareRSAKeys(j, signingMethod); err != nil {
		return nil, err
	}

	return j, nil
}

// GenerateToken 根据用户 ID 生成 JWT token。
// 自动写入 exp、iat、nbf 并生成唯一 TokenID。
// 可通过 claims.Option 附加业务字段。
func (j *JwtRSA) GenerateToken(uid int64, options ...claims.Option) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	return generateTokenImpl(&j.config, uid, options, func(cc *claims.Claims) (string, error) {
		return signToken(j.signingMethod, cc, j.keyID, j.privateKey)
	})
}

// RefreshToken 在刷新窗口内刷新 JWT token。
// 仅当 token 距过期不足 refreshWindow（5 分钟）时允许刷新，
// 否则返回 ErrRefreshTooEarly；超过 refreshDuration 则返回 ErrTokenExpired。
// 刷新成功后会生成新的 TokenID/jti，并重置 iat、nbf，旧 token 与新 token 可独立吊销。
func (j *JwtRSA) RefreshToken(tokenString string, opt ...jwtv5.ParserOption) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	return refreshTokenImplContext(context.Background(), &j.config, tokenString, opt, j.ParseTokenContext, func(cc *claims.Claims) (string, error) {
		return signToken(j.signingMethod, cc, j.keyID, j.privateKey)
	})
}

// RefreshTokenContext 在刷新窗口内刷新 JWT token，并尊重 ctx 取消和 deadline。
func (j *JwtRSA) RefreshTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	return refreshTokenImplContext(ctx, &j.config, tokenString, opt, j.ParseTokenContext, func(cc *claims.Claims) (string, error) {
		return signToken(j.signingMethod, cc, j.keyID, j.privateKey)
	})
}

// ParseToken 解析并验证 JWT token。
// 完成 RSA 签名验证后返回 *claims.Claims。
// 如果通过 WithBlacklistFunc 配置了黑名单检查函数，
// 解析成功后会自动检查 tokenID 是否被拉黑。
func (j *JwtRSA) ParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	return j.ParseTokenContext(context.Background(), tokenString, opt...)
}

// ParseTokenContext 解析并验证 JWT token，并尊重 ctx 取消和 deadline。
func (j *JwtRSA) ParseTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	return parseTokenImplContext(ctx, &j.config, tokenString, opt, func(_ *jwtv5.Token) (any, error) {
		return j.publicKey, nil
	}, j.signingMethod.Alg())
}

// CachedParseToken 带缓存的 ParseToken，相同 tokenString 不重复解析。
// 即使缓存命中，仍会检查黑名单。
// 当调用方传入 ParserOption 时，为避免缓存绕过更严格的校验条件，会直接退化为 ParseToken。
func (j *JwtRSA) CachedParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	return j.CachedParseTokenContext(context.Background(), tokenString, opt...)
}

// CachedParseTokenContext 带缓存解析 JWT token，并尊重 ctx 取消和 deadline。
func (j *JwtRSA) CachedParseTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	return cachedParseTokenImplContext(ctx, &j.config, &j.cache, tokenString, opt, j.ParseTokenContext)
}

// ParallelVerify 并发验证多个 token。
// results[i] 与 errs[i] 对应同一个输入 tokens[i]。
func (j *JwtRSA) ParallelVerify(tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error) {
	if j == nil {
		return nil, nil
	}
	return parallelVerifyImpl(tokens, opt, j.ParseToken)
}

// ParallelVerifyContext 并发验证多个 token，并在 ctx 取消后停止分发未开始的任务。
// results[i] 与 errs[i] 对应同一个输入 tokens[i]。
func (j *JwtRSA) ParallelVerifyContext(ctx context.Context, tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error) {
	if j == nil {
		return nil, nil
	}
	return parallelVerifyImplContext(ctx, tokens, opt, j.ParseTokenContext)
}

// readRSAPrivateKey 从 PEM 文件读取 RSA 私钥。
// 支持 "RSA PRIVATE KEY"（PKCS1 格式）和 "PRIVATE KEY"（PKCS8 格式）。
func readRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	block, err := readPEMBlock(path)
	if err != nil {
		return nil, err
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: expected RSA private key, got %T", ErrInvalidKeyType, key)
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("invalid private key PEM type: %s", block.Type)
	}
}

// readRSAPublicKey 从 PEM 文件读取 RSA 公钥。
// 支持 "RSA PUBLIC KEY"（PKCS1 格式）和 "PUBLIC KEY"（PKIX 格式）。
func readRSAPublicKey(path string) (*rsa.PublicKey, error) {
	block, err := readPEMBlock(path)
	if err != nil {
		return nil, err
	}

	switch block.Type {
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: expected RSA public key, got %T", ErrInvalidKeyType, key)
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("invalid public key PEM type: %s", block.Type)
	}
}

// resolveRSASigningMethod 解析 RSA 签名算法配置，默认 RS256。
func resolveRSASigningMethod(method jwtv5.SigningMethod, configured bool) (jwtv5.SigningMethod, error) {
	if !configured {
		return jwtv5.SigningMethodRS256, nil
	}
	if method == nil {
		return nil, fmt.Errorf("%w: RSA signing method must not be nil", ErrInvalidConfig)
	}

	switch method.Alg() {
	case jwtv5.SigningMethodRS256.Alg(),
		jwtv5.SigningMethodRS384.Alg(),
		jwtv5.SigningMethodRS512.Alg(),
		jwtv5.SigningMethodPS256.Alg(),
		jwtv5.SigningMethodPS384.Alg(),
		jwtv5.SigningMethodPS512.Alg():
		return method, nil
	default:
		return nil, fmt.Errorf("%w: unsupported RSA signing method %q", ErrInvalidConfig, method.Alg())
	}
}

// validateRSAKeySize 根据签名算法验证 RSA 密钥长度。
// RS256/PS256 要求至少 2048 bit，RS384/PS384 要求至少 3072 bit，
// RS512/PS512 要求至少 4096 bit。
func validateRSAKeySize(key *rsa.PrivateKey, method jwtv5.SigningMethod) error {
	if key == nil {
		return fmt.Errorf("%w: RSA private key must not be nil", ErrInvalidKey)
	}

	keyBits := key.N.BitLen()
	minBits := minRSAKeyBits(method)
	if keyBits < minBits {
		return fmt.Errorf("%w: RSA key must be at least %d bits for %s, got %d",
			ErrInvalidConfig, minBits, method.Alg(), keyBits)
	}
	return nil
}

func prepareRSAKeys(j *JwtRSA, signingMethod jwtv5.SigningMethod) error {
	privateKey, err := cloneRSAPrivateKey(j.privateKey)
	if err != nil {
		return err
	}
	publicKey, err := cloneRSAPublicKey(j.publicKey)
	if err != nil {
		return err
	}
	if privateKey.N.Cmp(publicKey.N) != 0 || privateKey.E != publicKey.E {
		return fmt.Errorf("%w: RSA private and public keys do not match", ErrInvalidKey)
	}
	if err := validateRSAKeySize(privateKey, signingMethod); err != nil {
		return err
	}
	privateKey.Precompute()
	if err := privateKey.Validate(); err != nil {
		return fmt.Errorf("%w: validate RSA private key: %w", ErrInvalidKey, err)
	}

	j.privateKey = privateKey
	j.publicKey = publicKey
	return nil
}

func cloneRSAPublicKey(key *rsa.PublicKey) (*rsa.PublicKey, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: RSA public key must not be nil", ErrInvalidKey)
	}
	if key.N == nil {
		return nil, fmt.Errorf("%w: RSA public key modulus must not be nil", ErrInvalidKey)
	}
	return &rsa.PublicKey{
		N: new(big.Int).Set(key.N),
		E: key.E,
	}, nil
}

func cloneRSAPrivateKey(key *rsa.PrivateKey) (*rsa.PrivateKey, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: RSA private key must not be nil", ErrInvalidKey)
	}
	if key.D == nil {
		return nil, fmt.Errorf("%w: RSA private exponent must not be nil", ErrInvalidKey)
	}
	if len(key.Primes) < 2 {
		return nil, fmt.Errorf("%w: RSA private key must contain at least two primes", ErrInvalidKey)
	}
	publicKey, err := cloneRSAPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	clone := &rsa.PrivateKey{
		PublicKey: *publicKey,
		D:         new(big.Int).Set(key.D),
		Primes:    make([]*big.Int, len(key.Primes)),
	}
	for i, prime := range key.Primes {
		if prime == nil {
			return nil, fmt.Errorf("%w: RSA prime %d must not be nil", ErrInvalidKey, i)
		}
		clone.Primes[i] = new(big.Int).Set(prime)
	}
	return clone, nil
}

func minRSAKeyBits(method jwtv5.SigningMethod) int {
	switch method.Alg() {
	case jwtv5.SigningMethodRS384.Alg(), jwtv5.SigningMethodPS384.Alg():
		return 3072
	case jwtv5.SigningMethodRS512.Alg(), jwtv5.SigningMethodPS512.Alg():
		return 4096
	default:
		return 2048
	}
}
