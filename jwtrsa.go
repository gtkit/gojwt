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

// minRSAKeyBits 是 RFC 7518 §3.3 对 RS/PS 全系列算法要求的最小模数长度。
const minRSAKeyBits = 2048

// JwtRSA 基于 RSA 签名的 JWT 实例。
// 默认使用 RS256，可通过 WithRSASigningMethod 切换到
// RS384 / RS512（PKCS1-v1_5）或 PS256 / PS384 / PS512（PSS）。
// JwtRSA 可被多个 goroutine 并发使用。
// 通过 NewJwtRSAVerifier / NewJwtRSAVerifierFromFile 创建的实例只持公钥，
// 其 GenerateToken / RefreshToken 返回 ErrNoSigningKey。
type JwtRSA struct {
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	signingMethod jwtv5.SigningMethod
	config
	cache claimsCache
}

// NewJwtRSA 从 PEM 文件加载 RSA 密钥对，创建 JWT 实例。
// priPath 为 PKCS1 或 PKCS8 格式私钥路径，pubPath 为 PKIX 或 PKCS1 格式公钥路径；两者不匹配返回 ErrInvalidKey。
// 默认使用 RS256，可通过 WithRSASigningMethod 切换算法。
func NewJwtRSA(priPath, pubPath string, options ...Option) (*JwtRSA, error) {
	privateKey, err := parseKeyFile(priPath, ParseRSAPrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	publicKey, err := parseKeyFile(pubPath, ParseRSAPublicKeyPEM)
	if err != nil {
		return nil, err
	}
	return newJwtRSA(privateKey, publicKey, options)
}

// NewJwtRSAFromKeys 直接使用内存中的 RSA 密钥对创建 JWT 实例。
// 适用于密钥来自 KMS、Vault 等外部系统的场景，PEM 字节可先用 ParseRSAPrivateKeyPEM /
// ParseRSAPublicKeyPEM 解析。输入密钥会被复制，构造后修改入参不影响实例。
func NewJwtRSAFromKeys(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, options ...Option) (*JwtRSA, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("%w: RSA private key must not be nil", ErrInvalidKey)
	}
	return newJwtRSA(privateKey, publicKey, options)
}

// NewJwtRSAVerifier 使用内存中的 RSA 公钥创建只做验签的实例。
// 适用于只持公钥的服务、网关，以及持有第三方公钥验签其 RS/PS 系列 token 的场景。
func NewJwtRSAVerifier(publicKey *rsa.PublicKey, options ...Option) (*JwtRSA, error) {
	return newJwtRSA(nil, publicKey, options)
}

// NewJwtRSAVerifierFromFile 从 PEM 文件加载 RSA 公钥，创建只做验签的实例。
func NewJwtRSAVerifierFromFile(pubPath string, options ...Option) (*JwtRSA, error) {
	publicKey, err := parseKeyFile(pubPath, ParseRSAPublicKeyPEM)
	if err != nil {
		return nil, err
	}
	return newJwtRSA(nil, publicKey, options)
}

func newJwtRSA(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, options []Option) (*JwtRSA, error) {
	cfg, err := newConfig(options...)
	if err != nil {
		return nil, err
	}
	if cfg.hmacSigningSet {
		return nil, fmt.Errorf("%w: HMAC signing method option is not applicable to RSA", ErrInvalidConfig)
	}
	if cfg.ecdsaSigningSet {
		return nil, fmt.Errorf("%w: ECDSA signing method option is not applicable to RSA", ErrInvalidConfig)
	}
	signingMethod, err := resolveRSASigningMethod(cfg.rsaSigningMethod, cfg.rsaSigningSet)
	if err != nil {
		return nil, err
	}

	j := &JwtRSA{signingMethod: signingMethod, config: cfg}
	j.publicKey, err = cloneRSAPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	if privateKey == nil {
		return j, nil
	}

	j.privateKey, err = cloneRSAPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	if j.privateKey.N.Cmp(j.publicKey.N) != 0 || j.privateKey.E != j.publicKey.E {
		return nil, fmt.Errorf("%w: RSA private and public keys do not match", ErrInvalidKey)
	}
	j.privateKey.Precompute()
	if err := j.privateKey.Validate(); err != nil {
		return nil, fmt.Errorf("%w: validate RSA private key: %w", ErrInvalidKey, err)
	}
	return j, nil
}

// GenerateToken 根据用户 ID 生成 JWT token。
// 自动写入 exp、iat、nbf、auth_time 并生成唯一 TokenID。
// 可通过 claims.Option 附加业务字段。只持公钥的实例返回 ErrNoSigningKey。
func (j *JwtRSA) GenerateToken(uid int64, options ...claims.Option) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	if j.privateKey == nil {
		return "", ErrNoSigningKey
	}
	return generateTokenImpl(&j.config, uid, options, j.sign)
}

// RefreshToken 在刷新窗口内刷新 JWT token。
// 仅当 token 距过期不足刷新窗口时允许刷新，否则返回 ErrRefreshTooEarly；
// 会话已到 auth_time + refreshDuration 则返回 ErrRefreshExpired。
// 刷新成功后会生成新的 TokenID/jti，并重置 iat、nbf，旧 token 与新 token 可独立吊销。
// 同一旧 token 可被重复或并发续签，不自动去重、消费或吊销旧 token。
// 只持公钥的实例返回 ErrNoSigningKey。
func (j *JwtRSA) RefreshToken(tokenString string, opt ...jwtv5.ParserOption) (string, error) {
	return j.RefreshTokenContext(context.Background(), tokenString, opt...)
}

// RefreshTokenContext 在刷新窗口内刷新 JWT token，并尊重 ctx 取消和 deadline。
// 每次调用独立续签；调用方负责刷新去重、一次性消费、幂等重试与多实例一致性。
func (j *JwtRSA) RefreshTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	if j.privateKey == nil {
		return "", ErrNoSigningKey
	}
	return refreshTokenImplContext(ctx, &j.config, tokenString, opt, j.ParseTokenContext, j.sign)
}

// ParseToken 解析并验证 JWT token。
// 完成 RSA 签名验证后返回 *claims.Claims。
// 配置了黑名单或吊销回调时，解析成功后会自动执行吊销检查。
func (j *JwtRSA) ParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	return j.ParseTokenContext(context.Background(), tokenString, opt...)
}

// ParseTokenContext 解析并验证 JWT token，并尊重 ctx 取消和 deadline。
func (j *JwtRSA) ParseTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	return parseTokenImplContext(ctx, &j.config, tokenString, opt, func(token *jwtv5.Token) (any, error) {
		// ParseWithClaims 原先从全局注册表选方法；这里覆盖为本实例的严格副本。
		token.Method = j.signingMethod
		return j.publicKey, nil
	}, j.signingMethod.Alg())
}

// CachedParseToken 带缓存的 ParseToken，相同 tokenString 不重复解析。
// 即使缓存命中，仍会执行吊销检查。
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
	return j.ParallelVerifyContext(context.Background(), tokens, opt...)
}

// ParallelVerifyContext 并发验证多个 token，并在 ctx 取消后停止分发未开始的任务。
// results[i] 与 errs[i] 对应同一个输入 tokens[i]。
func (j *JwtRSA) ParallelVerifyContext(ctx context.Context, tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error) {
	if j == nil {
		return notInitResults(len(tokens))
	}
	return parallelVerifyImplContext(ctx, tokens, opt, j.ParseTokenContext)
}

func (j *JwtRSA) sign(tokenClaims *claims.Claims) (string, error) {
	return signToken(j.signingMethod, tokenClaims, j.keyID, j.privateKey)
}

// ParseRSAPrivateKeyPEM 解析 PEM 编码的 RSA 私钥。
// 支持 "RSA PRIVATE KEY"（PKCS1）与 "PRIVATE KEY"（PKCS8）两种块类型。
// PEM 解码失败、结构解析失败返回 ErrInvalidKey；PKCS8 中不是 RSA 密钥返回 ErrInvalidKeyType。
func ParseRSAPrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, err := decodePEMBlock(data)
	if err != nil {
		return nil, err
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse PKCS1 private key: %w", ErrInvalidKey, err)
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse PKCS8 private key: %w", ErrInvalidKey, err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: expected RSA private key, got %T", ErrInvalidKeyType, key)
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("%w: unsupported private key PEM type %q", ErrInvalidKey, block.Type)
	}
}

// ParseRSAPublicKeyPEM 解析 PEM 编码的 RSA 公钥。
// 支持 "RSA PUBLIC KEY"（PKCS1）与 "PUBLIC KEY"（PKIX）两种块类型。
// PEM 解码失败、结构解析失败返回 ErrInvalidKey；PKIX 中不是 RSA 密钥返回 ErrInvalidKeyType。
func ParseRSAPublicKeyPEM(data []byte) (*rsa.PublicKey, error) {
	block, err := decodePEMBlock(data)
	if err != nil {
		return nil, err
	}

	switch block.Type {
	case "RSA PUBLIC KEY":
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse PKCS1 public key: %w", ErrInvalidKey, err)
		}
		return key, nil
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse PKIX public key: %w", ErrInvalidKey, err)
		}
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: expected RSA public key, got %T", ErrInvalidKeyType, key)
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("%w: unsupported public key PEM type %q", ErrInvalidKey, block.Type)
	}
}

// resolveRSASigningMethod 解析 RSA 签名算法配置，默认 RS256。
func resolveRSASigningMethod(method jwtv5.SigningMethod, configured bool) (jwtv5.SigningMethod, error) {
	if !configured {
		method = jwtv5.SigningMethodRS256
	}
	return strictPSSSigningMethod(method)
}

func cloneRSAPublicKey(key *rsa.PublicKey) (*rsa.PublicKey, error) {
	if err := validateRSAPublicKey(key); err != nil {
		return nil, err
	}
	return &rsa.PublicKey{
		N: new(big.Int).Set(key.N),
		E: key.E,
	}, nil
}

func cloneRSAPrivateKey(key *rsa.PrivateKey) (*rsa.PrivateKey, error) {
	if key == nil || key.D == nil || key.D.Sign() <= 0 {
		return nil, fmt.Errorf("%w: RSA private exponent must be positive", ErrInvalidKey)
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
		if prime == nil || prime.Sign() <= 0 {
			return nil, fmt.Errorf("%w: RSA prime %d must be positive", ErrInvalidKey, i)
		}
		clone.Primes[i] = new(big.Int).Set(prime)
	}
	return clone, nil
}
