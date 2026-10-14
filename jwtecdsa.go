package gojwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

// JwtECDSA 基于 NIST 曲线的 ECDSA JWT 实例，可被多个 goroutine 并发使用。
// 默认 ES256/P-256；WithECDSASigningMethod 可选择 ES384/P-384 或 ES512/P-521。
// 仅公钥实例的 GenerateToken / RefreshToken 返回 ErrNoSigningKey。
type JwtECDSA struct {
	privateKey    *ecdsa.PrivateKey
	publicKey     *ecdsa.PublicKey
	signingMethod *jwtv5.SigningMethodECDSA
	config
	cache claimsCache
}

// NewJwtECDSA 从 PKCS8 或 SEC1 私钥 PEM、PKIX 公钥 PEM 创建 JWT 实例。
// 公私钥不匹配或不符合算法的曲线时返回 ErrInvalidKey。
func NewJwtECDSA(priPath, pubPath string, options ...Option) (*JwtECDSA, error) {
	privateKey, err := parseKeyFile(priPath, ParseECDSAPrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	publicKey, err := parseKeyFile(pubPath, ParseECDSAPublicKeyPEM)
	if err != nil {
		return nil, err
	}
	return newJwtECDSA(privateKey, publicKey, options)
}

// NewJwtECDSAFromKeys 用内存中的 ECDSA 密钥对创建 JWT 实例。
// 只接受 P-256/P-384/P-521 的有效坐标与私有标量，并核对密钥对。
// 输入密钥会被复制，构造后修改入参不影响实例；默认算法 ES256。
func NewJwtECDSAFromKeys(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey, options ...Option) (*JwtECDSA, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("%w: ECDSA private key must not be nil", ErrInvalidKey)
	}
	return newJwtECDSA(privateKey, publicKey, options)
}

// NewJwtECDSAVerifier 使用内存中的 ECDSA 公钥创建只做验签的实例。
// 默认 ES256/P-256；其他曲线需使用 WithECDSASigningMethod 选择匹配算法。
func NewJwtECDSAVerifier(publicKey *ecdsa.PublicKey, options ...Option) (*JwtECDSA, error) {
	return newJwtECDSA(nil, publicKey, options)
}

// NewJwtECDSAVerifierFromFile 从 PKIX 公钥 PEM 创建只做验签的实例。
func NewJwtECDSAVerifierFromFile(pubPath string, options ...Option) (*JwtECDSA, error) {
	publicKey, err := parseKeyFile(pubPath, ParseECDSAPublicKeyPEM)
	if err != nil {
		return nil, err
	}
	return newJwtECDSA(nil, publicKey, options)
}

func newJwtECDSA(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey, options []Option) (*JwtECDSA, error) {
	cfg, err := newConfig(options...)
	if err != nil {
		return nil, err
	}
	if cfg.hmacSigningSet || cfg.rsaSigningSet {
		return nil, fmt.Errorf("%w: HMAC and RSA signing options are not applicable to ECDSA", ErrInvalidConfig)
	}
	method, err := resolveECDSASigningMethod(cfg.ecdsaSigningMethod, cfg.ecdsaSigningSet)
	if err != nil {
		return nil, err
	}
	publicCopy, err := cloneECDSAPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	expectedCurve, err := ecdsaCurveForAlgorithm(method.Alg())
	if err != nil {
		return nil, err
	}
	if publicCopy.Curve != expectedCurve {
		return nil, fmt.Errorf("%w: ECDSA curve does not match algorithm %s", ErrInvalidKey, method.Alg())
	}
	j := &JwtECDSA{publicKey: publicCopy, signingMethod: method, config: cfg}
	if privateKey == nil {
		return j, nil
	}
	j.privateKey, err = cloneECDSAPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	if !j.privateKey.PublicKey.Equal(j.publicKey) {
		return nil, fmt.Errorf("%w: ECDSA private and public keys do not match", ErrInvalidKey)
	}
	return j, nil
}

// GenerateToken 根据用户 ID 与可选业务 claims 生成 JWT；仅公钥实例返回 ErrNoSigningKey。
func (j *JwtECDSA) GenerateToken(uid int64, options ...claims.Option) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	if j.privateKey == nil {
		return "", ErrNoSigningKey
	}
	return generateTokenImpl(&j.config, uid, options, j.sign)
}

// RefreshToken 在刷新窗口与会话最长时限内刷新 JWT；仅公钥实例返回 ErrNoSigningKey。
// 同一旧 token 可被重复或并发续签，不自动去重、消费或吊销旧 token。
func (j *JwtECDSA) RefreshToken(tokenString string, opt ...jwtv5.ParserOption) (string, error) {
	return j.RefreshTokenContext(context.Background(), tokenString, opt...)
}

// RefreshTokenContext 刷新 JWT，并尊重 ctx 取消和 deadline。
// 每次调用独立续签；调用方负责刷新去重、一次性消费、幂等重试与多实例一致性。
func (j *JwtECDSA) RefreshTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	if j.privateKey == nil {
		return "", ErrNoSigningKey
	}
	return refreshTokenImplContext(ctx, &j.config, tokenString, opt, j.ParseTokenContext, j.sign)
}

// ParseToken 验证 JWT 的签名、标准 claims 与配置的应用和吊销规则。
func (j *JwtECDSA) ParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	return j.ParseTokenContext(context.Background(), tokenString, opt...)
}

// ParseTokenContext 验证 JWT，并尊重 ctx 取消和 deadline。
func (j *JwtECDSA) ParseTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	return parseTokenImplContext(ctx, &j.config, tokenString, opt, func(token *jwtv5.Token) (any, error) {
		token.Method = j.signingMethod
		return j.publicKey, nil
	}, j.signingMethod.Alg())
}

// CachedParseToken 缓存验签结果，命中仍执行时效、应用和吊销规则；单次选项绕过缓存。
func (j *JwtECDSA) CachedParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	return j.CachedParseTokenContext(context.Background(), tokenString, opt...)
}

// CachedParseTokenContext 带缓存验证 JWT，并尊重 ctx 取消和 deadline。
func (j *JwtECDSA) CachedParseTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	return cachedParseTokenImplContext(ctx, &j.config, &j.cache, tokenString, opt, j.ParseTokenContext)
}

// ParallelVerify 并发验证 JWT；results 与 errs 按输入下标对应。
func (j *JwtECDSA) ParallelVerify(tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error) {
	return j.ParallelVerifyContext(context.Background(), tokens, opt...)
}

// ParallelVerifyContext 并发验证 JWT，并在 ctx 取消后停止分发未开始的任务。
func (j *JwtECDSA) ParallelVerifyContext(ctx context.Context, tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error) {
	if j == nil {
		return notInitResults(len(tokens))
	}
	return parallelVerifyImplContext(ctx, tokens, opt, j.ParseTokenContext)
}

func (j *JwtECDSA) sign(tokenClaims *claims.Claims) (string, error) {
	return signToken(j.signingMethod, tokenClaims, j.keyID, j.privateKey)
}

// ParseECDSAPrivateKeyPEM 解析 PKCS8（PRIVATE KEY）或 SEC1（EC PRIVATE KEY）PEM。
// 只接受 P-256/P-384/P-521；结构或参数无效返回 ErrInvalidKey，其他密钥类型返回 ErrInvalidKeyType。
func ParseECDSAPrivateKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, err := decodePEMBlock(data)
	if err != nil {
		return nil, err
	}
	var privateKey *ecdsa.PrivateKey
	switch block.Type {
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse SEC1 private key: %w", ErrInvalidKey, err)
		}
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse PKCS8 private key: %w", ErrInvalidKey, err)
		}
		var ok bool
		privateKey, ok = key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: expected ECDSA private key, got %T", ErrInvalidKeyType, key)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported ECDSA private key PEM type %q", ErrInvalidKey, block.Type)
	}
	return cloneECDSAPrivateKey(privateKey)
}

// ParseECDSAPublicKeyPEM 解析 PKIX（PUBLIC KEY）PEM，要求有效 P-256/P-384/P-521 坐标。
// 结构或参数无效返回 ErrInvalidKey，其他密钥类型返回 ErrInvalidKeyType。
func ParseECDSAPublicKeyPEM(data []byte) (*ecdsa.PublicKey, error) {
	block, err := decodePEMBlock(data)
	if err != nil {
		return nil, err
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%w: unsupported ECDSA public key PEM type %q", ErrInvalidKey, block.Type)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse PKIX public key: %w", ErrInvalidKey, err)
	}
	publicKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: expected ECDSA public key, got %T", ErrInvalidKeyType, key)
	}
	return cloneECDSAPublicKey(publicKey)
}

func resolveECDSASigningMethod(method *jwtv5.SigningMethodECDSA, configured bool) (*jwtv5.SigningMethodECDSA, error) {
	if !configured {
		method = jwtv5.SigningMethodES256
	}
	if method == nil {
		return nil, fmt.Errorf("%w: ECDSA signing method must not be nil", ErrInvalidConfig)
	}
	var expected *jwtv5.SigningMethodECDSA
	switch method.Alg() {
	case "ES256":
		expected = jwtv5.SigningMethodES256
	case "ES384":
		expected = jwtv5.SigningMethodES384
	case "ES512":
		expected = jwtv5.SigningMethodES512
	default:
		return nil, fmt.Errorf("%w: unsupported ECDSA algorithm %q", ErrInvalidConfig, method.Alg())
	}
	// Name 不能冒充不同摘要或签名宽度；参数按 JOSE 的固定定义核对。
	if method.Hash != expected.Hash || method.KeySize != expected.KeySize || method.CurveBits != expected.CurveBits {
		return nil, fmt.Errorf("%w: ECDSA algorithm parameters do not match %s", ErrInvalidConfig, method.Alg())
	}
	copyMethod := *method
	return &copyMethod, nil
}

func ecdsaCurveForAlgorithm(algorithm string) (elliptic.Curve, error) {
	switch algorithm {
	case "ES256":
		return elliptic.P256(), nil
	case "ES384":
		return elliptic.P384(), nil
	case "ES512":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%w: unsupported ECDSA algorithm %q", ErrInvalidConfig, algorithm)
	}
}

func validateECDSAPublicKey(key *ecdsa.PublicKey) error {
	if key == nil || key.Curve == nil || key.X == nil || key.Y == nil { //nolint:staticcheck // PublicKey.Bytes dereferences missing coordinates; reject malformed caller input before encoding.
		return fmt.Errorf("%w: ECDSA public key, curve and coordinates must not be nil", ErrInvalidKey)
	}
	switch key.Curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
	default:
		return fmt.Errorf("%w: ECDSA only supports P-256, P-384 and P-521", ErrInvalidKey)
	}
	if _, err := key.Bytes(); err != nil {
		return fmt.Errorf("%w: encode ECDSA public key: %w", ErrInvalidKey, err)
	}
	return nil
}

func cloneECDSAPublicKey(key *ecdsa.PublicKey) (*ecdsa.PublicKey, error) {
	if err := validateECDSAPublicKey(key); err != nil {
		return nil, err
	}
	encoded, err := key.Bytes()
	if err != nil {
		return nil, fmt.Errorf("%w: encode ECDSA public key: %w", ErrInvalidKey, err)
	}
	copyKey, err := ecdsa.ParseUncompressedPublicKey(key.Curve, encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: parse ECDSA public key: %w", ErrInvalidKey, err)
	}
	return copyKey, nil
}

func cloneECDSAPrivateKey(key *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	if key == nil || key.D == nil { //nolint:staticcheck // PrivateKey.Bytes dereferences a missing scalar; guard malformed caller input before encoding.
		return nil, fmt.Errorf("%w: ECDSA private scalar must not be nil", ErrInvalidKey)
	}
	publicKey, err := cloneECDSAPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	encoded, err := key.Bytes()
	if err != nil {
		return nil, fmt.Errorf("%w: encode ECDSA private key: %w", ErrInvalidKey, err)
	}
	copyKey, err := ecdsa.ParseRawPrivateKey(key.Curve, encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: parse ECDSA private key: %w", ErrInvalidKey, err)
	}
	if !publicKey.Equal(&copyKey.PublicKey) {
		return nil, fmt.Errorf("%w: ECDSA private scalar and public point do not match", ErrInvalidKey)
	}
	return copyKey, nil
}
