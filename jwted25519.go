package gojwt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

// JwtEd25519 基于 Ed25519 (EdDSA) 签名的 JWT 实例。
// JwtEd25519 可被多个 goroutine 并发使用。
// 通过 NewJwtEd25519Verifier / NewJwtEd25519VerifierFromFile 创建的实例只持公钥，
// 其 GenerateToken / RefreshToken 返回 ErrNoSigningKey。
type JwtEd25519 struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	config
	cache claimsCache
}

// NewJwtEd25519 从 PEM 文件加载 Ed25519 密钥对，创建 JWT 实例。
// priPath 支持 PKCS8 或 64 字节原始格式私钥，pubPath 支持 PKIX 或 32 字节原始格式公钥。
// 私钥内部不一致或两把密钥不匹配时返回 ErrInvalidKey。
func NewJwtEd25519(priPath, pubPath string, options ...Option) (*JwtEd25519, error) {
	privateKey, err := parseKeyFile(priPath, ParseEd25519PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	publicKey, err := parseKeyFile(pubPath, ParseEd25519PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	return newJwtEd25519(privateKey, publicKey, options)
}

// NewJwtEd25519FromKeys 直接使用内存中的 Ed25519 密钥对创建 JWT 实例。
// 适用于密钥来自 KMS、Vault、环境变量等外部系统的场景，PEM 字节可先用 ParseEd25519PrivateKeyPEM /
// ParseEd25519PublicKeyPEM 解析。输入密钥会被复制，构造后修改入参不影响实例。
// 私钥内部不一致或两把密钥不匹配时返回 ErrInvalidKey。
func NewJwtEd25519FromKeys(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, options ...Option) (*JwtEd25519, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: Ed25519 private key must be %d bytes, got %d", ErrInvalidKey, ed25519.PrivateKeySize, len(privateKey))
	}
	return newJwtEd25519(privateKey, publicKey, options)
}

// NewJwtEd25519Verifier 使用内存中的 Ed25519 公钥创建只做验签的实例。
// 适用于只持公钥的服务与网关。
func NewJwtEd25519Verifier(publicKey ed25519.PublicKey, options ...Option) (*JwtEd25519, error) {
	return newJwtEd25519(nil, publicKey, options)
}

// NewJwtEd25519VerifierFromFile 从 PEM 文件加载 Ed25519 公钥，创建只做验签的实例。
func NewJwtEd25519VerifierFromFile(pubPath string, options ...Option) (*JwtEd25519, error) {
	publicKey, err := parseKeyFile(pubPath, ParseEd25519PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	return newJwtEd25519(nil, publicKey, options)
}

func newJwtEd25519(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, options []Option) (*JwtEd25519, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 public key must be %d bytes, got %d", ErrInvalidKey, ed25519.PublicKeySize, len(publicKey))
	}
	if privateKey != nil {
		if len(privateKey) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: Ed25519 private key must be %d bytes, got %d", ErrInvalidKey, ed25519.PrivateKeySize, len(privateKey))
		}
		// PrivateKey.Public 只读取尾部公钥；从 seed 重新导出，才能发现尾部被替换的私钥。
		derivedKey := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
		if !privateKey.Equal(derivedKey) {
			return nil, fmt.Errorf("%w: Ed25519 private key seed and public key do not match", ErrInvalidKey)
		}
		if !publicKey.Equal(derivedKey.Public()) {
			return nil, fmt.Errorf("%w: Ed25519 private and public keys do not match", ErrInvalidKey)
		}
	}
	cfg, err := newConfig(options...)
	if err != nil {
		return nil, err
	}
	if cfg.hmacSigningSet {
		return nil, fmt.Errorf("%w: HMAC signing method option is not applicable to Ed25519", ErrInvalidConfig)
	}
	if cfg.rsaSigningSet || cfg.ecdsaSigningSet {
		return nil, fmt.Errorf("%w: RSA/ECDSA signing method option is not applicable to Ed25519", ErrInvalidConfig)
	}

	return &JwtEd25519{
		privateKey: bytes.Clone(privateKey),
		publicKey:  bytes.Clone(publicKey),
		config:     cfg,
	}, nil
}

// GenerateToken 根据用户 ID 生成 JWT token。
// 自动写入 exp、iat、nbf、auth_time 并生成唯一 TokenID。
// 可通过 claims.Option 附加业务字段。只持公钥的实例返回 ErrNoSigningKey。
func (j *JwtEd25519) GenerateToken(uid int64, options ...claims.Option) (string, error) {
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
// 只持公钥的实例返回 ErrNoSigningKey。
func (j *JwtEd25519) RefreshToken(tokenString string, opt ...jwtv5.ParserOption) (string, error) {
	return j.RefreshTokenContext(context.Background(), tokenString, opt...)
}

// RefreshTokenContext 在刷新窗口内刷新 JWT token，并尊重 ctx 取消和 deadline。
func (j *JwtEd25519) RefreshTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	if j.privateKey == nil {
		return "", ErrNoSigningKey
	}
	return refreshTokenImplContext(ctx, &j.config, tokenString, opt, j.ParseTokenContext, j.sign)
}

// ParseToken 解析并验证 JWT token。
// 完成 Ed25519 签名验证后返回 *claims.Claims。
// 配置了黑名单或吊销回调时，解析成功后会自动执行吊销检查。
func (j *JwtEd25519) ParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	return j.ParseTokenContext(context.Background(), tokenString, opt...)
}

// ParseTokenContext 解析并验证 JWT token，并尊重 ctx 取消和 deadline。
func (j *JwtEd25519) ParseTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	return parseTokenImplContext(ctx, &j.config, tokenString, opt, func(_ *jwtv5.Token) (any, error) {
		return j.publicKey, nil
	}, jwtv5.SigningMethodEdDSA.Alg())
}

// CachedParseToken 带缓存的 ParseToken，相同 tokenString 不重复解析。
// 即使缓存命中，仍会执行吊销检查。
// 当调用方传入 ParserOption 时，为避免缓存绕过更严格的校验条件，会直接退化为 ParseToken。
func (j *JwtEd25519) CachedParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	return j.CachedParseTokenContext(context.Background(), tokenString, opt...)
}

// CachedParseTokenContext 带缓存解析 JWT token，并尊重 ctx 取消和 deadline。
func (j *JwtEd25519) CachedParseTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	return cachedParseTokenImplContext(ctx, &j.config, &j.cache, tokenString, opt, j.ParseTokenContext)
}

// ParallelVerify 并发验证多个 token。
// results[i] 与 errs[i] 对应同一个输入 tokens[i]。
func (j *JwtEd25519) ParallelVerify(tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error) {
	return j.ParallelVerifyContext(context.Background(), tokens, opt...)
}

// ParallelVerifyContext 并发验证多个 token，并在 ctx 取消后停止分发未开始的任务。
// results[i] 与 errs[i] 对应同一个输入 tokens[i]。
func (j *JwtEd25519) ParallelVerifyContext(ctx context.Context, tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error) {
	if j == nil {
		return notInitResults(len(tokens))
	}
	return parallelVerifyImplContext(ctx, tokens, opt, j.ParseTokenContext)
}

func (j *JwtEd25519) sign(tokenClaims *claims.Claims) (string, error) {
	return signToken(jwtv5.SigningMethodEdDSA, tokenClaims, j.keyID, j.privateKey)
}

// ParseEd25519PrivateKeyPEM 解析 PEM 编码的 Ed25519 私钥。
// 支持 "PRIVATE KEY"（PKCS8）与 "ED25519 PRIVATE KEY"（64 字节原始格式）两种块类型。
// PEM 解码失败、长度错误返回 ErrInvalidKey；PKCS8 中不是 Ed25519 密钥返回 ErrInvalidKeyType。
func ParseEd25519PrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, err := decodePEMBlock(data)
	if err != nil {
		return nil, err
	}

	switch block.Type {
	case "ED25519 PRIVATE KEY":
		if len(block.Bytes) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: Ed25519 private key must be %d bytes, got %d", ErrInvalidKey, ed25519.PrivateKeySize, len(block.Bytes))
		}
		return ed25519.PrivateKey(bytes.Clone(block.Bytes)), nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse PKCS8 private key: %w", ErrInvalidKey, err)
		}
		privateKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: expected Ed25519 private key, got %T", ErrInvalidKeyType, key)
		}
		return bytes.Clone(privateKey), nil
	default:
		return nil, fmt.Errorf("%w: unsupported private key PEM type %q", ErrInvalidKey, block.Type)
	}
}

// ParseEd25519PublicKeyPEM 解析 PEM 编码的 Ed25519 公钥。
// 支持 "PUBLIC KEY"（PKIX）与 "ED25519 PUBLIC KEY"（32 字节原始格式）两种块类型。
// PEM 解码失败、长度错误返回 ErrInvalidKey；PKIX 中不是 Ed25519 密钥返回 ErrInvalidKeyType。
func ParseEd25519PublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, err := decodePEMBlock(data)
	if err != nil {
		return nil, err
	}

	switch block.Type {
	case "ED25519 PUBLIC KEY":
		if len(block.Bytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: Ed25519 public key must be %d bytes, got %d", ErrInvalidKey, ed25519.PublicKeySize, len(block.Bytes))
		}
		return ed25519.PublicKey(bytes.Clone(block.Bytes)), nil
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse PKIX public key: %w", ErrInvalidKey, err)
		}
		publicKey, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: expected Ed25519 public key, got %T", ErrInvalidKeyType, key)
		}
		return bytes.Clone(publicKey), nil
	default:
		return nil, fmt.Errorf("%w: unsupported public key PEM type %q", ErrInvalidKey, block.Type)
	}
}
