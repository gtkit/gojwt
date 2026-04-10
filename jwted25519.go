package gojwt

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

// JwtEd25519 基于 Ed25519 (EdDSA) 签名的 JWT 实例。
type JwtEd25519 struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	config
	cache claimsCache
}

// NewJwtEd25519 从 PEM 文件加载 Ed25519 密钥对，创建 JWT 实例。
// priPath 为 PKCS8 格式私钥路径，pubPath 为 PKIX 格式公钥路径。
func NewJwtEd25519(priPath, pubPath string, options ...Option) (*JwtEd25519, error) {
	privateKey, err := readEd25519PrivateKey(priPath)
	if err != nil {
		return nil, err
	}
	publicKey, err := readEd25519PublicKey(pubPath)
	if err != nil {
		return nil, err
	}

	j := &JwtEd25519{
		privateKey: privateKey,
		publicKey:  publicKey,
		config:     defaultConfig(),
	}
	for _, opt := range options {
		opt(&j.config)
	}
	if err := validateConfig(j.config); err != nil {
		return nil, err
	}
	if j.config.hmacSigningSet {
		return nil, fmt.Errorf("%w: HMAC signing method option is not applicable to Ed25519", ErrInvalidConfig)
	}

	return j, nil
}

// GenerateToken 根据用户 ID 生成 JWT token。
// 自动写入 exp、iat、nbf 并生成唯一 TokenID。
// 可通过 claims.Option 附加业务字段。
func (j *JwtEd25519) GenerateToken(uid int64, options ...claims.Option) (string, error) {
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

	return createEd25519Token(*tokenClaims, j.privateKey)
}

// RefreshToken 在刷新窗口内刷新 JWT token。
// 仅当 token 距过期不足 refreshWindow（5 分钟）时允许刷新，
// 否则返回 ErrRefreshTooEarly；超过 refreshDuration 则返回 ErrTokenExpired。
// 刷新成功后会生成新的 TokenID/jti，并重置 iat、nbf，旧 token 与新 token 可独立吊销。
func (j *JwtEd25519) RefreshToken(tokenString string, opt ...jwtv5.ParserOption) (string, error) {
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
	return createEd25519Token(*tokenClaims, j.privateKey)
}

// ParseToken 解析并验证 JWT token。
// 完成 Ed25519 签名验证后返回 *claims.Claims。
// 如果通过 WithBlacklistFunc 配置了黑名单检查函数，
// 解析成功后会自动检查 tokenID 是否被拉黑。
func (j *JwtEd25519) ParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	if tokenString == "" {
		return nil, ErrTokenMalformed
	}
	parserOptions := append([]jwtv5.ParserOption{
		jwtv5.WithValidMethods([]string{jwtv5.SigningMethodEdDSA.Alg()}),
		jwtv5.WithLeeway(j.parseLeeway),
	}, opt...)
	token, err := jwtv5.ParseWithClaims(tokenString, &claims.Claims{}, func(token *jwtv5.Token) (any, error) {
		if token.Method == nil || token.Method.Alg() != jwtv5.SigningMethodEdDSA.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.publicKey, nil
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
// 即使缓存命中，仍会检查黑名单。
// 当调用方传入 ParserOption 时，为避免缓存绕过更严格的校验条件，会直接退化为 ParseToken。
func (j *JwtEd25519) CachedParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
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
func (j *JwtEd25519) ParallelVerify(tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error) {
	return parallelVerifyClaims(tokens, func(token string) (*claims.Claims, error) {
		return j.ParseToken(token, opt...)
	})
}

// createEd25519Token 使用 EdDSA 签名并返回 token 字符串。
func createEd25519Token(claims claims.Claims, signKey any) (string, error) {
	return jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, claims).SignedString(signKey)
}

// readEd25519PrivateKey 从 PEM 文件读取 Ed25519 私钥。
// 支持 "ED25519 PRIVATE KEY"（原始格式）和 "PRIVATE KEY"（PKCS8 格式）。
func readEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	block, err := readPEMBlock(path)
	if err != nil {
		return nil, err
	}

	switch block.Type {
	case "ED25519 PRIVATE KEY":
		if len(block.Bytes) != ed25519.PrivateKeySize {
			return nil, errors.New("invalid Ed25519 private key size")
		}
		return ed25519.PrivateKey(append([]byte(nil), block.Bytes...)), nil
	case "PRIVATE KEY":
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		key, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("invalid private key type")
		}
		return append(ed25519.PrivateKey(nil), key...), nil
	default:
		return nil, fmt.Errorf("invalid private key PEM type: %s", block.Type)
	}
}

// readEd25519PublicKey 从 PEM 文件读取 Ed25519 公钥。
// 支持 "ED25519 PUBLIC KEY"（原始格式）和 "PUBLIC KEY"（PKIX 格式）。
func readEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	block, err := readPEMBlock(path)
	if err != nil {
		return nil, err
	}

	switch block.Type {
	case "ED25519 PUBLIC KEY":
		if len(block.Bytes) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Ed25519 public key size")
		}
		return ed25519.PublicKey(append([]byte(nil), block.Bytes...)), nil
	case "PUBLIC KEY":
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		key, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("invalid public key type")
		}
		return append(ed25519.PublicKey(nil), key...), nil
	default:
		return nil, fmt.Errorf("invalid public key PEM type: %s", block.Type)
	}
}

// readPEMBlock 从文件读取并解码 PEM 块。
func readPEMBlock(path string) (*pem.Block, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data: %s", path)
	}
	return block, nil
}
