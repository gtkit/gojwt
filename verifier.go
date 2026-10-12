package gojwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

// KeyResolver 返回匹配 kid 和可信算法的验签密钥。
// 参数来自未验签 header，只能用于选键；实现必须从应用指定的可信来源读取，
// 并检查密钥自身的用途、算法及信任范围。实现需支持并发调用及 ctx 取消。
type KeyResolver interface {
	ResolveKey(ctx context.Context, kid, algorithm string) (any, error)
}

// KeyResolverFunc 将选键函数适配为 KeyResolver。
type KeyResolverFunc func(context.Context, string, string) (any, error)

// ResolveKey 调用函数本身；nil 函数返回 ErrInvalidConfig。
func (f KeyResolverFunc) ResolveKey(ctx context.Context, kid, algorithm string) (any, error) {
	if f == nil {
		return nil, ErrInvalidConfig
	}
	return f(ctx, kid, algorithm)
}

// TokenVerifier 使用自定义密钥来源验证第三方 JWT，实现 Verifier。
// 它只做验签，不签发或刷新。缓存入口每次重新选键并验签，避免动态密钥移除后
// 缓存继续授权。构造后可并发调用，resolver 和应用回调须支持并发。
type TokenVerifier struct {
	resolver   KeyResolver
	algorithms []string
	config     config
}

var _ Verifier = (*TokenVerifier)(nil)

// NewVerifier 创建带明确算法白名单的验签器。
// algorithms 不得为空，只支持 HS256/384/512、RS256/384/512、PS256/384/512、
// ES256/384/512 和 EdDSA。白名单被复制；不接受签发算法 Option。
// exp 默认必填；iss/aud/sub 通过 WithParserOptions 或应用校验回调配置。
func NewVerifier(resolver KeyResolver, algorithms []string, options ...Option) (*TokenVerifier, error) {
	if isNilValue(resolver) || len(algorithms) == 0 {
		return nil, fmt.Errorf("%w: resolver and algorithms are required", ErrInvalidConfig)
	}
	cfg, err := newConfig(options...)
	if err != nil {
		return nil, err
	}
	if cfg.hmacSigningSet || cfg.rsaSigningSet || cfg.ecdsaSigningSet {
		return nil, fmt.Errorf("%w: signing method options are not applicable to a resolver verifier", ErrInvalidConfig)
	}
	for _, algorithm := range algorithms {
		if _, err := verificationMethod(algorithm); err != nil {
			return nil, err
		}
	}
	return &TokenVerifier{resolver: resolver, algorithms: slices.Clone(algorithms), config: cfg}, nil
}

// ParseToken 按白名单算法和 resolver 返回的密钥验证 JWT。
func (v *TokenVerifier) ParseToken(raw string, opts ...jwtv5.ParserOption) (*claims.Claims, error) {
	return v.ParseTokenContext(context.Background(), raw, opts...)
}

// ParseTokenContext 验证 JWT；ctx 取消时不发起新的选键请求。
func (v *TokenVerifier) ParseTokenContext(ctx context.Context, raw string, opts ...jwtv5.ParserOption) (*claims.Claims, error) {
	if v == nil || v.resolver == nil {
		return nil, ErrJWTNotInit
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	header, err := readTokenHeader(raw)
	if err != nil {
		return nil, err
	}
	var algorithm string
	if err := json.Unmarshal(header["alg"], &algorithm); err != nil {
		return nil, fmt.Errorf("%w: algorithm: %w", ErrTokenMalformed, err)
	}
	if !slices.Contains(v.algorithms, algorithm) {
		return nil, fmt.Errorf("%w: algorithm is not allowed", ErrTokenUnverifiable)
	}
	kid, err := keyIDFromHeader(header)
	if err != nil {
		return nil, err
	}
	return parseTokenImplContext(ctx, &v.config, raw, opts, func(_ *jwtv5.Token) (any, error) {
		key, err := v.resolver.ResolveKey(ctx, kid, algorithm)
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := validateVerificationKey(algorithm, key); err != nil {
			return nil, err
		}
		return key, nil
	}, algorithm)
}

// CachedParseToken 重新选键验签；动态 resolver 不复用签名验证缓存。
func (v *TokenVerifier) CachedParseToken(raw string, opts ...jwtv5.ParserOption) (*claims.Claims, error) {
	return v.ParseToken(raw, opts...)
}

// CachedParseTokenContext 重新选键验签并透传 ctx。
func (v *TokenVerifier) CachedParseTokenContext(ctx context.Context, raw string, opts ...jwtv5.ParserOption) (*claims.Claims, error) {
	return v.ParseTokenContext(ctx, raw, opts...)
}

// ParallelVerify 并发验证 token；结果按输入下标排列。
func (v *TokenVerifier) ParallelVerify(tokens []string, opts ...jwtv5.ParserOption) ([]*claims.Claims, []error) {
	return v.ParallelVerifyContext(context.Background(), tokens, opts...)
}

// ParallelVerifyContext 并发验证并支持取消。
func (v *TokenVerifier) ParallelVerifyContext(ctx context.Context, tokens []string, opts ...jwtv5.ParserOption) ([]*claims.Claims, []error) {
	if v == nil {
		return notInitResults(len(tokens))
	}
	return parallelVerifyImplContext(ctx, tokens, opts, v.ParseTokenContext)
}

func isNilValue(value any) bool {
	if value == nil {
		return true
	}
	switch reflect.TypeOf(value).Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflect.ValueOf(value).IsNil()
	default:
		return false
	}
}

func verificationMethod(algorithm string) (jwtv5.SigningMethod, error) {
	switch algorithm {
	case "HS256":
		m := *jwtv5.SigningMethodHS256
		return &m, nil
	case "HS384":
		m := *jwtv5.SigningMethodHS384
		return &m, nil
	case "HS512":
		m := *jwtv5.SigningMethodHS512
		return &m, nil
	case "RS256":
		m := *jwtv5.SigningMethodRS256
		return &m, nil
	case "RS384":
		m := *jwtv5.SigningMethodRS384
		return &m, nil
	case "RS512":
		m := *jwtv5.SigningMethodRS512
		return &m, nil
	case "PS256":
		return strictPSSSigningMethod(jwtv5.SigningMethodPS256)
	case "PS384":
		return strictPSSSigningMethod(jwtv5.SigningMethodPS384)
	case "PS512":
		return strictPSSSigningMethod(jwtv5.SigningMethodPS512)
	case "ES256":
		m := *jwtv5.SigningMethodES256
		return &m, nil
	case "ES384":
		m := *jwtv5.SigningMethodES384
		return &m, nil
	case "ES512":
		m := *jwtv5.SigningMethodES512
		return &m, nil
	case "EdDSA":
		m := *jwtv5.SigningMethodEdDSA
		return &m, nil
	default:
		return nil, fmt.Errorf("%w: unsupported algorithm %q", ErrInvalidConfig, algorithm)
	}
}

func validateVerificationKey(algorithm string, key any) error {
	switch algorithm {
	case "HS256", "HS384", "HS512":
		secret, ok := key.([]byte)
		if !ok {
			return ErrInvalidKeyType
		}
		method, err := verificationMethod(algorithm)
		if err != nil {
			return err
		}
		return validateHMACSecretKey(secret, method.(*jwtv5.SigningMethodHMAC))
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		publicKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidKeyType
		}
		return validateRSAPublicKey(publicKey)
	case "ES256", "ES384", "ES512":
		publicKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidKeyType
		}
		if err := validateECDSAPublicKey(publicKey); err != nil {
			return err
		}
		curve, err := ecdsaCurveForAlgorithm(algorithm)
		if err != nil {
			return err
		}
		if publicKey.Curve != curve {
			return fmt.Errorf("%w: curve does not match algorithm", ErrInvalidKey)
		}
		return nil
	case "EdDSA":
		publicKey, ok := key.(ed25519.PublicKey)
		if !ok {
			return ErrInvalidKeyType
		}
		if len(publicKey) != ed25519.PublicKeySize {
			return ErrInvalidKey
		}
		return nil
	default:
		return ErrInvalidConfig
	}
}
