package gojwt

import (
	"context"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

// 编译期确保所有实现满足对应接口。
var (
	_ Tokener        = (*JwtHmac)(nil)
	_ Tokener        = (*JwtEd25519)(nil)
	_ Tokener        = (*JwtRSA)(nil)
	_ ContextTokener = (*JwtHmac)(nil)
	_ ContextTokener = (*JwtEd25519)(nil)
	_ ContextTokener = (*JwtRSA)(nil)
	_ Issuer         = (*JwtHmac)(nil)
	_ Issuer         = (*JwtEd25519)(nil)
	_ Issuer         = (*JwtRSA)(nil)
	_ Verifier       = (*JwtHmac)(nil)
	_ Verifier       = (*JwtEd25519)(nil)
	_ Verifier       = (*JwtRSA)(nil)
	_ Verifier       = (*KeyRing)(nil)
)

// Tokener 提供算法无关的 JWT 操作接口。
// JwtHmac、JwtEd25519、JwtRSA 和 JwtECDSA 均实现了此接口，
// 调用方可面向 Tokener 编程，在 HMAC、Ed25519、RSA 与 ECDSA 之间自由切换。
// 只需要解析能力时面向 Verifier 编程，只需要签发能力时面向 Issuer 编程。
type Tokener interface {
	// GenerateToken 根据用户 ID 和可选的 claims 选项生成 JWT。
	GenerateToken(uid int64, options ...claims.Option) (string, error)
	// ParseToken 解析并验证 JWT，返回解析后的 Claims。
	ParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error)
	// RefreshToken 在刷新窗口内刷新 JWT，返回新的 token 字符串。
	RefreshToken(tokenString string, opt ...jwtv5.ParserOption) (string, error)
	// CachedParseToken 允许缓存的 ParseToken；动态密钥实现可选择每次重新选键验签。
	// 传入 ParserOption 时会退化为 ParseToken，以确保每次都应用当前校验条件。
	CachedParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error)
	// ParallelVerify 并发验证多个 token，返回结果和错误数组（按下标对应）。
	ParallelVerify(tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error)
}

// ContextParser 额外提供带 context 取消能力的 token 解析。
type ContextParser interface {
	// ParseTokenContext 解析并验证 JWT，尊重 ctx 取消和 deadline。
	ParseTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error)
}

// ContextRefresher 额外提供带 context 取消能力的 token 刷新。
type ContextRefresher interface {
	// RefreshTokenContext 在刷新窗口内刷新 JWT，尊重 ctx 取消和 deadline。
	RefreshTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (string, error)
}

// ContextCachedParser 额外提供带 context 取消能力的缓存解析。
type ContextCachedParser interface {
	// CachedParseTokenContext 允许缓存的 ParseToken，尊重 ctx 取消和 deadline；动态密钥实现可每次重验。
	CachedParseTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error)
}

// ContextParallelVerifier 额外提供带 context 取消能力的并发验签。
type ContextParallelVerifier interface {
	// ParallelVerifyContext 并发验证多个 token，并尊重 ctx 取消和 deadline。
	ParallelVerifyContext(ctx context.Context, tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error)
}

// ContextTokener 组合 Tokener 和所有 context-aware 扩展接口。
type ContextTokener interface {
	Tokener
	ContextParser
	ContextRefresher
	ContextCachedParser
	ContextParallelVerifier
}

// Verifier 只包含解析类方法，供只持公钥的验签方与网关面向接口编程。
// JwtHmac、JwtEd25519、JwtRSA、JwtECDSA、KeyRing 与 TokenVerifier 均实现了此接口。
type Verifier interface {
	ContextParser
	ContextCachedParser
	ContextParallelVerifier
	// ParseToken 解析并验证 JWT，返回解析后的 Claims。
	ParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error)
	// CachedParseToken 允许缓存的 ParseToken；动态密钥实现可选择每次重新选键验签。
	CachedParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error)
	// ParallelVerify 并发验证多个 token，返回结果和错误数组（按下标对应）。
	ParallelVerify(tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error)
}

// Issuer 包含签发与刷新方法。JwtHmac、JwtEd25519、JwtRSA、JwtECDSA 均实现了此接口；
// 只持公钥的验签实例调用这些方法返回 ErrNoSigningKey。
type Issuer interface {
	ContextRefresher
	// GenerateToken 根据用户 ID 和可选的 claims 选项生成 JWT。
	GenerateToken(uid int64, options ...claims.Option) (string, error)
	// RefreshToken 在刷新窗口内刷新 JWT，返回新的 token 字符串。
	RefreshToken(tokenString string, opt ...jwtv5.ParserOption) (string, error)
}
