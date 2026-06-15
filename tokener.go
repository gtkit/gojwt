package gojwt

import (
	"context"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

// 编译期确保所有实现满足 Tokener 接口。
var (
	_ Tokener        = (*JwtHmac)(nil)
	_ Tokener        = (*JwtEd25519)(nil)
	_ Tokener        = (*JwtRSA)(nil)
	_ ContextTokener = (*JwtHmac)(nil)
	_ ContextTokener = (*JwtEd25519)(nil)
	_ ContextTokener = (*JwtRSA)(nil)
)

// Tokener 提供算法无关的 JWT 操作接口。
// JwtHmac、JwtEd25519 和 JwtRSA 均实现了此接口，
// 调用方可面向 Tokener 编程，在 HMAC、Ed25519 与 RSA 之间自由切换。
type Tokener interface {
	// GenerateToken 根据用户 ID 和可选的 claims 选项生成 JWT。
	GenerateToken(uid int64, options ...claims.Option) (string, error)
	// ParseToken 解析并验证 JWT，返回解析后的 Claims。
	ParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error)
	// RefreshToken 在刷新窗口内刷新 JWT，返回新的 token 字符串。
	RefreshToken(tokenString string, opt ...jwtv5.ParserOption) (string, error)
	// CachedParseToken 带缓存的 ParseToken，相同 token 不重复解析。
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
	// CachedParseTokenContext 带缓存的 ParseToken，相同 token 不重复解析，并尊重 ctx 取消和 deadline。
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
