package gojwt

import (
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

// Tokener 提供算法无关的 JWT 操作接口。
// JwtHmac 和 JwtEd25519 均实现了此接口，
// 调用方可面向 Tokener 编程，在 HMAC 与 Ed25519 之间自由切换。
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
