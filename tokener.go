package gojwt

import (
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

// Tokener provides an algorithm-agnostic JWT interface for callers.
type Tokener interface {
	GenerateToken(uid int64, options ...claims.Option) (string, error)
	ParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error)
	RefreshToken(tokenString string, opt ...jwtv5.ParserOption) (string, error)
	CachedParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error)
	ParallelVerify(tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error)
}
