package claims

import (
	"slices"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// Claims 是 JWT 载荷结构，内嵌 JWT 标准字段并扩展业务字段。
type Claims struct {
	jwtv5.RegisteredClaims

	// UserID 业务用户 ID。
	UserID int64 `json:"uid"`
	// Prv 业务域标识，例如 "admin"、"app"、"open-api"。
	Prv string `json:"prv,omitempty"`
	// Roles 角色集合。
	Roles []string `json:"roles,omitzero"`
	// TokenID 唯一 Token ID，创建时自动生成。
	TokenID string `json:"token_id"`
}

// Option 是签发 token 时附加 Claims 字段的选项函数。
type Option func(*Claims)

// Options 是 Option 的类型别名，保留向后兼容。
//
// Deprecated: 请直接使用 Option。
type Options = Option

// WithRole 向 Claims 添加单个角色。
func WithRole(role string) Option {
	return func(claims *Claims) {
		claims.Roles = append(claims.Roles, role)
	}
}

// WithRoles 向 Claims 添加多个角色。
func WithRoles(roles ...string) Option {
	return func(claims *Claims) {
		claims.Roles = append(claims.Roles, roles...)
	}
}

// WithPrv 设置业务域标识。
func WithPrv(prv string) Option {
	return func(claims *Claims) {
		claims.Prv = prv
	}
}

// WithIssuer 设置签发者（iss）。
func WithIssuer(issuer string) Option {
	return func(claims *Claims) {
		claims.Issuer = issuer
	}
}

// WithSubject 设置主题（sub）。
func WithSubject(subject string) Option {
	return func(claims *Claims) {
		claims.Subject = subject
	}
}

// WithAudience 追加受众（aud）。
func WithAudience(audience ...string) Option {
	return func(claims *Claims) {
		claims.Audience = append(claims.Audience, audience...)
	}
}

// WithExpiresIn 设置过期时间（从当前时刻起加上指定时长）。
func WithExpiresIn(d time.Duration) Option {
	return func(claims *Claims) {
		claims.ExpiresAt = jwtv5.NewNumericDate(time.Now().Add(d))
	}
}

// WithExpiresAt 设置绝对过期时间。
//
// Deprecated: 此函数原接收 time.Duration，语义与命名不一致。
// 如需设置相对时长，请使用 WithExpiresIn；如需设置绝对时间，请使用 WithExpiresAtTime。
func WithExpiresAt(d time.Duration) Option {
	return WithExpiresIn(d)
}

// WithExpiresAtTime 设置绝对过期时间。
func WithExpiresAtTime(t time.Time) Option {
	return func(claims *Claims) {
		claims.ExpiresAt = jwtv5.NewNumericDate(t)
	}
}

// WithJwtID 设置 JWT ID（jti）。
func WithJwtID(jwtID string) Option {
	return func(claims *Claims) {
		claims.ID = jwtID
	}
}

// UserId 返回业务用户 ID。
func (c Claims) UserId() int64 {
	return c.UserID
}

// VerifyRole 校验 Claims 是否同时包含所有指定角色。
// 缺少任意一个角色时返回 ErrTokenRole。
func (c Claims) VerifyRole(roles ...string) error {
	for _, role := range roles {
		if !slices.Contains(c.Roles, role) {
			return ErrTokenRole
		}
	}
	return nil
}

// VerifyPrv 校验业务域是否匹配，不匹配时返回 ErrTokenPrv。
func (c Claims) VerifyPrv(prv string) error {
	if c.Prv == prv {
		return nil
	}
	return ErrTokenPrv
}

// TTL 返回 token 的剩余有效时间。
// 如果未设置过期时间或已过期则返回 0。
func (c Claims) TTL() time.Duration {
	if c.ExpiresAt == nil {
		return 0
	}
	if d := time.Until(c.ExpiresAt.Time); d > 0 {
		return d
	}
	return 0
}
