package claims

import (
	"encoding/json"
	"math"
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
	// AuthTime 会话起点，即首次签发（登录）的时刻，对应 OIDC 的 auth_time。
	// RefreshToken 产出的新 token 原样继承此值，刷新链以它加 refreshDuration 为终点。
	AuthTime *jwtv5.NumericDate `json:"auth_time,omitempty"`
	// Ext 业务扩展字段，例如 tenant_id、device_id。
	// 值经 JSON 往返后整数会变成 float64，读取时用 ExtInt64 / ExtString。
	Ext map[string]any `json:"ext,omitempty"`
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

// WithExt 写入一个扩展字段。value 必须能被 encoding/json 编码，否则签发时返回错误。
func WithExt(key string, value any) Option {
	return func(claims *Claims) {
		if claims.Ext == nil {
			claims.Ext = make(map[string]any)
		}
		claims.Ext[key] = value
	}
}

// UserId 返回业务用户 ID。
func (c Claims) UserId() int64 {
	return c.UserID
}

// ExtString 读取扩展字段中的字符串值。
// 键不存在或值不是字符串时第二个返回值为 false。
func (c Claims) ExtString(key string) (string, bool) {
	v, ok := c.Ext[key].(string)
	return v, ok
}

// ExtInt64 读取扩展字段中的整数值。
// 兼容签发侧写入的 int / int64 与 JSON 解码得到的 float64 / json.Number；
// 键不存在、类型不符、数值带小数或超出 int64 范围时第二个返回值为 false。
func (c Claims) ExtInt64(key string) (int64, bool) {
	switch v := c.Ext[key].(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case float64:
		// float64 能精确表示 -2^63，但 2^63 已越界，故上界取严格小于。
		if v != math.Trunc(v) || v >= math.MaxInt64 || v < math.MinInt64 {
			return 0, false
		}
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	default:
		return 0, false
	}
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
