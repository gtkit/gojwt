package gojwt

import (
	"fmt"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// config 是 JwtHmac / JwtEd25519 的内部配置。
type config struct {
	tokenDuration   time.Duration
	refreshDuration time.Duration
	parseLeeway     time.Duration

	// isBlacklisted 是外部注入的黑名单检查函数。
	// 返回 true 表示该 tokenID 已被拉黑（已注销/已撤回）。
	// 为 nil 时跳过黑名单检查。
	isBlacklisted func(tokenID string) bool

	// blacklistCheckFunc 支持返回错误的黑名单检查函数。
	// 用于 Redis/DB 等外部存储故障时 fail closed。
	blacklistCheckFunc func(tokenID string) (bool, error)

	// hmacSigningMethod 为 JwtHmac 指定签名算法。
	// 默认使用 HS256，可显式切换到 HS384 / HS512。
	hmacSigningMethod *jwtv5.SigningMethodHMAC
	hmacSigningSet    bool

	// rsaSigningMethod 为 JwtRSA 指定签名算法。
	// 默认使用 RS256，可显式切换到 RS384 / RS512 / PS256 / PS384 / PS512。
	rsaSigningMethod jwtv5.SigningMethod
	rsaSigningSet    bool
}

// Option 配置 JwtHmac / JwtEd25519 实例的选项函数。
type Option func(*config)

// Options 是 Option 的类型别名，保留向后兼容。
//
// Deprecated: 请直接使用 Option。
type Options = Option

// WithTokenDuration 设置 access token 的有效时长，默认 2 小时。
func WithTokenDuration(t time.Duration) Option {
	return func(c *config) {
		c.tokenDuration = t
	}
}

// WithRefreshDuration 设置 refresh token 的最大刷新窗口时长，默认 7 天。
func WithRefreshDuration(t time.Duration) Option {
	return func(c *config) {
		c.refreshDuration = t
	}
}

// WithParseLeeway 设置 JWT 解析时对 exp / nbf / iat 的容忍时间。
// 默认 5 秒，用于吸收多机之间的轻微时钟漂移。
func WithParseLeeway(t time.Duration) Option {
	return func(c *config) {
		c.parseLeeway = t
	}
}

// WithBlacklistFunc 注入外部黑名单检查函数。
//
// fn 接收 tokenID（即 Claims.TokenID / RegisteredClaims.ID），
// 返回 true 表示该 token 已被拉黑，ParseToken / CachedParseToken 将返回 ErrTokenBlacklisted。
//
// 调用方可以注入任意实现，例如：
//
//   - 内存黑名单：
//     gojwt.WithBlacklistFunc(blacklist.In)
//
//   - Redis 黑名单：
//     gojwt.WithBlacklistFunc(func(tid string) bool {
//     return rdb.Exists(ctx, "jwt:blacklist:"+tid).Val() > 0
//     })
//
//   - DB 查询：
//     gojwt.WithBlacklistFunc(func(tid string) bool {
//     return repo.IsTokenRevoked(tid)
//     })
func WithBlacklistFunc(fn func(tokenID string) bool) Option {
	return func(c *config) {
		c.isBlacklisted = fn
	}
}

// WithBlacklistCheckFunc 注入支持返回错误的黑名单检查函数。
// 当底层存储不可用时，应返回 error，使鉴权链路能够 fail closed。
func WithBlacklistCheckFunc(fn func(tokenID string) (bool, error)) Option {
	return func(c *config) {
		c.blacklistCheckFunc = fn
	}
}

// WithHMACSigningMethod 为 JwtHmac 设置签名算法。
// 默认使用 HS256，可选 HS384、HS512。
func WithHMACSigningMethod(method *jwtv5.SigningMethodHMAC) Option {
	return func(c *config) {
		c.hmacSigningMethod = method
		c.hmacSigningSet = true
	}
}

// WithRSASigningMethod 为 JwtRSA 设置签名算法。
// 默认使用 RS256，可选 RS384、RS512（PKCS1-v1_5）或 PS256、PS384、PS512（PSS）。
// PSS 系列更安全，推荐在新项目中使用；RS256 兼容性最好，适合对接第三方 OAuth2/OIDC。
func WithRSASigningMethod(method jwtv5.SigningMethod) Option {
	return func(c *config) {
		c.rsaSigningMethod = method
		c.rsaSigningSet = true
	}
}

// defaultConfig 返回默认配置。
func defaultConfig() config {
	return config{
		tokenDuration:   2 * time.Hour,
		refreshDuration: 7 * 24 * time.Hour,
		parseLeeway:     5 * time.Second,
	}
}

func validateConfig(cfg config) error {
	if cfg.tokenDuration <= 0 {
		return fmt.Errorf("%w: token duration must be greater than zero", ErrInvalidConfig)
	}
	if cfg.refreshDuration <= 0 {
		return fmt.Errorf("%w: refresh duration must be greater than zero", ErrInvalidConfig)
	}
	if cfg.parseLeeway < 0 {
		return fmt.Errorf("%w: parse leeway must be greater than or equal to zero", ErrInvalidConfig)
	}
	return nil
}
