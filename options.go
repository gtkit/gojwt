package gojwt

import (
	"context"
	"fmt"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// config 是 JwtHmac / JwtEd25519 的内部配置。
type config struct {
	tokenDuration   time.Duration
	refreshDuration time.Duration
	parseLeeway     time.Duration
	cacheMaxEntries int

	// isBlacklisted 是外部注入的黑名单检查函数。
	// 返回 true 表示该 tokenID 已被拉黑（已注销/已撤回）。
	// 为 nil 时跳过黑名单检查。
	isBlacklisted func(tokenID string) bool

	// blacklistCheckFunc 支持返回错误的黑名单检查函数。
	// 用于 Redis/DB 等外部存储故障时 fail closed。
	blacklistCheckFunc func(tokenID string) (bool, error)

	// blacklistCheckContextFunc 支持 context 取消和超时的黑名单检查函数。
	// 当同时配置 blacklistCheckFunc 时，优先使用此函数。
	blacklistCheckContextFunc func(ctx context.Context, tokenID string) (bool, error)

	// hmacSigningMethod 为 JwtHmac 指定签名算法。
	// 默认使用 HS256，可显式切换到 HS384 / HS512。
	hmacSigningMethod *jwtv5.SigningMethodHMAC
	hmacSigningSet    bool

	// rsaSigningMethod 为 JwtRSA 指定签名算法。
	// 默认使用 RS256，可显式切换到 RS384 / RS512 / PS256 / PS384 / PS512。
	rsaSigningMethod jwtv5.SigningMethod
	rsaSigningSet    bool

	// keyID 写入 JWT header 的 kid 字段，标识本实例使用的密钥。
	// 为空时不写入 kid，保持与旧版本一致的 header。
	keyID string
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

// WithCacheMaxEntries 设置 CachedParseToken 的最大缓存条目数，默认 4096。
//
// n 为 0 时禁用缓存；当缓存已满时，会按 LRU 淘汰最久未使用的条目。
func WithCacheMaxEntries(n int) Option {
	return func(c *config) {
		c.cacheMaxEntries = n
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

// WithBlacklistCheckContextFunc 注入支持 context 取消和超时的黑名单检查函数。
// 当同时配置 WithBlacklistCheckFunc 时，优先使用此函数。
func WithBlacklistCheckContextFunc(fn func(ctx context.Context, tokenID string) (bool, error)) Option {
	return func(c *config) {
		c.blacklistCheckContextFunc = fn
	}
}

// WithKeyID 设置签发时写入 JWT header 的 kid 字段。
//
// kid 用于让验证方在多个密钥中定位到本 token 使用的那一个，
// 典型场景是密钥轮换期新旧密钥并存，以及网关侧按 kid 选择验签密钥。
// 不设置或设置为空字符串时不写入 kid，header 与旧版本保持一致。
//
// kid 只是密钥标识，会以明文出现在 token 里，不要放密钥本身或任何敏感信息。
//
// 使用示例：
//
//	j, err := gojwt.NewJwtHmac(secret, gojwt.WithKeyID("app-2026"))
//
// 签出的 token header 为 {"alg":"HS256","kid":"app-2026","typ":"JWT"}。
func WithKeyID(kid string) Option {
	return func(c *config) {
		c.keyID = kid
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
		cacheMaxEntries: 4096,
	}
}

func newConfig(options ...Option) (config, error) {
	cfg := defaultConfig()
	for _, opt := range options {
		if opt == nil {
			continue
		}
		opt(&cfg)
	}
	if err := validateConfig(cfg); err != nil {
		return config{}, err
	}
	return cfg, nil
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
	if cfg.cacheMaxEntries < 0 {
		return fmt.Errorf("%w: cache max entries must be greater than or equal to zero", ErrInvalidConfig)
	}
	return nil
}
