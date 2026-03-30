package gojwt

import "time"

// config 是 JwtHmac / JwtEd25519 的内部配置。
type config struct {
	tokenDuration   time.Duration
	refreshDuration time.Duration

	// isBlacklisted 是外部注入的黑名单检查函数。
	// 返回 true 表示该 tokenID 已被拉黑（已注销/已撤回）。
	// 为 nil 时跳过黑名单检查。
	isBlacklisted func(tokenID string) bool
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
//         return rdb.Exists(ctx, "jwt:blacklist:"+tid).Val() > 0
//     })
//
//   - DB 查询：
//     gojwt.WithBlacklistFunc(func(tid string) bool {
//         return repo.IsTokenRevoked(tid)
//     })
func WithBlacklistFunc(fn func(tokenID string) bool) Option {
	return func(c *config) {
		c.isBlacklisted = fn
	}
}

// defaultConfig 返回默认配置。
func defaultConfig() config {
	return config{
		tokenDuration:   2 * time.Hour,
		refreshDuration: 7 * 24 * time.Hour,
	}
}
