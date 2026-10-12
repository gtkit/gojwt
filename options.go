package gojwt

import (
	"context"
	"fmt"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

// defaultRefreshWindow 是未配置 WithRefreshWindow 时的刷新窗口；
// token 有效期短于它时窗口取整段有效期。
const defaultRefreshWindow = 5 * time.Minute

// config 是 JwtHmac / JwtEd25519 / JwtRSA 的内部配置。
type config struct {
	tokenDuration    time.Duration
	refreshDuration  time.Duration
	refreshWindow    time.Duration
	refreshWindowSet bool
	parseLeeway      time.Duration
	cacheMaxEntries  int

	// parserOptions 是实例级解析选项，在包内默认选项之后、单次调用选项之前应用。
	parserOptions []jwtv5.ParserOption

	// 三个黑名单 Option 各写各的字段，构造期校验互斥后归一到 blacklistCheck。
	isBlacklisted             func(tokenID string) bool
	blacklistCheckFunc        func(tokenID string) (bool, error)
	blacklistCheckContextFunc func(ctx context.Context, tokenID string) (bool, error)
	blacklistCheck            func(ctx context.Context, tokenID string) (bool, error)

	// revocationCheck 接收完整 claims 的吊销回调，在黑名单检查之后执行。
	revocationCheck func(ctx context.Context, tokenClaims *claims.Claims) (bool, error)

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

// Option 配置 JwtHmac / JwtEd25519 / JwtRSA 实例的选项函数。
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

// WithRefreshDuration 设置会话最长时长，默认 7 天。
//
// 会话从首次签发时刻（claims 的 auth_time）起算，RefreshToken 只在
// auth_time + refreshDuration 之前允许刷新，且新 token 的 exp 不会越过这个终点；
// 到达终点后返回 ErrRefreshExpired，用户需要重新登录。
// 取值必须不短于 WithTokenDuration。
func WithRefreshDuration(t time.Duration) Option {
	return func(c *config) {
		c.refreshDuration = t
	}
}

// WithRefreshWindow 设置允许刷新的时间窗口：token 距过期不足此时长时才允许 RefreshToken。
//
// 默认 5 分钟；token 有效期短于 5 分钟时默认窗口等于整段有效期。
// 取值必须大于零且不超过 WithTokenDuration，等于有效期即整段有效期内随时可刷新。
func WithRefreshWindow(t time.Duration) Option {
	return func(c *config) {
		c.refreshWindow = t
		c.refreshWindowSet = true
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

// WithParserOptions 设置实例级的 jwtv5.ParserOption，每次解析都会应用。
//
// 典型用法是固定 issuer / audience 校验：
//
//	j, err := gojwt.NewJwtHmac(secret, gojwt.WithParserOptions(
//	    jwtv5.WithIssuer("auth-center"),
//	    jwtv5.WithAudience("web"),
//	))
//
// 应用顺序为包内默认选项 → 实例级选项 → 单次调用传入的选项。
// 实例级选项固定不变，CachedParseToken 的缓存对它仍然生效；单次调用选项仍会绕过缓存。
func WithParserOptions(opts ...jwtv5.ParserOption) Option {
	return func(c *config) {
		for _, opt := range opts {
			if opt != nil {
				c.parserOptions = append(c.parserOptions, opt)
			}
		}
	}
}

// WithBlacklistFunc 注入外部黑名单检查函数。
//
// fn 接收 tokenID（即 Claims.TokenID / RegisteredClaims.ID），
// 返回 true 表示该 token 已被拉黑，ParseToken / CachedParseToken 将返回 ErrTokenBlacklisted。
// 与 WithBlacklistCheckFunc、WithBlacklistCheckContextFunc 三者只能配置一个。
//
// 调用方可以注入任意实现，例如：
//
//   - 内存黑名单：
//     gojwt.WithBlacklistFunc(blacklist.In)
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
// 与 WithBlacklistFunc、WithBlacklistCheckContextFunc 三者只能配置一个。
func WithBlacklistCheckFunc(fn func(tokenID string) (bool, error)) Option {
	return func(c *config) {
		c.blacklistCheckFunc = fn
	}
}

// WithBlacklistCheckContextFunc 注入支持 context 取消和超时的黑名单检查函数。
// 与 WithBlacklistFunc、WithBlacklistCheckFunc 三者只能配置一个。
func WithBlacklistCheckContextFunc(fn func(ctx context.Context, tokenID string) (bool, error)) Option {
	return func(c *config) {
		c.blacklistCheckContextFunc = fn
	}
}

// WithRevocationCheck 注入接收完整 claims 的吊销回调。
//
// 回调在签名与 claims 校验通过、黑名单检查之后执行，CachedParseToken 缓存命中时同样执行。
// 返回 true 表示该 token 已被吊销，解析返回 ErrTokenBlacklisted；返回 error 时鉴权 fail closed。
// 典型用法是用户级吊销，例如改密后让该用户在改密时刻之前签发的全部 token 作废：
//
//	gojwt.WithRevocationCheck(func(ctx context.Context, c *claims.Claims) (bool, error) {
//	    cutoff, err := store.PasswordChangedAt(ctx, c.UserID)
//	    if err != nil {
//	        return false, err
//	    }
//	    return c.IssuedAt != nil && c.IssuedAt.Time.Before(cutoff), nil
//	})
func WithRevocationCheck(fn func(ctx context.Context, tokenClaims *claims.Claims) (bool, error)) Option {
	return func(c *config) {
		c.revocationCheck = fn
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
// 验证侧用 KeyRing 按 kid 汇集多个实例，或用 ParseKeyID 自行选键。
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
// PSS 系列更安全，推荐在新项目中使用；RS256 兼容性最好，适合与使用 RS256 的第三方系统互通。
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
	if !cfg.refreshWindowSet {
		cfg.refreshWindow = min(defaultRefreshWindow, cfg.tokenDuration)
	}
	if err := validateConfig(cfg); err != nil {
		return config{}, err
	}
	cfg.blacklistCheck = resolveBlacklistCheck(cfg)
	return cfg, nil
}

func validateConfig(cfg config) error {
	if cfg.tokenDuration <= 0 {
		return fmt.Errorf("%w: token duration must be greater than zero", ErrInvalidConfig)
	}
	if cfg.refreshDuration <= 0 {
		return fmt.Errorf("%w: refresh duration must be greater than zero", ErrInvalidConfig)
	}
	if cfg.refreshDuration < cfg.tokenDuration {
		return fmt.Errorf("%w: refresh duration %s must not be shorter than token duration %s; raise WithRefreshDuration or lower WithTokenDuration",
			ErrInvalidConfig, cfg.refreshDuration, cfg.tokenDuration)
	}
	if cfg.refreshWindow <= 0 {
		return fmt.Errorf("%w: refresh window must be greater than zero (WithRefreshWindow)", ErrInvalidConfig)
	}
	if cfg.refreshWindow > cfg.tokenDuration {
		return fmt.Errorf("%w: refresh window %s must not exceed token duration %s (WithRefreshWindow)",
			ErrInvalidConfig, cfg.refreshWindow, cfg.tokenDuration)
	}
	if cfg.parseLeeway < 0 {
		return fmt.Errorf("%w: parse leeway must be greater than or equal to zero", ErrInvalidConfig)
	}
	if cfg.cacheMaxEntries < 0 {
		return fmt.Errorf("%w: cache max entries must be greater than or equal to zero", ErrInvalidConfig)
	}
	if countBlacklistOptions(cfg) > 1 {
		return fmt.Errorf("%w: only one of WithBlacklistFunc, WithBlacklistCheckFunc, WithBlacklistCheckContextFunc may be set", ErrInvalidConfig)
	}
	return nil
}

func countBlacklistOptions(cfg config) int {
	n := 0
	if cfg.isBlacklisted != nil {
		n++
	}
	if cfg.blacklistCheckFunc != nil {
		n++
	}
	if cfg.blacklistCheckContextFunc != nil {
		n++
	}
	return n
}

// resolveBlacklistCheck 把三种黑名单回调归一为一种签名，解析路径只需处理一条分支。
func resolveBlacklistCheck(cfg config) func(ctx context.Context, tokenID string) (bool, error) {
	switch {
	case cfg.blacklistCheckContextFunc != nil:
		return cfg.blacklistCheckContextFunc
	case cfg.blacklistCheckFunc != nil:
		fn := cfg.blacklistCheckFunc
		return func(_ context.Context, tokenID string) (bool, error) {
			return fn(tokenID)
		}
	case cfg.isBlacklisted != nil:
		fn := cfg.isBlacklisted
		return func(_ context.Context, tokenID string) (bool, error) {
			return fn(tokenID), nil
		}
	default:
		return nil
	}
}
